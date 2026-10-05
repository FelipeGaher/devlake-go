package authmw

import (
	"sync"
	"time"
)

// DefaultCacheTTL is how long a subject → principal resolution is reused.
const DefaultCacheTTL = 5 * time.Minute

// DefaultCacheMaxEntries bounds the cache between prune ticks — well above any
// realistic distinct-user count across the shared realm.
const DefaultCacheMaxEntries = 10_000

const cachePruneEvery = 2 * time.Minute

// Cache memoizes Config.Resolve per Keycloak subject. An entry is also
// treated as a miss when the token's email differs from the cached one, so an
// email change in Keycloak re-runs Resolve (which can sync it) immediately
// instead of after the TTL.
//
// In-process state: correct only for a single backend replica. Invalidate on
// one replica doesn't reach the others.
type Cache[T any] struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry[T]
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
}

type cacheEntry[T any] struct {
	val    T
	email  string
	expiry time.Time
}

type CacheOption func(*cacheOpts)

type cacheOpts struct {
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
}

// WithTTL overrides DefaultCacheTTL.
func WithTTL(d time.Duration) CacheOption { return func(o *cacheOpts) { o.ttl = d } }

// WithMaxEntries overrides DefaultCacheMaxEntries.
func WithMaxEntries(n int) CacheOption { return func(o *cacheOpts) { o.maxEntries = n } }

// WithCacheClock injects a clock (tests).
func WithCacheClock(now func() time.Time) CacheOption { return func(o *cacheOpts) { o.now = now } }

// NewCache creates a Cache and starts its background prune goroutine. Create
// exactly one per process and share the pointer with everything that calls
// Invalidate (e.g. a billing webhook after a plan change, account deletion).
func NewCache[T any](opts ...CacheOption) *Cache[T] {
	c := newCache[T](opts...)
	go c.pruneLoop()
	return c
}

func newCache[T any](opts ...CacheOption) *Cache[T] {
	o := cacheOpts{ttl: DefaultCacheTTL, maxEntries: DefaultCacheMaxEntries, now: time.Now}
	for _, f := range opts {
		f(&o)
	}
	if o.ttl <= 0 {
		o.ttl = DefaultCacheTTL
	}
	if o.maxEntries <= 0 {
		o.maxEntries = DefaultCacheMaxEntries
	}
	if o.now == nil {
		o.now = time.Now
	}
	return &Cache[T]{entries: make(map[string]cacheEntry[T]), ttl: o.ttl, maxEntries: o.maxEntries, now: o.now}
}

// Invalidate immediately drops sub, so its next request re-runs Resolve.
func (c *Cache[T]) Invalidate(sub string) {
	c.mu.Lock()
	delete(c.entries, sub)
	c.mu.Unlock()
}

// Len reports the number of cached subjects.
func (c *Cache[T]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache[T]) get(sub, email string) (T, bool) {
	c.mu.RLock()
	e, ok := c.entries[sub]
	c.mu.RUnlock()
	if !ok || c.now().After(e.expiry) || e.email != email {
		var zero T
		return zero, false
	}
	return e.val, true
}

func (c *Cache[T]) set(sub, email string, val T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[sub]; !exists && len(c.entries) >= c.maxEntries {
		c.evictOldestLocked()
	}
	c.entries[sub] = cacheEntry[T]{val: val, email: email, expiry: c.now().Add(c.ttl)}
}

func (c *Cache[T]) evictOldestLocked() {
	var oldestSub string
	var oldest time.Time
	found := false
	for sub, e := range c.entries {
		if !found || e.expiry.Before(oldest) {
			oldestSub, oldest, found = sub, e.expiry, true
		}
	}
	if found {
		delete(c.entries, oldestSub)
	}
}

func (c *Cache[T]) pruneLoop() {
	t := time.NewTicker(cachePruneEvery)
	defer t.Stop()
	for range t.C {
		c.prune()
	}
}

func (c *Cache[T]) prune() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for sub, e := range c.entries {
		if now.After(e.expiry) {
			delete(c.entries, sub)
		}
	}
}
