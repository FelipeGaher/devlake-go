// Package ratelimit is an in-memory, per-key token-bucket rate limiter
// (golang.org/x/time/rate) backed by a pruned, size-capped map. Use one Store
// per policy: per-IP HTTP limiting, per-user HTTP limiting, per-actor push
// throttling, per-reporter abuse limiting, etc.
//
// State is per-process: correct for a single backend replica. Running several
// replicas behind a load balancer multiplies the effective limit by the
// replica count.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DefaultMaxEntries hard-caps map growth between prune ticks — a burst of many
// distinct keys (e.g. spoofed X-Forwarded-For values) could otherwise grow the
// map faster than it's pruned.
const DefaultMaxEntries = 50_000

const (
	pruneEvery = 2 * time.Minute
	idleAfter  = 5 * time.Minute
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Store is a set of independent token buckets, one per key, all sharing the
// same rps/burst configuration.
type Store struct {
	mu         sync.Mutex
	entries    map[string]*entry
	rps        rate.Limit
	burst      int
	maxEntries int
	now        func() time.Time
}

type Option func(*Store)

// WithMaxEntries overrides DefaultMaxEntries (n <= 0 keeps the default).
func WithMaxEntries(n int) Option {
	return func(s *Store) {
		if n > 0 {
			s.maxEntries = n
		}
	}
}

// WithClock injects a clock (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// NewStore creates a Store allowing rps sustained requests per second per key
// with bursts up to burst, and starts its background pruning goroutine (idle
// keys are dropped after 5 minutes). Stores are meant to be created once at
// startup and live for the process lifetime.
func NewStore(rps float64, burst int, opts ...Option) *Store {
	s := newStore(rps, burst, opts...)
	go s.pruneLoop()
	return s
}

// PerMinute is NewStore with a per-minute rate.
func PerMinute(n float64, burst int, opts ...Option) *Store {
	return NewStore(n/60, burst, opts...)
}

func newStore(rps float64, burst int, opts ...Option) *Store {
	s := &Store{
		entries:    make(map[string]*entry),
		rps:        rate.Limit(rps),
		burst:      burst,
		maxEntries: DefaultMaxEntries,
		now:        time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Store) pruneLoop() {
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for range t.C {
		s.prune()
	}
}

func (s *Store) prune() {
	cutoff := s.now().Add(-idleAfter)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if e.lastSeen.Before(cutoff) {
			delete(s.entries, k)
		}
	}
}

// Allow reports whether the caller identified by key may proceed right now,
// consuming one token from key's bucket if so. Safe for concurrent use.
func (s *Store) Allow(key string) bool {
	now := s.now()
	s.mu.Lock()
	e, ok := s.entries[key]
	if !ok {
		if len(s.entries) >= s.maxEntries {
			s.evictLRULocked()
		}
		e = &entry{limiter: rate.NewLimiter(s.rps, s.burst)}
		s.entries[key] = e
	}
	e.lastSeen = now
	s.mu.Unlock()
	return e.limiter.AllowN(now, 1)
}

// evictLRULocked drops the least-recently-seen key. Caller holds s.mu. O(n),
// but only runs when the map is already at its cap.
func (s *Store) evictLRULocked() {
	var oldestKey string
	var oldest time.Time
	found := false
	for k, e := range s.entries {
		if !found || e.lastSeen.Before(oldest) {
			oldestKey, oldest, found = k, e.lastSeen, true
		}
	}
	if found {
		delete(s.entries, oldestKey)
	}
}

// Len reports the number of tracked keys.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
