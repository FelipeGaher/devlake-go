package authmw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/FelipeGaher/devlake-go/accesslog"
	"github.com/FelipeGaher/devlake-go/auth"
	"github.com/FelipeGaher/devlake-go/httpx"
)

type fakeVerifier map[string]auth.Identity

func (f fakeVerifier) Verify(_ context.Context, token string) (auth.Identity, error) {
	if id, ok := f[token]; ok {
		return id, nil
	}
	return auth.Identity{}, auth.ErrInvalidToken
}

type principal struct {
	UserID int64
	Plan   string
}

func setup(t *testing.T, cache *Cache[principal]) (http.Handler, *int) {
	t.Helper()
	calls := 0
	v := fakeVerifier{
		"tok-alice": {Subject: "sub-a", Email: "a@x.io", RealmRoles: []string{"admin"}},
		"tok-bob":   {Subject: "sub-b", Email: "b@x.io"},
		"tok-fail":  {Subject: "sub-f"},
	}
	mw := Middleware(Config[principal]{
		Verifier: v,
		Cache:    cache,
		Resolve: func(_ context.Context, id auth.Identity) (principal, error) {
			calls++
			if id.Subject == "sub-f" {
				return principal{}, errors.New("db down")
			}
			return principal{UserID: int64(calls), Plan: "FREE"}, nil
		},
		LogUserID: func(p principal) int64 { return p.UserID },
	})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := Principal[principal](r.Context())
		id, _ := IdentityFrom(r.Context())
		httpx.WriteJSON(w, 200, map[string]any{"user_id": p.UserID, "sub": id.Subject})
	}))
	return h, &calls
}

func do(h http.Handler, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/x", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMiddleware_StatusCodes(t *testing.T) {
	h, _ := setup(t, nil)
	cases := map[string]int{
		"":                 401,
		"Basic abc":        401,
		"Bearer nope":      401,
		"Bearer tok-alice": 200,
		"bearer tok-alice": 200,
		"Bearer tok-fail":  500,
	}
	for hdr, want := range cases {
		rec := do(h, hdr)
		if rec.Code != want {
			t.Errorf("Authorization %q: status %d, want %d", hdr, rec.Code, want)
		}
		if want != 200 {
			var body httpx.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" {
				t.Errorf("Authorization %q: body %q is not an ErrorResponse", hdr, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Authorization %q: Content-Type %q", hdr, ct)
			}
		}
	}
}

func TestMiddleware_CachesPerSubject(t *testing.T) {
	cache := newCache[principal]()
	h, calls := setup(t, cache)
	for i := 0; i < 3; i++ {
		do(h, "Bearer tok-alice")
	}
	if *calls != 1 {
		t.Fatalf("Resolve called %d times for one subject, want 1", *calls)
	}
	do(h, "Bearer tok-bob")
	if *calls != 2 {
		t.Fatalf("Resolve called %d times after second subject, want 2", *calls)
	}
	cache.Invalidate("sub-a")
	do(h, "Bearer tok-alice")
	if *calls != 3 {
		t.Fatalf("Resolve called %d times after Invalidate, want 3", *calls)
	}
	// Failures are not cached.
	do(h, "Bearer tok-fail")
	do(h, "Bearer tok-fail")
	if *calls != 5 {
		t.Fatalf("Resolve called %d times after 2 failures, want 5", *calls)
	}
}

func TestCache_EmailChangeIsMiss(t *testing.T) {
	c := newCache[principal]()
	c.set("s", "old@x.io", principal{UserID: 1})
	if _, ok := c.get("s", "old@x.io"); !ok {
		t.Fatal("same email: want hit")
	}
	if _, ok := c.get("s", "new@x.io"); ok {
		t.Fatal("changed email: want miss")
	}
}

func TestCache_TTLAndCap(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := newCache[principal](WithTTL(time.Minute), WithMaxEntries(2), WithCacheClock(func() time.Time { return now }))
	c.set("a", "", principal{UserID: 1})
	now = now.Add(time.Second)
	c.set("b", "", principal{UserID: 2})
	now = now.Add(time.Second)
	c.set("c", "", principal{UserID: 3}) // at cap → evicts "a" (soonest expiry)
	if _, ok := c.get("a", ""); ok {
		t.Error("expected a evicted")
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2", c.Len())
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.get("c", ""); ok {
		t.Error("expected c expired")
	}
	c.prune()
	if c.Len() != 0 {
		t.Errorf("Len after prune = %d, want 0", c.Len())
	}
}

func TestAccessLogReceivesUserID(t *testing.T) {
	h, _ := setup(t, nil)
	var buf bytes.Buffer
	accesslog.SetOutput(&buf)
	t.Cleanup(func() { accesslog.SetOutput(os.Stdout) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	httpx.AccessLog(h).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var e accesslog.Entry
	if err := json.Unmarshal(buf.Bytes(), &e); err != nil {
		t.Fatalf("access log line %q: %v", buf.String(), err)
	}
	if e.UserID != 1 || e.StatusCode != 200 || e.Type != accesslog.TypeIncoming {
		t.Errorf("entry = %+v, want user_id 1, status 200, incoming", e)
	}
}

func TestRequireRoles(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	run := func(mw func(http.Handler) http.Handler, id *auth.Identity) int {
		req := httptest.NewRequest("GET", "/admin", nil)
		if id != nil {
			req = req.WithContext(WithPrincipal(req.Context(), principal{}, *id))
		}
		rec := httptest.NewRecorder()
		mw(ok).ServeHTTP(rec, req)
		return rec.Code
	}
	admin := &auth.Identity{RealmRoles: []string{"admin"}, ClientRoles: map[string][]string{"ops-console": {"op"}}}
	user := &auth.Identity{}
	if c := run(RequireRealmRole("admin", nil), admin); c != 204 {
		t.Errorf("admin realm role: %d", c)
	}
	if c := run(RequireRealmRole("admin", nil), user); c != 403 {
		t.Errorf("non-admin: %d", c)
	}
	if c := run(RequireRealmRole("admin", nil), nil); c != 403 {
		t.Errorf("no identity: %d", c)
	}
	if c := run(RequireClientRole("ops-console", "op", nil), admin); c != 204 {
		t.Errorf("client role: %d", c)
	}
	if c := run(RequireClientRole("other", "op", nil), admin); c != 403 {
		t.Errorf("client role on other client: %d", c)
	}
}

func TestResolveReject(t *testing.T) {
	calls := 0
	v := fakeVerifier{"tok-noaccess": {Subject: "sub-n"}}
	cache := newCache[principal]()
	h := Middleware(Config[principal]{
		Verifier: v,
		Cache:    cache,
		Resolve: func(_ context.Context, id auth.Identity) (principal, error) {
			calls++
			return principal{}, Reject(http.StatusForbidden, "no_access", "no app role")
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for i := 0; i < 2; i++ {
		rec := do(h, "Bearer tok-noaccess")
		var body httpx.ErrorResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 403 || body.Error != "no_access" || body.Message != "no app role" {
			t.Fatalf("got %d %+v, want 403 no_access", rec.Code, body)
		}
	}
	if calls != 2 || cache.Len() != 0 {
		t.Errorf("rejections must not be cached: calls=%d cached=%d", calls, cache.Len())
	}
	var rej *RejectError
	if err := Reject(401, "x", "y"); !errors.As(err, &rej) || rej.Status != 401 {
		t.Errorf("Reject() = %v", err)
	}
}
