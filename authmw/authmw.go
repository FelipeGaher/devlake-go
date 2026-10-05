// Package authmw is net/http authentication middleware for services that
// accept Keycloak access tokens. It verifies the bearer token (package auth), resolves the caller
// to an app-defined principal T (typically by find-or-creating the local user
// row keyed on the Keycloak subject), caches that resolution per subject, and
// stores both the principal and the token's Identity in the request context.
//
// T is whatever the app needs on every request — e.g.
// struct{ UserID int64; Plan string }, or just the user id.
package authmw

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/FelipeGaher/devlake-go/auth"
	"github.com/FelipeGaher/devlake-go/httpx"
)

// Config configures Middleware.
type Config[T any] struct {
	// Verifier checks the bearer token. Required.
	Verifier auth.TokenVerifier
	// Resolve maps a verified identity to the app principal, e.g. a race-safe
	// INSERT ... ON CONFLICT find-or-create on the users table. Called only
	// on a cache miss. Required.
	Resolve func(ctx context.Context, id auth.Identity) (T, error)
	// Cache memoizes Resolve per subject. Optional (nil = resolve on every
	// request). Must be a single shared instance per process: anything that
	// calls Invalidate needs the same pointer the middleware uses.
	Cache *Cache[T]
	// LogUserID, if set, reports the principal's user id to httpx.AccessLog.
	LogUserID func(T) int64
	// ErrorWriter writes 401/500 responses. Optional (default httpx.WriteError).
	ErrorWriter httpx.ErrorWriter
}

type principalKey struct{}
type identityKey struct{}

// Middleware returns the authentication middleware. Requests without a valid
// bearer token get 401; a Resolve failure gets 500.
func Middleware[T any](cfg Config[T]) func(http.Handler) http.Handler {
	if cfg.Verifier == nil || cfg.Resolve == nil {
		panic("authmw: Config.Verifier and Config.Resolve are required")
	}
	ew := cfg.ErrorWriter.OrDefault()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := BearerToken(r)
			if token == "" {
				ew(w, http.StatusUnauthorized, httpx.CodeUnauthorized, "missing bearer token")
				return
			}
			id, err := cfg.Verifier.Verify(r.Context(), token)
			if err != nil {
				ew(w, http.StatusUnauthorized, httpx.CodeUnauthorized, "invalid or expired token")
				return
			}

			var p T
			cached := false
			if cfg.Cache != nil {
				p, cached = cfg.Cache.get(id.Subject, id.Email)
			}
			if !cached {
				p, err = cfg.Resolve(r.Context(), id)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						slog.ErrorContext(r.Context(), "authmw: resolve principal failed", "sub", id.Subject, "error", err)
					}
					ew(w, http.StatusInternalServerError, httpx.CodeInternal, "could not resolve user")
					return
				}
				if cfg.Cache != nil {
					cfg.Cache.set(id.Subject, id.Email, p)
				}
			}

			if cfg.LogUserID != nil {
				httpx.SetLogUserID(r.Context(), cfg.LogUserID(p))
			}
			ctx := context.WithValue(r.Context(), principalKey{}, p)
			ctx = context.WithValue(ctx, identityKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Principal returns the principal Middleware stored in ctx.
func Principal[T any](ctx context.Context) (T, bool) {
	p, ok := ctx.Value(principalKey{}).(T)
	return p, ok
}

// IdentityFrom returns the verified token identity Middleware stored in ctx.
// Roles always come from here (the current token), never from the cache.
func IdentityFrom(ctx context.Context) (auth.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(auth.Identity)
	return id, ok
}

// WithPrincipal returns ctx carrying p and id, as Middleware would. Intended
// for handler tests.
func WithPrincipal[T any](ctx context.Context, p T, id auth.Identity) context.Context {
	ctx = context.WithValue(ctx, principalKey{}, p)
	return context.WithValue(ctx, identityKey{}, id)
}

// BearerToken extracts the token from "Authorization: Bearer <token>", or "".
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// RequireRealmRole allows the request only if the caller has role in
// realm_access.roles; otherwise 403. Mount after Middleware.
func RequireRealmRole(role string, ew httpx.ErrorWriter) func(http.Handler) http.Handler {
	return require(func(id auth.Identity) bool { return id.HasRealmRole(role) }, ew)
}

// RequireClientRole allows the request only if the caller has role in
// resource_access.<client>.roles; otherwise 403. Mount after Middleware.
func RequireClientRole(client, role string, ew httpx.ErrorWriter) func(http.Handler) http.Handler {
	return require(func(id auth.Identity) bool { return id.HasClientRole(client, role) }, ew)
}

func require(ok func(auth.Identity) bool, ew httpx.ErrorWriter) func(http.Handler) http.Handler {
	ew = ew.OrDefault()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id, found := IdentityFrom(r.Context()); found && ok(id) {
				next.ServeHTTP(w, r)
				return
			}
			ew(w, http.StatusForbidden, httpx.CodeForbidden, "forbidden")
		})
	}
}
