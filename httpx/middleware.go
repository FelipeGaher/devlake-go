package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/FelipeGaher/devlake-go/accesslog"
	"github.com/FelipeGaher/devlake-go/ratelimit"
)

// ClientIP returns the caller's IP, trusting X-Forwarded-For from any peer:
// it takes the rightmost value, which is the address that connected to a
// reverse proxy that appends to the header (e.g. nginx's
// $proxy_add_x_forwarded_for); leading values are client-controlled and
// ignored. Falls back to X-Real-IP, then RemoteAddr.
//
// Only safe when the backend is reachable solely through that proxy: a
// client connecting directly can send any X-Forwarded-For it likes. Prefer
// TrustedProxyClientIP, which only honours the header from known proxies.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// KeyedRateLimit limits requests by keyFn(r) using store. An empty key is not
// limited (e.g. an unauthenticated request reaching a per-user limiter).
// Responds 429 with Retry-After: 1.
func KeyedRateLimit(store *ratelimit.Store, keyFn func(*http.Request) string, ew ErrorWriter) func(http.Handler) http.Handler {
	ew = ew.OrDefault()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if key := keyFn(r); key != "" && !store.Allow(key) {
				w.Header().Set("Retry-After", "1")
				ew(w, http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IPRateLimit limits requests per ClientIP. Apply before authentication. To
// identify clients with TrustedProxyClientIP instead, use KeyedRateLimit:
//
//	ipOf, err := httpx.TrustedProxyClientIP(cfg.TrustedProxies)
//	r.Use(httpx.KeyedRateLimit(ratelimit.NewStore(50, 100), ipOf, nil))
func IPRateLimit(rps float64, burst int, ew ErrorWriter) func(http.Handler) http.Handler {
	return KeyedRateLimit(ratelimit.NewStore(rps, burst), ClientIP, ew)
}

// SecurityHeaders sets a safe-by-default header set for a JSON API.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// DefaultMaxBodyBytes is a sensible request body cap for a JSON API.
const DefaultMaxBodyBytes = 1 << 20 // 1 MiB

// MaxBytes caps every request body at n bytes (reads past it fail).
func MaxBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

type logSlotKey struct{}

// SetLogUserID records the authenticated user id for the AccessLog line of
// the current request. Auth middleware calls it (authmw does so when
// configured with a LogUserID func). It is a no-op outside AccessLog.
//
// A slot is needed because AccessLog only holds the *outer* request: auth
// middleware mounted after it attaches the user to a derived request
// (r.WithContext), which AccessLog never sees.
func SetLogUserID(ctx context.Context, id int64) {
	if slot, ok := ctx.Value(logSlotKey{}).(*int64); ok {
		*slot = id
	}
}

// AccessLog writes one accesslog.Entry (type "incoming") per request. Mount
// it early (right after chi's RequestID) so it wraps every layer; the user id
// comes from SetLogUserID.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var uid int64
		r = r.WithContext(context.WithValue(r.Context(), logSlotKey{}, &uid))
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		accesslog.Write(accesslog.Entry{
			Type:       accesslog.TypeIncoming,
			Timestamp:  start.UTC().Format(accesslog.TimeFormat),
			ClientIP:   ClientIP(r),
			HTTPMethod: r.Method,
			RequestURI: r.URL.RequestURI(),
			StatusCode: ww.Status(),
			BytesSent:  ww.BytesWritten(),
			DurationMs: float64(time.Since(start).Microseconds()) / 1000.0,
			UserID:     uid,
			UserAgent:  r.Header.Get("User-Agent"),
		})
	})
}
