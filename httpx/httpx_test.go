package httpx

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"

	"github.com/FelipeGaher/devlake-go/ratelimit"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name, xff, xri, remote, want string
	}{
		{"rightmost XFF wins over spoofed leading values", "1.1.1.1, 6.6.6.6, 203.0.113.9", "", "10.0.0.1:5000", "203.0.113.9"},
		{"single XFF", "203.0.113.9", "", "10.0.0.1:5000", "203.0.113.9"},
		{"X-Real-IP fallback", "", " 198.51.100.4 ", "10.0.0.1:5000", "198.51.100.4"},
		{"RemoteAddr fallback", "", "", "192.0.2.7:443", "192.0.2.7"},
		{"RemoteAddr without port", "", "", "192.0.2.7", "192.0.2.7"},
		{"trailing empty XFF entry falls through", "1.1.1.1, ", "", "192.0.2.7:1", "192.0.2.7"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remote
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		if tt.xri != "" {
			r.Header.Set("X-Real-IP", tt.xri)
		}
		if got := ClientIP(r); got != tt.want {
			t.Errorf("%s: ClientIP = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestKeyedRateLimit(t *testing.T) {
	store := ratelimit.NewStore(1.0/60, 2)
	h := KeyedRateLimit(store, func(r *http.Request) string { return r.Header.Get("X-Key") }, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	run := func(key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Key", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	run("a")
	run("a")
	rec := run("a")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("third call: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != CodeRateLimited {
		t.Errorf("body = %q", rec.Body.String())
	}
	for i := 0; i < 5; i++ {
		if c := run("").Code; c != 204 {
			t.Fatalf("empty key must not be limited, got %d", c)
		}
	}
}

func TestCustomErrorWriter(t *testing.T) {
	var gotCode string
	ew := ErrorWriter(func(w http.ResponseWriter, status int, code, _ string) {
		gotCode = code
		w.WriteHeader(status)
	})
	h := KeyedRateLimit(ratelimit.NewStore(1.0/60, 1), func(*http.Request) string { return "k" }, ew)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for i := 0; i < 2; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}
	if gotCode != CodeRateLimited {
		t.Errorf("custom ErrorWriter got code %q", gotCode)
	}
}

func TestFormatValidationError(t *testing.T) {
	type req struct {
		DisplayName string   `json:"display_name" validate:"required"`
		Username    string   `json:"username" validate:"omitempty,min=3,username_chars"`
		Tags        []string `json:"tags" validate:"max=2"`
		Color       string   `json:"color" validate:"omitempty,hexcolor"`
	}
	v := NewValidator()
	_ = v.RegisterValidation("username_chars", func(fl validator.FieldLevel) bool { return true })
	custom := map[string]string{"username_chars": "may only contain letters, numbers, and underscores"}

	tests := []struct {
		in   req
		want string
	}{
		{req{}, "display name is required"},
		{req{DisplayName: "x", Username: "ab"}, "username must be at least 3 characters"},
		{req{DisplayName: "x", Tags: []string{"a", "b", "c"}}, "tags must have at most 2 item(s)"},
		{req{DisplayName: "x", Color: "red"}, "color must be a valid hex color"},
	}
	for _, tt := range tests {
		if got := FormatValidationError(v.Struct(tt.in), custom); got != tt.want {
			t.Errorf("FormatValidationError = %q, want %q", got, tt.want)
		}
	}
	if got := FormatValidationError(io.EOF, nil); got != "invalid request" {
		t.Errorf("non-validation error: %q", got)
	}
}

func TestMaxBytesAndSecurityHeaders(t *testing.T) {
	var readErr error
	h := SecurityHeaders(MaxBytes(4)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", strings.NewReader("123456789")))
	if readErr == nil {
		t.Error("body over the cap should fail to read")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("security headers missing: %v", rec.Header())
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	ipOf, err := TrustedProxyClientIP([]string{"127.0.0.1/32", " 10.0.0.0/8 ", "", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, remote, xff, want string
	}{
		{"direct client: forged XFF ignored", "203.0.113.5:4000", "6.6.6.6", "203.0.113.5"},
		{"via trusted proxy: rightmost non-proxy XFF", "127.0.0.1:5000", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"via proxy chain: skips trusted hops", "127.0.0.1:5000", "198.51.100.7, 10.1.2.3", "198.51.100.7"},
		{"bare-IP proxy entry", "192.0.2.1:80", "198.51.100.9", "198.51.100.9"},
		{"trusted proxy, no XFF", "127.0.0.1:5000", "", "127.0.0.1"},
		{"trusted proxy, only junk/trusted XFF", "127.0.0.1:5000", "not-an-ip, 10.0.0.1", "127.0.0.1"},
		{"IPv4-mapped IPv6 peer is trusted", "[::ffff:127.0.0.1]:5000", "198.51.100.7", "198.51.100.7"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remote
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		if got := ipOf(r); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}

	none, _ := TrustedProxyClientIP(nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := none(r); got != "127.0.0.1" {
		t.Errorf("no trusted proxies: got %q, want RemoteAddr", got)
	}
	if _, err := TrustedProxyClientIP([]string{"10.0.0.0/33"}); err == nil {
		t.Error("invalid CIDR: want error")
	}
}
