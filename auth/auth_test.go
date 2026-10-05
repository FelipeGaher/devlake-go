package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/FelipeGaher/devlake-go/auth"
)

const issuer = "http://kc.test/realms/example"

// NewTestJWKS-style helpers live here rather than in an exported testutil
// package to keep the library's public API small.
func newVerifier(t *testing.T) (*auth.Verifier, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	v, err := auth.New(context.Background(), srv.URL, []string{issuer}, []string{"app-frontend", "app-loadtest"})
	if err != nil {
		t.Fatal(err)
	}
	return v, key
}

func sign(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, c)
	tok.Header["kid"] = "k1"
	var signKey any = key
	if method == jwt.SigningMethodHS256 {
		signKey = []byte("shared-secret")
	}
	s, err := tok.SignedString(signKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerify(t *testing.T) {
	v, key := newVerifier(t)
	now := time.Now()
	claims := func(mod func(jwt.MapClaims)) jwt.MapClaims {
		c := jwt.MapClaims{
			"iss": issuer, "azp": "app-frontend", "sub": "user-1", "email": "a@b.c",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		}
		if mod != nil {
			mod(c)
		}
		return c
	}

	ok := []struct {
		name string
		c    jwt.MapClaims
	}{
		{"valid", claims(nil)},
		{"second allowed client", claims(func(c jwt.MapClaims) { c["azp"] = "app-loadtest" })},
		{"expired 10s ago, within leeway", claims(func(c jwt.MapClaims) { c["exp"] = now.Add(-10 * time.Second).Unix() })},
		{"issued 10s in the future (skewed clock)", claims(func(c jwt.MapClaims) {
			c["iat"] = now.Add(10 * time.Second).Unix()
			c["nbf"] = now.Add(10 * time.Second).Unix()
		})},
	}
	for _, tc := range ok {
		if id, err := v.Verify(context.Background(), sign(t, key, jwt.SigningMethodRS256, tc.c)); err != nil || id.Subject != "user-1" {
			t.Errorf("%s: %v (subject %q), want accepted", tc.name, err, id.Subject)
		}
	}

	bad := []struct {
		name   string
		method jwt.SigningMethod
		c      jwt.MapClaims
	}{
		{"expired a minute ago", jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Minute).Unix() })},
		{"no exp", jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { delete(c, "exp") })},
		{"wrong issuer", jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { c["iss"] = "http://evil/realms/example" })},
		{"another app's client", jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { c["azp"] = "other-app-frontend" })},
		{"no azp", jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { delete(c, "azp") })},
		{"no sub", jwt.SigningMethodRS256, claims(func(c jwt.MapClaims) { delete(c, "sub") })},
		{"HS256 (alg confusion)", jwt.SigningMethodHS256, claims(nil)},
	}
	for _, tc := range bad {
		_, err := v.Verify(context.Background(), sign(t, key, tc.method, tc.c))
		if err == nil {
			t.Errorf("%s: accepted, want refused", tc.name)
		} else if !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("%s: error %v does not wrap ErrInvalidToken", tc.name, err)
		}
	}
	if _, err := v.Verify(context.Background(), "not-a-jwt"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("garbage token: %v, want ErrInvalidToken", err)
	}
}

func TestVerify_Roles(t *testing.T) {
	v, key := newVerifier(t)
	now := time.Now()
	tok := sign(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer, "azp": "app-frontend", "sub": "u", "exp": now.Add(time.Minute).Unix(),
		"realm_access":    map[string]any{"roles": []string{"admin", "offline_access"}},
		"resource_access": map[string]any{"ops-console": map[string]any{"roles": []string{"operator"}}},
	})
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if !id.HasRealmRole("admin") || id.HasRealmRole("nope") {
		t.Errorf("realm roles = %v", id.RealmRoles)
	}
	if !id.HasClientRole("ops-console", "operator") || id.HasClientRole("app-frontend", "operator") {
		t.Errorf("client roles = %v", id.ClientRoles)
	}
}

func TestNew_RequiresIssuersAndAzps(t *testing.T) {
	if _, err := auth.New(context.Background(), "http://unused", nil, []string{"x"}); err == nil {
		t.Error("no issuers: want error")
	}
	if _, err := auth.New(context.Background(), "http://unused", []string{issuer}, []string{" ", ""}); err == nil {
		t.Error("blank azps: want error")
	}
}

func TestSplitList(t *testing.T) {
	got := auth.SplitList(" a, b ,,c ")
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SplitList = %v, want %v", got, want)
	}
}

func TestDisplayNameFallback(t *testing.T) {
	tests := []struct {
		id   auth.Identity
		want string
	}{
		{auth.Identity{PreferredUsername: "alice", Email: "a@x.io"}, "alice"},
		{auth.Identity{PreferredUsername: "alice@gmail.com", Email: "alice@gmail.com"}, "alice"},
		{auth.Identity{Email: "bob@x.io"}, "bob"},
		{auth.Identity{}, "Player"},
		{auth.Identity{Email: "@weird"}, "Player"},
	}
	for _, tt := range tests {
		if got := auth.DisplayNameFallback(tt.id, "Player"); got != tt.want {
			t.Errorf("DisplayNameFallback(%+v) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

// A cancelled startup context must not break verification afterwards (the
// background refresh is tied to the process, not to New's ctx).
func TestNew_CancelledStartupContext(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	v, err := auth.New(ctx, srv.URL, []string{issuer}, []string{"app-frontend"})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	tok := sign(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer, "azp": "app-frontend", "sub": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("verify after startup ctx cancelled: %v", err)
	}
}

// An unreachable JWKS at startup is not fatal; tokens are refused until a
// fetch succeeds.
func TestNew_UnreachableJWKSIsNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	v, err := auth.New(context.Background(), url, []string{issuer}, []string{"app-frontend"})
	if err != nil {
		t.Fatalf("New with unreachable JWKS: %v, want nil error", err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := sign(t, key, jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer, "azp": "app-frontend", "sub": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("verify with no keys: %v, want ErrInvalidToken", err)
	}
}
