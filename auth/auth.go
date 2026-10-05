// Package auth verifies access tokens issued by a Keycloak realm: RS256 signatures against the realm's JWKS (fetched at startup,
// refreshed in the background by keyfunc), plus issuer and authorized-party
// (azp) allow-lists.
//
// Why azp is mandatory: when several applications share one realm, they all
// get tokens with the same issuer, signed by the same JWKS. A valid signature
// + issuer therefore only proves "some client in this realm requested this
// token". Keycloak's `aud` defaults to the generic
// "account" for every client, so it can't tell the apps apart; `azp` (the
// client id that requested the token) is the claim that does.
//
// Revocation: tokens are verified offline against the realm's signing keys,
// so a user disabled in Keycloak keeps API access until their access token
// expires (the realm's accessTokenLifespan).
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// ClockSkewLeeway is how far apart Keycloak's clock and ours may drift before
// a fresh token is refused as "not valid yet" or a just-refreshed one as
// expired.
const ClockSkewLeeway = 30 * time.Second

// ErrInvalidToken wraps every verification failure, so callers can map any
// of them to 401 with errors.Is.
var ErrInvalidToken = errors.New("auth: invalid token")

// Identity is what the API learns about the caller from a verified token.
type Identity struct {
	Subject           string
	Email             string
	Name              string
	PreferredUsername string
	// Azp is the Keycloak client id that requested the token.
	Azp string
	// RealmRoles are realm_access.roles.
	RealmRoles []string
	// ClientRoles are resource_access.<client>.roles, keyed by client id.
	ClientRoles map[string][]string
}

// HasRealmRole reports whether role is one of the caller's realm roles.
func (id Identity) HasRealmRole(role string) bool {
	for _, r := range id.RealmRoles {
		if r == role {
			return true
		}
	}
	return false
}

// HasClientRole reports whether role is one of the caller's roles on client.
func (id Identity) HasClientRole(client, role string) bool {
	for _, r := range id.ClientRoles[client] {
		if r == role {
			return true
		}
	}
	return false
}

// TokenVerifier is the interface the HTTP middleware depends on, so tests can
// substitute a fake without running a JWKS server.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (Identity, error)
}

// Verifier implements TokenVerifier against a Keycloak realm.
type Verifier struct {
	jwks    keyfunc.Keyfunc
	issuers map[string]bool
	azps    map[string]bool
	parser  *jwt.Parser
}

type claims struct {
	jwt.RegisteredClaims
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Azp               string `json:"azp"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// New fetches the JWKS at jwksURL (failing fast if it is unreachable) and
// returns a verifier accepting tokens whose iss is one of issuers and whose
// azp is one of authorizedParties. Both lists are required.
//
// jwksURL and issuers are deliberately separate: inside Docker the backend
// reaches Keycloak by its container hostname, while tokens carry the
// browser-facing hostname in iss.
func New(ctx context.Context, jwksURL string, issuers, authorizedParties []string) (*Verifier, error) {
	issuers = compact(issuers)
	authorizedParties = compact(authorizedParties)
	if len(issuers) == 0 {
		return nil, errors.New("auth: at least one issuer is required")
	}
	if len(authorizedParties) == 0 {
		return nil, errors.New("auth: at least one authorized party (azp) is required")
	}
	k, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("auth: load JWKS from %s: %w", jwksURL, err)
	}
	return newWithKeyfunc(k, issuers, authorizedParties), nil
}

func newWithKeyfunc(k keyfunc.Keyfunc, issuers, authorizedParties []string) *Verifier {
	return &Verifier{
		jwks:    k,
		issuers: toSet(issuers),
		azps:    toSet(authorizedParties),
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(ClockSkewLeeway),
		),
	}
}

// Verify checks token and returns the caller's identity. Every failure wraps
// ErrInvalidToken.
func (v *Verifier) Verify(_ context.Context, token string) (Identity, error) {
	var c claims
	parsed, err := v.parser.ParseWithClaims(token, &c, v.jwks.Keyfunc)
	if err != nil || !parsed.Valid {
		return Identity{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !v.issuers[c.Issuer] {
		return Identity{}, fmt.Errorf("%w: unexpected issuer %q", ErrInvalidToken, c.Issuer)
	}
	if !v.azps[c.Azp] {
		return Identity{}, fmt.Errorf("%w: token not issued to an allowed client (azp %q)", ErrInvalidToken, c.Azp)
	}
	if c.Subject == "" {
		return Identity{}, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	var clientRoles map[string][]string
	if len(c.ResourceAccess) > 0 {
		clientRoles = make(map[string][]string, len(c.ResourceAccess))
		for client, ra := range c.ResourceAccess {
			clientRoles[client] = ra.Roles
		}
	}
	return Identity{
		Subject:           c.Subject,
		Email:             c.Email,
		Name:              c.Name,
		PreferredUsername: c.PreferredUsername,
		Azp:               c.Azp,
		RealmRoles:        c.RealmAccess.Roles,
		ClientRoles:       clientRoles,
	}, nil
}

// SplitList parses a comma-separated env value (e.g. KEYCLOAK_ISSUER or
// KEYCLOAK_AUTHORIZED_PARTIES) into trimmed, non-empty entries.
func SplitList(s string) []string {
	return compact(strings.Split(s, ","))
}

// DisplayNameFallback picks a human handle for a user who has no explicit
// name. It never returns an email address: Keycloak defaults a federated
// (e.g. Google) user's preferred_username to their email when no username
// mapper is configured, and that must not leak to other users. Order:
// a non-email preferred_username → email local part → fallback.
func DisplayNameFallback(id Identity, fallback string) string {
	if id.PreferredUsername != "" && !strings.Contains(id.PreferredUsername, "@") {
		return id.PreferredUsername
	}
	if at := strings.Index(id.Email, "@"); at > 0 {
		return id.Email[:at]
	}
	return fallback
}

func compact(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
