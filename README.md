# devlake-go

Reusable Go building blocks for JSON API backends that authenticate with
Keycloak: token verification and auth middleware, HTTP helpers, rate
limiting, OpenAPI request validation, PostgreSQL (pgx) helpers, Web Push and
more. It is especially aimed at several services sharing one Keycloak realm,
so the same plumbing lives in one place instead of being copy-pasted between
services and drifting apart.

```
go get github.com/FelipeGaher/devlake-go@latest
```

| Package | What it does |
|---|---|
| `auth` | Verifies Keycloak access tokens: RS256 against the realm JWKS, required `iss` **and `azp`** allow-lists, 30s clock-skew leeway. Returns an `Identity` (sub, email, names, realm + client roles). `DisplayNameFallback` never leaks an email as a username. |
| `authmw` | net/http auth middleware, generic over the app's principal type `T`. A `Resolve` callback find-or-creates the local user; a per-subject `Cache[T]` (TTL, re-resolve when the email changes, size cap, `Invalidate`) avoids a DB hit per request. `RequireRealmRole` / `RequireClientRole`. |
| `httpx` | `{error, message}` JSON error body + pluggable `ErrorWriter`; JSON-tag-aware validator + plain-English `FormatValidationError`; `ClientIP` (rightmost `X-Forwarded-For`, behind a reverse proxy); `IPRateLimit` / `KeyedRateLimit`; `SecurityHeaders`; `MaxBytes`; structured `AccessLog`. |
| `accesslog` | Fixed-schema JSON traffic log line (incoming requests and outgoing calls). |
| `ratelimit` | In-memory per-key token buckets with idle pruning and a size cap. |
| `oapi` | OpenAPI request-validation middleware (kin-openapi) + `Lint` for a CI spec check. |
| `sqid` | Opaque Sqids encoding of int64 database ids for the API surface. |
| `pgxutil` | pgx pool `Connect`, `DBTX`, `WithTx`, unique-violation helpers. |
| `webpush` | Batch Web Push send with Urgency High + 1h TTL, dead-subscription callback, access logging. |
| `mdsafety` | Write-time validation that Markdown sticks to a safe subset (no raw HTML, https/mailto links, https images, bounded nesting). |
| `kcadmin` | Dev-tooling Keycloak client: seed users through the Admin API, get user tokens through the password grant. |

## Wiring auth

```go
verifier, err := auth.New(ctx, cfg.KeycloakJWKSURL,
    auth.SplitList(cfg.KeycloakIssuer),             // browser-facing iss value(s)
    auth.SplitList(cfg.KeycloakAuthorizedParties))  // this service's client id(s), e.g. "my-app-frontend"
if err != nil { log.Fatal(err) }

type Principal struct{ UserID int64; Plan string }
cache := authmw.NewCache[Principal]() // ONE per process; share with anything that calls Invalidate

r.Use(httpx.AccessLog)
r.Use(httpx.IPRateLimit(50, 100, nil))
r.Group(func(r chi.Router) {
    r.Use(authmw.Middleware(authmw.Config[Principal]{
        Verifier: verifier,
        Cache:    cache,
        Resolve: func(ctx context.Context, id auth.Identity) (Principal, error) {
            uid, plan, err := users.FindOrCreateByKeycloakSub(ctx, id.Subject, id.Email,
                auth.DisplayNameFallback(id, "user"), id.Name)
            return Principal{uid, plan}, err
        },
        LogUserID: func(p Principal) int64 { return p.UserID },
    }))
    // handlers: p, _ := authmw.Principal[Principal](r.Context())
})
```

**Always set the `azp` allow-list.** Applications sharing a realm all get
tokens with the same issuer and signing keys, so without it a token minted
for one application's client is accepted by every other application.

## Rules

- Packages never import application code; applications plug in through
  interfaces, callbacks and type parameters.
- Pin a tagged version in each consumer's `go.mod`. Avoid committing a
  `replace` directive pointing at a local checkout: it breaks builds (e.g.
  Docker) that only see the consumer's own directory. For local
  co-development use a gitignored `go.work`:

  ```
  go work init . /path/to/devlake-go
  ```
- Breaking changes are fine while on `v0.x`. Once at `v1`, follow semver.
