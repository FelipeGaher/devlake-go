# Changelog

All notable changes to this module. Versions follow [semver](https://semver.org/):
from v1.0.0 on, breaking API changes only happen in a new major version.

## v1.0.0

First stable release. The API is unchanged from v0.4.0; this tag commits to it.

## v0.4.0

- `authmw.Reject(status, code, message)`: a `Config.Resolve` error created with
  it is written as that response (e.g. 403 when the identity lacks an app role
  or a local account is disabled) instead of a 500. Rejections are never cached.

## v0.3.1

- `oapi.Message` reports the innermost schema error, so a failure inside an
  `allOf`/`anyOf`/`oneOf` request schema names the actual field instead of
  "doesn't match all schemas".

## v0.3.0

- `oapi.Options.RejectUnknownRoutes`: treat the spec as a strict route
  allow-list — a request matching no spec route gets 404 `NOT_FOUND` instead of
  passing through. Off by default.
- `oapi.Lint` also builds the request router, catching specs that validate but
  can't be routed at runtime.

## v0.2.0

- `httpx.TrustedProxyClientIP(cidrs)`: honour `X-Forwarded-For` only when the
  direct peer is a configured proxy.
- `pgxutil.PoolOptions.StatementTimeout`: per-connection `statement_timeout`.
- Fix: `auth.New` no longer ties the hourly background JWKS refresh to its
  context (a short startup-timeout context used to stop the refresh). Documented
  that an unreachable JWKS at startup is not an error.

## v0.1.0

Initial release: `auth`, `authmw`, `httpx`, `accesslog`, `ratelimit`, `oapi`,
`sqid`, `pgxutil`, `webpush`, `mdsafety`, `kcadmin`.
