# ADR-004: Trusted-proxy client IP resolution and browser hardening

## Status

Accepted.

## Context

Forwarded headers are attacker-controlled unless the direct TCP peer is a
trusted proxy. Trusting the leftmost `X-Forwarded-For` value lets a client spoof
its address. Browser-facing services also need consistent framing, MIME,
referrer, cache, HSTS, and CSRF protections.

## Decision

### Client IP resolution (`realip`)

- Parse `RemoteAddr` with `net.SplitHostPort`; if that fails, strip optional
  surrounding brackets and parse the value as an IP.
- Honor `X-Forwarded-For` and `X-Real-IP` only when `behindReverseProxy` is true
  **and** the direct peer is inside `trustedCIDRs`.
- Walk `X-Forwarded-For` right-to-left, skipping trusted proxy hops and invalid
  tokens, and return the first untrusted valid IP.
- Fall back to `X-Real-IP`, then to the direct peer.
- `ParseTrustedProxyCIDRs` accepts CIDRs and bare IPs, skips empty entries, and
  returns an error wrapping `domain.ErrInvalidCIDR` or `domain.ErrInvalidIP` for
  invalid entries. This is stricter than silently skipping typos.

### Browser hardening (`headers`)

- Always set `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and
  `Content-Security-Policy: frame-ancestors 'none'`.
- Set `Cache-Control: no-store` for `/api` and `/api/` paths.
- Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` when the
  request is TLS.
- Validate `Origin` (falling back to the `Referer` origin) on `POST`, `PUT`,
  `PATCH`, and `DELETE` against an explicit allowlist. Requests without either
  header (non-browser clients) pass through. An empty allowlist or `"*"` allows
  any origin.

## Consequences

- Client-prepended `X-Forwarded-For` values are harmless.
- A typo in the trusted-proxy list fails closed instead of silently disabling
  proxy trust.
- Browser responses carry consistent hardening headers and mutation requests are
  protected against cross-origin CSRF.
