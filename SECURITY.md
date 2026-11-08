# Security Policy

## Supported versions

Security fixes are provided for the latest released minor version of
`github.com/disaster37/go-secguard`.

## Reporting a vulnerability

Please do **not** open a public issue for security vulnerabilities. Report them
privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Include a description, reproduction steps, affected versions, and any
   suggested remediation.

You will receive an acknowledgement as soon as possible. Please allow time for a
fix and coordinated disclosure before publishing details.

## Threat model

| CWE | Threat | Defense |
|---|---|---|
| CWE-307 | Improper restriction of excessive authentication attempts | `lockout.Limiter` (exponential backoff 30s -> 15m), `ratelimit.LoginThrottle` (per-account sliding window), `bantracker.BanTracker` (per-IP unique credential failure ban). |
| CWE-400 / CWE-770 | Uncontrolled resource consumption / allocation without limits | All state maps are bounded by `MaxEntries` (default 4096) with oldest-entry eviction; full-map sweeps are throttled to at most once per window. |
| CWE-362 | Concurrent execution using a shared resource (`race`) | All state mutations are guarded by `sync.Mutex`; hot paths use a single lock acquisition; verified by `go test -race`. |
| CWE-290 / CWE-348 | Authentication bypass by spoofing / use of a less trusted source | `realip.ExtractRealIP` ignores `X-Forwarded-For` and `X-Real-IP` unless `behindReverseProxy` is true and the direct peer is inside `trustedCIDRs`; XFF is walked right-to-left. |
| CWE-352 | Cross-site request forgery (CSRF) | `headers.CheckMutationOrigin` validates `Origin` (or the `Referer` origin fallback) on `POST`, `PUT`, `PATCH`, and `DELETE`. |
| CWE-693 | Protection mechanism failure | `headers.DefaultSecurityHeaders` sets `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: frame-ancestors 'none'`, and `/api/` `Cache-Control: no-store`. |
| CWE-1021 | Improper restriction of rendered UI layers (clickjacking) | `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`. |
| CWE-319 | Cleartext transmission of sensitive information | `Strict-Transport-Security: max-age=31536000; includeSubDomains` is emitted when `isTLS` is true. |
| CWE-532 | Insertion of sensitive information into logs or memory | Raw usernames, passwords, tokens, and webhook signatures are never stored or logged; only domain-separated SHA-256 hex digests (`login:`, `chpw:`, `token:`, `signature:`) are kept. |

## Operational best practices

- Set `proxy.behind_reverse_proxy` only when the service actually runs behind a
  trusted proxy, and list every proxy hop in `proxy.trusted_proxy_cidrs`.
- Keep `cors.allowed_origins` as an explicit allowlist. Use `"*"` only for
  intentionally public, non-credentialed endpoints.
- Run the service with a bounded number of replicas and treat all tracker state
  as per-process. Distributed deployments should enforce limits at the edge as
  well.
- Monitor `bantracker.ListBans()` and the `nethttp` admin handlers to detect
  credential-stuffing campaigns.
- Keep the library updated and run the Dagger CI gate before deploying.
