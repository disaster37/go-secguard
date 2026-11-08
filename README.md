# go-secguard

`github.com/disaster37/go-secguard` is a standalone, production-grade,
framework-agnostic security-guardrail library for Go HTTP/API services. It
unifies brute-force protection, credential-stuffing detection, trusted-proxy
client-IP resolution, and browser hardening behind a small, pure-standard-library
API.

- **Zero third-party dependencies** in the root module.
- **Framework agnostic**: use the core packages directly, or the optional
  `nethttp` adapter for `net/http`.
- **Bounded, race-safe state**: every tracker is capped and guarded by a mutex.
- **Privacy first**: usernames, tokens, and webhook signatures are only ever
  stored as domain-separated SHA-256 digests.

## Architecture

```text
                    +-------------------+
                    |   secguard.Guard  |  root facade
                    +---------+---------+
                              |
        +---------------------+---------------------+
        |                     |                     |
   +----v----+          +-----v------+        +-----v------+
   | lockout |          | ratelimit  |        | bantracker |
   +---------+          +------------+        +------------+
        |                     |                     |
        +---------------------+---------------------+
                              |
                    +---------v---------+
                    |      domain       |  sentinels + defaults
                    +-------------------+

   realip  -> trusted-proxy client IP resolution
   headers -> browser hardening + mutation origin checks
   config  -> validated configuration structs
   observ  -> stdlib/slog logging adapters
   nethttp -> net/http middleware + JSON admin handlers
   testutil-> fake clock + free listener
```

## Packages

| Package | Purpose |
|---|---|
| `domain` | Sentinel errors and shared defaults. |
| `lockout` | Per-key exponential backoff with overflow-safe doubling and SHA-256 key builders. |
| `ratelimit` | Bounded sliding-window `RateLimiter` and per-account `LoginThrottle`. |
| `bantracker` | Per-IP unique credential failure detection, bans, and fingerprint helpers. |
| `realip` | Trusted-proxy CIDR parsing and right-to-left `X-Forwarded-For` extraction. |
| `headers` | Browser hardening headers and `Origin`/`Referer` mutation validation. |
| `config` | Validated configuration structs with `mapstructure`, `json`, and `yaml` tags. |
| `observ` | Minimal `Logger` interface with stdlib and `slog` adapters. |
| `nethttp` | `net/http` middleware and JSON ban admin handlers. |
| `testutil` | `FakeClock` and `FreeListener` test helpers. |
| `secguard` | Root `Guard` facade and re-exported sentinel errors. |

## Quick start

### Guard facade

```go
cfg := config.DefaultConfig()
cfg.Proxy.BehindReverseProxy = true
cfg.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
cfg.CORS.AllowedOrigins = []string{"https://app.example.com"}

guard, err := secguard.New(cfg)
if err != nil {
    return err
}

ip, err := guard.ClientIPFromRequest(r)
if err != nil {
    return err
}

if guard.BanTracker.IsBanned(ip.String()) {
    return secguard.ErrIPBanned
}
```

### Exponential lockout

```go
limiter := lockout.New(lockout.Config{})
key := lockout.LoginLimitKey(username, clientIP)

if !limiter.Allow(key) {
    return secguard.ErrAccountLocked
}
if err := authenticate(username, password); err != nil {
    limiter.RecordFailure(key)
    return err
}
limiter.RecordSuccess(key)
```

### Sliding-window rate limiting

```go
limiter := ratelimit.NewRateLimiter(4096, nil)
if !limiter.Allow(clientIP, 60, time.Minute) {
    return secguard.ErrRateLimited
}
```

### Credential-stuffing bans

```go
tracker := bantracker.New(4096, nil)
fingerprint := bantracker.FingerprintLogin(username)
if tracker.RecordAndBan(clientIP, fingerprint, 10, 15*time.Minute, 5*time.Minute) {
    return secguard.ErrIPBanned
}
```

### Trusted-proxy client IP

```go
trusted, err := realip.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
if err != nil {
    return err
}
ip, err := realip.GetRealIPFromRequest(r, true, trusted)
```

### Browser hardening

```go
for name, value := range headers.DefaultSecurityHeaders(r.URL.Path, r.TLS != nil) {
    w.Header().Set(name, value)
}
if err := headers.CheckMutationOrigin(r.Method, r.Header.Get("Origin"), r.Header.Get("Referer"), allowedOrigins); err != nil {
    return err
}
```

### net/http middleware

```go
handler := nethttp.RealIPMiddleware(true, trusted)(
    nethttp.SecurityHeadersMiddleware(
        nethttp.MutationOriginMiddleware(allowedOrigins)(
            nethttp.BanCheckMiddleware(tracker, true, trusted)(
                nethttp.RateLimitMiddleware(limiter, 60, time.Minute, true, trusted)(mux),
            ),
        ),
    ),
)
```

## Security highlights

- **CWE-307**: layered exponential lockout, per-account throttle, per-IP rate
  limit, and unique-credential ban tracking.
- **CWE-400 / CWE-770**: every map is bounded by `MaxEntries` (default 4096) and
  full-map sweeps are throttled.
- **CWE-362**: all state is guarded by `sync.Mutex`; verified with `-race`.
- **CWE-290 / CWE-348**: forwarded headers are only honored from trusted direct
  peers, and `X-Forwarded-For` is walked right-to-left.
- **CWE-352 / CWE-693 / CWE-1021 / CWE-319**: strict framing denial, MIME
  sniffing prevention, referrer stripping, API cache disabling, HSTS, and
  mutation origin validation.
- **CWE-532**: raw usernames, tokens, and signatures are never retained; only
  domain-separated SHA-256 digests are stored.

See [SECURITY.md](SECURITY.md) for the full threat model.

## Configuration

See [docs/configuration.md](docs/configuration.md) for the complete YAML/JSON
reference and validation rules.

## CI

The repository uses a local Dagger module:

```bash
dagger call -m ./dagger --src . ci export --path out
```

That single command runs `gofmt` verification, `golangci-lint`, `govulncheck`,
`gosec`, `go vet`, race-enabled tests, fuzz smoke tests, the 95% coverage gate,
and API documentation generation.

## License

MIT. See [LICENSE](LICENSE).
