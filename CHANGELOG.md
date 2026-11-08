# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release of `github.com/disaster37/go-secguard`.
- `domain` package with sentinel errors and shared defaults.
- `lockout` package with per-key exponential backoff, overflow-safe doubling,
  SHA-256 key builders, bounded state, and throttled sweeps.
- `ratelimit` package with bounded sliding-window `RateLimiter` and per-account
  `LoginThrottle`.
- `bantracker` package with per-IP unique credential failure detection,
  single-lock `RecordAndBan`, bounded `failures`/`banned` maps, SHA-256
  fingerprinting, and webhook signature extraction.
- `realip` package with trusted-proxy CIDR parsing and right-to-left
  `X-Forwarded-For` client IP extraction.
- `headers` package with browser hardening headers and `Origin`/`Referer`
  mutation validation.
- `config` package with validated configuration structs.
- `observ` package with stdlib and `slog` logging adapters.
- `nethttp` package with `net/http` middleware and JSON ban admin handlers.
- `testutil` package with `FakeClock` and `FreeListener`.
- Root `secguard.Guard` facade and re-exported sentinel errors.
- Dagger CI module, GitHub Actions workflow, documentation, and ADRs.
