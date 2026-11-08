# ADR-002: Exponential lockout and sliding-window rate limiting

## Status

Accepted.

## Context

Brute-force and credential-stuffing attacks need layered defenses that are
cheap on the hot path and cannot be turned into a memory or CPU denial of
service. Naive implementations grow maps without bound and scan the whole map on
every request.

## Decision

### Exponential lockout (`lockout`)

- Count consecutive failures per key.
- Once `MaxFailedAttempts` is reached, lock the key for `BaseLockout` and double
  the duration for each further failure, capped at `MaxLockout`.
- Compute the duration iteratively and clamp before doubling so the result can
  never overflow `int64`, even with a multi-day `BaseLockout`.
- Normalize login keys with `strings.ToLower(strings.TrimSpace(username))` and
  hash them with SHA-256 (`login|<digest>|<ip>`). Password-change keys use
  `chpw|<digest>|<ip>`. Raw usernames are never retained (CWE-532).
- Bound the map at `MaxEntries` and evict the oldest `lastSeen` entry.
- Throttle full-map sweeps to once per `EntryTTL`, while still checking
  single-key expiry on every access.

### Sliding-window rate limiting (`ratelimit`)

- Store a slice of timestamps per key.
- On `Allow`, filter timestamps in place to the current window, reject when the
  count reaches the limit, and otherwise append the current time.
- Bound the map at `MaxEntries` and evict the key with the oldest latest
  timestamp.
- Throttle full-map sweeps to once per window.
- Use `DefaultRateLimitWindow` as the fallback for `RateLimiter` and
  `DefaultLoginThrottleWindow` as the fallback for `LoginThrottle`; do not share
  a single fallback between the two.

## Consequences

- The hot path is O(window entries per key), not O(number of keys).
- Memory is strictly bounded.
- Lockout durations are predictable and cannot overflow.
- Raw usernames and passwords never appear in limiter state.
