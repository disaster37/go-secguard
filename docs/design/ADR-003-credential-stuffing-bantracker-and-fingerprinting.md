# ADR-003: Credential-stuffing ban tracking and fingerprinting

## Status

Accepted.

## Context

A single misconfigured client may repeat the same stale credential many times.
That should not be treated the same as an attacker trying many different
credentials. Ban decisions must also be cheap, race-free, and bounded.

## Decision

- Track failures per IP as `(fingerprint, timestamp)` entries in a sliding
  window.
- Ignore a failure when the same fingerprint already exists within the window;
  this tolerates a misconfigured client repeating one credential.
- Count distinct fingerprints. When the count reaches `MaxUniqueFailures`, ban
  the IP for `BanDuration`.
- Execute sweep, failure recording, and ban evaluation under a single mutex
  acquisition in `RecordAndBan`.
- Bound both the `failures` and `banned` maps at `MaxEntries`:
  - Evict the IP with the oldest last-failure timestamp from `failures`.
  - Purge expired bans first, then evict the ban with the earliest `until`
    timestamp from `banned`.
- Return `ListBans()` sorted by IP for deterministic API responses.
- Fingerprint identifiers with domain-separated SHA-256:
  - `FingerprintLogin`: `login:<lowercased-trimmed-username>`
  - `FingerprintToken`: `token:<token>`
  - `FingerprintSignature`: `signature:<channel>:<signatureValue>`
- Extract webhook signatures from `X-Hub-Signature-256`, `X-Gitlab-Token`,
  `X-Hub-Signature`, and `X-Gitea-Signature` in priority order, returning
  `"unknown"` when none are present.

## Consequences

- Credential-stuffing campaigns are detected per IP without penalizing a single
  broken integration.
- The hot path pays at most one throttled map scan per window.
- Ban state and failure state cannot grow without bound.
- Raw credentials and signatures are never stored.
