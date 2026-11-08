# ADR-001: Framework-agnostic architecture

## Status

Accepted.

## Context

The same security primitives were implemented independently in
`dagger-kubernetes` (CloudWeGo Hertz), `gohookbridge` (`net/http` + chi), and
`go-auth` (a monolithic `secguard` package). The implementations drifted in
defaults, key formats, and edge-case handling. Pulling a router or logging
framework into a shared library would force every consumer to adopt that
framework.

## Decision

- Ship a **pure standard library** root module with zero third-party
  dependencies.
- Split the library into cohesive subpackages:
  - `domain`: sentinel errors and shared defaults.
  - `lockout`, `ratelimit`, `bantracker`: stateful protections.
  - `realip`, `headers`: stateless request helpers.
  - `config`: validated configuration structs.
  - `observ`: a minimal `Logger` interface with stdlib and `slog` adapters.
  - `nethttp`: an optional `net/http` adapter.
  - `testutil`: deterministic test helpers.
  - Root `secguard`: a `Guard` facade and re-exported sentinel errors.
- Keep framework adapters outside the core. Hertz integration is documented in
  `docs/hertz-integration.md` and uses only the exported core APIs.
- Keep the Dagger CI module in its own nested Go module so its dependencies do
  not leak into the library.

## Consequences

- Consumers can adopt individual packages without pulling in a router or logger.
- The `nethttp` adapter is the only package that imports `net/http` for
  middleware; the core packages remain transport agnostic.
- Migration is incremental: `dagger-kubernetes`, `gohookbridge`, and `go-auth`
  can replace their private helpers package by package.
- The library cannot rely on framework-specific request contexts; callers pass
  raw request fields or use the provided adapters.
