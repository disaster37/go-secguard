# Contributing

## Development workflow

1. Fork the repository and create a feature branch from `main`.
2. Make focused changes with tests.
3. Run the local verification suite.
4. Open a pull request describing the change and its security impact.

## Coding conventions

- **Standard library only** in the root module. Do not add third-party
  dependencies.
- **No string concatenation** with `+` or `+=`; use `fmt.Sprintf`.
- **Wrap errors** with `%w` so callers can use `errors.Is` / `errors.As`.
- **Standard library `testing` only**; do not use testify or ginkgo.
- **No dead or unused symbols**. `golangci-lint` runs the `unused` linter and CI
  fails on any unreferenced function, type, or variable.
- **Formatting**: `gofmt -s` and `goimports` with the local prefix
  `github.com/disaster37/go-secguard`.
- **Coverage**: at least 95% statement coverage overall and per package.
- **Concurrency**: every stateful type must be safe for concurrent use and
  covered by a `-race` test.

## Verification

Run the full local gate:

```bash
gofmt -s -l .
goimports -l -local github.com/disaster37/go-secguard .
go build ./...
go vet ./...
go test -race -covermode=atomic -timeout 180s ./...
golangci-lint run
```

Fuzz smoke tests:

```bash
go test -run=^$ -fuzz=FuzzLoginLimitKey -fuzztime=5s ./lockout
go test -run=^$ -fuzz=FuzzPasswordChangeLimitKey -fuzztime=5s ./lockout
go test -run=^$ -fuzz=FuzzFingerprints -fuzztime=5s ./bantracker
go test -run=^$ -fuzz=FuzzExtractSignatureValue -fuzztime=5s ./bantracker
go test -run=^$ -fuzz=FuzzExtractRealIP -fuzztime=5s ./realip
go test -run=^$ -fuzz=FuzzParseTrustedProxyCIDRs -fuzztime=5s ./realip
go test -run=^$ -fuzz=FuzzCheckMutationOrigin -fuzztime=5s ./headers
go test -run=^$ -fuzz=FuzzExtractRequestOrigin -fuzztime=5s ./headers
```

The authoritative CI gate is the local Dagger module:

```bash
dagger call -m ./dagger --src . ci export --path out
```

## Documentation

Update the relevant documentation in the same changeset as the code:

- `README.md` for user-facing behavior.
- `docs/configuration.md` for configuration keys and validation rules.
- `docs/design/` for architectural decisions.
- `docs/api.md` is generated with `gomarkdoc`; do not edit it by hand.
