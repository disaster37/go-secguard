package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/go-secguard/internal/dagger"
)

const (
	golangImage         = "golang:1.27-bookworm"
	golangciLintVersion = "v2.14.0"
	govulncheckVersion  = "v1.9.0"
	gosecVersion        = "v2.30.0"
	gomarkdocVersion    = "v1.1.0"

	fuzzCommand = `go test -run=^$ -fuzz=FuzzLoginLimitKey -fuzztime=5s ./lockout && go test -run=^$ -fuzz=FuzzPasswordChangeLimitKey -fuzztime=5s ./lockout && go test -run=^$ -fuzz=FuzzFingerprints -fuzztime=5s ./bantracker && go test -run=^$ -fuzz=FuzzExtractSignatureValue -fuzztime=5s ./bantracker && go test -run=^$ -fuzz=FuzzExtractRealIP -fuzztime=5s ./realip && go test -run=^$ -fuzz=FuzzParseTrustedProxyCIDRs -fuzztime=5s ./realip && go test -run=^$ -fuzz=FuzzCheckMutationOrigin -fuzztime=5s ./headers && go test -run=^$ -fuzz=FuzzExtractRequestOrigin -fuzztime=5s ./headers`
)

// GoSecguard is the Dagger CI module for github.com/disaster37/go-secguard.
type GoSecguard struct {
	Src *dagger.Directory
}

// New initializes the go-secguard CI module.
func New(
	// The source directory.
	// +required
	src *dagger.Directory,
) *GoSecguard {
	return &GoSecguard{Src: src}
}

func (m *GoSecguard) base() *dagger.Container {
	return dag.Container().From(golangImage).WithDirectory("/src", m.Src).WithWorkdir("/src")
}

// FormatCheck fails when any Go file is not gofmt-formatted.
func (m *GoSecguard) FormatCheck(ctx context.Context) error {
	_, err := m.base().WithExec([]string{"sh", "-c", "test -z \"$(gofmt -s -l .)\""}).Sync(ctx)
	return err
}

// Lint runs golangci-lint.
func (m *GoSecguard) Lint(ctx context.Context) (string, error) {
	base := m.base().WithExec([]string{"sh", "-c", fmt.Sprintf("GOBIN=/usr/local/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@%s", golangciLintVersion)})
	return dag.Golang(m.Src, dagger.GolangOpts{Base: base}).Lint(ctx)
}

// Vulncheck runs govulncheck.
func (m *GoSecguard) Vulncheck(ctx context.Context) (string, error) {
	base := m.base().WithExec([]string{"sh", "-c", fmt.Sprintf("GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@%s", govulncheckVersion)})
	return dag.Golang(m.Src, dagger.GolangOpts{Base: base}).Vulncheck(ctx)
}

// Gosec runs gosec.
func (m *GoSecguard) Gosec(ctx context.Context) (string, error) {
	return m.base().WithExec([]string{"sh", "-c", fmt.Sprintf("go install github.com/securego/gosec/v2/cmd/gosec@%s && gosec -exclude-generated -quiet ./...", gosecVersion)}).Stdout(ctx)
}

// TestRace runs go vet, the race-enabled test suite, and the fuzz smoke tests.
func (m *GoSecguard) TestRace(ctx context.Context) (*dagger.File, error) {
	ctr := m.base().
		WithExec([]string{"go", "vet", "./..."}).
		WithExec([]string{"go", "test", "-race", "-coverprofile=coverage.out", "-covermode=atomic", "./..."}).
		WithExec([]string{"sh", "-c", fuzzCommand})
	return ctr.File("coverage.out"), nil
}

// Coverage enforces the minimum statement coverage.
func (m *GoSecguard) Coverage(ctx context.Context, minTotal float64) (string, error) {
	file, err := m.TestRace(ctx)
	if err != nil {
		return "", err
	}
	return m.checkCoverageFile(ctx, file, minTotal)
}

func (m *GoSecguard) checkCoverageFile(ctx context.Context, coverage *dagger.File, minTotal float64) (string, error) {
	script := `go tool cover -func=coverage.out | tail -1
awk 'NR>1 { split($1,a,":"); file=a[1]; n=split(file,parts,"/"); pkg=parts[n-1]; stmts=$2; count=$3; total[pkg]+=stmts; if (count+0>0) covered[pkg]+=stmts } END { for (pkg in total) printf "pkg %s %.1f\n", pkg, 100*covered[pkg]/total[pkg] }' coverage.out`
	out, err := m.base().WithFile("coverage.out", coverage).WithExec([]string{"sh", "-c", script}).Stdout(ctx)
	if err != nil {
		return "", err
	}
	var total float64
	required := map[string]float64{
		"go-secguard": 95.0,
		"lockout":     95.0,
		"ratelimit":   95.0,
		"bantracker":  95.0,
		"realip":      95.0,
		"headers":     95.0,
		"config":      95.0,
		"nethttp":     95.0,
		"observ":      95.0,
		"testutil":    95.0,
	}
	found := map[string]float64{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "total:") {
			if _, err := fmt.Sscanf(line, "total:\t(statements)\t%f%%", &total); err != nil {
				return "", fmt.Errorf("parse coverage: %w", err)
			}
			continue
		}
		var pkg string
		var pct float64
		if _, err := fmt.Sscanf(line, "pkg %s %f", &pkg, &pct); err == nil {
			found[pkg] = pct
		}
	}
	if total < minTotal {
		return "", fmt.Errorf("coverage %.1f%% is below %.1f%%", total, minTotal)
	}
	for pkg, min := range required {
		pct, ok := found[pkg]
		if !ok {
			return "", fmt.Errorf("coverage for package %s not found", pkg)
		}
		if pct < min {
			return "", fmt.Errorf("coverage for package %s is %.1f%% (below %.1f%%)", pkg, pct, min)
		}
	}
	return out, nil
}

// Docs generates docs/api.md with gomarkdoc.
func (m *GoSecguard) Docs(ctx context.Context, check bool) (*dagger.File, error) {
	cmd := fmt.Sprintf("go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@%s && gomarkdoc ./... --exclude-dirs ./dagger/... --output docs/api.md", gomarkdocVersion)
	if check {
		cmd = fmt.Sprintf("go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@%s && gomarkdoc ./... --exclude-dirs ./dagger/... --output docs/api.md --check", gomarkdocVersion)
	}
	ctr, err := m.base().WithExec([]string{"sh", "-c", cmd}).Sync(ctx)
	if err != nil {
		return nil, err
	}
	return ctr.File("docs/api.md"), nil
}

// Ci runs the full CI pipeline.
func (m *GoSecguard) Ci(ctx context.Context) (*dagger.Directory, error) {
	if err := m.FormatCheck(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Lint(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Vulncheck(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Gosec(ctx); err != nil {
		return nil, err
	}
	coverage, err := m.TestRace(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := m.checkCoverageFile(ctx, coverage, 95.0); err != nil {
		return nil, err
	}
	docs, err := m.Docs(ctx, false)
	if err != nil {
		return nil, err
	}
	return dag.Directory().WithFile("coverage.out", coverage).WithFile("docs/api.md", docs), nil
}
