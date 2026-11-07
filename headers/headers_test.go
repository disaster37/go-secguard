package headers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/disaster37/go-secguard/domain"
)

func TestDefaultSecurityHeaders(t *testing.T) {
	t.Parallel()

	base := DefaultSecurityHeaders("/", false)
	for name, want := range map[string]string{
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "frame-ancestors 'none'",
	} {
		if got := base[name]; got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if _, ok := base["Cache-Control"]; ok {
		t.Fatal("non-API path should not set Cache-Control")
	}
	if _, ok := base["Strict-Transport-Security"]; ok {
		t.Fatal("non-TLS response should not set HSTS")
	}

	for _, path := range []string{"/api", "/api/", "/api/v1/engines"} {
		if got := DefaultSecurityHeaders(path, false)["Cache-Control"]; got != "no-store" {
			t.Fatalf("path %q Cache-Control = %q, want no-store", path, got)
		}
	}
	if _, ok := DefaultSecurityHeaders("/apix", false)["Cache-Control"]; ok {
		t.Fatal("path /apix should not set Cache-Control")
	}

	if got := DefaultSecurityHeaders("/", true)["Strict-Transport-Security"]; got != "max-age=31536000; includeSubDomains" {
		t.Fatalf("HSTS = %q", got)
	}
}

func TestExtractRequestOrigin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		origin  string
		referer string
		want    string
	}{
		{"origin", "https://app.example.com", "", "https://app.example.com"},
		{"trimmed origin", "  https://app.example.com  ", "", "https://app.example.com"},
		{"referer fallback", "", "https://app.example.com/path?q=1", "https://app.example.com"},
		{"invalid referer", "", "://bad", ""},
		{"relative referer", "", "/path", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtractRequestOrigin(tc.origin, tc.referer); got != tc.want {
				t.Fatalf("ExtractRequestOrigin(%q, %q) = %q, want %q", tc.origin, tc.referer, got, tc.want)
			}
		})
	}
}

func TestCheckMutationOrigin(t *testing.T) {
	t.Parallel()

	allowed := []string{"https://app.example.com"}

	cases := []struct {
		name    string
		method  string
		origin  string
		referer string
		allowed []string
		wantErr bool
	}{
		{"safe method", http.MethodGet, "https://evil.example.com", "", allowed, false},
		{"no origin", http.MethodPost, "", "", allowed, false},
		{"empty allowlist", http.MethodPost, "https://evil.example.com", "", nil, false},
		{"wildcard", http.MethodPost, "https://evil.example.com", "", []string{"*"}, false},
		{"exact match", http.MethodPost, "https://app.example.com", "", allowed, false},
		{"trimmed match", http.MethodPut, "https://app.example.com", "", []string{" https://app.example.com "}, false},
		{"referer match", http.MethodPatch, "", "https://app.example.com/page", allowed, false},
		{"lowercase method", "post", "https://app.example.com", "", allowed, false},
		{"mismatch", http.MethodDelete, "https://evil.example.com", "", allowed, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckMutationOrigin(tc.method, tc.origin, tc.referer, tc.allowed)
			if tc.wantErr {
				if !errors.Is(err, domain.ErrOriginNotAllowed) {
					t.Fatalf("error = %v, want ErrOriginNotAllowed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
