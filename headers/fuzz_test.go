package headers

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/disaster37/go-secguard/domain"
)

func FuzzCheckMutationOrigin(f *testing.F) {
	f.Add(http.MethodPost, "https://app.example.com", "", "https://app.example.com")
	f.Add(http.MethodGet, "https://evil.example.com", "", "https://app.example.com")
	f.Add(http.MethodPut, "", "https://app.example.com/page", "*")
	f.Add(http.MethodDelete, "https://evil.example.com", "", "")
	f.Add("post", "https://app.example.com", "", "https://other.example.com")

	f.Fuzz(func(t *testing.T, method, originHeader, refererHeader, allowed string) {
		var allowedOrigins []string
		if allowed != "" {
			allowedOrigins = []string{allowed}
		}
		err := CheckMutationOrigin(method, originHeader, refererHeader, allowedOrigins)

		mutating := false
		switch strings.ToUpper(strings.TrimSpace(method)) {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			mutating = true
		}
		origin := ExtractRequestOrigin(originHeader, refererHeader)
		hasAllowlist := allowed != ""
		allowed = strings.TrimSpace(allowed)
		wantErr := mutating && origin != "" && hasAllowlist && allowed != "*" && allowed != origin
		if wantErr {
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

func FuzzExtractRequestOrigin(f *testing.F) {
	f.Add("https://app.example.com", "")
	f.Add("", "https://app.example.com/path")
	f.Add("", "not a url")
	f.Add("  https://app.example.com  ", "https://ignored.example.com")

	f.Fuzz(func(t *testing.T, originHeader, refererHeader string) {
		got := ExtractRequestOrigin(originHeader, refererHeader)
		if trimmed := strings.TrimSpace(originHeader); trimmed != "" {
			if got != trimmed {
				t.Fatalf("ExtractRequestOrigin() = %q, want %q", got, trimmed)
			}
			return
		}
		if got != "" && !strings.Contains(got, "://") {
			t.Fatalf("ExtractRequestOrigin() = %q, want empty or scheme://host", got)
		}
	})
}
