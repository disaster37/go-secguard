// Package headers provides browser hardening response headers and
// Origin/Referer validation for mutating requests (CWE-352, CWE-693, CWE-1021,
// CWE-319).
package headers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/disaster37/go-secguard/domain"
)

// DefaultSecurityHeaders returns the browser hardening response headers
// (CWE-693, CWE-1021, CWE-319):
//   - X-Frame-Options: DENY
//   - X-Content-Type-Options: nosniff
//   - Referrer-Policy: no-referrer
//   - Content-Security-Policy: frame-ancestors 'none'
//   - Cache-Control: no-store (when path is /api or has prefix /api/)
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (when isTLS is true)
func DefaultSecurityHeaders(path string, isTLS bool) map[string]string {
	headers := map[string]string{
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "frame-ancestors 'none'",
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		headers["Cache-Control"] = "no-store"
	}
	if isTLS {
		headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
	}
	return headers
}

// ExtractRequestOrigin returns originHeader when non-empty, or the
// "scheme://host" origin parsed from refererHeader when originHeader is empty.
// Returns "" if neither yields a valid origin.
func ExtractRequestOrigin(originHeader, refererHeader string) string {
	if origin := strings.TrimSpace(originHeader); origin != "" {
		return origin
	}
	referer := strings.TrimSpace(refererHeader)
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

// CheckMutationOrigin validates Origin/Referer on mutating HTTP methods (POST,
// PUT, PATCH, DELETE) against allowedOrigins (CWE-352). Non-mutating methods,
// requests without Origin/Referer (non-browser clients), empty allowedOrigins,
// or an allowedOrigins entry of "*" return nil. Otherwise returns
// domain.ErrOriginNotAllowed.
func CheckMutationOrigin(method, originHeader, refererHeader string, allowedOrigins []string) error {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil
	}

	origin := ExtractRequestOrigin(originHeader, refererHeader)
	if origin == "" {
		return nil
	}
	if len(allowedOrigins) == 0 {
		return nil
	}
	for _, allowed := range allowedOrigins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" || allowed == origin {
			return nil
		}
	}
	return domain.ErrOriginNotAllowed
}
