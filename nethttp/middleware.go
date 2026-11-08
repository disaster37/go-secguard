// Package nethttp provides standard library net/http middleware and JSON admin
// handlers for go-secguard components.
package nethttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/disaster37/go-secguard/bantracker"
	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/headers"
	"github.com/disaster37/go-secguard/lockout"
	"github.com/disaster37/go-secguard/ratelimit"
	"github.com/disaster37/go-secguard/realip"
)

type clientIPKey struct{}

// ClientIPFromContext returns the client IP resolved by RealIPMiddleware, or "".
func ClientIPFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if ip, ok := ctx.Value(clientIPKey{}).(string); ok {
		return ip
	}
	return ""
}

// ContextWithClientIP stores clientIP in ctx.
func ContextWithClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, clientIP)
}

// RealIPMiddleware resolves the real client IP via realip.GetRealIPFromRequest
// and stores it in the request context. If remoteAddr is malformed, it writes
// 400.
func RealIPMiddleware(behindProxy bool, trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, err := realip.GetRealIPFromRequest(r, behindProxy, trustedCIDRs)
			if err != nil {
				WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithClientIP(r.Context(), ip.String())))
		})
	}
}

// SecurityHeadersMiddleware applies headers.DefaultSecurityHeaders to every
// response.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range headers.DefaultSecurityHeaders(r.URL.Path, r.TLS != nil) {
			w.Header().Set(name, value)
		}
		next.ServeHTTP(w, r)
	})
}

// MutationOriginMiddleware enforces headers.CheckMutationOrigin on mutating
// requests.
func MutationOriginMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := headers.CheckMutationOrigin(r.Method, r.Header.Get("Origin"), r.Header.Get("Referer"), allowedOrigins)
			if err != nil {
				WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BanCheckMiddleware rejects requests from banned client IPs with 403
// Forbidden. It uses ClientIPFromContext if present, otherwise resolves via
// realip.GetRealIPFromRequest.
func BanCheckMiddleware(tracker *bantracker.BanTracker, behindProxy bool, trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, err := resolveClientIP(r, behindProxy, trustedCIDRs)
			if err != nil {
				WriteError(w, err)
				return
			}
			if tracker.IsBanned(ip.String()) {
				WriteError(w, domain.ErrIPBanned)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware enforces per-IP sliding-window rate limiting with 429 Too
// Many Requests.
func RateLimitMiddleware(limiter *ratelimit.RateLimiter, maxRequests int, window time.Duration, behindProxy bool, trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, err := resolveClientIP(r, behindProxy, trustedCIDRs)
			if err != nil {
				WriteError(w, err)
				return
			}
			if !limiter.Allow(ip.String(), maxRequests, window) {
				WriteError(w, domain.ErrRateLimited)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LockoutMiddleware enforces lockout.Limiter using a caller-supplied
// keyExtractor function. When keyExtractor returns a non-empty key that is
// currently locked out, it responds with 429 Too Many Requests.
func LockoutMiddleware(limiter *lockout.Limiter, keyExtractor func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if keyExtractor != nil {
				if key := keyExtractor(r); key != "" && !limiter.Allow(key) {
					WriteError(w, domain.ErrAccountLocked)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteError maps err to an HTTP status code and writes `{"error": "<message>"}`.
func WriteError(w http.ResponseWriter, err error) {
	status, message := StatusCodeForError(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, message)
}

// StatusCodeForError maps sentinel errors to HTTP status codes and safe client
// messages.
func StatusCodeForError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		return http.StatusBadRequest, "validation error"
	case errors.Is(err, domain.ErrInvalidIP):
		return http.StatusBadRequest, "invalid IP address"
	case errors.Is(err, domain.ErrInvalidCIDR):
		return http.StatusBadRequest, "invalid CIDR"
	case errors.Is(err, domain.ErrOriginNotAllowed):
		return http.StatusForbidden, "origin not allowed"
	case errors.Is(err, domain.ErrIPBanned):
		return http.StatusForbidden, "IP address is banned due to suspicious activity"
	case errors.Is(err, domain.ErrRateLimited):
		return http.StatusTooManyRequests, "rate limit exceeded"
	case errors.Is(err, domain.ErrAccountLocked):
		return http.StatusTooManyRequests, "too many failed attempts, try again later"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

func resolveClientIP(r *http.Request, behindProxy bool, trustedCIDRs []*net.IPNet) (net.IP, error) {
	if value := ClientIPFromContext(r.Context()); value != "" {
		if ip := net.ParseIP(value); ip != nil {
			return ip, nil
		}
	}
	return realip.GetRealIPFromRequest(r, behindProxy, trustedCIDRs)
}
