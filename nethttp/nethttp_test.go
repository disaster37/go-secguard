package nethttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/disaster37/go-secguard/bantracker"
	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/lockout"
	"github.com/disaster37/go-secguard/ratelimit"
	"github.com/disaster37/go-secguard/realip"
	"github.com/disaster37/go-secguard/testutil"
)

func TestClientIPContext(t *testing.T) {
	t.Parallel()

	var nilCtx context.Context
	if got := ClientIPFromContext(nilCtx); got != "" {
		t.Fatalf("ClientIPFromContext(nil) = %q, want empty", got)
	}
	if got := ClientIPFromContext(context.Background()); got != "" {
		t.Fatalf("ClientIPFromContext(background) = %q, want empty", got)
	}
	ctx := ContextWithClientIP(context.Background(), "203.0.113.5")
	if got := ClientIPFromContext(ctx); got != "203.0.113.5" {
		t.Fatalf("ClientIPFromContext() = %q, want 203.0.113.5", got)
	}
}

func TestRealIPMiddleware(t *testing.T) {
	t.Parallel()

	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	RealIPMiddleware(false, nil)(next).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if seen != "203.0.113.5" {
		t.Fatalf("context IP = %q, want 203.0.113.5", seen)
	}

	seen = ""
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "bad"
	w = httptest.NewRecorder()
	RealIPMiddleware(false, nil)(next).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if seen != "" {
		t.Fatalf("next handler was called with IP %q", seen)
	}

	trusted, err := realip.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse CIDRs: %v", err)
	}
	seen = ""
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	w = httptest.NewRecorder()
	RealIPMiddleware(true, trusted)(next).ServeHTTP(w, r)
	if seen != "203.0.113.9" {
		t.Fatalf("context IP = %q, want 203.0.113.9", seen)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/engines", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	SecurityHeadersMiddleware(next).ServeHTTP(w, r)
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("HSTS header missing")
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	SecurityHeadersMiddleware(next).ServeHTTP(w, r)
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("Cache-Control = %q, want empty", got)
	}
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS = %q, want empty", got)
	}
}

func TestMutationOriginMiddleware(t *testing.T) {
	t.Parallel()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	allowed := []string{"https://app.example.com"}

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	MutationOriginMiddleware(allowed)(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("allowed origin: called=%v status=%d", called, w.Code)
	}

	called = false
	r = httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	w = httptest.NewRecorder()
	MutationOriginMiddleware(allowed)(next).ServeHTTP(w, r)
	if called {
		t.Fatal("next handler was called for a disallowed origin")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}

	called = false
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	w = httptest.NewRecorder()
	MutationOriginMiddleware(allowed)(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("safe method: called=%v status=%d", called, w.Code)
	}
}

func TestBanCheckMiddleware(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	tracker := bantracker.New(10, clock.Now)
	tracker.RecordAndBan("203.0.113.5", "fp", 1, time.Minute, time.Minute)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(ContextWithClientIP(r.Context(), "203.0.113.5"))
	w := httptest.NewRecorder()
	BanCheckMiddleware(tracker, false, nil)(next).ServeHTTP(w, r)
	if called {
		t.Fatal("next handler was called for a banned IP")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}

	called = false
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	w = httptest.NewRecorder()
	BanCheckMiddleware(tracker, false, nil)(next).ServeHTTP(w, r)
	if called || w.Code != http.StatusForbidden {
		t.Fatalf("resolved banned IP: called=%v status=%d", called, w.Code)
	}

	called = false
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.6:1234"
	w = httptest.NewRecorder()
	BanCheckMiddleware(tracker, false, nil)(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("unbanned IP: called=%v status=%d", called, w.Code)
	}

	called = false
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "bad"
	w = httptest.NewRecorder()
	BanCheckMiddleware(tracker, false, nil)(next).ServeHTTP(w, r)
	if called || w.Code != http.StatusBadRequest {
		t.Fatalf("invalid remote addr: called=%v status=%d", called, w.Code)
	}

	called = false
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.6:1234"
	r = r.WithContext(ContextWithClientIP(r.Context(), "not-an-ip"))
	w = httptest.NewRecorder()
	BanCheckMiddleware(tracker, false, nil)(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("invalid context IP fallback: called=%v status=%d", called, w.Code)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	limiter := ratelimit.NewRateLimiter(10, clock.Now)

	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	mw := RateLimitMiddleware(limiter, 1, time.Minute, false, nil)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	mw(next).ServeHTTP(w, r)
	if called != 1 || w.Code != http.StatusOK {
		t.Fatalf("first request: called=%d status=%d", called, w.Code)
	}

	w = httptest.NewRecorder()
	mw(next).ServeHTTP(w, r)
	if called != 1 {
		t.Fatal("next handler was called for a rate-limited request")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "bad"
	w = httptest.NewRecorder()
	mw(next).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid remote addr status = %d, want 400", w.Code)
	}

	called = 0
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "bad"
	r = r.WithContext(ContextWithClientIP(r.Context(), "203.0.113.7"))
	w = httptest.NewRecorder()
	mw(next).ServeHTTP(w, r)
	if called != 1 || w.Code != http.StatusOK {
		t.Fatalf("context IP: called=%d status=%d", called, w.Code)
	}
}

func TestLockoutMiddleware(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	limiter := lockout.New(lockout.Config{MaxFailedAttempts: 1, Clock: clock.Now})
	limiter.RecordFailure("locked")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	LockoutMiddleware(limiter, nil)(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("nil extractor: called=%v status=%d", called, w.Code)
	}

	called = false
	w = httptest.NewRecorder()
	LockoutMiddleware(limiter, func(*http.Request) string { return "" })(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("empty key: called=%v status=%d", called, w.Code)
	}

	called = false
	w = httptest.NewRecorder()
	LockoutMiddleware(limiter, func(*http.Request) string { return "locked" })(next).ServeHTTP(w, r)
	if called {
		t.Fatal("next handler was called for a locked key")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}

	called = false
	w = httptest.NewRecorder()
	LockoutMiddleware(limiter, func(*http.Request) string { return "allowed" })(next).ServeHTTP(w, r)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("allowed key: called=%v status=%d", called, w.Code)
	}
}

func TestStatusCodeForError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantMsg    string
	}{
		{"validation", domain.ErrValidation, http.StatusBadRequest, "validation error"},
		{"invalid ip", domain.ErrInvalidIP, http.StatusBadRequest, "invalid IP address"},
		{"invalid cidr", domain.ErrInvalidCIDR, http.StatusBadRequest, "invalid CIDR"},
		{"origin", domain.ErrOriginNotAllowed, http.StatusForbidden, "origin not allowed"},
		{"banned", domain.ErrIPBanned, http.StatusForbidden, "IP address is banned due to suspicious activity"},
		{"rate limited", domain.ErrRateLimited, http.StatusTooManyRequests, "rate limit exceeded"},
		{"locked", domain.ErrAccountLocked, http.StatusTooManyRequests, "too many failed attempts, try again later"},
		{"wrapped", errors.Join(domain.ErrRateLimited, errors.New("detail")), http.StatusTooManyRequests, "rate limit exceeded"},
		{"unknown", errors.New("boom"), http.StatusInternalServerError, "internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, msg := StatusCodeForError(tc.err)
			if status != tc.wantStatus || msg != tc.wantMsg {
				t.Fatalf("StatusCodeForError() = (%d, %q), want (%d, %q)", status, msg, tc.wantStatus, tc.wantMsg)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	WriteError(w, domain.ErrRateLimited)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"rate limit exceeded"}` {
		t.Fatalf("body = %q", got)
	}
}

func TestAPIBansHandler(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	tracker := bantracker.New(10, clock.Now)
	tracker.RecordAndBan("203.0.113.5", "fp", 1, time.Minute, time.Minute)

	w := httptest.NewRecorder()
	APIBansHandler(tracker)(w, httptest.NewRequest(http.MethodGet, "/api/bans", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	var bans []bantracker.BanInfo
	if err := json.Unmarshal(w.Body.Bytes(), &bans); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != "203.0.113.5" {
		t.Fatalf("unexpected bans: %+v", bans)
	}

	w = httptest.NewRecorder()
	APIBansHandler(bantracker.New(10, clock.Now))(w, httptest.NewRequest(http.MethodGet, "/api/bans", nil))
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("empty body = %q, want []", got)
	}
}

func TestAPIUnbanHandler(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	tracker := bantracker.New(10, clock.Now)
	tracker.RecordAndBan("203.0.113.5", "fp", 1, time.Minute, time.Minute)

	w := httptest.NewRecorder()
	APIUnbanHandler(tracker, func(*http.Request) string { return " 203.0.113.5 " })(w, httptest.NewRequest(http.MethodDelete, "/api/bans/203.0.113.5", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if tracker.IsBanned("203.0.113.5") {
		t.Fatal("IP was not unbanned")
	}

	tracker.RecordAndBan("203.0.113.6", "fp", 1, time.Minute, time.Minute)
	r := httptest.NewRequest(http.MethodDelete, "/api/bans/203.0.113.6", nil)
	r.SetPathValue("ip", "203.0.113.6")
	w = httptest.NewRecorder()
	APIUnbanHandler(tracker, nil)(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if tracker.IsBanned("203.0.113.6") {
		t.Fatal("IP was not unbanned via PathValue")
	}

	w = httptest.NewRecorder()
	APIUnbanHandler(tracker, func(*http.Request) string { return "not-an-ip" })(w, httptest.NewRequest(http.MethodDelete, "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	w = httptest.NewRecorder()
	APIUnbanHandler(tracker, func(*http.Request) string { return "" })(w, httptest.NewRequest(http.MethodDelete, "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
