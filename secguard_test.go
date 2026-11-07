package secguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/disaster37/go-secguard/config"
	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/observ"
	"github.com/disaster37/go-secguard/testutil"
)

func TestNew(t *testing.T) {
	t.Parallel()

	g, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Lockout == nil || g.RateLimiter == nil || g.LoginThrottle == nil || g.BanTracker == nil {
		t.Fatal("New did not initialize all components")
	}
	if g.Logger == nil {
		t.Fatal("New did not initialize a logger")
	}
	if len(g.TrustedCIDRs) != 0 {
		t.Fatalf("TrustedCIDRs length = %d, want 0", len(g.TrustedCIDRs))
	}
	g.Lockout.RecordFailure("key")
}

func TestNewInvalidConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Lockout.MaxFailedAttempts = -1
	if _, err := New(cfg); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("New error = %v, want ErrValidation", err)
	}
}

func TestNewInvalidCIDR(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Proxy.TrustedProxyCIDRs = []string{"not-an-ip"}
	_, err := New(cfg)
	if !errors.Is(err, domain.ErrValidation) || !errors.Is(err, domain.ErrInvalidIP) {
		t.Fatalf("New error = %v, want ErrValidation and ErrInvalidIP", err)
	}
}

func TestNewWithOptions(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	logger := observ.NewNoopLogger()
	cfg := config.DefaultConfig()
	cfg.Lockout.MaxFailedAttempts = 1
	cfg.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/8"}

	g, err := New(cfg, WithClock(clock.Now), WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Logger != logger {
		t.Fatal("WithLogger was not applied")
	}
	if len(g.TrustedCIDRs) != 1 {
		t.Fatalf("TrustedCIDRs length = %d, want 1", len(g.TrustedCIDRs))
	}

	key := "login|key|203.0.113.5"
	g.Lockout.RecordFailure(key)
	if g.Lockout.Allow(key) {
		t.Fatal("lockout should use the injected clock")
	}
	clock.Advance(time.Minute)
	if !g.Lockout.Allow(key) {
		t.Fatal("lockout should expire after advancing the injected clock")
	}
}

func TestNewWithNilOptions(t *testing.T) {
	t.Parallel()

	g, err := New(config.DefaultConfig(), nil, WithClock(nil), WithLogger(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Logger == nil {
		t.Fatal("nil logger option should fall back to a no-op logger")
	}
	if g.Lockout == nil {
		t.Fatal("nil clock option should fall back to the default clock")
	}
	g.Lockout.RecordFailure("key")
}

func TestClientIP(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Proxy.BehindReverseProxy = true
	cfg.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip, err := g.ClientIP("10.0.0.1:1234", "203.0.113.9", "")
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if ip.String() != "203.0.113.9" {
		t.Fatalf("IP = %s, want 203.0.113.9", ip)
	}

	if _, err := g.ClientIP("bad", "", ""); !errors.Is(err, domain.ErrInvalidIP) {
		t.Fatalf("error = %v, want ErrInvalidIP", err)
	}
}

func TestClientIPFromRequest(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Proxy.BehindReverseProxy = true
	cfg.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	ip, err := g.ClientIPFromRequest(r)
	if err != nil {
		t.Fatalf("ClientIPFromRequest: %v", err)
	}
	if ip.String() != "203.0.113.9" {
		t.Fatalf("IP = %s, want 203.0.113.9", ip)
	}
}

func TestSweepAll(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	cfg := config.DefaultConfig()
	cfg.Ban.MaxUniqueFailures = 1
	g, err := New(cfg, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	g.Lockout.RecordFailure("key")
	g.RateLimiter.Allow("203.0.113.5", 10, cfg.RateLimit.Window)
	g.LoginThrottle.Allow("acct", 10, cfg.RateLimit.LoginThrottleWindow)
	g.BanTracker.RecordAndBan("203.0.113.5", "fp", 1, cfg.Ban.BanDuration, cfg.Ban.Window)

	clock.Advance(31 * time.Minute)
	g.SweepAll()

	if g.Lockout.Len() != 0 {
		t.Fatalf("Lockout.Len() = %d, want 0", g.Lockout.Len())
	}
	if g.RateLimiter.Len() != 0 {
		t.Fatalf("RateLimiter.Len() = %d, want 0", g.RateLimiter.Len())
	}
	if g.LoginThrottle.Len() != 0 {
		t.Fatalf("LoginThrottle.Len() = %d, want 0", g.LoginThrottle.Len())
	}
	if g.BanTracker.IsBanned("203.0.113.5") {
		t.Fatal("BanTracker ban was not swept")
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	g, err := New(config.DefaultConfig(), WithClock(clock.Now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Lockout.Allow("key")
			g.Lockout.RecordFailure("key")
			g.Lockout.RecordSuccess("key")
			g.RateLimiter.Allow("203.0.113.5", 10, time.Minute)
			g.LoginThrottle.Allow("acct", 10, time.Minute)
			g.BanTracker.RecordAndBan("203.0.113.5", "fp", 5, time.Minute, time.Minute)
			g.BanTracker.IsBanned("203.0.113.5")
			g.BanTracker.ListBans()
			g.SweepAll()
			_, _ = g.ClientIP("203.0.113.5:1234", "", "")
		}()
	}
	wg.Wait()
}
