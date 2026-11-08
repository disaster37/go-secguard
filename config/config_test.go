package config

import (
	"errors"
	"testing"
	"time"

	"github.com/disaster37/go-secguard/domain"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	if !cfg.Lockout.Enabled || !cfg.RateLimit.Enabled || !cfg.Ban.Enabled {
		t.Fatal("default config should enable all protections")
	}
	if cfg.Lockout.MaxFailedAttempts != domain.DefaultMaxFailedAttempts {
		t.Fatalf("MaxFailedAttempts = %d", cfg.Lockout.MaxFailedAttempts)
	}
	if cfg.Lockout.BaseLockout != domain.DefaultBaseLockout {
		t.Fatalf("BaseLockout = %s", cfg.Lockout.BaseLockout)
	}
	if cfg.Lockout.MaxLockout != domain.DefaultMaxLockout {
		t.Fatalf("MaxLockout = %s", cfg.Lockout.MaxLockout)
	}
	if cfg.Lockout.EntryTTL != domain.DefaultEntryTTL {
		t.Fatalf("EntryTTL = %s", cfg.Lockout.EntryTTL)
	}
	if cfg.Lockout.MaxEntries != domain.DefaultMaxEntries {
		t.Fatalf("Lockout MaxEntries = %d", cfg.Lockout.MaxEntries)
	}
	if cfg.RateLimit.MaxRequests != domain.DefaultRateLimitMax {
		t.Fatalf("MaxRequests = %d", cfg.RateLimit.MaxRequests)
	}
	if cfg.RateLimit.Window != domain.DefaultRateLimitWindow {
		t.Fatalf("Window = %s", cfg.RateLimit.Window)
	}
	if cfg.RateLimit.LoginThrottleAttempts != domain.DefaultLoginThrottleAttempts {
		t.Fatalf("LoginThrottleAttempts = %d", cfg.RateLimit.LoginThrottleAttempts)
	}
	if cfg.RateLimit.LoginThrottleWindow != domain.DefaultLoginThrottleWindow {
		t.Fatalf("LoginThrottleWindow = %s", cfg.RateLimit.LoginThrottleWindow)
	}
	if cfg.RateLimit.MaxEntries != domain.DefaultMaxEntries {
		t.Fatalf("RateLimit MaxEntries = %d", cfg.RateLimit.MaxEntries)
	}
	if cfg.Ban.MaxUniqueFailures != domain.DefaultBanMaxUniqueFailures {
		t.Fatalf("MaxUniqueFailures = %d", cfg.Ban.MaxUniqueFailures)
	}
	if cfg.Ban.BanDuration != domain.DefaultBanDuration {
		t.Fatalf("BanDuration = %s", cfg.Ban.BanDuration)
	}
	if cfg.Ban.Window != domain.DefaultBanWindow {
		t.Fatalf("Ban Window = %s", cfg.Ban.Window)
	}
	if cfg.Ban.MaxEntries != domain.DefaultMaxEntries {
		t.Fatalf("Ban MaxEntries = %d", cfg.Ban.MaxEntries)
	}
	if cfg.Proxy.BehindReverseProxy {
		t.Fatal("BehindReverseProxy should default to false")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() = %v", err)
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/8", "203.0.113.7", "2001:db8::/32"}
	cfg.CORS.AllowedOrigins = []string{"https://example.com", "http://localhost:3000", "*", "", "  "}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	var zero Config
	if err := zero.Validate(); err != nil {
		t.Fatalf("zero Config Validate() = %v", err)
	}
}

func TestValidateInvalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"lockout max failed attempts", func(c *Config) { c.Lockout.MaxFailedAttempts = -1 }},
		{"lockout max entries", func(c *Config) { c.Lockout.MaxEntries = -1 }},
		{"lockout base lockout", func(c *Config) { c.Lockout.BaseLockout = -1 }},
		{"lockout max lockout", func(c *Config) { c.Lockout.MaxLockout = -1 }},
		{"lockout entry ttl", func(c *Config) { c.Lockout.EntryTTL = -1 }},
		{"lockout max below base", func(c *Config) {
			c.Lockout.BaseLockout = 2 * time.Minute
			c.Lockout.MaxLockout = time.Minute
		}},
		{"rate limit max requests", func(c *Config) { c.RateLimit.MaxRequests = -1 }},
		{"rate limit login attempts", func(c *Config) { c.RateLimit.LoginThrottleAttempts = -1 }},
		{"rate limit max entries", func(c *Config) { c.RateLimit.MaxEntries = -1 }},
		{"rate limit window", func(c *Config) { c.RateLimit.Window = -1 }},
		{"rate limit login window", func(c *Config) { c.RateLimit.LoginThrottleWindow = -1 }},
		{"ban max unique failures", func(c *Config) { c.Ban.MaxUniqueFailures = -1 }},
		{"ban max entries", func(c *Config) { c.Ban.MaxEntries = -1 }},
		{"ban duration", func(c *Config) { c.Ban.BanDuration = -1 }},
		{"ban window", func(c *Config) { c.Ban.Window = -1 }},
		{"invalid trusted ip", func(c *Config) { c.Proxy.TrustedProxyCIDRs = []string{"not-an-ip"} }},
		{"invalid trusted cidr", func(c *Config) { c.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/99"} }},
		{"cors bad scheme", func(c *Config) { c.CORS.AllowedOrigins = []string{"ftp://example.com"} }},
		{"cors path", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://example.com/path"} }},
		{"cors query", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://example.com?q=1"} }},
		{"cors fragment", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://example.com#frag"} }},
		{"cors userinfo", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://user:pass@example.com"} }},
		{"cors missing host", func(c *Config) { c.CORS.AllowedOrigins = []string{"https://"} }},
		{"cors not a url", func(c *Config) { c.CORS.AllowedOrigins = []string{"not a url"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Validate() = %v, want ErrValidation", err)
			}
		})
	}
}

func TestValidateTrustedCIDRSentinels(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Proxy.TrustedProxyCIDRs = []string{"not-an-ip"}
	err := cfg.Validate()
	if !errors.Is(err, domain.ErrValidation) || !errors.Is(err, domain.ErrInvalidIP) {
		t.Fatalf("error = %v, want ErrValidation and ErrInvalidIP", err)
	}

	cfg.Proxy.TrustedProxyCIDRs = []string{"10.0.0.0/99"}
	err = cfg.Validate()
	if !errors.Is(err, domain.ErrValidation) || !errors.Is(err, domain.ErrInvalidCIDR) {
		t.Fatalf("error = %v, want ErrValidation and ErrInvalidCIDR", err)
	}
}

func TestToLockoutConfig(t *testing.T) {
	t.Parallel()

	clock := func() time.Time { return time.Unix(0, 0) }
	cfg := LockoutConfig{
		MaxFailedAttempts: 3,
		BaseLockout:       time.Second,
		MaxLockout:        time.Minute,
		EntryTTL:          time.Hour,
		MaxEntries:        11,
	}
	got := cfg.ToLockoutConfig(clock)
	if got.MaxFailedAttempts != 3 || got.BaseLockout != time.Second ||
		got.MaxLockout != time.Minute || got.EntryTTL != time.Hour ||
		got.MaxEntries != 11 || got.Clock == nil {
		t.Fatalf("unexpected lockout config: %+v", got)
	}
}

func TestParseTrustedCIDRs(t *testing.T) {
	t.Parallel()

	proxy := ProxyConfig{TrustedProxyCIDRs: []string{"10.0.0.0/8", "203.0.113.7"}}
	nets, err := proxy.ParseTrustedCIDRs()
	if err != nil {
		t.Fatalf("ParseTrustedCIDRs: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("len = %d, want 2", len(nets))
	}

	proxy.TrustedProxyCIDRs = []string{"bad"}
	if _, err := proxy.ParseTrustedCIDRs(); !errors.Is(err, domain.ErrInvalidIP) {
		t.Fatalf("error = %v, want ErrInvalidIP", err)
	}
}
