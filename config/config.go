// Package config defines validated configuration structs for go-secguard
// components. The structs carry mapstructure, json, and yaml tags so they can be
// embedded in any application configuration loader.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/lockout"
	"github.com/disaster37/go-secguard/realip"
)

// Config holds the complete configuration for go-secguard components.
type Config struct {
	Lockout   LockoutConfig   `mapstructure:"lockout" json:"lockout" yaml:"lockout"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit" json:"rate_limit" yaml:"rate_limit"`
	Ban       BanConfig       `mapstructure:"ban" json:"ban" yaml:"ban"`
	Proxy     ProxyConfig     `mapstructure:"proxy" json:"proxy" yaml:"proxy"`
	CORS      CORSConfig      `mapstructure:"cors" json:"cors" yaml:"cors"`
}

// LockoutConfig configures the exponential lockout limiter.
type LockoutConfig struct {
	Enabled           bool          `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	MaxFailedAttempts int           `mapstructure:"max_failed_attempts" json:"max_failed_attempts" yaml:"max_failed_attempts"`
	BaseLockout       time.Duration `mapstructure:"base_lockout" json:"base_lockout" yaml:"base_lockout"`
	MaxLockout        time.Duration `mapstructure:"max_lockout" json:"max_lockout" yaml:"max_lockout"`
	EntryTTL          time.Duration `mapstructure:"entry_ttl" json:"entry_ttl" yaml:"entry_ttl"`
	MaxEntries        int           `mapstructure:"max_entries" json:"max_entries" yaml:"max_entries"`
}

// RateLimitConfig configures the request and login-attempt limiters.
type RateLimitConfig struct {
	Enabled               bool          `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	MaxRequests           int           `mapstructure:"max_requests" json:"max_requests" yaml:"max_requests"`
	Window                time.Duration `mapstructure:"window" json:"window" yaml:"window"`
	LoginThrottleAttempts int           `mapstructure:"login_throttle_attempts" json:"login_throttle_attempts" yaml:"login_throttle_attempts"`
	LoginThrottleWindow   time.Duration `mapstructure:"login_throttle_window" json:"login_throttle_window" yaml:"login_throttle_window"`
	MaxEntries            int           `mapstructure:"max_entries" json:"max_entries" yaml:"max_entries"`
}

// BanConfig configures the credential-stuffing ban tracker.
type BanConfig struct {
	Enabled           bool          `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	MaxUniqueFailures int           `mapstructure:"max_unique_failures" json:"max_unique_failures" yaml:"max_unique_failures"`
	BanDuration       time.Duration `mapstructure:"ban_duration" json:"ban_duration" yaml:"ban_duration"`
	Window            time.Duration `mapstructure:"window" json:"window" yaml:"window"`
	MaxEntries        int           `mapstructure:"max_entries" json:"max_entries" yaml:"max_entries"`
}

// ProxyConfig configures trusted reverse-proxy client IP resolution.
type ProxyConfig struct {
	BehindReverseProxy bool     `mapstructure:"behind_reverse_proxy" json:"behind_reverse_proxy" yaml:"behind_reverse_proxy"`
	TrustedProxyCIDRs  []string `mapstructure:"trusted_proxy_cidrs" json:"trusted_proxy_cidrs" yaml:"trusted_proxy_cidrs"`
}

// CORSConfig configures allowed browser origins for mutation validation.
type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins" json:"allowed_origins" yaml:"allowed_origins"`
}

// DefaultConfig returns a Config populated with production-safe defaults.
func DefaultConfig() Config {
	return Config{
		Lockout: LockoutConfig{
			Enabled:           true,
			MaxFailedAttempts: domain.DefaultMaxFailedAttempts,
			BaseLockout:       domain.DefaultBaseLockout,
			MaxLockout:        domain.DefaultMaxLockout,
			EntryTTL:          domain.DefaultEntryTTL,
			MaxEntries:        domain.DefaultMaxEntries,
		},
		RateLimit: RateLimitConfig{
			Enabled:               true,
			MaxRequests:           domain.DefaultRateLimitMax,
			Window:                domain.DefaultRateLimitWindow,
			LoginThrottleAttempts: domain.DefaultLoginThrottleAttempts,
			LoginThrottleWindow:   domain.DefaultLoginThrottleWindow,
			MaxEntries:            domain.DefaultMaxEntries,
		},
		Ban: BanConfig{
			Enabled:           true,
			MaxUniqueFailures: domain.DefaultBanMaxUniqueFailures,
			BanDuration:       domain.DefaultBanDuration,
			Window:            domain.DefaultBanWindow,
			MaxEntries:        domain.DefaultMaxEntries,
		},
		Proxy: ProxyConfig{BehindReverseProxy: false},
		CORS:  CORSConfig{},
	}
}

// Validate checks all durations, thresholds, and TrustedProxyCIDRs, returning
// an error wrapping domain.ErrValidation on invalid configuration.
func (c *Config) Validate() error {
	if c.Lockout.MaxFailedAttempts < 0 {
		return invalid("lockout.max_failed_attempts must be >= 0")
	}
	if c.Lockout.MaxEntries < 0 {
		return invalid("lockout.max_entries must be >= 0")
	}
	if c.Lockout.BaseLockout < 0 {
		return invalid("lockout.base_lockout must be >= 0")
	}
	if c.Lockout.MaxLockout < 0 {
		return invalid("lockout.max_lockout must be >= 0")
	}
	if c.Lockout.EntryTTL < 0 {
		return invalid("lockout.entry_ttl must be >= 0")
	}
	if c.Lockout.BaseLockout > 0 && c.Lockout.MaxLockout > 0 && c.Lockout.MaxLockout < c.Lockout.BaseLockout {
		return invalid("lockout.max_lockout must be >= lockout.base_lockout")
	}
	if c.RateLimit.MaxRequests < 0 {
		return invalid("rate_limit.max_requests must be >= 0")
	}
	if c.RateLimit.LoginThrottleAttempts < 0 {
		return invalid("rate_limit.login_throttle_attempts must be >= 0")
	}
	if c.RateLimit.MaxEntries < 0 {
		return invalid("rate_limit.max_entries must be >= 0")
	}
	if c.RateLimit.Window < 0 {
		return invalid("rate_limit.window must be >= 0")
	}
	if c.RateLimit.LoginThrottleWindow < 0 {
		return invalid("rate_limit.login_throttle_window must be >= 0")
	}
	if c.Ban.MaxUniqueFailures < 0 {
		return invalid("ban.max_unique_failures must be >= 0")
	}
	if c.Ban.MaxEntries < 0 {
		return invalid("ban.max_entries must be >= 0")
	}
	if c.Ban.BanDuration < 0 {
		return invalid("ban.ban_duration must be >= 0")
	}
	if c.Ban.Window < 0 {
		return invalid("ban.window must be >= 0")
	}
	if _, err := c.Proxy.ParseTrustedCIDRs(); err != nil {
		return fmt.Errorf("invalid proxy.trusted_proxy_cidrs: %w: %w", domain.ErrValidation, err)
	}
	for _, origin := range c.CORS.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" || origin == "*" {
			continue
		}
		if !validOrigin(origin) {
			return invalid("cors.allowed_origins entry %q is not a valid origin", origin)
		}
	}
	return nil
}

// ToLockoutConfig converts LockoutConfig to lockout.Config with an optional
// clock.
func (c LockoutConfig) ToLockoutConfig(clock func() time.Time) lockout.Config {
	return lockout.Config{
		MaxFailedAttempts: c.MaxFailedAttempts,
		BaseLockout:       c.BaseLockout,
		MaxLockout:        c.MaxLockout,
		EntryTTL:          c.EntryTTL,
		MaxEntries:        c.MaxEntries,
		Clock:             clock,
	}
}

// ParseTrustedCIDRs parses and returns ProxyConfig.TrustedProxyCIDRs.
func (c ProxyConfig) ParseTrustedCIDRs() ([]*net.IPNet, error) {
	return realip.ParseTrustedProxyCIDRs(c.TrustedProxyCIDRs)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", domain.ErrValidation, fmt.Sprintf(format, args...))
}

func validOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" || u.User != nil {
		return false
	}
	return u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
