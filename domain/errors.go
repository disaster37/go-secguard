// Package domain defines the sentinel errors and shared defaults used by every
// go-secguard package. It depends only on the Go standard library.
package domain

import (
	"errors"
	"time"
)

const (
	// DefaultMaxEntries bounds in-memory tracker maps (CWE-770).
	DefaultMaxEntries = 4096

	// DefaultMaxFailedAttempts is the number of consecutive failures before
	// lockout starts (CWE-307).
	DefaultMaxFailedAttempts = 5

	// DefaultBaseLockout is the initial lockout duration at threshold.
	DefaultBaseLockout = 30 * time.Second

	// DefaultMaxLockout caps exponential lockout growth.
	DefaultMaxLockout = 15 * time.Minute

	// DefaultEntryTTL is how long an idle lockout record is retained.
	DefaultEntryTTL = 30 * time.Minute

	// MaxLockoutShift caps exponential shift to prevent int64 duration overflow.
	MaxLockoutShift = 16

	// DefaultRateLimitMax is the default per-IP request limit per window.
	DefaultRateLimitMax = 60

	// DefaultRateLimitWindow is the default sliding window for RateLimiter.
	DefaultRateLimitWindow = time.Minute

	// DefaultLoginThrottleAttempts is the default per-account attempt limit per window.
	DefaultLoginThrottleAttempts = 10

	// DefaultLoginThrottleWindow is the default sliding window for LoginThrottle.
	DefaultLoginThrottleWindow = 5 * time.Minute

	// DefaultBanMaxUniqueFailures is the default unique credential failure
	// threshold before banning an IP.
	DefaultBanMaxUniqueFailures = 10

	// DefaultBanDuration is the default IP ban duration.
	DefaultBanDuration = 15 * time.Minute

	// DefaultBanWindow is the default sliding window for counting unique
	// credential failures.
	DefaultBanWindow = 5 * time.Minute
)

// Sentinel errors matched via errors.Is across all packages.
var (
	ErrValidation       = errors.New("secguard: validation error")
	ErrRateLimited      = errors.New("secguard: too many attempts; try again later")
	ErrAccountLocked    = errors.New("secguard: account temporarily locked due to failed attempts")
	ErrIPBanned         = errors.New("secguard: client IP is temporarily banned")
	ErrOriginNotAllowed = errors.New("secguard: origin not allowed")
	ErrInvalidIP        = errors.New("secguard: invalid IP address")
	ErrInvalidCIDR      = errors.New("secguard: invalid CIDR")
)
