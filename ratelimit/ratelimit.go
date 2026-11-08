// Package ratelimit provides bounded sliding-window request and login-attempt
// limiters with throttled sweeps (CWE-307, CWE-400, CWE-770).
package ratelimit

import (
	"sync"
	"time"

	"github.com/disaster37/go-secguard/domain"
)

// ClampWindow returns window when positive, or fallback (or
// DefaultLoginThrottleWindow when fallback <= 0).
func ClampWindow(window, fallback time.Duration) time.Duration {
	if window > 0 {
		return window
	}
	if fallback > 0 {
		return fallback
	}
	return domain.DefaultLoginThrottleWindow
}

// RateLimiter is a bounded sliding-window per-key (typically per-IP) request
// limiter.
type RateLimiter struct {
	mu        sync.Mutex
	entries   map[string][]time.Time
	lastSweep time.Time
	max       int
	clock     func() time.Time
}

// NewRateLimiter returns a RateLimiter bounded to maxEntries keys.
func NewRateLimiter(maxEntries int, clock func() time.Time) *RateLimiter {
	if maxEntries <= 0 {
		maxEntries = domain.DefaultMaxEntries
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &RateLimiter{entries: make(map[string][]time.Time), max: maxEntries, clock: clock}
}

// Allow reports whether key may make another request within window (clamped via
// ClampWindow). When maxRequests <= 0, DefaultRateLimitMax is used so a zero or
// negative limit cannot turn the limiter into an unbounded "deny all" map.
func (rl *RateLimiter) Allow(key string, maxRequests int, window time.Duration) bool {
	if maxRequests <= 0 {
		maxRequests = domain.DefaultRateLimitMax
	}
	window = ClampWindow(window, domain.DefaultRateLimitWindow)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.clock()
	maybeSweep(rl.entries, &rl.lastSweep, now, window)

	valid := filterWindow(rl.entries[key], now.Add(-window))
	if len(valid) >= maxRequests {
		rl.entries[key] = valid
		return false
	}
	if _, exists := rl.entries[key]; !exists && len(rl.entries) >= rl.max {
		evictOldest(rl.entries)
	}
	rl.entries[key] = append(valid, now)
	return true
}

// Sweep removes keys with no timestamps within window.
func (rl *RateLimiter) Sweep(window time.Duration) {
	window = ClampWindow(window, domain.DefaultRateLimitWindow)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.clock()
	rl.lastSweep = now
	sweep(rl.entries, now, window)
}

// Len returns the current number of tracked keys.
func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.entries)
}

// LoginThrottle is a bounded sliding-window per-account login attempt limiter.
type LoginThrottle struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	lastSweep time.Time
	max       int
	clock     func() time.Time
}

// NewLoginThrottle returns a LoginThrottle bounded to maxEntries keys.
func NewLoginThrottle(maxEntries int, clock func() time.Time) *LoginThrottle {
	if maxEntries <= 0 {
		maxEntries = domain.DefaultMaxEntries
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &LoginThrottle{attempts: make(map[string][]time.Time), max: maxEntries, clock: clock}
}

// Allow reports whether key may attempt another login within window. When
// maxAttempts <= 0, DefaultLoginThrottleAttempts is used.
func (lt *LoginThrottle) Allow(key string, maxAttempts int, window time.Duration) bool {
	if maxAttempts <= 0 {
		maxAttempts = domain.DefaultLoginThrottleAttempts
	}
	window = ClampWindow(window, domain.DefaultLoginThrottleWindow)

	lt.mu.Lock()
	defer lt.mu.Unlock()

	now := lt.clock()
	maybeSweep(lt.attempts, &lt.lastSweep, now, window)

	valid := filterWindow(lt.attempts[key], now.Add(-window))
	if len(valid) >= maxAttempts {
		lt.attempts[key] = valid
		return false
	}
	if _, exists := lt.attempts[key]; !exists && len(lt.attempts) >= lt.max {
		evictOldest(lt.attempts)
	}
	lt.attempts[key] = append(valid, now)
	return true
}

// Clear resets the throttle state for key after a successful login.
func (lt *LoginThrottle) Clear(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.attempts, key)
}

// Sweep removes keys with no attempts within window.
func (lt *LoginThrottle) Sweep(window time.Duration) {
	window = ClampWindow(window, domain.DefaultLoginThrottleWindow)

	lt.mu.Lock()
	defer lt.mu.Unlock()

	now := lt.clock()
	lt.lastSweep = now
	sweep(lt.attempts, now, window)
}

// Len returns the current number of tracked keys.
func (lt *LoginThrottle) Len() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return len(lt.attempts)
}

func filterWindow(times []time.Time, cutoff time.Time) []time.Time {
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	return valid
}

func maybeSweep(entries map[string][]time.Time, lastSweep *time.Time, now time.Time, window time.Duration) {
	if !lastSweep.IsZero() && now.Sub(*lastSweep) < window {
		return
	}
	*lastSweep = now
	sweep(entries, now, window)
}

func sweep(entries map[string][]time.Time, now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	for key, times := range entries {
		if len(times) == 0 || times[len(times)-1].Before(cutoff) {
			delete(entries, key)
		}
	}
}

func evictOldest(entries map[string][]time.Time) {
	var oldestKey string
	var oldest time.Time
	first := true
	for key, times := range entries {
		if len(times) == 0 {
			delete(entries, key)
			continue
		}
		last := times[len(times)-1]
		if first || last.Before(oldest) {
			oldestKey = key
			oldest = last
			first = false
		}
	}
	if !first {
		delete(entries, oldestKey)
	}
}
