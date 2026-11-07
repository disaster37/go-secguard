// Package lockout provides a per-key exponential backoff limiter for failed
// authentication attempts (CWE-307) with bounded state and throttled sweeps.
package lockout

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/disaster37/go-secguard/domain"
)

// Config configures a Limiter.
type Config struct {
	MaxFailedAttempts int
	BaseLockout       time.Duration
	MaxLockout        time.Duration
	EntryTTL          time.Duration
	MaxEntries        int
	Clock             func() time.Time
}

func (c Config) withDefaults() Config {
	if c.MaxFailedAttempts <= 0 {
		c.MaxFailedAttempts = domain.DefaultMaxFailedAttempts
	}
	if c.BaseLockout <= 0 {
		c.BaseLockout = domain.DefaultBaseLockout
	}
	if c.MaxLockout <= 0 {
		c.MaxLockout = domain.DefaultMaxLockout
	}
	if c.EntryTTL <= 0 {
		c.EntryTTL = domain.DefaultEntryTTL
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = domain.DefaultMaxEntries
	}
	if c.Clock == nil {
		c.Clock = func() time.Time { return time.Now().UTC() }
	}
	return c
}

type entry struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// Limiter tracks failed authentication attempts per key and imposes
// exponentially growing lockouts after repeated failures (CWE-307).
type Limiter struct {
	mu        sync.Mutex
	entries   map[string]*entry
	lastSweep time.Time
	cfg       Config
}

// New returns a new Limiter initialized with cfg (applying safe defaults for
// zero/negative fields).
func New(cfg Config) *Limiter {
	return &Limiter{entries: make(map[string]*entry), cfg: cfg.withDefaults()}
}

// LoginLimitKey returns a collision-resistant, case-normalized lockout key for a
// login attempt: "login|<sha256(lower(trim(username)))>|<trim(clientIP)>".
// Raw usernames are hashed to prevent CWE-532 memory/log leakage.
func LoginLimitKey(username, clientIP string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	return fmt.Sprintf("login|%s|%s", hash(normalized), strings.TrimSpace(clientIP))
}

// PasswordChangeLimitKey returns a collision-resistant lockout key for a
// password-change attempt: "chpw|<sha256(trim(userID))>|<trim(clientIP)>".
func PasswordChangeLimitKey(userID, clientIP string) string {
	normalized := strings.TrimSpace(userID)
	return fmt.Sprintf("chpw|%s|%s", hash(normalized), strings.TrimSpace(clientIP))
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Allow reports whether key may attempt authentication right now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.cfg.Clock()
	info, ok := l.entries[key]
	if ok && l.expiredLocked(info, now) {
		delete(l.entries, key)
		ok = false
	}
	l.maybeSweepLocked(now)
	if !ok {
		return true
	}
	return !now.Before(info.lockedUntil)
}

// RecordFailure records a failed attempt for key and returns the lockout
// duration triggered (0 when the failure count is still below
// MaxFailedAttempts).
func (l *Limiter) RecordFailure(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.cfg.Clock()

	info, ok := l.entries[key]
	if ok && l.expiredLocked(info, now) {
		info.failures = 0
	}
	if !ok {
		if len(l.entries) >= l.cfg.MaxEntries {
			l.evictOldestLocked()
		}
		info = &entry{}
		l.entries[key] = info
	}

	info.failures++
	info.lastSeen = now
	l.maybeSweepLocked(now)
	if info.failures < l.cfg.MaxFailedAttempts {
		return 0
	}
	lock := l.lockDuration(info.failures)
	info.lockedUntil = now.Add(lock)
	return lock
}

// RecordSuccess clears the failure history for key after successful
// authentication.
func (l *Limiter) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Sweep immediately removes idle unlocked entries older than EntryTTL.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.cfg.Clock()
	l.lastSweep = now
	l.sweepLocked(now)
}

// Len returns the current number of tracked keys (for metrics/testing).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *Limiter) lockDuration(failures int) time.Duration {
	shift := failures - l.cfg.MaxFailedAttempts
	if shift > domain.MaxLockoutShift {
		shift = domain.MaxLockoutShift
	}
	lock := l.cfg.BaseLockout
	for i := 0; i < shift && lock < l.cfg.MaxLockout; i++ {
		if lock > l.cfg.MaxLockout/2 {
			lock = l.cfg.MaxLockout
			break
		}
		lock *= 2
	}
	if lock > l.cfg.MaxLockout {
		lock = l.cfg.MaxLockout
	}
	return lock
}

func (l *Limiter) expiredLocked(info *entry, now time.Time) bool {
	return now.Sub(info.lastSeen) > l.cfg.EntryTTL && !now.Before(info.lockedUntil)
}

func (l *Limiter) maybeSweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < l.cfg.EntryTTL {
		return
	}
	l.lastSweep = now
	l.sweepLocked(now)
}

func (l *Limiter) sweepLocked(now time.Time) {
	for key, info := range l.entries {
		if l.expiredLocked(info, now) {
			delete(l.entries, key)
		}
	}
}

func (l *Limiter) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, info := range l.entries {
		if first || info.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = info.lastSeen
			first = false
		}
	}
	if !first {
		delete(l.entries, oldestKey)
	}
}
