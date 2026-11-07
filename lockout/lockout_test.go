package lockout

import (
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/testutil"
)

func TestNewAppliesDefaults(t *testing.T) {
	t.Parallel()

	l := New(Config{})
	if l.cfg.MaxFailedAttempts != domain.DefaultMaxFailedAttempts {
		t.Fatalf("MaxFailedAttempts = %d", l.cfg.MaxFailedAttempts)
	}
	if l.cfg.BaseLockout != domain.DefaultBaseLockout {
		t.Fatalf("BaseLockout = %s", l.cfg.BaseLockout)
	}
	if l.cfg.MaxLockout != domain.DefaultMaxLockout {
		t.Fatalf("MaxLockout = %s", l.cfg.MaxLockout)
	}
	if l.cfg.EntryTTL != domain.DefaultEntryTTL {
		t.Fatalf("EntryTTL = %s", l.cfg.EntryTTL)
	}
	if l.cfg.MaxEntries != domain.DefaultMaxEntries {
		t.Fatalf("MaxEntries = %d", l.cfg.MaxEntries)
	}
	if l.cfg.Clock == nil {
		t.Fatal("Clock is nil")
	}
}

func TestNewKeepsCustomConfig(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	cfg := Config{
		MaxFailedAttempts: 2,
		BaseLockout:       time.Second,
		MaxLockout:        time.Minute,
		EntryTTL:          time.Hour,
		MaxEntries:        7,
		Clock:             clock.Now,
	}
	l := New(cfg)
	if l.cfg.MaxFailedAttempts != 2 || l.cfg.BaseLockout != time.Second ||
		l.cfg.MaxLockout != time.Minute || l.cfg.EntryTTL != time.Hour ||
		l.cfg.MaxEntries != 7 {
		t.Fatalf("custom config not preserved: %+v", l.cfg)
	}
}

func TestLoginLimitKey(t *testing.T) {
	t.Parallel()

	base := LoginLimitKey("Alice", "203.0.113.7")
	if base != LoginLimitKey("ALICE", "203.0.113.7") {
		t.Fatal("login key is not case-insensitive")
	}
	if base != LoginLimitKey("  alice  ", " 203.0.113.7 ") {
		t.Fatal("login key is not whitespace-normalized")
	}
	if !strings.HasPrefix(base, "login|") {
		t.Fatalf("login key %q lacks prefix", base)
	}
	if strings.Contains(base, "alice") {
		t.Fatalf("login key %q leaks the raw username", base)
	}
	if base == LoginLimitKey("alice", "203.0.113.8") {
		t.Fatal("login key ignores the client IP")
	}
	if base == LoginLimitKey("alice|203.0.113.7", "") {
		t.Fatal("delimiter injection produced a collision")
	}
}

func TestPasswordChangeLimitKey(t *testing.T) {
	t.Parallel()

	base := PasswordChangeLimitKey("user-1", "203.0.113.7")
	if base != PasswordChangeLimitKey(" user-1 ", "203.0.113.7") {
		t.Fatal("password-change key is not whitespace-normalized")
	}
	if !strings.HasPrefix(base, "chpw|") {
		t.Fatalf("password-change key %q lacks prefix", base)
	}
	if strings.Contains(base, "user-1") {
		t.Fatalf("password-change key %q leaks the raw user ID", base)
	}
	if base == LoginLimitKey("user-1", "203.0.113.7") {
		t.Fatal("login and password-change keys collide")
	}
}

func TestAllowUnknownKey(t *testing.T) {
	t.Parallel()

	l := New(Config{})
	if !l.Allow("missing") {
		t.Fatal("unknown key should be allowed")
	}
}

func TestRecordFailureThresholdAndBackoff(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{
		MaxFailedAttempts: 3,
		BaseLockout:       10 * time.Second,
		MaxLockout:        time.Minute,
		EntryTTL:          time.Hour,
		Clock:             clock.Now,
	})

	for i := 1; i < 3; i++ {
		if got := l.RecordFailure("k"); got != 0 {
			t.Fatalf("failure %d returned %s, want 0", i, got)
		}
	}
	if got := l.RecordFailure("k"); got != 10*time.Second {
		t.Fatalf("threshold lockout = %s, want 10s", got)
	}
	if l.Allow("k") {
		t.Fatal("locked key should not be allowed")
	}
	if got := l.RecordFailure("k"); got != 20*time.Second {
		t.Fatalf("second lockout = %s, want 20s", got)
	}
	if got := l.RecordFailure("k"); got != 40*time.Second {
		t.Fatalf("third lockout = %s, want 40s", got)
	}
	if got := l.RecordFailure("k"); got != time.Minute {
		t.Fatalf("capped lockout = %s, want 1m", got)
	}

	clock.Advance(time.Minute)
	if !l.Allow("k") {
		t.Fatal("key should be allowed after lockout expires")
	}
}

func TestRecordFailureShiftClamp(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{
		MaxFailedAttempts: 1,
		BaseLockout:       time.Nanosecond,
		MaxLockout:        time.Hour,
		EntryTTL:          time.Hour,
		Clock:             clock.Now,
	})

	var last time.Duration
	for i := 0; i < domain.MaxLockoutShift+5; i++ {
		last = l.RecordFailure("k")
	}
	want := time.Duration(1<<domain.MaxLockoutShift) * time.Nanosecond
	if last != want {
		t.Fatalf("shift-clamped lockout = %s, want %s", last, want)
	}
}

func TestRecordFailureOverflowProtection(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{
		MaxFailedAttempts: 1,
		BaseLockout:       time.Duration(1) << 62,
		MaxLockout:        time.Duration(math.MaxInt64),
		EntryTTL:          time.Hour,
		Clock:             clock.Now,
	})

	got := l.RecordFailure("k")
	if got != time.Duration(1)<<62 {
		t.Fatalf("first lockout = %s, want 1<<62", got)
	}
	got = l.RecordFailure("k")
	if got != time.Duration(math.MaxInt64) {
		t.Fatalf("overflow-protected lockout = %s, want MaxInt64", got)
	}
}

func TestRecordFailureIdleReset(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{
		MaxFailedAttempts: 5,
		BaseLockout:       time.Second,
		MaxLockout:        time.Minute,
		EntryTTL:          10 * time.Second,
		Clock:             clock.Now,
	})

	if got := l.RecordFailure("k"); got != 0 {
		t.Fatalf("first failure = %s, want 0", got)
	}
	clock.Advance(9 * time.Second)
	if got := l.RecordFailure("other"); got != 0 {
		t.Fatalf("other failure = %s, want 0", got)
	}
	clock.Advance(2 * time.Second)

	// "k" is now idle beyond EntryTTL but the throttled sweep has not run yet,
	// so its failure counter must be reset before incrementing.
	if got := l.RecordFailure("k"); got != 0 {
		t.Fatalf("reset failure = %s, want 0", got)
	}
	for i := 0; i < 3; i++ {
		if got := l.RecordFailure("k"); got != 0 {
			t.Fatalf("failure %d after reset = %s, want 0", i, got)
		}
	}
	if got := l.RecordFailure("k"); got != time.Second {
		t.Fatalf("threshold after reset = %s, want 1s", got)
	}
}

func TestAllowExpiredEntry(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{
		MaxFailedAttempts: 5,
		BaseLockout:       time.Second,
		MaxLockout:        time.Minute,
		EntryTTL:          10 * time.Second,
		Clock:             clock.Now,
	})

	l.RecordFailure("k")
	clock.Advance(9 * time.Second)
	l.RecordFailure("other")
	clock.Advance(2 * time.Second)

	if !l.Allow("k") {
		t.Fatal("idle expired key should be allowed")
	}
	if l.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", l.Len())
	}
}

func TestRecordSuccess(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{MaxFailedAttempts: 1, Clock: clock.Now})
	l.RecordFailure("k")
	if l.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", l.Len())
	}
	l.RecordSuccess("k")
	if l.Len() != 0 {
		t.Fatalf("Len() after success = %d, want 0", l.Len())
	}
	if !l.Allow("k") {
		t.Fatal("key should be allowed after success")
	}
}

func TestEviction(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{MaxEntries: 2, EntryTTL: time.Hour, Clock: clock.Now})

	l.RecordFailure("a")
	clock.Advance(time.Second)
	l.RecordFailure("b")
	clock.Advance(time.Second)
	l.RecordFailure("c")

	if l.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", l.Len())
	}
	if _, ok := l.entries["a"]; ok {
		t.Fatal("oldest entry was not evicted")
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{
		MaxFailedAttempts: 5,
		BaseLockout:       time.Minute,
		MaxLockout:        time.Minute,
		EntryTTL:          10 * time.Second,
		Clock:             clock.Now,
	})

	l.RecordFailure("idle")
	for i := 0; i < 5; i++ {
		l.RecordFailure("locked")
	}

	clock.Advance(11 * time.Second)
	l.Sweep()
	if l.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 (locked entry retained)", l.Len())
	}

	clock.Advance(time.Minute)
	l.Sweep()
	if l.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", l.Len())
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	l := New(Config{MaxEntries: 32, Clock: clock.Now})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := LoginLimitKey("user", "203.0.113.1")
			l.Allow(key)
			l.RecordFailure(key)
			l.RecordSuccess(key)
			l.Sweep()
			_ = l.Len()
		}(i)
	}
	wg.Wait()
}
