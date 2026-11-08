package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/testutil"
)

func TestClampWindow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		window   time.Duration
		fallback time.Duration
		want     time.Duration
	}{
		{"positive window", time.Second, time.Minute, time.Second},
		{"zero window positive fallback", 0, time.Minute, time.Minute},
		{"negative window positive fallback", -time.Second, time.Minute, time.Minute},
		{"zero window zero fallback", 0, 0, domain.DefaultLoginThrottleWindow},
		{"negative window negative fallback", -time.Second, -time.Second, domain.DefaultLoginThrottleWindow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClampWindow(tc.window, tc.fallback); got != tc.want {
				t.Fatalf("ClampWindow(%s, %s) = %s, want %s", tc.window, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestNewRateLimiterDefaults(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(0, nil)
	if rl.max != domain.DefaultMaxEntries {
		t.Fatalf("max = %d, want %d", rl.max, domain.DefaultMaxEntries)
	}
	if rl.clock == nil {
		t.Fatal("clock is nil")
	}

	rl = NewRateLimiter(-1, func() time.Time { return time.Unix(0, 0) })
	if rl.max != domain.DefaultMaxEntries {
		t.Fatalf("max = %d, want %d", rl.max, domain.DefaultMaxEntries)
	}
}

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(10, clock.Now)
	window := time.Minute

	if !rl.Allow("a", 2, window) {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow("a", 2, window) {
		t.Fatal("second request should be allowed")
	}
	if rl.Allow("a", 2, window) {
		t.Fatal("third request should be rate limited")
	}
	if rl.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", rl.Len())
	}

	clock.Advance(window + time.Second)
	if !rl.Allow("a", 2, window) {
		t.Fatal("request after window should be allowed")
	}
}

func TestRateLimiterWindowFallback(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(10, clock.Now)

	if !rl.Allow("a", 1, 0) {
		t.Fatal("first request should be allowed")
	}
	if rl.Allow("a", 1, 0) {
		t.Fatal("second request should be rate limited")
	}
	clock.Advance(domain.DefaultRateLimitWindow + time.Second)
	if !rl.Allow("a", 1, -time.Second) {
		t.Fatal("request after default window should be allowed")
	}
}

func TestRateLimiterAllowClampsMaxRequests(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(10, clock.Now)

	// A zero/negative maxRequests must be clamped to DefaultRateLimitMax rather
	// than interpreted as "deny all", which would also grow the map unboundedly.
	for i := 0; i < domain.DefaultRateLimitMax; i++ {
		if !rl.Allow("a", 0, time.Minute) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.Allow("a", 0, time.Minute) {
		t.Fatal("request over the default limit should be denied")
	}
	if rl.Allow("a", -1, time.Minute) {
		t.Fatal("negative maxRequests should clamp to the default limit")
	}
}

func TestRateLimiterAllowZeroMaxRequestsBounded(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(10, clock.Now)

	// Even with a zero maxRequests, the map must stay bounded by max.
	for i := 0; i < 100; i++ {
		rl.Allow(fmt.Sprintf("key-%d", i), 0, time.Minute)
	}
	if rl.Len() > 10 {
		t.Fatalf("Len() = %d, want <= 10", rl.Len())
	}
}

func TestRateLimiterEviction(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(2, clock.Now)
	window := time.Minute

	rl.Allow("a", 10, window)
	clock.Advance(time.Second)
	rl.Allow("b", 10, window)
	clock.Advance(time.Second)
	rl.Allow("c", 10, window)

	if rl.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", rl.Len())
	}
	if _, ok := rl.entries["a"]; ok {
		t.Fatal("oldest key was not evicted")
	}
}

func TestRateLimiterEvictionSkipsEmpty(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(1, clock.Now)
	rl.entries["empty"] = nil

	if !rl.Allow("new", 10, time.Minute) {
		t.Fatal("request should be allowed")
	}
	if _, ok := rl.entries["empty"]; ok {
		t.Fatal("empty entry was not evicted")
	}
	if rl.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", rl.Len())
	}
}

func TestRateLimiterSweep(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(10, clock.Now)
	rl.Allow("a", 10, time.Minute)
	rl.entries["empty"] = nil

	clock.Advance(2 * time.Minute)
	rl.Sweep(time.Minute)
	if rl.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", rl.Len())
	}
}

func TestNewLoginThrottleDefaults(t *testing.T) {
	t.Parallel()

	lt := NewLoginThrottle(0, nil)
	if lt.max != domain.DefaultMaxEntries {
		t.Fatalf("max = %d, want %d", lt.max, domain.DefaultMaxEntries)
	}
	if lt.clock == nil {
		t.Fatal("clock is nil")
	}

	lt = NewLoginThrottle(-1, func() time.Time { return time.Unix(0, 0) })
	if lt.max != domain.DefaultMaxEntries {
		t.Fatalf("max = %d, want %d", lt.max, domain.DefaultMaxEntries)
	}
}

func TestLoginThrottleAllow(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	lt := NewLoginThrottle(10, clock.Now)
	window := time.Minute

	for i := 0; i < 3; i++ {
		if !lt.Allow("acct", 3, window) {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if lt.Allow("acct", 3, window) {
		t.Fatal("attempt over limit should be throttled")
	}
	if lt.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", lt.Len())
	}

	clock.Advance(window + time.Second)
	if !lt.Allow("acct", 3, window) {
		t.Fatal("attempt after window should be allowed")
	}
}

func TestLoginThrottleDefaults(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	lt := NewLoginThrottle(10, clock.Now)

	for i := 0; i < domain.DefaultLoginThrottleAttempts; i++ {
		if !lt.Allow("acct", 0, 0) {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if lt.Allow("acct", 0, 0) {
		t.Fatal("attempt over default limit should be throttled")
	}

	clock.Advance(domain.DefaultLoginThrottleWindow + time.Second)
	if !lt.Allow("acct", 0, 0) {
		t.Fatal("attempt after default window should be allowed")
	}
}

func TestLoginThrottleClear(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	lt := NewLoginThrottle(10, clock.Now)
	lt.Allow("acct", 1, time.Minute)
	if lt.Allow("acct", 1, time.Minute) {
		t.Fatal("second attempt should be throttled")
	}
	lt.Clear("acct")
	if lt.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", lt.Len())
	}
	if !lt.Allow("acct", 1, time.Minute) {
		t.Fatal("attempt after Clear should be allowed")
	}
}

func TestLoginThrottleEviction(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	lt := NewLoginThrottle(2, clock.Now)
	window := time.Minute

	lt.Allow("a", 10, window)
	clock.Advance(time.Second)
	lt.Allow("b", 10, window)
	clock.Advance(time.Second)
	lt.Allow("c", 10, window)

	if lt.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", lt.Len())
	}
	if _, ok := lt.attempts["a"]; ok {
		t.Fatal("oldest key was not evicted")
	}
}

func TestLoginThrottleEvictionSkipsEmpty(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	lt := NewLoginThrottle(1, clock.Now)
	lt.attempts["empty"] = nil

	if !lt.Allow("new", 10, time.Minute) {
		t.Fatal("attempt should be allowed")
	}
	if _, ok := lt.attempts["empty"]; ok {
		t.Fatal("empty entry was not evicted")
	}
}

func TestLoginThrottleSweep(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	lt := NewLoginThrottle(10, clock.Now)
	lt.Allow("a", 10, time.Minute)
	lt.attempts["empty"] = nil

	clock.Advance(2 * time.Minute)
	lt.Sweep(time.Minute)
	if lt.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", lt.Len())
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	rl := NewRateLimiter(32, clock.Now)
	lt := NewLoginThrottle(32, clock.Now)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Allow("ip", 10, time.Minute)
			rl.Sweep(time.Minute)
			_ = rl.Len()
			lt.Allow("acct", 10, time.Minute)
			lt.Clear("acct")
			lt.Sweep(time.Minute)
			_ = lt.Len()
		}()
	}
	wg.Wait()
}
