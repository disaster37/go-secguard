package domain

import (
	"errors"
	"testing"
	"time"
)

func TestSentinelErrorsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		ErrValidation,
		ErrRateLimited,
		ErrAccountLocked,
		ErrIPBanned,
		ErrOriginNotAllowed,
		ErrInvalidIP,
		ErrInvalidCIDR,
	}
	for i, a := range sentinels {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Fatalf("sentinel %d unexpectedly matches sentinel %d", i, j)
			}
		}
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()

	if DefaultMaxEntries != 4096 {
		t.Fatalf("DefaultMaxEntries = %d", DefaultMaxEntries)
	}
	if DefaultMaxFailedAttempts != 5 {
		t.Fatalf("DefaultMaxFailedAttempts = %d", DefaultMaxFailedAttempts)
	}
	if DefaultBaseLockout != 30*time.Second {
		t.Fatalf("DefaultBaseLockout = %s", DefaultBaseLockout)
	}
	if DefaultMaxLockout != 15*time.Minute {
		t.Fatalf("DefaultMaxLockout = %s", DefaultMaxLockout)
	}
	if DefaultEntryTTL != 30*time.Minute {
		t.Fatalf("DefaultEntryTTL = %s", DefaultEntryTTL)
	}
	if MaxLockoutShift != 16 {
		t.Fatalf("MaxLockoutShift = %d", MaxLockoutShift)
	}
	if DefaultRateLimitMax != 60 {
		t.Fatalf("DefaultRateLimitMax = %d", DefaultRateLimitMax)
	}
	if DefaultRateLimitWindow != time.Minute {
		t.Fatalf("DefaultRateLimitWindow = %s", DefaultRateLimitWindow)
	}
	if DefaultLoginThrottleAttempts != 10 {
		t.Fatalf("DefaultLoginThrottleAttempts = %d", DefaultLoginThrottleAttempts)
	}
	if DefaultLoginThrottleWindow != 5*time.Minute {
		t.Fatalf("DefaultLoginThrottleWindow = %s", DefaultLoginThrottleWindow)
	}
	if DefaultBanMaxUniqueFailures != 10 {
		t.Fatalf("DefaultBanMaxUniqueFailures = %d", DefaultBanMaxUniqueFailures)
	}
	if DefaultBanDuration != 15*time.Minute {
		t.Fatalf("DefaultBanDuration = %s", DefaultBanDuration)
	}
	if DefaultBanWindow != 5*time.Minute {
		t.Fatalf("DefaultBanWindow = %s", DefaultBanWindow)
	}
}
