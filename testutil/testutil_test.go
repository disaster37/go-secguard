package testutil

import (
	"sync"
	"testing"
	"time"
)

func TestFakeClock(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := NewFakeClock(start)
	if got := clock.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %s, want %s", got, start)
	}

	clock.Advance(90 * time.Second)
	if got, want := clock.Now(), start.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("Now() after Advance = %s, want %s", got, want)
	}

	replacement := start.Add(24 * time.Hour)
	clock.Set(replacement)
	if got := clock.Now(); !got.Equal(replacement) {
		t.Fatalf("Now() after Set = %s, want %s", got, replacement)
	}
}

func TestFakeClockConcurrent(t *testing.T) {
	t.Parallel()

	clock := NewFakeClock(time.Unix(0, 0))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clock.Advance(time.Second)
			_ = clock.Now()
		}()
	}
	wg.Wait()

	if got, want := clock.Now(), time.Unix(50, 0); !got.Equal(want) {
		t.Fatalf("Now() = %s, want %s", got, want)
	}
}

func TestFreeListener(t *testing.T) {
	t.Parallel()

	l := FreeListener(t)
	if l == nil {
		t.Fatal("FreeListener returned nil")
	}
	if l.Addr() == nil {
		t.Fatal("listener has no address")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
}

type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(string, ...any) { f.failed = true }

func (f *fakeTB) Cleanup(func()) {}

func TestFreeListenerFailure(t *testing.T) {
	t.Parallel()

	fake := &fakeTB{TB: t}
	if l := freeListenerAt(fake, "invalid-address"); l != nil {
		t.Fatalf("freeListenerAt returned %v, want nil", l)
	}
	if !fake.failed {
		t.Fatal("freeListenerAt did not report the listen failure")
	}
}
