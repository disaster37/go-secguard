// Package testutil provides deterministic helpers for tests: a manually
// advanced clock and an ephemeral loopback listener.
package testutil

import (
	"net"
	"sync"
	"testing"
	"time"
)

// FakeClock is a thread-safe manually-advanced clock for deterministic testing.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a FakeClock initialized to initial.
func NewFakeClock(initial time.Time) *FakeClock {
	return &FakeClock{now: initial}
}

// Now returns the current fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set replaces the current fake time.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// FreeListener binds an ephemeral loopback TCP port (127.0.0.1:0) and registers
// t.Cleanup to close it if unused.
func FreeListener(t testing.TB) net.Listener {
	t.Helper()
	return freeListenerAt(t, "127.0.0.1:0")
}

func freeListenerAt(t testing.TB, addr string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("free listener: %v", err)
		return nil
	}
	t.Cleanup(func() {
		_ = l.Close()
	})
	return l
}
