package lockout

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func FuzzLoginLimitKey(f *testing.F) {
	f.Add("alice", "203.0.113.7")
	f.Add("", "")
	f.Add("a|b", "c:d")
	f.Add("  MixedCase  ", " 198.51.100.1 ")

	f.Fuzz(func(t *testing.T, username, clientIP string) {
		key := LoginLimitKey(username, clientIP)
		if key != LoginLimitKey(username, clientIP) {
			t.Fatal("login key is not deterministic")
		}
		if key != LoginLimitKey(strings.ToLower(username), clientIP) {
			t.Fatal("login key is not lower-case normalized")
		}
		if key != LoginLimitKey(fmt.Sprintf(" %s ", username), clientIP) {
			t.Fatal("login key is not whitespace normalized")
		}
		assertKeyFormat(t, key, "login")
	})
}

func FuzzPasswordChangeLimitKey(f *testing.F) {
	f.Add("user-1", "203.0.113.7")
	f.Add("", "")
	f.Add("a|b", "c:d")

	f.Fuzz(func(t *testing.T, userID, clientIP string) {
		key := PasswordChangeLimitKey(userID, clientIP)
		if key != PasswordChangeLimitKey(userID, clientIP) {
			t.Fatal("password-change key is not deterministic")
		}
		if key != PasswordChangeLimitKey(fmt.Sprintf(" %s ", userID), clientIP) {
			t.Fatal("password-change key is not whitespace normalized")
		}
		assertKeyFormat(t, key, "chpw")
		if key == LoginLimitKey(userID, clientIP) {
			t.Fatal("login and password-change keys collide")
		}
	})
}

func assertKeyFormat(t *testing.T, key, prefix string) {
	t.Helper()

	parts := strings.SplitN(key, "|", 3)
	if len(parts) != 3 {
		t.Fatalf("key %q does not have three parts", key)
	}
	if parts[0] != prefix {
		t.Fatalf("key %q has prefix %q, want %q", key, parts[0], prefix)
	}
	if len(parts[1]) != 64 {
		t.Fatalf("key %q digest length = %d, want 64", key, len(parts[1]))
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		t.Fatalf("key %q digest is not hex: %v", key, err)
	}
}
