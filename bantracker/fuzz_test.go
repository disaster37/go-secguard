package bantracker

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func FuzzFingerprints(f *testing.F) {
	f.Add("alice", "token", "github", "signature")
	f.Add("", "", "", "")
	f.Add("  MixedCase  ", "secret", "gitlab", "sha256=abc")

	f.Fuzz(func(t *testing.T, username, token, channel, signature string) {
		login := FingerprintLogin(username)
		if login != FingerprintLogin(username) {
			t.Fatal("login fingerprint is not deterministic")
		}
		if login != FingerprintLogin(strings.ToLower(username)) {
			t.Fatal("login fingerprint is not lower-case normalized")
		}
		if login != FingerprintLogin(fmt.Sprintf(" %s ", username)) {
			t.Fatal("login fingerprint is not whitespace normalized")
		}
		assertFingerprint(t, login)

		tokenFP := FingerprintToken(token)
		if tokenFP != FingerprintToken(token) {
			t.Fatal("token fingerprint is not deterministic")
		}
		assertFingerprint(t, tokenFP)

		signatureFP := FingerprintSignature(channel, signature)
		if signatureFP != FingerprintSignature(channel, signature) {
			t.Fatal("signature fingerprint is not deterministic")
		}
		assertFingerprint(t, signatureFP)

		if login == tokenFP {
			t.Fatal("login and token fingerprints are not domain separated")
		}
		if tokenFP == signatureFP {
			t.Fatal("token and signature fingerprints are not domain separated")
		}
	})
}

func FuzzExtractSignatureValue(f *testing.F) {
	f.Add("X-Hub-Signature-256", "sha256=abc")
	f.Add("X-Gitlab-Token", "token")
	f.Add("X-Hub-Signature", "sha1=def")
	f.Add("X-Gitea-Signature", "sig")
	f.Add("X-Unknown", "value")
	f.Add("X-Hub-Signature-256", "")

	f.Fuzz(func(t *testing.T, name, value string) {
		get := func(header string) string {
			if header == name {
				return value
			}
			return ""
		}
		got := ExtractSignatureValue(get)
		if value != "" && isSignatureHeader(name) {
			if got != value {
				t.Fatalf("ExtractSignatureValue() = %q, want %q", got, value)
			}
			return
		}
		if got != "unknown" {
			t.Fatalf("ExtractSignatureValue() = %q, want unknown", got)
		}
	})
}

func assertFingerprint(t *testing.T, fp string) {
	t.Helper()

	if len(fp) != 64 {
		t.Fatalf("fingerprint %q length = %d, want 64", fp, len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Fatalf("fingerprint %q is not hex: %v", fp, err)
	}
}

func isSignatureHeader(name string) bool {
	switch name {
	case "X-Hub-Signature-256", "X-Gitlab-Token", "X-Hub-Signature", "X-Gitea-Signature":
		return true
	default:
		return false
	}
}
