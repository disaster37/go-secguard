package bantracker

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/testutil"
)

func TestNewDefaults(t *testing.T) {
	t.Parallel()

	bt := New(0, nil)
	if bt.max != domain.DefaultMaxEntries {
		t.Fatalf("max = %d, want %d", bt.max, domain.DefaultMaxEntries)
	}
	if bt.clock == nil {
		t.Fatal("clock is nil")
	}

	bt = New(-1, func() time.Time { return time.Unix(0, 0) })
	if bt.max != domain.DefaultMaxEntries {
		t.Fatalf("max = %d, want %d", bt.max, domain.DefaultMaxEntries)
	}
}

func TestIsBanned(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)

	if bt.IsBanned("203.0.113.1") {
		t.Fatal("unknown IP should not be banned")
	}
	if !bt.RecordAndBan("203.0.113.1", "fp", 1, time.Minute, time.Minute) {
		t.Fatal("IP should be banned at threshold")
	}
	if !bt.IsBanned("203.0.113.1") {
		t.Fatal("IP should be banned")
	}

	clock.Advance(time.Minute)
	if bt.IsBanned("203.0.113.1") {
		t.Fatal("expired ban should not be active")
	}
	if len(bt.banned) != 0 {
		t.Fatalf("expired ban was not removed: %d", len(bt.banned))
	}
}

func TestRecordAndBanThreshold(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)
	window := time.Minute

	if bt.RecordAndBan("203.0.113.1", "fp1", 3, time.Minute, window) {
		t.Fatal("single failure should not ban")
	}
	if bt.RecordAndBan("203.0.113.1", "fp1", 3, time.Minute, window) {
		t.Fatal("duplicate fingerprint should not ban")
	}
	if bt.RecordAndBan("203.0.113.1", "fp2", 3, time.Minute, window) {
		t.Fatal("two unique failures should not ban")
	}
	if !bt.RecordAndBan("203.0.113.1", "fp3", 3, time.Minute, window) {
		t.Fatal("three unique failures should ban")
	}

	bans := bt.ListBans()
	if len(bans) != 1 {
		t.Fatalf("ListBans() length = %d, want 1", len(bans))
	}
	if bans[0].IP != "203.0.113.1" || bans[0].UniqueFailures != 3 {
		t.Fatalf("unexpected ban: %+v", bans[0])
	}

	clock.Advance(time.Minute)
	if bans := bt.ListBans(); len(bans) != 0 {
		t.Fatalf("expired ban was not pruned: %+v", bans)
	}
}

func TestRecordAndBanDefaults(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)

	for i := 0; i < domain.DefaultBanMaxUniqueFailures-1; i++ {
		if bt.RecordAndBan("203.0.113.1", FingerprintToken(string(rune('a'+i))), 0, 0, 0) {
			t.Fatalf("failure %d should not ban", i)
		}
	}
	if !bt.RecordAndBan("203.0.113.1", "last", 0, 0, 0) {
		t.Fatal("default threshold should ban")
	}

	bans := bt.ListBans()
	if len(bans) != 1 {
		t.Fatalf("ListBans() length = %d, want 1", len(bans))
	}
	wantUntil := clock.Now().Add(domain.DefaultBanDuration)
	if !bans[0].Until.Equal(wantUntil) {
		t.Fatalf("ban until = %s, want %s", bans[0].Until, wantUntil)
	}
}

func TestRecordAndBanDuplicateOutsideWindow(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)
	window := time.Minute

	if bt.RecordAndBan("203.0.113.1", "fp1", 2, time.Minute, window) {
		t.Fatal("single failure should not ban")
	}
	clock.Advance(window + time.Second)
	if bt.RecordAndBan("203.0.113.1", "fp1", 2, time.Minute, window) {
		t.Fatal("expired duplicate should count as one failure")
	}
	if !bt.RecordAndBan("203.0.113.1", "fp2", 2, time.Minute, window) {
		t.Fatal("second unique failure should ban")
	}
}

func TestListBansSorted(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)

	bt.RecordAndBan("203.0.113.2", "fp", 1, time.Minute, time.Minute)
	bt.RecordAndBan("203.0.113.1", "fp", 1, time.Minute, time.Minute)

	bans := bt.ListBans()
	if len(bans) != 2 {
		t.Fatalf("ListBans() length = %d, want 2", len(bans))
	}
	if bans[0].IP != "203.0.113.1" || bans[1].IP != "203.0.113.2" {
		t.Fatalf("bans are not sorted: %+v", bans)
	}
}

func TestUnban(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)
	bt.RecordAndBan("203.0.113.1", "fp", 1, time.Minute, time.Minute)

	bt.Unban("203.0.113.1")
	if bt.IsBanned("203.0.113.1") {
		t.Fatal("IP should be unbanned")
	}
	if len(bt.failures) != 0 {
		t.Fatalf("failure history was not removed: %d", len(bt.failures))
	}
}

func TestSweep(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(10, clock.Now)

	bt.RecordAndBan("203.0.113.1", "fp", 10, time.Minute, time.Minute)
	bt.RecordAndBan("203.0.113.2", "fp", 1, 10*time.Minute, time.Minute)

	clock.Advance(2 * time.Minute)
	bt.Sweep(time.Minute)
	if _, ok := bt.failures["203.0.113.1"]; ok {
		t.Fatal("expired failure history was not swept")
	}
	if !bt.IsBanned("203.0.113.2") {
		t.Fatal("active ban was swept")
	}

	clock.Advance(10 * time.Minute)
	bt.Sweep(time.Minute)
	if bt.IsBanned("203.0.113.2") {
		t.Fatal("expired ban was not swept")
	}
}

func TestEvictOldestFailure(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(2, clock.Now)
	window := time.Minute

	bt.RecordAndBan("a", "fp", 10, time.Minute, window)
	clock.Advance(time.Second)
	bt.RecordAndBan("b", "fp", 10, time.Minute, window)
	clock.Advance(time.Second)
	bt.RecordAndBan("c", "fp", 10, time.Minute, window)

	if len(bt.failures) != 2 {
		t.Fatalf("failures length = %d, want 2", len(bt.failures))
	}
	if _, ok := bt.failures["a"]; ok {
		t.Fatal("oldest failure entry was not evicted")
	}
}

func TestEvictOldestFailureSkipsEmpty(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(1, clock.Now)
	bt.failures["empty"] = nil

	bt.RecordAndBan("new", "fp", 10, time.Minute, time.Minute)
	if _, ok := bt.failures["empty"]; ok {
		t.Fatal("empty failure entry was not evicted")
	}
	if len(bt.failures) != 1 {
		t.Fatalf("failures length = %d, want 1", len(bt.failures))
	}
}

func TestEvictEarliestBan(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(2, clock.Now)

	bt.RecordAndBan("a", "fp", 1, 10*time.Minute, time.Minute)
	clock.Advance(time.Minute)
	bt.RecordAndBan("b", "fp", 1, 5*time.Minute, time.Minute)
	clock.Advance(time.Minute)
	bt.RecordAndBan("c", "fp", 1, 10*time.Minute, time.Minute)

	if len(bt.banned) != 2 {
		t.Fatalf("banned length = %d, want 2", len(bt.banned))
	}
	if _, ok := bt.banned["b"]; ok {
		t.Fatal("earliest-expiring ban was not evicted")
	}
	if _, ok := bt.banned["a"]; !ok {
		t.Fatal("active ban a was evicted")
	}
	if _, ok := bt.banned["c"]; !ok {
		t.Fatal("new ban c was not stored")
	}
}

func TestEvictEarliestBanPurgesExpired(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(1, clock.Now)

	bt.RecordAndBan("a", "fp", 1, time.Minute, time.Minute)
	clock.Advance(2 * time.Minute)
	bt.RecordAndBan("b", "fp", 1, time.Minute, time.Minute)

	if _, ok := bt.banned["a"]; ok {
		t.Fatal("expired ban was not purged")
	}
	if _, ok := bt.banned["b"]; !ok {
		t.Fatal("new ban was not stored")
	}
}

func TestFingerprints(t *testing.T) {
	t.Parallel()

	if FingerprintLogin("Alice") != FingerprintLogin("  alice  ") {
		t.Fatal("login fingerprint is not case/whitespace normalized")
	}
	if FingerprintLogin("alice") == FingerprintLogin("bob") {
		t.Fatal("distinct usernames produced the same fingerprint")
	}
	if FingerprintLogin("x") == FingerprintToken("x") {
		t.Fatal("login and token fingerprints are not domain separated")
	}
	if FingerprintToken("x") == FingerprintSignature("github", "x") {
		t.Fatal("token and signature fingerprints are not domain separated")
	}
	if FingerprintSignature("github", "x") == FingerprintSignature("gitlab", "x") {
		t.Fatal("signature fingerprints ignore the channel")
	}

	for _, fp := range []string{
		FingerprintLogin("alice"),
		FingerprintToken("token"),
		FingerprintSignature("github", "sig"),
	} {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %q length = %d, want 64", fp, len(fp))
		}
		if _, err := hex.DecodeString(fp); err != nil {
			t.Fatalf("fingerprint %q is not hex: %v", fp, err)
		}
	}
}

func TestExtractSignatureValue(t *testing.T) {
	t.Parallel()

	headers := map[string]string{
		"X-Hub-Signature-256": "sha256=abc",
		"X-Gitlab-Token":      "gitlab-token",
		"X-Hub-Signature":     "sha1=def",
		"X-Gitea-Signature":   "gitea-sig",
	}
	get := func(name string) string { return headers[name] }

	if got := ExtractSignatureValue(get); got != "sha256=abc" {
		t.Fatalf("ExtractSignatureValue() = %q, want sha256=abc", got)
	}

	delete(headers, "X-Hub-Signature-256")
	if got := ExtractSignatureValue(get); got != "gitlab-token" {
		t.Fatalf("ExtractSignatureValue() = %q, want gitlab-token", got)
	}

	delete(headers, "X-Gitlab-Token")
	if got := ExtractSignatureValue(get); got != "sha1=def" {
		t.Fatalf("ExtractSignatureValue() = %q, want sha1=def", got)
	}

	delete(headers, "X-Hub-Signature")
	if got := ExtractSignatureValue(get); got != "gitea-sig" {
		t.Fatalf("ExtractSignatureValue() = %q, want gitea-sig", got)
	}

	delete(headers, "X-Gitea-Signature")
	if got := ExtractSignatureValue(get); got != "unknown" {
		t.Fatalf("ExtractSignatureValue() = %q, want unknown", got)
	}

	if got := ExtractSignatureValue(nil); got != "unknown" {
		t.Fatalf("ExtractSignatureValue(nil) = %q, want unknown", got)
	}
}

func TestExtractSignatureValueFromRequest(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/hook", nil)
	r.Header.Set("X-Gitlab-Token", "secret")
	if got := ExtractSignatureValueFromRequest(r); got != "secret" {
		t.Fatalf("ExtractSignatureValueFromRequest() = %q, want secret", got)
	}

	if got := ExtractSignatureValueFromRequest(nil); got != "unknown" {
		t.Fatalf("ExtractSignatureValueFromRequest(nil) = %q, want unknown", got)
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Unix(0, 0))
	bt := New(32, clock.Now)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "203.0.113.1"
			bt.RecordAndBan(ip, FingerprintToken(string(rune('a'+i%26))), 5, time.Minute, time.Minute)
			bt.IsBanned(ip)
			bt.ListBans()
			bt.Sweep(time.Minute)
			bt.Unban(ip)
		}(i)
	}
	wg.Wait()
}
