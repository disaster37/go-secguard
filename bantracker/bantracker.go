// Package bantracker detects credential-stuffing clients by counting unique
// credential fingerprints per IP within a sliding window and banning abusive
// IPs. It also provides domain-separated SHA-256 fingerprint helpers and
// webhook signature extraction.
package bantracker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/disaster37/go-secguard/domain"
)

// BanInfo describes an active IP ban.
type BanInfo struct {
	IP             string    `json:"ip"`
	Until          time.Time `json:"until"`
	UniqueFailures int       `json:"unique_failures"`
}

type banEntry struct {
	fingerprint string
	timestamp   time.Time
}

// BanTracker counts unique credential failures per IP within a sliding window
// and bans suspicious clients (credential stuffing), while tolerating a single
// misconfigured client repeating the same credential.
type BanTracker struct {
	mu        sync.Mutex
	failures  map[string][]banEntry
	banned    map[string]time.Time
	lastSweep time.Time
	max       int
	clock     func() time.Time
}

// New returns a BanTracker bounded to maxEntries IPs.
func New(maxEntries int, clock func() time.Time) *BanTracker {
	if maxEntries <= 0 {
		maxEntries = domain.DefaultMaxEntries
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &BanTracker{
		failures: make(map[string][]banEntry),
		banned:   make(map[string]time.Time),
		max:      maxEntries,
		clock:    clock,
	}
}

// IsBanned reports whether ip is currently banned. Expired bans are lazily
// removed.
func (bt *BanTracker) IsBanned(ip string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	until, ok := bt.banned[ip]
	if !ok {
		return false
	}
	if bt.clock().Before(until) {
		return true
	}
	delete(bt.banned, ip)
	return false
}

// RecordAndBan records a credential failure for ip with the given SHA-256
// fingerprint and bans the IP for banDuration when the count of unique
// fingerprints within window reaches maxUniqueFailures. Executed under a single
// lock with throttled sweeps. Returns true if the IP is banned.
func (bt *BanTracker) RecordAndBan(ip, fingerprint string, maxUniqueFailures int, banDuration, window time.Duration) bool {
	if maxUniqueFailures <= 0 {
		maxUniqueFailures = domain.DefaultBanMaxUniqueFailures
	}
	if banDuration <= 0 {
		banDuration = domain.DefaultBanDuration
	}
	if window <= 0 {
		window = domain.DefaultBanWindow
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := bt.clock()
	bt.maybeSweepLocked(now, window)
	bt.recordFailureLocked(ip, fingerprint, window, now)
	return bt.banIfSuspiciousLocked(ip, maxUniqueFailures, banDuration, window, now)
}

// ListBans returns all active bans sorted deterministically by IP. Expired bans
// are pruned.
func (bt *BanTracker) ListBans() []BanInfo {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := bt.clock()
	bans := make([]BanInfo, 0, len(bt.banned))
	for ip, until := range bt.banned {
		if !now.Before(until) {
			delete(bt.banned, ip)
			continue
		}
		bans = append(bans, BanInfo{
			IP:             ip,
			Until:          until,
			UniqueFailures: uniqueFingerprints(bt.failures[ip]),
		})
	}
	sort.Slice(bans, func(i, j int) bool { return bans[i].IP < bans[j].IP })
	return bans
}

// Unban removes any active ban and failure history for ip.
func (bt *BanTracker) Unban(ip string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	delete(bt.banned, ip)
	delete(bt.failures, ip)
}

// Sweep removes expired failure entries and expired bans.
func (bt *BanTracker) Sweep(window time.Duration) {
	if window <= 0 {
		window = domain.DefaultBanWindow
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := bt.clock()
	bt.lastSweep = now
	bt.sweepLocked(now, window)
}

// FingerprintLogin returns a deterministic SHA-256 hex digest of
// "login:<lowercased-trimmed-username>".
func FingerprintLogin(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	return fingerprint(fmt.Sprintf("login:%s", normalized))
}

// FingerprintToken returns a deterministic SHA-256 hex digest of "token:<token>".
func FingerprintToken(token string) string {
	return fingerprint(fmt.Sprintf("token:%s", token))
}

// FingerprintSignature returns a deterministic SHA-256 hex digest of
// "signature:<channel>:<signatureValue>".
func FingerprintSignature(channel, signatureValue string) string {
	return fingerprint(fmt.Sprintf("signature:%s:%s", channel, signatureValue))
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// ExtractSignatureValue extracts a webhook signature/token header using a
// framework-agnostic header lookup function, checking X-Hub-Signature-256,
// X-Gitlab-Token, X-Hub-Signature, and X-Gitea-Signature in priority order.
// It returns "unknown" when none are present.
func ExtractSignatureValue(getHeader func(string) string) string {
	if getHeader == nil {
		return "unknown"
	}
	for _, name := range []string{
		"X-Hub-Signature-256",
		"X-Gitlab-Token",
		"X-Hub-Signature",
		"X-Gitea-Signature",
	} {
		if value := getHeader(name); value != "" {
			return value
		}
	}
	return "unknown"
}

// ExtractSignatureValueFromRequest extracts a webhook signature/token header
// from an *http.Request.
func ExtractSignatureValueFromRequest(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	return ExtractSignatureValue(r.Header.Get)
}

func (bt *BanTracker) recordFailureLocked(ip, fingerprint string, window time.Duration, now time.Time) {
	windowStart := now.Add(-window)
	entries := bt.failures[ip]
	for _, e := range entries {
		if e.timestamp.After(windowStart) && e.fingerprint == fingerprint {
			return
		}
	}

	valid := entries[:0]
	for _, e := range entries {
		if e.timestamp.After(windowStart) {
			valid = append(valid, e)
		}
	}
	if _, exists := bt.failures[ip]; !exists && len(bt.failures) >= bt.max {
		bt.evictOldestFailureLocked()
	}
	bt.failures[ip] = append(valid, banEntry{fingerprint: fingerprint, timestamp: now})
}

func (bt *BanTracker) banIfSuspiciousLocked(ip string, maxUniqueFailures int, banDuration, window time.Duration, now time.Time) bool {
	windowStart := now.Add(-window)
	fingerprints := make(map[string]struct{})
	valid := bt.failures[ip][:0]
	for _, e := range bt.failures[ip] {
		if e.timestamp.After(windowStart) {
			valid = append(valid, e)
			fingerprints[e.fingerprint] = struct{}{}
		}
	}
	bt.failures[ip] = valid

	if len(fingerprints) < maxUniqueFailures {
		return false
	}
	if _, exists := bt.banned[ip]; !exists && len(bt.banned) >= bt.max {
		bt.evictEarliestBanLocked(now)
	}
	bt.banned[ip] = now.Add(banDuration)
	return true
}

func (bt *BanTracker) maybeSweepLocked(now time.Time, window time.Duration) {
	if !bt.lastSweep.IsZero() && now.Sub(bt.lastSweep) < window {
		return
	}
	bt.lastSweep = now
	bt.sweepLocked(now, window)
}

func (bt *BanTracker) sweepLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	for ip, entries := range bt.failures {
		kept := entries[:0]
		for _, e := range entries {
			if e.timestamp.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(bt.failures, ip)
		} else {
			bt.failures[ip] = kept
		}
	}
	for ip, until := range bt.banned {
		if !now.Before(until) {
			delete(bt.banned, ip)
		}
	}
}

func (bt *BanTracker) evictOldestFailureLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for ip, entries := range bt.failures {
		if len(entries) == 0 {
			delete(bt.failures, ip)
			continue
		}
		last := entries[len(entries)-1].timestamp
		if first || last.Before(oldest) {
			oldestKey = ip
			oldest = last
			first = false
		}
	}
	if !first {
		delete(bt.failures, oldestKey)
	}
}

func (bt *BanTracker) evictEarliestBanLocked(now time.Time) {
	for ip, until := range bt.banned {
		if !now.Before(until) {
			delete(bt.banned, ip)
		}
	}
	if len(bt.banned) < bt.max {
		return
	}
	var earliestKey string
	var earliest time.Time
	first := true
	for ip, until := range bt.banned {
		if first || until.Before(earliest) {
			earliestKey = ip
			earliest = until
			first = false
		}
	}
	if !first {
		delete(bt.banned, earliestKey)
	}
}

func uniqueFingerprints(entries []banEntry) int {
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		seen[e.fingerprint] = struct{}{}
	}
	return len(seen)
}
