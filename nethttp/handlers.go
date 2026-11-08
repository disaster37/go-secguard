package nethttp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/disaster37/go-secguard/bantracker"
	"github.com/disaster37/go-secguard/domain"
)

// APIBansHandler returns an http.HandlerFunc that writes tracker.ListBans() as
// JSON.
func APIBansHandler(tracker *bantracker.BanTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := json.Marshal(tracker.ListBans())
		if err != nil {
			WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}
}

// APIUnbanHandler returns an http.HandlerFunc that extracts an IP using
// ipExtractor (or r.PathValue("ip") when nil), validates it with net.ParseIP,
// calls tracker.Unban(ip), and responds with 204 No Content.
func APIUnbanHandler(tracker *bantracker.BanTracker, ipExtractor func(r *http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ""
		if ipExtractor != nil {
			ip = ipExtractor(r)
		} else {
			ip = r.PathValue("ip")
		}
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			WriteError(w, fmt.Errorf("invalid IP address %q: %w", ip, domain.ErrInvalidIP))
			return
		}
		tracker.Unban(ip)
		w.WriteHeader(http.StatusNoContent)
	}
}
