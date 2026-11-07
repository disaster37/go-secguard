// Package realip resolves the real client IP behind trusted reverse proxies
// using a right-to-left X-Forwarded-For walk (CWE-290, CWE-348).
package realip

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/disaster37/go-secguard/domain"
)

// ParseTrustedProxyCIDRs parses a slice of CIDR strings or bare IP addresses
// into []*net.IPNet. Bare IPv4 addresses become /32 and bare IPv6 addresses
// become /128. Empty/whitespace-only entries are skipped. Invalid entries
// return an error wrapping domain.ErrInvalidCIDR or domain.ErrInvalidIP.
func ParseTrustedProxyCIDRs(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, domain.ErrInvalidCIDR)
			}
			nets = append(nets, network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", entry, domain.ErrInvalidIP)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// ExtractRealIP resolves the client IP address. Forwarded headers
// (X-Forwarded-For, X-Real-IP) are honored ONLY when behindReverseProxy is true
// AND the direct peer (remoteAddr) belongs to trustedCIDRs. X-Forwarded-For is
// walked right-to-left, skipping trusted proxy hops, returning the first
// untrusted valid IP (CWE-348).
func ExtractRealIP(remoteAddr, xForwardedFor, xRealIP string, behindReverseProxy bool, trustedCIDRs []*net.IPNet) (net.IP, error) {
	peer, err := parseRemoteIP(remoteAddr)
	if err != nil {
		return nil, err
	}
	if !behindReverseProxy || !ipInAny(peer, trustedCIDRs) {
		return peer, nil
	}

	if xForwardedFor != "" {
		parts := strings.Split(xForwardedFor, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(parts[i]))
			if candidate == nil {
				continue
			}
			if ipInAny(candidate, trustedCIDRs) {
				continue
			}
			return candidate, nil
		}
	}
	if xRealIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(xRealIP)); ip != nil {
			return ip, nil
		}
	}
	return peer, nil
}

// GetRealIPFromRequest extracts the client IP from an *http.Request using
// ExtractRealIP.
func GetRealIPFromRequest(r *http.Request, behindReverseProxy bool, trustedCIDRs []*net.IPNet) (net.IP, error) {
	return ExtractRealIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), behindReverseProxy, trustedCIDRs)
}

func parseRemoteIP(remoteAddr string) (net.IP, error) {
	trimmed := strings.TrimSpace(remoteAddr)
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		candidate := strings.TrimPrefix(trimmed, "[")
		candidate = strings.TrimSuffix(candidate, "]")
		if ip := net.ParseIP(candidate); ip != nil {
			return ip, nil
		}
		return nil, fmt.Errorf("invalid RemoteAddr %q: %w", remoteAddr, domain.ErrInvalidIP)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q: %w", host, domain.ErrInvalidIP)
	}
	return ip, nil
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
