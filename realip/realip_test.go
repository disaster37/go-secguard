package realip

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/disaster37/go-secguard/domain"
)

func mustCIDRs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	nets, err := ParseTrustedProxyCIDRs(entries)
	if err != nil {
		t.Fatalf("ParseTrustedProxyCIDRs(%v): %v", entries, err)
	}
	return nets
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	t.Parallel()

	nets, err := ParseTrustedProxyCIDRs([]string{"", "  ", "10.0.0.0/8", "203.0.113.7", "2001:db8::1"})
	if err != nil {
		t.Fatalf("ParseTrustedProxyCIDRs: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("len = %d, want 3", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Fatal("CIDR entry does not contain expected IP")
	}
	if ones, bits := nets[1].Mask.Size(); ones != 32 || bits != 32 {
		t.Fatalf("bare IPv4 mask = %d/%d, want 32/32", ones, bits)
	}
	if ones, bits := nets[2].Mask.Size(); ones != 128 || bits != 128 {
		t.Fatalf("bare IPv6 mask = %d/%d, want 128/128", ones, bits)
	}
}

func TestParseTrustedProxyCIDRsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := ParseTrustedProxyCIDRs([]string{"10.0.0.0/99"}); !errors.Is(err, domain.ErrInvalidCIDR) {
		t.Fatalf("invalid CIDR error = %v, want ErrInvalidCIDR", err)
	}
	if _, err := ParseTrustedProxyCIDRs([]string{"not-an-ip"}); !errors.Is(err, domain.ErrInvalidIP) {
		t.Fatalf("invalid IP error = %v, want ErrInvalidIP", err)
	}
}

func TestExtractRealIPInvalidRemoteAddr(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"", "not-an-ip", "host:port", "bad:addr:here"} {
		if _, err := ExtractRealIP(addr, "", "", false, nil); !errors.Is(err, domain.ErrInvalidIP) {
			t.Fatalf("ExtractRealIP(%q) error = %v, want ErrInvalidIP", addr, err)
		}
	}
}

func TestExtractRealIPPeerForms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"host port", "203.0.113.5:1234", "203.0.113.5"},
		{"bare ipv4", "203.0.113.5", "203.0.113.5"},
		{"bare ipv6", "2001:db8::1", "2001:db8::1"},
		{"bracketed ipv6", "[2001:db8::1]", "2001:db8::1"},
		{"ipv6 host port", "[2001:db8::1]:443", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ip, err := ExtractRealIP(tc.remoteAddr, "", "", false, nil)
			if err != nil {
				t.Fatalf("ExtractRealIP: %v", err)
			}
			if !ip.Equal(net.ParseIP(tc.want)) {
				t.Fatalf("IP = %s, want %s", ip, tc.want)
			}
		})
	}
}

func TestExtractRealIPIgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")

	ip, err := ExtractRealIP("203.0.113.5:1234", "198.51.100.9", "198.51.100.10", false, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.5")) {
		t.Fatalf("IP = %s, want peer 203.0.113.5", ip)
	}

	ip, err = ExtractRealIP("203.0.113.5:1234", "198.51.100.9", "198.51.100.10", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.5")) {
		t.Fatalf("IP = %s, want untrusted peer 203.0.113.5", ip)
	}
}

func TestExtractRealIPRightToLeft(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")

	ip, err := ExtractRealIP("10.0.0.1:1234", "1.2.3.4, 203.0.113.9, 10.0.0.2", "", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("IP = %s, want 203.0.113.9", ip)
	}
}

func TestExtractRealIPSkipsInvalidTokens(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")

	ip, err := ExtractRealIP("10.0.0.1:1234", "garbage, 203.0.113.9", "", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("IP = %s, want 203.0.113.9", ip)
	}
}

func TestExtractRealIPXRealIPFallback(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")

	ip, err := ExtractRealIP("10.0.0.1:1234", "10.0.0.2", "203.0.113.9", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("IP = %s, want X-Real-IP 203.0.113.9", ip)
	}

	ip, err = ExtractRealIP("10.0.0.1:1234", "", "203.0.113.9", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("IP = %s, want X-Real-IP 203.0.113.9", ip)
	}
}

func TestExtractRealIPInvalidXRealIPFallsBackToPeer(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")

	ip, err := ExtractRealIP("10.0.0.1:1234", "", "not-an-ip", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("IP = %s, want peer 10.0.0.1", ip)
	}
}

func TestExtractRealIPNoForwardedHeaders(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")

	ip, err := ExtractRealIP("10.0.0.1:1234", "", "", true, trusted)
	if err != nil {
		t.Fatalf("ExtractRealIP: %v", err)
	}
	if !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("IP = %s, want peer 10.0.0.1", ip)
	}
}

func TestGetRealIPFromRequest(t *testing.T) {
	t.Parallel()

	trusted := mustCIDRs(t, "10.0.0.0/8")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	ip, err := GetRealIPFromRequest(r, true, trusted)
	if err != nil {
		t.Fatalf("GetRealIPFromRequest: %v", err)
	}
	if !ip.Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("IP = %s, want 203.0.113.9", ip)
	}

	r.RemoteAddr = "bad"
	if _, err := GetRealIPFromRequest(r, true, trusted); !errors.Is(err, domain.ErrInvalidIP) {
		t.Fatalf("error = %v, want ErrInvalidIP", err)
	}
}
