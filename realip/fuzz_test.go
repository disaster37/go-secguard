package realip

import (
	"errors"
	"testing"

	"github.com/disaster37/go-secguard/domain"
)

func FuzzExtractRealIP(f *testing.F) {
	f.Add("203.0.113.5:1234", "198.51.100.9", "198.51.100.10", false, "10.0.0.0/8")
	f.Add("10.0.0.1:1234", "1.2.3.4, 203.0.113.9, 10.0.0.2", "", true, "10.0.0.0/8")
	f.Add("", "", "", true, "")
	f.Add("[2001:db8::1]:443", "2001:db8::2", "", true, "2001:db8::/32")

	f.Fuzz(func(t *testing.T, remoteAddr, xff, xrip string, behind bool, cidr string) {
		nets, _ := ParseTrustedProxyCIDRs([]string{cidr})
		ip, err := ExtractRealIP(remoteAddr, xff, xrip, behind, nets)

		peer, peerErr := parseRemoteIP(remoteAddr)
		if peerErr != nil {
			if err == nil {
				t.Fatal("expected an error for an invalid remote address")
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !behind || !ipInAny(peer, nets) {
			if !ip.Equal(peer) {
				t.Fatalf("untrusted peer returned forwarded IP %s instead of %s", ip, peer)
			}
		}
	})
}

func FuzzParseTrustedProxyCIDRs(f *testing.F) {
	f.Add("10.0.0.0/8")
	f.Add("203.0.113.7")
	f.Add("2001:db8::1")
	f.Add("")
	f.Add("not-a-cidr")
	f.Add("10.0.0.0/99")

	f.Fuzz(func(t *testing.T, entry string) {
		nets, err := ParseTrustedProxyCIDRs([]string{entry})
		if err != nil {
			if !errors.Is(err, domain.ErrInvalidCIDR) && !errors.Is(err, domain.ErrInvalidIP) {
				t.Fatalf("error %v does not wrap a sentinel", err)
			}
			return
		}
		if entry == "" && len(nets) != 0 {
			t.Fatalf("empty entry produced %d networks", len(nets))
		}
	})
}
