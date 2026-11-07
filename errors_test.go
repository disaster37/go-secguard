package secguard

import (
	"errors"
	"testing"

	"github.com/disaster37/go-secguard/domain"
)

func TestReexportedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		reexport error
		sentinel error
	}{
		{"validation", ErrValidation, domain.ErrValidation},
		{"rate limited", ErrRateLimited, domain.ErrRateLimited},
		{"account locked", ErrAccountLocked, domain.ErrAccountLocked},
		{"ip banned", ErrIPBanned, domain.ErrIPBanned},
		{"origin", ErrOriginNotAllowed, domain.ErrOriginNotAllowed},
		{"invalid ip", ErrInvalidIP, domain.ErrInvalidIP},
		{"invalid cidr", ErrInvalidCIDR, domain.ErrInvalidCIDR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tc.reexport, tc.sentinel) {
				t.Fatalf("%v does not match %v", tc.reexport, tc.sentinel)
			}
		})
	}
}
