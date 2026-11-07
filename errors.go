// Package secguard is the root facade for the go-secguard library. It
// re-exports the sentinel errors and provides a Guard that wires the lockout,
// rate-limit, ban-tracking, and client-IP components together.
package secguard

import "github.com/disaster37/go-secguard/domain"

// Sentinel errors re-exported from domain for single-import convenience.
var (
	ErrValidation       = domain.ErrValidation
	ErrRateLimited      = domain.ErrRateLimited
	ErrAccountLocked    = domain.ErrAccountLocked
	ErrIPBanned         = domain.ErrIPBanned
	ErrOriginNotAllowed = domain.ErrOriginNotAllowed
	ErrInvalidIP        = domain.ErrInvalidIP
	ErrInvalidCIDR      = domain.ErrInvalidCIDR
)
