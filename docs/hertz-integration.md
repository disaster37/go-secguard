# CloudWeGo Hertz integration

`go-secguard` is framework agnostic. The core packages work with any HTTP stack;
this page shows a compact CloudWeGo Hertz adapter suitable for
`dagger-kubernetes`.

```go
package security

import (
	"context"
	"net"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol/consts"

	"github.com/disaster37/go-secguard/bantracker"
	"github.com/disaster37/go-secguard/headers"
	"github.com/disaster37/go-secguard/lockout"
	"github.com/disaster37/go-secguard/ratelimit"
	"github.com/disaster37/go-secguard/realip"
)

type Guard struct {
	Trusted      []*net.IPNet
	BehindProxy  bool
	Allowed      []string
	Bans         *bantracker.BanTracker
	Rate         *ratelimit.RateLimiter
	Login        *ratelimit.LoginThrottle
	Lockout      *lockout.Limiter
}

func (g *Guard) Middleware() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ip, err := realip.ExtractRealIP(
			string(c.RemoteAddr().String()),
			string(c.Request.Header.Peek("X-Forwarded-For")),
			string(c.Request.Header.Peek("X-Real-IP")),
			g.BehindProxy,
			g.Trusted,
		)
		if err != nil {
			c.AbortWithStatusJSON(consts.StatusBadRequest, map[string]string{"error": "invalid IP address"})
			return
		}
		clientIP := ip.String()

		for name, value := range headers.DefaultSecurityHeaders(string(c.Path()), c.IsTLS()) {
			c.Response.Header.Set(name, value)
		}
		if err := headers.CheckMutationOrigin(
			string(c.Method()),
			string(c.Request.Header.Peek("Origin")),
			string(c.Request.Header.Peek("Referer")),
			g.Allowed,
		); err != nil {
			c.AbortWithStatusJSON(consts.StatusForbidden, map[string]string{"error": "origin not allowed"})
			return
		}
		if g.Bans.IsBanned(clientIP) {
			c.AbortWithStatusJSON(consts.StatusForbidden, map[string]string{"error": "IP address is banned"})
			return
		}
		if !g.Rate.Allow(clientIP, 60, 0) {
			c.AbortWithStatusJSON(consts.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		c.Next(ctx)
	}
}
```

Register it before the route handlers:

```go
h.Use(guard.Middleware())
```

For login routes, add a lockout check using the same key builders:

```go
key := lockout.LoginLimitKey(username, clientIP)
if !guard.Lockout.Allow(key) {
	c.AbortWithStatusJSON(consts.StatusTooManyRequests, map[string]string{"error": "account temporarily locked"})
	return
}
```

On a failed login, call `guard.Lockout.RecordFailure(key)` and
`guard.Bans.RecordAndBan(clientIP, bantracker.FingerprintLogin(username), 10, 15*time.Minute, 5*time.Minute)`.
On success, call `guard.Lockout.RecordSuccess(key)` and `guard.Login.Clear(key)`.

## Migration notes

### `dagger-kubernetes`

- Replace the private `attemptLimiter` in `internal/handler/ratelimit.go` with
  `lockout.Limiter` and `lockout.LoginLimitKey` / `lockout.PasswordChangeLimitKey`.
- Replace any ad-hoc per-IP counters with `ratelimit.RateLimiter`.
- Keep the existing Hertz handlers; only the stateful helpers change.

### `gohookbridge`

- Replace `internal/service.RateLimiter`, `LoginThrottle`, and `BanTracker` with
  the `ratelimit` and `bantracker` packages.
- Replace `GetRealIP` with `realip.GetRealIPFromRequest`.
- Replace `SecurityHeadersMiddleware` and `MutationOriginValidation` with the
  `headers` helpers or the `nethttp` middleware.

### `go-auth`

- Replace the monolithic `secguard` package with the focused subpackages.
- `LockoutLimiter` becomes `lockout.Limiter`; `LockoutConfig` becomes
  `lockout.Config`.
- `FingerprintLogin`, `FingerprintToken`, and `FingerprintSignature` keep the
  same domain-separated SHA-256 behavior.
