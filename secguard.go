package secguard

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/disaster37/go-secguard/bantracker"
	"github.com/disaster37/go-secguard/config"
	"github.com/disaster37/go-secguard/domain"
	"github.com/disaster37/go-secguard/lockout"
	"github.com/disaster37/go-secguard/observ"
	"github.com/disaster37/go-secguard/ratelimit"
	"github.com/disaster37/go-secguard/realip"
)

// Guard is a unified coordinator holding configured security components.
type Guard struct {
	Config        config.Config
	Lockout       *lockout.Limiter
	RateLimiter   *ratelimit.RateLimiter
	LoginThrottle *ratelimit.LoginThrottle
	BanTracker    *bantracker.BanTracker
	TrustedCIDRs  []*net.IPNet
	Logger        observ.Logger
}

type guardOptions struct {
	clock  func() time.Time
	logger observ.Logger
}

// Option configures a Guard.
type Option func(*guardOptions)

// WithClock overrides the clock used by every stateful component.
func WithClock(clock func() time.Time) Option {
	return func(o *guardOptions) { o.clock = clock }
}

// WithLogger sets the structured logger used by the Guard.
func WithLogger(logger observ.Logger) Option {
	return func(o *guardOptions) { o.logger = logger }
}

// New validates cfg and returns a Guard with all components initialized.
func New(cfg config.Config, opts ...Option) (*Guard, error) {
	options := guardOptions{
		clock:  func() time.Time { return time.Now().UTC() },
		logger: observ.NewNoopLogger(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.clock == nil {
		options.clock = func() time.Time { return time.Now().UTC() }
	}
	if options.logger == nil {
		options.logger = observ.NewNoopLogger()
	}

	trustedCIDRs, err := cfg.Proxy.ParseTrustedCIDRs()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrValidation, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Guard{
		Config:        cfg,
		Lockout:       lockout.New(cfg.Lockout.ToLockoutConfig(options.clock)),
		RateLimiter:   ratelimit.NewRateLimiter(cfg.RateLimit.MaxEntries, options.clock),
		LoginThrottle: ratelimit.NewLoginThrottle(cfg.RateLimit.MaxEntries, options.clock),
		BanTracker:    bantracker.New(cfg.Ban.MaxEntries, options.clock),
		TrustedCIDRs:  trustedCIDRs,
		Logger:        options.logger,
	}, nil
}

// ClientIP resolves the client IP from raw request fields.
func (g *Guard) ClientIP(remoteAddr, xff, xrip string) (net.IP, error) {
	return realip.ExtractRealIP(remoteAddr, xff, xrip, g.Config.Proxy.BehindReverseProxy, g.TrustedCIDRs)
}

// ClientIPFromRequest resolves the client IP from an *http.Request.
func (g *Guard) ClientIPFromRequest(r *http.Request) (net.IP, error) {
	return realip.GetRealIPFromRequest(r, g.Config.Proxy.BehindReverseProxy, g.TrustedCIDRs)
}

// SweepAll immediately sweeps every stateful component.
func (g *Guard) SweepAll() {
	g.Lockout.Sweep()
	g.RateLimiter.Sweep(g.Config.RateLimit.Window)
	g.LoginThrottle.Sweep(g.Config.RateLimit.LoginThrottleWindow)
	g.BanTracker.Sweep(g.Config.Ban.Window)
}
