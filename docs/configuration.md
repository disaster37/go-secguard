# Configuration

`go-secguard` exposes validated configuration structs in the `config` package.
Every field carries `mapstructure`, `json`, and `yaml` tags, so the same struct
can be loaded by Viper, `encoding/json`, or `gopkg.in/yaml.v3`.

```go
cfg := config.DefaultConfig()
if err := cfg.Validate(); err != nil {
    return err
}
guard, err := secguard.New(cfg)
```

## Complete reference

```yaml
lockout:
  enabled: true
  max_failed_attempts: 5
  base_lockout: 30s
  max_lockout: 15m
  entry_ttl: 30m
  max_entries: 4096

rate_limit:
  enabled: true
  max_requests: 60
  window: 1m
  login_throttle_attempts: 10
  login_throttle_window: 5m
  max_entries: 4096

ban:
  enabled: true
  max_unique_failures: 10
  ban_duration: 15m
  window: 5m
  max_entries: 4096

proxy:
  behind_reverse_proxy: false
  trusted_proxy_cidrs: []

cors:
  allowed_origins: []
```

### `lockout`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enables the exponential lockout limiter. |
| `max_failed_attempts` | int | `5` | Consecutive failures before lockout starts. |
| `base_lockout` | duration | `30s` | Initial lockout duration at the threshold. |
| `max_lockout` | duration | `15m` | Upper bound for exponential growth. |
| `entry_ttl` | duration | `30m` | How long an idle unlocked record is retained. |
| `max_entries` | int | `4096` | Maximum number of tracked keys. |

### `rate_limit`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enables request and login-attempt limiting. |
| `max_requests` | int | `60` | Per-IP requests allowed per window. |
| `window` | duration | `1m` | Sliding window for `RateLimiter`. |
| `login_throttle_attempts` | int | `10` | Per-account login attempts per window. |
| `login_throttle_window` | duration | `5m` | Sliding window for `LoginThrottle`. |
| `max_entries` | int | `4096` | Maximum number of tracked keys. |

### `ban`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enables credential-stuffing ban tracking. |
| `max_unique_failures` | int | `10` | Unique credential failures before an IP is banned. |
| `ban_duration` | duration | `15m` | How long an IP remains banned. |
| `window` | duration | `5m` | Sliding window for counting unique failures. |
| `max_entries` | int | `4096` | Maximum number of tracked IPs (failures and bans). |

### `proxy`

| Key | Type | Default | Description |
|---|---|---|---|
| `behind_reverse_proxy` | bool | `false` | Whether forwarded headers may be trusted. |
| `trusted_proxy_cidrs` | []string | `[]` | CIDRs or bare IPs of trusted proxy peers. |

`trusted_proxy_cidrs` accepts CIDR strings (`10.0.0.0/8`) and bare IP addresses.
Bare IPv4 addresses become `/32`; bare IPv6 addresses become `/128`.
Empty/whitespace-only entries are skipped.

**Strict parsing:** unlike some source implementations that silently skip
invalid entries, `realip.ParseTrustedProxyCIDRs` returns an error wrapping
`domain.ErrInvalidCIDR` or `domain.ErrInvalidIP` for any invalid entry. This
prevents a typo in a trusted-proxy list from silently disabling proxy trust.
`config.Config.Validate` surfaces the same failure wrapped in
`domain.ErrValidation`.

### `cors`

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | []string | `[]` | Origins allowed to perform mutating requests. |

Each entry must be `*`, empty, or a valid `http://` / `https://` origin of the
form `scheme://host` with no path, query, fragment, or userinfo.

## Validation rules

`(*config.Config).Validate()` returns an error wrapping
`domain.ErrValidation` when:

- `lockout.max_failed_attempts < 0` or `lockout.max_entries < 0`
- `lockout.base_lockout < 0`, `lockout.max_lockout < 0`, or
  `lockout.entry_ttl < 0`
- `lockout.base_lockout > 0`, `lockout.max_lockout > 0`, and
  `lockout.max_lockout < lockout.base_lockout`
- `rate_limit.max_requests < 0`, `rate_limit.login_throttle_attempts < 0`, or
  `rate_limit.max_entries < 0`
- `rate_limit.window < 0` or `rate_limit.login_throttle_window < 0`
- `ban.max_unique_failures < 0`, `ban.max_entries < 0`,
  `ban.ban_duration < 0`, or `ban.window < 0`
- `proxy.trusted_proxy_cidrs` contains an invalid CIDR or IP address
- `cors.allowed_origins` contains a non-empty, non-`*` entry that is not a valid
  `http://` or `https://` origin

Zero values are accepted and are replaced by safe defaults at construction time.
Negative values are rejected.

## JSON example

```json
{
  "lockout": {
    "enabled": true,
    "max_failed_attempts": 5,
    "base_lockout": 30000000000,
    "max_lockout": 900000000000,
    "entry_ttl": 1800000000000,
    "max_entries": 4096
  },
  "rate_limit": {
    "enabled": true,
    "max_requests": 60,
    "window": 60000000000,
    "login_throttle_attempts": 10,
    "login_throttle_window": 300000000000,
    "max_entries": 4096
  },
  "ban": {
    "enabled": true,
    "max_unique_failures": 10,
    "ban_duration": 900000000000,
    "window": 300000000000,
    "max_entries": 4096
  },
  "proxy": {
    "behind_reverse_proxy": true,
    "trusted_proxy_cidrs": ["10.0.0.0/8"]
  },
  "cors": {
    "allowed_origins": ["https://app.example.com"]
  }
}
```

Durations are encoded as nanoseconds by `encoding/json`, matching Go's
`time.Duration` representation.
