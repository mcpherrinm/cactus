package pollinate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the cactus-pollinate JSON configuration.
type Config struct {
	// DataDir holds the state file and the mirrorpush resume state.
	DataDir string `json:"data_dir"`
	// Cosigners locates the Chrome cosigners list and its key bundle.
	Cosigners CosignersConfig `json:"cosigners"`
	// PollIntervalMS is how often every log head and mirror copy is
	// polled.
	PollIntervalMS int `json:"poll_interval_ms"`
	// PushDelayMS is the grace period: a mirror is only pushed to when
	// it is missing entries the log head already had this long ago. CAs
	// usually push on their own; the delay keeps pollinate from racing
	// them over every fresh flush.
	PushDelayMS int `json:"push_delay_ms"`
	// Discovery controls probing issuers for their logs.
	Discovery DiscoveryConfig `json:"discovery"`
	// NotCarriedRecheckMS is how long a "mirror does not know this
	// origin" verdict is believed before re-probing. A cosigners file
	// version change also resets the verdicts.
	NotCarriedRecheckMS int `json:"not_carried_recheck_ms"`
	// RequestTimeoutMS bounds each individual HTTP request.
	RequestTimeoutMS int `json:"request_timeout_ms"`
	// PushTimeoutMS bounds one complete push (add-checkpoint plus the
	// whole add-entries loop) to one mirror.
	PushTimeoutMS int `json:"push_timeout_ms"`
	// MaxConcurrentPushes bounds simultaneous pushes across all
	// (log, mirror) pairs.
	MaxConcurrentPushes int `json:"max_concurrent_pushes"`
	// Mirrors carries optional per-mirror overrides, matched by the
	// mirror's base_id from the cosigners file.
	Mirrors  []MirrorOverride `json:"mirrors"`
	Metrics  MetricsConfig    `json:"metrics"`
	LogLevel string           `json:"log_level"`
}

// CosignersConfig locates the cosigners list. Both fields accept an
// http(s) URL or a local file path.
type CosignersConfig struct {
	List string `json:"list"`
	Keys string `json:"keys"`
	// RefreshMS is how often the list and keys are re-fetched.
	RefreshMS int `json:"refresh_ms"`
}

// DiscoveryConfig controls how issuer base URLs are probed for logs.
// Each issuer is probed at its bare base URL and at /1../<max_log_number>,
// since both single-log CAs (checkpoint at the base URL) and
// mtc-tlog-profile CAs (<CA prefix>/<log number>) exist in the wild.
type DiscoveryConfig struct {
	MaxLogNumber int `json:"max_log_number"`
	IntervalMS   int `json:"interval_ms"`
}

// MirrorOverride adjusts how one mirror from the cosigners file is
// treated.
type MirrorOverride struct {
	ID string `json:"id"`
	// SubmissionPrefix overrides the write-API base URL. By default the
	// mirror's base_url (its monitoring prefix) is used for both, which
	// tlog-mirror explicitly permits.
	SubmissionPrefix string `json:"submission_prefix"`
	// Disable excludes the mirror from polling and pushing entirely.
	Disable bool `json:"disable"`
}

// MetricsConfig configures the Prometheus listener.
type MetricsConfig struct {
	Listen string `json:"listen"`
}

// Typed-time accessors, following the cactus config convention.
func (c Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalMS) * time.Millisecond
}
func (c Config) PushDelay() time.Duration { return time.Duration(c.PushDelayMS) * time.Millisecond }
func (c Config) NotCarriedRecheck() time.Duration {
	return time.Duration(c.NotCarriedRecheckMS) * time.Millisecond
}
func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMS) * time.Millisecond
}
func (c Config) PushTimeout() time.Duration { return time.Duration(c.PushTimeoutMS) * time.Millisecond }
func (c CosignersConfig) Refresh() time.Duration {
	return time.Duration(c.RefreshMS) * time.Millisecond
}
func (d DiscoveryConfig) Interval() time.Duration {
	return time.Duration(d.IntervalMS) * time.Millisecond
}

// DefaultConfig returns a Config populated with the documented
// defaults: the Chrome cosigners list, a one-minute poll, and a
// ten-minute push delay.
func DefaultConfig() Config {
	return Config{
		DataDir: "/var/lib/cactus-pollinate",
		Cosigners: CosignersConfig{
			List:      "https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json",
			Keys:      "https://www.gstatic.com/mtcs/cosigners/v1/cosigners.pem",
			RefreshMS: 900000, // 15 min
		},
		PollIntervalMS: 60000,  // 1 min
		PushDelayMS:    600000, // 10 min
		Discovery: DiscoveryConfig{
			MaxLogNumber: 8,
			IntervalMS:   900000, // 15 min
		},
		NotCarriedRecheckMS: 21600000, // 6 h
		RequestTimeoutMS:    30000,
		PushTimeoutMS:       300000, // same 5 min budget as cactus mirror_push
		MaxConcurrentPushes: 4,
		Metrics:             MetricsConfig{Listen: "127.0.0.1:14091"},
		LogLevel:            "info",
	}
}

// LoadConfig reads and validates the configuration at path.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir must be set")
	}
	if c.Cosigners.List == "" {
		return fmt.Errorf("cosigners.list must be set")
	}
	if c.Cosigners.Keys == "" {
		return fmt.Errorf("cosigners.keys must be set")
	}
	if c.Cosigners.RefreshMS <= 0 {
		return fmt.Errorf("cosigners.refresh_ms must be > 0")
	}
	if c.PollIntervalMS <= 0 {
		return fmt.Errorf("poll_interval_ms must be > 0")
	}
	if c.PushDelayMS < 0 {
		return fmt.Errorf("push_delay_ms must be >= 0")
	}
	if c.Discovery.MaxLogNumber < 0 || c.Discovery.MaxLogNumber > 65535 {
		return fmt.Errorf("discovery.max_log_number must be in [0, 65535]")
	}
	if c.Discovery.IntervalMS <= 0 {
		return fmt.Errorf("discovery.interval_ms must be > 0")
	}
	if c.NotCarriedRecheckMS <= 0 {
		return fmt.Errorf("not_carried_recheck_ms must be > 0")
	}
	if c.RequestTimeoutMS <= 0 {
		return fmt.Errorf("request_timeout_ms must be > 0")
	}
	if c.PushTimeoutMS <= 0 {
		return fmt.Errorf("push_timeout_ms must be > 0")
	}
	if c.MaxConcurrentPushes <= 0 {
		return fmt.Errorf("max_concurrent_pushes must be > 0")
	}
	for i, m := range c.Mirrors {
		if m.ID == "" {
			return fmt.Errorf("mirrors[%d].id required", i)
		}
	}
	if c.Metrics.Listen == "" {
		return fmt.Errorf("metrics.listen must be set")
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q invalid", c.LogLevel)
	}
	return nil
}
