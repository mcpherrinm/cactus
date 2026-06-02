// Package config loads the cactus JSON configuration file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	DataDir          string           `json:"data_dir"`
	Log              LogConfig        `json:"log"`
	CACosigner       CosignerConfig   `json:"ca_cosigner"`
	CACosignerQuorum CACosignerQuorum `json:"ca_cosigner_quorum"`
	ACME             ACMEConfig       `json:"acme"`
	Monitoring       ListenerConfig   `json:"monitoring"`
	Metrics          MetricsConfig    `json:"metrics"`
	Landmarks        LandmarkConfig   `json:"landmarks"`
	Mirror           MirrorConfig     `json:"mirror"`
	LogLevel         string           `json:"log_level"`
}

// CACosignerQuorum configures the CA-mode multi-mirror cosignature
// collection (Phase 9 client). When `Mirrors` is non-empty, the
// log's flush invokes a MirrorRequester that fans out a §C.2
// sign-subtree request in parallel to all of them.
type CACosignerQuorum struct {
	Mirrors                []MirrorEndpointConfig `json:"mirrors"`
	MinSignatures          int                    `json:"min_signatures"`
	RequestTimeoutMS       int                    `json:"request_timeout_ms"`
	BestEffortAfterMinimum bool                   `json:"best_effort_after_minimum"`
	// MirrorRetryDeadlineMS is how long the requester closure keeps
	// re-trying when mirrors haven't caught up yet.
	MirrorRetryDeadlineMS int `json:"mirror_retry_deadline_ms"`
}

// RequestTimeout is a typed-time accessor.
func (c CACosignerQuorum) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMS) * time.Millisecond
}

// RetryDeadline is a typed-time accessor.
func (c CACosignerQuorum) RetryDeadline() time.Duration {
	return time.Duration(c.MirrorRetryDeadlineMS) * time.Millisecond
}

// MirrorEndpointConfig is one mirror the CA fans out to.
type MirrorEndpointConfig struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	Algorithm    string `json:"algorithm"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// MirrorConfig configures cactus's mirror operating mode (Phase 9).
// When Enabled, the binary brings up a Follower + sign-subtree
// listener alongside (or instead of) its CA-mode duties.
type MirrorConfig struct {
	Enabled                     bool           `json:"enabled"`
	CosignerID                  string         `json:"cosigner_id"`
	SeedPath                    string         `json:"seed_path"`
	Algorithm                   string         `json:"algorithm"`
	Upstream                    UpstreamConfig `json:"upstream"`
	SignSubtreeListen           string         `json:"sign_subtree_listen"`
	SignSubtreePath             string         `json:"sign_subtree_path"`
	RequireCASignatureOnSubtree bool           `json:"require_ca_signature_on_subtree"`
}

// UpstreamConfig describes the log being mirrored.
type UpstreamConfig struct {
	TileURL          string `json:"tile_url"`
	LogID            string `json:"log_id"`
	CACosignerID     string `json:"ca_cosigner_id"`
	CACosignerKeyPEM string `json:"ca_cosigner_key_pem"` // PEM block; body is the raw ML-DSA-44 public key
	PollIntervalMS   int    `json:"poll_interval_ms"`
}

// PollInterval is a typed-time accessor.
func (u UpstreamConfig) PollInterval() time.Duration {
	return time.Duration(u.PollIntervalMS) * time.Millisecond
}

// LandmarkConfig configures the §6.3 landmark sequence + URL.
// Disabled by default; set Enabled=true to opt in. In draft-04 landmark
// trust anchor IDs are derived from the CA ID and log number
// (CA-ID.1.logNumber.L), so there is no separate base_id parameter.
type LandmarkConfig struct {
	Enabled                bool   `json:"enabled"`
	TimeBetweenLandmarksMS int    `json:"time_between_landmarks_ms"`
	MaxCertLifetimeMS      int    `json:"max_cert_lifetime_ms"`
	URLPath                string `json:"landmark_url_path"`
}

// TimeBetweenLandmarks returns the §6.3.2 interval as a time.Duration.
func (l LandmarkConfig) TimeBetweenLandmarks() time.Duration {
	return time.Duration(l.TimeBetweenLandmarksMS) * time.Millisecond
}

// MaxCertLifetime returns the configured max cert lifetime.
func (l LandmarkConfig) MaxCertLifetime() time.Duration {
	return time.Duration(l.MaxCertLifetimeMS) * time.Millisecond
}

type LogConfig struct {
	// Number is the issuance log's log number (draft-04 §5.2), in
	// [1, 65535]. The log ID is derived as CA-ID.0.Number; the CA ID is
	// the CA cosigner's ID (ca_cosigner.id).
	Number             uint16 `json:"number"`
	ShortName          string `json:"shortname"`
	Hash               string `json:"hash"`
	CheckpointPeriodMS int    `json:"checkpoint_period_ms"`
	PoolSize           int    `json:"pool_size"`
}

func (l LogConfig) CheckpointPeriod() time.Duration {
	return time.Duration(l.CheckpointPeriodMS) * time.Millisecond
}

type CosignerConfig struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	SeedPath  string `json:"seed_path"`
}

type ACMEConfig struct {
	Listen        string `json:"listen"`
	ExternalURL   string `json:"external_url"`
	TLSCert       string `json:"tls_cert"`
	TLSKey        string `json:"tls_key"`
	ChallengeMode string `json:"challenge_mode"`
}

type ListenerConfig struct {
	Listen      string `json:"listen"`
	ExternalURL string `json:"external_url"`
}

type MetricsConfig struct {
	Listen string `json:"listen"`
}

// Default returns a Config populated with the documented defaults.
func Default() Config {
	return Config{
		DataDir: "/var/lib/cactus",
		Log: LogConfig{
			Hash:               "sha256",
			CheckpointPeriodMS: 1000,
			PoolSize:           256,
		},
		CACosigner: CosignerConfig{
			Algorithm: "mldsa-44",
			SeedPath:  "keys/ca-cosigner.seed",
		},
		ACME: ACMEConfig{
			Listen:        ":14000",
			ChallengeMode: "auto-pass",
		},
		Monitoring: ListenerConfig{Listen: ":14080"},
		Metrics:    MetricsConfig{Listen: "127.0.0.1:14090"},
		Landmarks: LandmarkConfig{
			URLPath:                "/landmarks",
			TimeBetweenLandmarksMS: 3600000,   // 1 hour
			MaxCertLifetimeMS:      604800000, // 7 days
		},
		Mirror: MirrorConfig{
			Algorithm:                   "mldsa-44",
			SignSubtreePath:             "/sign-subtree",
			RequireCASignatureOnSubtree: true,
			Upstream: UpstreamConfig{
				PollIntervalMS: 1000,
			},
		},
		LogLevel: "info",
	}
}

// Load reads and validates the configuration at path.
func Load(path string) (Config, error) {
	c := Default()
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
	if c.Log.Number == 0 {
		return fmt.Errorf("log.number must be set and >= 1 (draft-04 §5.2)")
	}
	if c.Log.ShortName == "" {
		return fmt.Errorf("log.shortname must be set")
	}
	if c.Log.Hash != "sha256" {
		return fmt.Errorf("log.hash %q not supported (only sha256)", c.Log.Hash)
	}
	if c.Log.CheckpointPeriodMS <= 0 {
		return fmt.Errorf("log.checkpoint_period_ms must be > 0")
	}
	if c.Log.PoolSize <= 0 {
		return fmt.Errorf("log.pool_size must be > 0")
	}
	if c.CACosigner.ID == "" {
		return fmt.Errorf("ca_cosigner.id must be set")
	}
	// The MTC-with-tlog profile requires every MTC cosigner — including
	// the CA cosigner that signs checkpoints — to use an ML-DSA-44 key and
	// produce ML-DSA-44 signed messages (c2sp.org/tlog-cosignature), since
	// that is currently the only signature algorithm available in both
	// X.509 and C2SP in a subtree-capable form. ML-DSA-44 validates here
	// regardless of toolchain, but only produces a working signer when
	// built with Go 1.27+ (where crypto/mldsa exists); on older toolchains
	// signer.FromSeed reports the missing support at startup.
	if c.CACosigner.Algorithm != "mldsa-44" {
		return fmt.Errorf("ca_cosigner.algorithm must be \"mldsa-44\" (the MTC-with-tlog profile requires ML-DSA-44 cosigners), got %q", c.CACosigner.Algorithm)
	}
	if c.CACosigner.SeedPath == "" {
		return fmt.Errorf("ca_cosigner.seed_path must be set")
	}
	// draft-04 §5.4: the CA cosigner ID is the CA ID. ca_cosigner.id is
	// therefore the CA ID, and the log ID is derived from it as
	// CA-ID.0.<log.number>.
	if c.ACME.Listen == "" {
		return fmt.Errorf("acme.listen must be set")
	}
	if c.ACME.ExternalURL == "" {
		return fmt.Errorf("acme.external_url must be set (the public base URL ACME clients see)")
	}
	switch c.ACME.ChallengeMode {
	case "auto-pass", "http-01":
	default:
		return fmt.Errorf("acme.challenge_mode %q must be auto-pass or http-01", c.ACME.ChallengeMode)
	}
	if c.Monitoring.Listen == "" {
		return fmt.Errorf("monitoring.listen must be set")
	}
	if c.Metrics.Listen == "" {
		return fmt.Errorf("metrics.listen must be set")
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q invalid", c.LogLevel)
	}
	if c.Landmarks.Enabled {
		if c.Landmarks.TimeBetweenLandmarksMS <= 0 {
			return fmt.Errorf("landmarks.time_between_landmarks_ms must be > 0")
		}
		if c.Landmarks.MaxCertLifetimeMS <= 0 {
			return fmt.Errorf("landmarks.max_cert_lifetime_ms must be > 0")
		}
		if c.Landmarks.URLPath == "" {
			return fmt.Errorf("landmarks.landmark_url_path must be set")
		}
	}
	if len(c.CACosignerQuorum.Mirrors) > 0 {
		if c.CACosignerQuorum.MinSignatures < 1 {
			return fmt.Errorf("ca_cosigner_quorum.min_signatures must be >= 1 when mirrors are configured")
		}
		if c.CACosignerQuorum.MinSignatures > len(c.CACosignerQuorum.Mirrors) {
			return fmt.Errorf("ca_cosigner_quorum.min_signatures (%d) > number of mirrors (%d)",
				c.CACosignerQuorum.MinSignatures, len(c.CACosignerQuorum.Mirrors))
		}
		if c.CACosignerQuorum.RequestTimeoutMS <= 0 {
			return fmt.Errorf("ca_cosigner_quorum.request_timeout_ms must be > 0")
		}
		if c.CACosignerQuorum.MirrorRetryDeadlineMS <= 0 {
			return fmt.Errorf("ca_cosigner_quorum.mirror_retry_deadline_ms must be > 0 when mirrors are configured")
		}
		for i, m := range c.CACosignerQuorum.Mirrors {
			if m.ID == "" {
				return fmt.Errorf("ca_cosigner_quorum.mirrors[%d].id required", i)
			}
			if m.URL == "" {
				return fmt.Errorf("ca_cosigner_quorum.mirrors[%d].url required", i)
			}
			if m.Algorithm == "" {
				return fmt.Errorf("ca_cosigner_quorum.mirrors[%d].algorithm required", i)
			}
			if m.PublicKeyPEM == "" {
				return fmt.Errorf("ca_cosigner_quorum.mirrors[%d].public_key_pem required", i)
			}
		}
	}
	if c.Mirror.Enabled {
		if c.Mirror.CosignerID == "" {
			return fmt.Errorf("mirror.cosigner_id must be set when mirror.enabled")
		}
		if c.Mirror.CosignerID == c.CACosigner.ID {
			return fmt.Errorf("mirror.cosigner_id %q must differ from ca_cosigner.id", c.Mirror.CosignerID)
		}
		if c.Mirror.SeedPath == "" {
			return fmt.Errorf("mirror.seed_path must be set when mirror.enabled")
		}
		if c.Mirror.SeedPath == c.CACosigner.SeedPath {
			return fmt.Errorf("mirror.seed_path %q must differ from ca_cosigner.seed_path", c.Mirror.SeedPath)
		}
		if c.Mirror.Algorithm == "" {
			return fmt.Errorf("mirror.algorithm must be set when mirror.enabled")
		}
		// The c2sp.org/tlog-witness sign-subtree response is an ML-DSA-44
		// cosignature (c2sp.org/tlog-cosignature defines no ECDSA
		// cosignature type), so a mirror's cosigner MUST be ML-DSA-44.
		if c.Mirror.Algorithm != "mldsa-44" {
			return fmt.Errorf("mirror.algorithm must be \"mldsa-44\" (the witness path is ML-DSA-44 only), got %q", c.Mirror.Algorithm)
		}
		if c.Mirror.Upstream.TileURL == "" {
			return fmt.Errorf("mirror.upstream.tile_url required")
		}
		if c.Mirror.Upstream.LogID == "" {
			return fmt.Errorf("mirror.upstream.log_id required")
		}
		if c.Mirror.Upstream.CACosignerID == "" {
			return fmt.Errorf("mirror.upstream.ca_cosigner_id required")
		}
		if c.Mirror.Upstream.CACosignerKeyPEM == "" {
			return fmt.Errorf("mirror.upstream.ca_cosigner_key_pem required")
		}
		if c.Mirror.Upstream.PollIntervalMS <= 0 {
			return fmt.Errorf("mirror.upstream.poll_interval_ms must be > 0")
		}
		if c.Mirror.SignSubtreeListen == "" {
			return fmt.Errorf("mirror.sign_subtree_listen required")
		}
		if c.Mirror.SignSubtreePath == "" {
			return fmt.Errorf("mirror.sign_subtree_path required")
		}
	}
	return nil
}
