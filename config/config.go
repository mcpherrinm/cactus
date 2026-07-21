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
	MirrorPush       MirrorPushConfig `json:"mirror_push"`
	ACME             ACMEConfig       `json:"acme"`
	Monitoring       ListenerConfig   `json:"monitoring"`
	Metrics          MetricsConfig    `json:"metrics"`
	Landmarks        LandmarkConfig   `json:"landmarks"`
	LogLevel         string           `json:"log_level"`
}

// CACosignerQuorum configures the CA-mode multi-mirror cosignature
// collection client. When `Mirrors` is non-empty, the log's flush
// invokes a MirrorRequester that fans out a tlog-witness sign-subtree
// request in parallel to all of them.
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

// MirrorPushConfig configures the c2sp.org/tlog-mirror push client.
// When Targets is non-empty, every log flush pushes the new checkpoint
// and entries to each target. With no targets the whole subsystem is
// inert and cactus behaves exactly as it does without it.
//
// This is a separate section from ca_cosigner_quorum on purpose, even
// though a deployment will typically list the same mirror in both. They
// are different relationships: ca_cosigner_quorum is the CA asking a
// mirror to cosign subtrees for certificates, while mirror_push is the
// log replicating itself to that mirror. The push is what makes the
// cosignature request answerable at all — a mirror only signs a subtree
// against a checkpoint carrying its own cosignature, which it produces
// only in an add-entries response — but a mirror can be pushed to
// without being in the issuance quorum.
type MirrorPushConfig struct {
	Targets []MirrorPushTarget `json:"targets"`
	// RequestTimeoutMS bounds each individual HTTP request.
	RequestTimeoutMS int `json:"request_timeout_ms"`
	// PushTimeoutMS bounds one complete push (add-checkpoint plus the
	// whole add-entries 202 loop) to a single mirror.
	PushTimeoutMS int `json:"push_timeout_ms"`
	// DisableGzip turns off request compression. tlog-mirror says
	// clients SHOULD compress add-entries bodies, so this defaults off.
	DisableGzip bool `json:"disable_gzip"`
}

// RequestTimeout is a typed-time accessor.
func (m MirrorPushConfig) RequestTimeout() time.Duration {
	return time.Duration(m.RequestTimeoutMS) * time.Millisecond
}

// PushTimeout is a typed-time accessor.
func (m MirrorPushConfig) PushTimeout() time.Duration {
	return time.Duration(m.PushTimeoutMS) * time.Millisecond
}

// MirrorPushTarget is one mirror the log replicates itself to.
type MirrorPushTarget struct {
	// ID is the mirror's cosigner trust anchor ID, in the same
	// relative-OID form as ca_cosigner.id.
	ID string `json:"id"`
	// SubmissionPrefix is the base URL of the mirror's write APIs; the
	// client appends "/add-checkpoint" and "/add-entries".
	SubmissionPrefix string `json:"submission_prefix"`
	// MonitoringPrefix is the base URL of the mirror's read APIs, under
	// which it serves "<origin hash>/checkpoint". Used only to
	// bootstrap a starting index for a mirror we have no state for.
	MonitoringPrefix string `json:"monitoring_prefix"`
	Algorithm        string `json:"algorithm"`
	// PublicKeyPath points to a PEM "PUBLIC KEY" file holding the
	// mirror's cosigner key, resolved relative to data_dir.
	PublicKeyPath string `json:"public_key_path"`
}

// MirrorEndpointConfig is one mirror the CA fans out to.
type MirrorEndpointConfig struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Algorithm string `json:"algorithm"`
	// PublicKeyPath points to a PEM "PUBLIC KEY" file holding the mirror's
	// cosigner key, resolved relative to data_dir. The PEM body is the raw
	// ML-DSA-44 public key.
	PublicKeyPath string `json:"public_key_path"`
}

// LandmarkConfig configures the §6.4 landmark sequence. Landmarks are
// always on; only their cadence and the max cert lifetime (which sets
// max_active_landmarks) are tunable. In draft-05 landmark trust anchor
// IDs are derived from the CA ID and log number (CA-ID.1.logNumber.L),
// so there is no separate base_id parameter. The §6.4.1 list is always
// served at "/landmarks".
type LandmarkConfig struct {
	TimeBetweenLandmarksMS int `json:"time_between_landmarks_ms"`
	MaxCertLifetimeMS      int `json:"max_cert_lifetime_ms"`
}

// TimeBetweenLandmarks returns the §6.4.2 interval as a time.Duration.
func (l LandmarkConfig) TimeBetweenLandmarks() time.Duration {
	return time.Duration(l.TimeBetweenLandmarksMS) * time.Millisecond
}

// MaxCertLifetime returns the configured max cert lifetime.
func (l LandmarkConfig) MaxCertLifetime() time.Duration {
	return time.Duration(l.MaxCertLifetimeMS) * time.Millisecond
}

type LogConfig struct {
	// Number is the issuance log's log number (draft-05 §5.2), in
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
		MirrorPush: MirrorPushConfig{
			RequestTimeoutMS: 30000,
			// Mirrors are permitted a five-minute deadline on an
			// add-entries request; allow a whole push the same budget.
			PushTimeoutMS: 300000,
		},
		Landmarks: LandmarkConfig{
			TimeBetweenLandmarksMS: 3600000,   // 1 hour
			MaxCertLifetimeMS:      604800000, // 7 days
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
		return fmt.Errorf("log.number must be set and >= 1 (draft-05 §5.2)")
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
	// draft-05 §5.4: the CA cosigner ID is the CA ID. ca_cosigner.id is
	// therefore the CA ID, and the log ID is derived from it as
	// CA-ID.0.<log.number>.
	if c.ACME.Listen == "" {
		return fmt.Errorf("acme.listen must be set")
	}
	if c.ACME.ExternalURL == "" {
		return fmt.Errorf("acme.external_url must be set (the public base URL ACME clients see)")
	}
	// TLS is optional, but a lone cert or key would silently serve
	// plaintext, so require both or neither.
	if (c.ACME.TLSCert == "") != (c.ACME.TLSKey == "") {
		return fmt.Errorf("acme.tls_cert and acme.tls_key must be set together")
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
	// Landmarks are mandatory; their cadence and max cert lifetime
	// always apply.
	if c.Landmarks.TimeBetweenLandmarksMS <= 0 {
		return fmt.Errorf("landmarks.time_between_landmarks_ms must be > 0")
	}
	if c.Landmarks.MaxCertLifetimeMS <= 0 {
		return fmt.Errorf("landmarks.max_cert_lifetime_ms must be > 0")
	}
	if len(c.MirrorPush.Targets) > 0 {
		if c.MirrorPush.RequestTimeoutMS <= 0 {
			return fmt.Errorf("mirror_push.request_timeout_ms must be > 0")
		}
		if c.MirrorPush.PushTimeoutMS <= 0 {
			return fmt.Errorf("mirror_push.push_timeout_ms must be > 0")
		}
		for i, t := range c.MirrorPush.Targets {
			if t.ID == "" {
				return fmt.Errorf("mirror_push.targets[%d].id required", i)
			}
			if t.SubmissionPrefix == "" {
				return fmt.Errorf("mirror_push.targets[%d].submission_prefix required", i)
			}
			// The monitoring prefix is only used to bootstrap a
			// starting index, and a 409 corrects any guess, so it is
			// optional.
			if t.Algorithm != "mldsa-44" {
				return fmt.Errorf("mirror_push.targets[%d].algorithm must be \"mldsa-44\" (c2sp.org/tlog-cosignature has no other subtree-capable type), got %q", i, t.Algorithm)
			}
			if t.PublicKeyPath == "" {
				return fmt.Errorf("mirror_push.targets[%d].public_key_path required", i)
			}
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
			if m.Algorithm != "mldsa-44" {
				return fmt.Errorf("ca_cosigner_quorum.mirrors[%d].algorithm must be \"mldsa-44\" (c2sp.org/tlog-cosignature has no other subtree-capable type), got %q", i, m.Algorithm)
			}
			if m.PublicKeyPath == "" {
				return fmt.Errorf("ca_cosigner_quorum.mirrors[%d].public_key_path required", i)
			}
		}
	}
	return nil
}
