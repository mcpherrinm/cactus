package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	const body = `{
	"data_dir": "/tmp/cactus",
	"log": {
		"number": 1,
		"shortname": "test",
		"hash": "sha256",
		"checkpoint_period_ms": 500,
		"pool_size": 128
	},
	"ca_cosigner": {
		"id": "44363.47.1.99",
		"algorithm": "mldsa-44",
		"seed_path": "keys/ca.seed"
	},
	"acme": {
		"listen": ":14000",
		"external_url": "https://localhost:14000",
		"tls_cert": "k/c.crt",
		"tls_key": "k/c.key",
		"challenge_mode": "auto-pass"
	},
	"monitoring": {"listen": ":14080", "external_url": "http://localhost:14080"},
	"metrics": {"listen": "127.0.0.1:14090"},
	"log_level": "debug"
}`
	c, err := Load(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Log.CheckpointPeriod() != 500*1_000_000 {
		t.Errorf("CheckpointPeriod = %v, want 500ms", c.Log.CheckpointPeriod())
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", c.LogLevel)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing log.number", `{"data_dir":"/tmp","log":{"shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"bad challenge", `{"data_dir":"/tmp","log":{"number":1,"shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"nope"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"bad hash", `{"data_dir":"/tmp","log":{"number":1,"shortname":"x","hash":"sha512","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"bad algorithm", `{"data_dir":"/tmp","log":{"number":1,"shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"rsa","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"unknown field", `{"data_dir":"/tmp","unknown":1,"log":{"number":1,"shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, tc.body)); err == nil {
				t.Fatalf("Load %q: expected error, got nil", tc.name)
			}
		})
	}
}

// TestRedactedOmitsSecretsAndPaths fills every secret/path-bearing field with a
// recognizable sentinel, then asserts none of those sentinels survive into the
// JSON of Redacted(). Because Redacted() is an allowlist, this also guards
// against a future path/secret field being copied across by mistake.
func TestRedactedOmitsSecretsAndPaths(t *testing.T) {
	const secret = "SENSITIVE-DO-NOT-LEAK"
	c := Config{
		DataDir: "/var/lib/" + secret,
		CACosigner: CosignerConfig{
			ID:        "id-ca",
			Algorithm: "mldsa-44",
			SeedPath:  "keys/" + secret,
		},
		ACME: ACMEConfig{
			Listen:        secret + ":14000",
			ExternalURL:   "https://example.test",
			TLSCert:       "tls/" + secret + ".crt",
			TLSKey:        "tls/" + secret + ".key",
			ChallengeMode: "auto-pass",
		},
		Monitoring: ListenerConfig{
			Listen:      secret + ":14080",
			ExternalURL: "https://mon.test",
		},
		Metrics: MetricsConfig{Listen: secret + ":14090"},
		CACosignerQuorum: CACosignerQuorum{
			Mirrors: []MirrorEndpointConfig{{
				ID:            "id-mirror",
				URL:           "https://mirror.test",
				Algorithm:     "mldsa-44",
				PublicKeyPath: "keys/" + secret,
			}},
			MinSignatures: 1,
		},
		MirrorPush: MirrorPushConfig{
			Targets: []MirrorPushTarget{{
				ID:               "id-push",
				SubmissionPrefix: "https://push.test/sub",
				MonitoringPrefix: "https://push.test/mon",
				Algorithm:        "mldsa-44",
				PublicKeyPath:    "keys/" + secret,
			}},
			RequestTimeoutMS: 1000,
			PushTimeoutMS:    2000,
		},
	}

	out, err := json.Marshal(c.Redacted())
	if err != nil {
		t.Fatalf("marshal redacted config: %v", err)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("redacted config leaked a secret/path sentinel:\n%s", out)
	}

	// Sanity: a non-sensitive field still comes through, so the test would
	// actually catch a leak rather than passing on an empty result.
	if !strings.Contains(string(out), "https://example.test") {
		t.Fatalf("redacted config dropped a public field; got:\n%s", out)
	}
	// The push targets' URL prefixes are public endpoints and are meant
	// to be exposed; if they vanished, the sentinel check above would
	// pass vacuously for that section.
	if !strings.Contains(string(out), "https://push.test/sub") {
		t.Fatalf("redacted config dropped the mirror_push submission prefix; got:\n%s", out)
	}
}

// TestMirrorPushConfig covers the mirror_push section: it is optional,
// its defaults are applied, and its per-target validation fires.
func TestMirrorPushConfig(t *testing.T) {
	base := func(push string) string {
		return `{
	"data_dir": "/tmp/cactus",
	"log": {"number": 1, "shortname": "test", "hash": "sha256", "checkpoint_period_ms": 500, "pool_size": 128},
	"ca_cosigner": {"id": "44363.47.1.99", "algorithm": "mldsa-44", "seed_path": "keys/ca.seed"},
	"acme": {"listen": ":14000", "external_url": "https://localhost:14000", "challenge_mode": "auto-pass"},
	"monitoring": {"listen": ":14080"},
	"metrics": {"listen": "127.0.0.1:14090"}` + push + `
}`
	}

	t.Run("absent section keeps defaults and validates", func(t *testing.T) {
		c, err := Load(writeTemp(t, base("")))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(c.MirrorPush.Targets) != 0 {
			t.Errorf("Targets = %v, want none", c.MirrorPush.Targets)
		}
		if c.MirrorPush.RequestTimeout() == 0 || c.MirrorPush.PushTimeout() == 0 {
			t.Error("mirror_push timeouts have no defaults")
		}
	})

	t.Run("valid target", func(t *testing.T) {
		c, err := Load(writeTemp(t, base(`,
	"mirror_push": {
		"targets": [{
			"id": "44363.47.2.1",
			"submission_prefix": "http://mirror.test",
			"monitoring_prefix": "http://mirror.test/mon",
			"algorithm": "mldsa-44",
			"public_key_path": "keys/mirror.pem"
		}],
		"request_timeout_ms": 5000,
		"push_timeout_ms": 60000
	}`)))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(c.MirrorPush.Targets) != 1 {
			t.Fatalf("got %d targets, want 1", len(c.MirrorPush.Targets))
		}
		if c.MirrorPush.Targets[0].SubmissionPrefix != "http://mirror.test" {
			t.Errorf("submission prefix = %q", c.MirrorPush.Targets[0].SubmissionPrefix)
		}
	})

	for _, tc := range []struct {
		name string
		push string
	}{
		{"missing id", `,"mirror_push":{"targets":[{"submission_prefix":"http://m","algorithm":"mldsa-44","public_key_path":"k"}]}`},
		{"missing submission prefix", `,"mirror_push":{"targets":[{"id":"1.2","algorithm":"mldsa-44","public_key_path":"k"}]}`},
		{"missing public key path", `,"mirror_push":{"targets":[{"id":"1.2","submission_prefix":"http://m","algorithm":"mldsa-44"}]}`},
		{"non-mldsa algorithm", `,"mirror_push":{"targets":[{"id":"1.2","submission_prefix":"http://m","algorithm":"ed25519","public_key_path":"k"}]}`},
		{"zero request timeout", `,"mirror_push":{"targets":[{"id":"1.2","submission_prefix":"http://m","algorithm":"mldsa-44","public_key_path":"k"}],"request_timeout_ms":0}`},
		{"unknown field in target", `,"mirror_push":{"targets":[{"id":"1.2","submission_prefix":"http://m","algorithm":"mldsa-44","public_key_path":"k","nope":1}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, base(tc.push))); err == nil {
				t.Errorf("Load accepted %s", tc.name)
			}
		})
	}

	// The monitoring prefix is optional: it only bootstraps a starting
	// index, and a 409 corrects any guess.
	t.Run("monitoring prefix optional", func(t *testing.T) {
		if _, err := Load(writeTemp(t, base(`,"mirror_push":{"targets":[{"id":"1.2","submission_prefix":"http://m","algorithm":"mldsa-44","public_key_path":"k"}]}`))); err != nil {
			t.Errorf("Load rejected a target without a monitoring prefix: %v", err)
		}
	})
}
