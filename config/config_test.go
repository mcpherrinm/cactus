package config

import (
	"os"
	"path/filepath"
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
		"id": "1.3.6.1.4.1.44363.47.1.99",
		"shortname": "test",
		"hash": "sha256",
		"checkpoint_period_ms": 500,
		"pool_size": 128
	},
	"ca_cosigner": {
		"id": "1.3.6.1.4.1.44363.47.1.99.ca",
		"algorithm": "ecdsa-p256-sha256",
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
		{"missing log.id", `{"data_dir":"/tmp","log":{"shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"bad challenge", `{"data_dir":"/tmp","log":{"id":"a","shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"nope"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"bad hash", `{"data_dir":"/tmp","log":{"id":"a","shortname":"x","hash":"sha512","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"bad algorithm", `{"data_dir":"/tmp","log":{"id":"a","shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"rsa","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
		{"unknown field", `{"data_dir":"/tmp","unknown":1,"log":{"id":"a","shortname":"x","hash":"sha256","checkpoint_period_ms":1,"pool_size":1},"ca_cosigner":{"id":"a","algorithm":"ecdsa-p256-sha256","seed_path":"x"},"acme":{"listen":":1","challenge_mode":"auto-pass"},"monitoring":{"listen":":2"},"metrics":{"listen":":3"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, tc.body)); err == nil {
				t.Fatalf("Load %q: expected error, got nil", tc.name)
			}
		})
	}
}
