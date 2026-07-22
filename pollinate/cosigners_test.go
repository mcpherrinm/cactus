package pollinate

import (
	"os"
	"testing"
)

// The testdata files are a snapshot of the real published list
// (https://www.gstatic.com/mtcs/cosigners/v1/), taken 2026-07-22, so the
// parser is exercised against the wire format as it actually exists:
// two issuers (one with an Ed25519 key, one ML-DSA-44) and one mirror.
func TestParseRealCosigners(t *testing.T) {
	data, err := os.ReadFile("testdata/cosigners.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseCosigners(data)
	if err != nil {
		t.Fatal(err)
	}
	if l.Version != "2.0.2" {
		t.Errorf("version = %q, want 2.0.2", l.Version)
	}
	if len(l.Operators) != 3 || len(l.Issuers) != 2 || len(l.Mirrors) != 1 {
		t.Fatalf("got %d operators, %d issuers, %d mirrors", len(l.Operators), len(l.Issuers), len(l.Mirrors))
	}
	cf := l.Issuers[0]
	if cf.BaseID != "44363.48.8" || cf.BaseURL != "https://bootstrap-mtca-shard3.cloudflareresearch.com" {
		t.Errorf("unexpected first issuer: %+v", cf)
	}
	if cf.CurrentState() != "" {
		t.Errorf("issuer with no state history has state %q", cf.CurrentState())
	}
	m := l.Mirrors[0]
	if m.CurrentState() != "USABLE" {
		t.Errorf("mirror state = %q, want USABLE", m.CurrentState())
	}
	if m.BaseID != "11129.11.99.2" {
		t.Errorf("mirror base_id = %q", m.BaseID)
	}
}

func TestParseRealKeys(t *testing.T) {
	jsonData, err := os.ReadFile("testdata/cosigners.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseCosigners(jsonData)
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := os.ReadFile("testdata/cosigners.pem")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeys(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	// Every signer's key_sha256 must resolve to a bundle entry — this is
	// the join the schema promises.
	for _, sg := range append(append([]Signer(nil), l.Issuers...), l.Mirrors...) {
		if _, ok := keys[sg.KeySHA256]; !ok {
			t.Errorf("no key in bundle for %s (%s)", sg.BaseID, sg.KeySHA256)
		}
	}
	// Cloudflare's issuer key is Ed25519: present in the bundle but not
	// usable for ML-DSA-44 verification.
	if raw, ok := mldsa44KeyFromSPKI(keys[l.Issuers[0].KeySHA256]); ok {
		t.Errorf("Ed25519 SPKI parsed as ML-DSA-44 (%d bytes)", len(raw))
	}
	// The mtcs.dev keys are ML-DSA-44 (1312-byte raw keys).
	for _, sg := range []Signer{l.Issuers[1], l.Mirrors[0]} {
		raw, ok := mldsa44KeyFromSPKI(keys[sg.KeySHA256])
		if !ok {
			t.Errorf("%s key did not parse as ML-DSA-44", sg.BaseID)
			continue
		}
		if len(raw) != 1312 {
			t.Errorf("%s raw key is %d bytes, want 1312", sg.BaseID, len(raw))
		}
	}
}

func TestParseCosignersRejectsBadInput(t *testing.T) {
	for name, in := range map[string]string{
		"no version":     `{"operators":[]}`,
		"missing url":    `{"version":"1","operators":[],"mirrors":[{"friendly_name":"m","base_id":"1.2","key_sha256":"` + hex64 + `"}]}`,
		"short key hash": `{"version":"1","operators":[],"issuers":[{"base_id":"1.2","base_url":"https://x","key_sha256":"abcd"}]}`,
		"not json":       `hello`,
	} {
		if _, err := ParseCosigners([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

const hex64 = "0000000000000000000000000000000000000000000000000000000000000000"

func TestParseKeysRejectsNonKeys(t *testing.T) {
	if _, err := ParseKeys([]byte("no pem here")); err == nil {
		t.Error("expected error for PEM-free input")
	}
	cert := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if _, err := ParseKeys([]byte(cert)); err == nil {
		t.Error("expected error for non-PUBLIC KEY block")
	}
}
