package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/signer"
)

// TestCactusBinaryMirrorMode brings up two cactus binaries:
//   - One in CA mode (issues certs).
//   - One in mirror mode, pointed at the CA.
//
// Issues a few certs on the CA, then waits for the mirror's
// /metrics or /sign-subtree to come up and confirms it's listening.
// This is the binary smoke test; the full end-to-end "mirror
// cosignature in cert" path is covered by TestEndToEndCAWithThreeMirrors.
func TestCactusBinaryMirrorMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}

	// Generate a stable seed for the CA cosigner so the smoke test
	// can compute its public key for the mirror config.
	caSeed := make([]byte, signer.SeedSize)
	for i := range caSeed {
		caSeed[i] = byte(i ^ 0xAB)
	}
	caSigner, err := signer.FromSeed(signer.AlgMLDSA44, caSeed)
	if err != nil {
		t.Fatal(err)
	}

	// CA binary.
	caDataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(caDataDir, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDataDir, "keys/ca-cosigner.seed"), caSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	caAcmePort, caMonPort, caMetricsPort := freePort(t), freePort(t), freePort(t)
	caCfgPath := filepath.Join(t.TempDir(), "ca-config.json")
	caCfg := standardConfig(caDataDir, caAcmePort, caMonPort, caMetricsPort)
	if b, _ := json.MarshalIndent(caCfg, "", "  "); true {
		os.WriteFile(caCfgPath, b, 0o600)
	}

	bin := buildBinary(t, "cmd/cactus")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caCmd := exec.CommandContext(ctx, bin, "-config", caCfgPath)
	caCmd.Stdout = &capWriter{prefix: "ca.stdout"}
	caCmd.Stderr = &capWriter{prefix: "ca.stderr"}
	if err := caCmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if caCmd.Process != nil {
			_ = caCmd.Process.Signal(syscall.SIGTERM)
		}
		_ = caCmd.Wait()
	})
	caBase := fmt.Sprintf("http://127.0.0.1:%d", caAcmePort)
	caTileBase := fmt.Sprintf("http://127.0.0.1:%d", caMonPort)
	if err := waitForHTTP(caBase+"/directory", 5*time.Second); err != nil {
		t.Fatalf("CA never came up: %v", err)
	}

	// PEM-wrap the CA's raw ML-DSA-44 public key for the mirror config
	// (loadPEMSPKI returns the PEM body verbatim, which for ML-DSA is the
	// raw FIPS 204 key the verifier expects).
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: caSigner.PublicKey()})

	// Mirror binary.
	mDataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mDataDir, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The upstream CA cosigner key is loaded from a PEM file resolved
	// relative to data_dir.
	if err := os.WriteFile(filepath.Join(mDataDir, "keys", "ca-cosigner.pub.pem"), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	mAcmePort, mMonPort, mMetricsPort, mSignPort := freePort(t), freePort(t), freePort(t), freePort(t)
	mCfgPath := filepath.Join(t.TempDir(), "mirror-config.json")
	mCfg := standardConfig(mDataDir, mAcmePort, mMonPort, mMetricsPort)
	mCfg["mirror"] = map[string]any{
		"enabled":                         true,
		"cosigner_id":                     "44363.47.2.1",
		"seed_path":                       "keys/mirror-cosigner.seed",
		"algorithm":                       "mldsa-44",
		"sign_subtree_listen":             fmt.Sprintf("127.0.0.1:%d", mSignPort),
		"sign_subtree_path":               "/sign-subtree",
		"require_ca_signature_on_subtree": false,
		"upstream": map[string]any{
			// The profile serves each log at <prefix>/<log number>; the CA's
			// log number is 1 (standardConfig).
			"tile_url": caTileBase + "/1",
			// draft-04 §5.2: the upstream log ID is the CA ID with the
			// log number appended (CA-ID.0.1); the CA cosigner ID is the
			// CA ID (§5.4).
			"log_id":               "44363.47.1.99.0.1",
			"ca_cosigner_id":       "44363.47.1.99",
			"ca_cosigner_key_path": "keys/ca-cosigner.pub.pem",
			"poll_interval_ms":     100,
		},
	}
	b, _ := json.MarshalIndent(mCfg, "", "  ")
	if err := os.WriteFile(mCfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	mCmd := exec.CommandContext(ctx, bin, "-config", mCfgPath)
	mCmd.Stdout = &capWriter{prefix: "mirror.stdout"}
	mCmd.Stderr = &capWriter{prefix: "mirror.stderr"}
	if err := mCmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if mCmd.Process != nil {
			_ = mCmd.Process.Signal(syscall.SIGTERM)
		}
		_ = mCmd.Wait()
	})
	mSignBase := fmt.Sprintf("http://127.0.0.1:%d", mSignPort)
	if err := waitForListening(mSignBase+"/sign-subtree", 5*time.Second); err != nil {
		t.Fatalf("mirror never came up: %v", err)
	}

	// Issue a few certs on the CA.
	for i := 0; i < 3; i++ {
		if _, err := acmeIssueOne(caBase, fmt.Sprintf("bm%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	// Give the mirror time to advance (poll interval = 100 ms).
	time.Sleep(500 * time.Millisecond)

	// Sanity: the mirror's /sign-subtree responds 405 to GET (since
	// it only handles POST). Confirms the listener is up and the
	// path is mounted.
	resp, err := http.Get(mSignBase + "/sign-subtree")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("mirror /sign-subtree GET = %d, want 405", resp.StatusCode)
	}

	// Mirror /metrics should expose the Phase-9 instruments.
	mMetricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", mMetricsPort)
	mResp, err := http.Get(mMetricsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer mResp.Body.Close()
	mBody, _ := io.ReadAll(mResp.Body)
	for _, want := range []string{
		"cactus_mirror_upstream_checkpoint_size",
		"cactus_mirror_signsubtree_requests_total",
		"cactus_mirror_signsubtree_duration_seconds",
		"cactus_mirror_consistency_failures_total",
	} {
		if !strings.Contains(string(mBody), want) {
			t.Errorf("mirror metrics missing %s", want)
		}
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "method not allowed") {
		t.Errorf("unexpected body: %q", body)
	}
}

// standardConfig builds a vanilla CA-mode config for tests.
func standardConfig(dataDir string, acmePort, monPort, metricsPort int) map[string]any {
	return map[string]any{
		"data_dir": dataDir,
		"log": map[string]any{
			"number":               1,
			"shortname":            "smoke",
			"hash":                 "sha256",
			"checkpoint_period_ms": 50,
			"pool_size":            16,
		},
		"ca_cosigner": map[string]any{
			"id":        "44363.47.1.99",
			"algorithm": "mldsa-44",
			"seed_path": "keys/ca-cosigner.seed",
		},
		"acme": map[string]any{
			"listen":         fmt.Sprintf("127.0.0.1:%d", acmePort),
			"external_url":   fmt.Sprintf("http://127.0.0.1:%d", acmePort),
			"challenge_mode": "auto-pass",
		},
		"monitoring": map[string]any{
			"listen":       fmt.Sprintf("127.0.0.1:%d", monPort),
			"external_url": fmt.Sprintf("http://127.0.0.1:%d", monPort),
		},
		"metrics": map[string]any{
			"listen": fmt.Sprintf("127.0.0.1:%d", metricsPort),
		},
		"log_level": "info",
	}
}

// waitForListening polls url until any HTTP response (even an error
// code) — confirms the listener is up.
func waitForListening(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", url)
}
