package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/landmark"
)

// startLandmarkBinary builds and starts the cactus binary with the given
// landmark cadence and max cert lifetime, waits for /landmarks to
// answer, and returns the ACME and monitoring base URLs. The process is
// stopped at test cleanup.
func startLandmarkBinary(t *testing.T, interval, lifetime time.Duration) (acmeBase, monBase string) {
	t.Helper()
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.json")

	acmePort := freePort(t)
	monPort := freePort(t)
	metricsPort := freePort(t)

	cfg := map[string]any{
		"data_dir": dataDir,
		"log": map[string]any{
			"number":               1,
			"shortname":            "lm-smoke",
			"hash":                 "sha256",
			"checkpoint_period_ms": 25,
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
		"landmarks": map[string]any{
			"time_between_landmarks_ms": interval.Milliseconds(),
			"max_cert_lifetime_ms":      lifetime.Milliseconds(),
		},
		"log_level": "info",
	}
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, cfgBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	bin := buildBinary(t, "cmd/cactus")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, bin, "-config", configPath)
	cmd.Stderr = &capWriter{prefix: "cactus.stderr"}
	cmd.Stdout = &capWriter{prefix: "cactus.stdout"}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cactus: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	acmeBase = fmt.Sprintf("http://127.0.0.1:%d", acmePort)
	monBase = fmt.Sprintf("http://127.0.0.1:%d", monPort)
	if err := waitForHTTP(monBase+"/1/landmarks", 5*time.Second); err != nil {
		t.Fatalf("/landmarks never answered: %v", err)
	}
	return acmeBase, monBase
}

// waitForLandmark polls /landmarks until the latest landmark's tree size
// is at least minTreeSize, and fails the test if that doesn't happen
// within timeout.
func waitForLandmark(t *testing.T, monBase string, minTreeSize uint64, timeout time.Duration) landmark.Landmark {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastBody string
	for time.Now().Before(deadline) {
		resp, err := http.Get(monBase + "/1/landmarks")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastBody = string(b)
			lms, err := landmark.ParseList(b, time.Now())
			if err != nil {
				t.Fatalf("/landmarks: %v\n%s", err, b)
			}
			if lms[0].TreeSize >= minTreeSize {
				return lms[0]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no landmark reached tree size %d within %v; last /landmarks body:\n%s", minTreeSize, timeout, lastBody)
	return landmark.Landmark{}
}

// TestCactusBinaryWithLandmarks builds the cactus binary, lets it
// allocate landmarks (using a 50ms interval) while issuing, then hits
// /landmarks and confirms the body parses in the §6.4.3 format with at
// least one allocated landmark.
func TestCactusBinaryWithLandmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	acmeBase, monBase := startLandmarkBinary(t, 50*time.Millisecond, 300*time.Millisecond)

	// Issue a few certs through the live ACME endpoint so the log
	// grows and a non-zero landmark gets allocated.
	for i := 0; i < 3; i++ {
		_, err := acmeIssueOne(acmeBase, fmt.Sprintf("bin-lm%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		// Sleep so the 50ms landmark interval rolls between issuances.
		time.Sleep(80 * time.Millisecond)
	}
	if lm := waitForLandmark(t, monBase, 1, 3*time.Second); lm.Number == 0 {
		t.Errorf("latest landmark is landmark 0")
	}
}

// TestCactusBinaryLandmarkWithoutFurtherIssuance covers a quiet log: a
// cert issued early in the landmark interval, with no issuance after
// it, must still be covered by a landmark once the interval elapses. A
// landmark used to be allocated only on a log flush, i.e. only on the
// next issuance, which left the entry without a landmark-relative
// certificate indefinitely.
func TestCactusBinaryLandmarkWithoutFurtherIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	acmeBase, monBase := startLandmarkBinary(t, 500*time.Millisecond, time.Hour)
	if _, err := acmeIssueOne(acmeBase, "quiet.test"); err != nil {
		t.Fatal(err)
	}
	lm := waitForLandmark(t, monBase, 1, 5*time.Second)
	if lm.Number != 1 || lm.TreeSize != 1 {
		t.Errorf("latest landmark = %+v, want landmark 1 at tree size 1", lm)
	}
}
