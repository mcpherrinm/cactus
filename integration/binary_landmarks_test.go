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
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCactusBinaryWithLandmarks builds the cactus binary with
// landmarks enabled in config, lets it allocate at least one landmark
// (using a 50ms interval), then hits /landmarks and confirms the body
// matches the §6.3.1 format with at least one allocated landmark.
func TestCactusBinaryWithLandmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.json")

	acmePort := freePort(t)
	monPort := freePort(t)
	metricsPort := freePort(t)

	cfg := map[string]any{
		"data_dir": dataDir,
		"log": map[string]any{
			"id":                   "1.3.6.1.4.1.44363.47.1.99",
			"shortname":            "lm-smoke",
			"hash":                 "sha256",
			"checkpoint_period_ms": 25,
			"pool_size":            16,
		},
		"ca_cosigner": map[string]any{
			"id":        "1.3.6.1.4.1.44363.47.1.99.ca",
			"algorithm": "ecdsa-p256-sha256",
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
			"enabled":                   true,
			"base_id":                   "1.3.6.1.4.1.44363.47.1.99.lm",
			"time_between_landmarks_ms": 50, // 50ms so a landmark allocates fast
			"max_cert_lifetime_ms":      300,
			"landmark_url_path":         "/landmarks",
		},
		"log_level": "info",
	}
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, cfgBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	bin := buildBinary(t, "cmd/cactus")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-config", configPath)
	stderrCap := &capWriter{prefix: "cactus.stderr"}
	stdoutCap := &capWriter{prefix: "cactus.stdout"}
	cmd.Stderr = stderrCap
	cmd.Stdout = stdoutCap
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

	monBase := fmt.Sprintf("http://127.0.0.1:%d", monPort)

	// Wait for /landmarks to come up.
	if err := waitForHTTP(monBase+"/landmarks", 5*time.Second); err != nil {
		t.Fatalf("/landmarks never answered: %v", err)
	}

	// Issue a few certs through the live ACME endpoint so the log
	// grows and a non-zero landmark gets allocated.
	acmeBase := fmt.Sprintf("http://127.0.0.1:%d", acmePort)
	for i := 0; i < 3; i++ {
		_, err := acmeIssueOne(acmeBase, fmt.Sprintf("bin-lm%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		// Sleep so the 50ms landmark interval rolls between issuances.
		time.Sleep(80 * time.Millisecond)
	}

	// Poll /landmarks until the binary has allocated at least one
	// non-zero landmark.
	deadline := time.Now().Add(3 * time.Second)
	var lastBody string
	for time.Now().Before(deadline) {
		resp, err := http.Get(monBase + "/landmarks")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastBody = string(b)
			lines := strings.Split(strings.TrimRight(lastBody, "\n"), "\n")
			if len(lines) >= 2 {
				header := strings.Fields(lines[0])
				if header[0] != "0" {
					// Got at least one non-zero landmark.
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no non-zero landmark allocated within deadline; last /landmarks body:\n%s", lastBody)
}
