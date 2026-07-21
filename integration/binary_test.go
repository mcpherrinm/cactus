package integration

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
)

// freePort asks the kernel for an unused TCP port, returns it (closed),
// and leaves the caller to bind. There's a tiny TOCTOU race; we run a
// few tests so a collision would just make one flake.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func buildBinary(t *testing.T, pkg string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, filepath.Base(pkg))
	// Build with the same toolchain that's running the test, so a binary
	// exercising ML-DSA (the witness path) is compiled with Go 1.27+ when
	// the test itself runs under gotip.
	cmd := exec.Command(goToolPath(), "build", "-o", bin, "../"+pkg)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build %s: %v", pkg, err)
	}
	return bin
}

// goToolPath returns the `go` binary of the toolchain running the test
// (via GOROOT), falling back to whatever `go` is on PATH.
func goToolPath() string {
	if gr := runtime.GOROOT(); gr != "" {
		cand := filepath.Join(gr, "bin", "go")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "go"
}

// TestCactusBinaryStartsAndServes is an end-to-end smoke test of
// cmd/cactus: build the binary, write a config, run it, hit
// /directory and /metrics, then SIGTERM.
func TestCactusBinaryStartsAndServes(t *testing.T) {
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
			"number":               1,
			"shortname":            "smoke",
			"hash":                 "sha256",
			"checkpoint_period_ms": 100,
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
		// SIGTERM then wait; SIGKILL after timeout.
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

	// Poll /directory until it answers (binary takes a moment to start).
	directoryURL := fmt.Sprintf("http://127.0.0.1:%d/directory", acmePort)
	if err := waitForHTTP(directoryURL, 5*time.Second); err != nil {
		t.Fatalf("/directory never answered: %v", err)
	}

	// /directory contents.
	resp, err := http.Get(directoryURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/directory status = %d", resp.StatusCode)
	}
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode /directory: %v", err)
	}
	if d["newAccount"] == "" {
		t.Errorf("missing newAccount in directory: %v", d)
	}
	// CORS: the ACME endpoint is usable from any web origin.
	assertCORS(t, "acme /directory", resp.Header)

	// /metrics on the metrics listener.
	mURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)
	resp2, err := http.Get(mURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("/metrics status = %d", resp2.StatusCode)
	}
	body := readAll(resp2.Body)
	if !strings.Contains(body, "cactus_log_") {
		t.Errorf("metrics body missing cactus_log_ instruments: %.200s", body)
	}

	// /checkpoint on the monitoring listener — a fresh log publishes an
	// initial empty (size 0) checkpoint (draft-05 §5.2.1: no reserved
	// null entry).
	cpURL := fmt.Sprintf("http://127.0.0.1:%d/1/checkpoint", monPort)
	resp3, err := http.Get(cpURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("/checkpoint status = %d", resp3.StatusCode)
	}
	// CORS: the monitoring endpoint is usable from any web origin.
	assertCORS(t, "monitor /checkpoint", resp3.Header)

	// §5.5 / §7.1 / §7.2 end-to-end: fetch the CA certificate the server
	// serves, derive a relying-party config from it, issue a real cert,
	// and run full §7.2 verification (binary cosigner_id, re-derived
	// cosigner_name/log_origin, cosignature check). Regression for the
	// review findings.
	caCertURL := fmt.Sprintf("http://127.0.0.1:%d/ca-certificate", monPort)
	caResp, err := http.Get(caCertURL)
	if err != nil {
		t.Fatal(err)
	}
	caBody := readAll(caResp.Body)
	caResp.Body.Close()
	if caResp.StatusCode != 200 {
		t.Fatalf("/ca-certificate status = %d", caResp.StatusCode)
	}
	block, _ := pem.Decode([]byte(caBody))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("/ca-certificate not a PEM CERTIFICATE: %q", caBody)
	}
	rpCfg, err := cert.ConfigFromCACertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ConfigFromCACertificate: %v", err)
	}
	if string(rpCfg.CAID) != "44363.47.1.99" {
		t.Errorf("RP config CAID = %q, want 44363.47.1.99", rpCfg.CAID)
	}
	acmeBase := fmt.Sprintf("http://127.0.0.1:%d", acmePort)
	certDER, err := acmeIssueOne(acmeBase, "ca-cert-smoke.test")
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	if err := cert.VerifyCertificate(certDER, rpCfg); err != nil {
		t.Fatalf("VerifyCertificate against served CA cert: %v", err)
	}

	// Confirm the seed file got auto-created.
	seedPath := filepath.Join(dataDir, "keys", "ca-cosigner.seed")
	info, err := os.Stat(seedPath)
	if err != nil {
		t.Fatalf("seed not created: %v", err)
	}
	if info.Size() != 32 {
		t.Errorf("seed size = %d, want 32", info.Size())
	}

	// §9 Definition-of-Done literal: slog output parses as JSON.
	// main.go points slog at os.Stdout, so check the captured stdout.
	gotJSON := 0
	for _, line := range stdoutCap.snapshot() {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Errorf("stdout line is not JSON: %q (%v)", line, err)
			continue
		}
		// slog records have at minimum "time", "level", "msg".
		for _, k := range []string{"time", "level", "msg"} {
			if _, ok := v[k]; !ok {
				t.Errorf("stdout JSON missing %q: %q", k, line)
			}
		}
		gotJSON++
	}
	if gotJSON == 0 {
		t.Errorf("no JSON log lines observed on stdout")
	}
}

func waitForHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", url)
}

// readAll drains body to a string.
func readAll(r interface {
	Read(p []byte) (n int, err error)
}) string {
	var buf [16384]byte
	var sb strings.Builder
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// capWriter forwards subprocess output to the test log on a best-effort
// basis AND accumulates lines for later inspection. Reduces the chance
// of useful stderr being swallowed.
type capWriter struct {
	prefix string
	mu     sync.Mutex
	lines  []string
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		c.lines = append(c.lines, line)
		fmt.Fprintf(os.Stderr, "[%s] %s\n", c.prefix, line)
	}
	return len(p), nil
}

func (c *capWriter) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

// assertCORS checks that a response carries the permissive CORS headers
// (Access-Control-Allow-Origin: * and the Boulder-compatible
// Access-Control-Expose-Headers set) so the endpoint is usable from any
// webpage.
func assertCORS(t *testing.T, what string, h http.Header) {
	t.Helper()
	if got := h.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("%s: Access-Control-Allow-Origin = %q, want *", what, got)
	}
	if got := h.Get("Access-Control-Expose-Headers"); got != "Link, Replay-Nonce, Location, Retry-After" {
		t.Errorf("%s: Access-Control-Expose-Headers = %q, want Boulder's set", what, got)
	}
}
