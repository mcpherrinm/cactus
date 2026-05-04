package landmark

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/storage"
)

// TestHandlerEmptySequence confirms the just-landmark-0 case: the body
// is "0 0\n0\n" — `<last> <num_active>` followed by 1 tree-size line.
func TestHandlerEmptySequence(t *testing.T) {
	s, _, _ := newTestSeq(t)
	body := requestBody(t, s, "GET")
	if body != "0 0\n0\n" {
		t.Errorf("body = %q, want %q", body, "0 0\n0\n")
	}
}

// TestHandlerHappyPath drives the §6.3.1 example: with N landmarks and
// MaxActive larger than N, num_active = N, and we emit N+1 tree sizes,
// strictly decreasing.
func TestHandlerHappyPath(t *testing.T) {
	s, _, t0 := newTestSeq(t)
	for i := 1; i <= 5; i++ {
		_, ok, err := s.Append(context.Background(), uint64(i*100),
			t0.Add(time.Duration(i)*time.Hour))
		if !ok || err != nil {
			t.Fatal(err)
		}
	}
	body := requestBody(t, s, "GET")
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("not enough lines: %q", body)
	}
	first := strings.SplitN(lines[0], " ", 2)
	if len(first) != 2 {
		t.Fatalf("first line missing space: %q", lines[0])
	}
	last, err := strconv.ParseUint(first[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	numActive, err := strconv.ParseUint(first[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if last != 5 {
		t.Errorf("last = %d, want 5", last)
	}
	if numActive != 5 {
		// MaxActive in this fixture is 169 (7d/1h), so num_active is
		// capped by `last_landmark = 5`.
		t.Errorf("num_active = %d, want 5", numActive)
	}
	if uint64(len(lines)-1) != numActive+1 {
		t.Errorf("got %d tree-size lines, want %d", len(lines)-1, numActive+1)
	}
	// Tree sizes are strictly decreasing.
	prev := uint64(0)
	for i, line := range lines[1:] {
		n, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if i > 0 && n >= prev {
			t.Errorf("not strictly decreasing at line %d: %d >= %d", i, n, prev)
		}
		prev = n
	}
}

// TestHandlerCapsAtMaxActive: when the sequence has more landmarks
// than MaxActive(), the response includes only the most recent
// MaxActive landmarks plus the one prior tree size for the floor.
func TestHandlerCapsAtMaxActive(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		BaseID:               cert.TrustAnchorID("32473.1.lm"),
		TimeBetweenLandmarks: time.Hour,
		MaxCertLifetime:      3 * time.Hour, // MaxActive = 4
	}
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s, err2 := New(cfg, fs, t0)
	if err2 != nil {
		t.Fatal(err2)
	}
	for i := 1; i <= 10; i++ {
		_, ok, err := s.Append(context.Background(), uint64(i*10),
			t0.Add(time.Duration(i)*time.Hour))
		if !ok || err != nil {
			t.Fatal(err)
		}
	}
	body := requestBody(t, s, "GET")
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	first := strings.Fields(lines[0])
	last, _ := strconv.ParseUint(first[0], 10, 64)
	numActive, _ := strconv.ParseUint(first[1], 10, 64)
	if last != 10 {
		t.Errorf("last = %d, want 10", last)
	}
	if numActive != 4 {
		t.Errorf("num_active = %d, want 4 (MaxActive)", numActive)
	}
	if len(lines)-1 != int(numActive)+1 {
		t.Errorf("got %d tree-size lines, want %d", len(lines)-1, numActive+1)
	}
	// Highest reported tree size is the latest landmark's (= 100).
	if got, _ := strconv.ParseUint(lines[1], 10, 64); got != 100 {
		t.Errorf("first tree size = %d, want 100", got)
	}
}

// TestHandlerHeaders confirms the §6.3.1 Content-Type and the
// no-cache directive.
func TestHandlerHeaders(t *testing.T) {
	s, _, _ := newTestSeq(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got, want := resp.Header.Get("Content-Type"), "text/plain; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q, want to contain no-cache", cc)
	}
}

// TestHandlerHEAD confirms HEAD returns headers but no body.
func TestHandlerHEAD(t *testing.T) {
	s, _, _ := newTestSeq(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodHead, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("HEAD status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD body should be empty, got %q", body)
	}
}

// TestHandlerRejectsNonGet confirms 405 for POST/PUT/etc.
func TestHandlerRejectsNonGet(t *testing.T) {
	s, _, _ := newTestSeq(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(""))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", resp.StatusCode)
	}
}

// requestBody builds a test server, hits it, returns the body string.
func requestBody(t *testing.T, s *Sequence, method string) string {
	t.Helper()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest(method, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
