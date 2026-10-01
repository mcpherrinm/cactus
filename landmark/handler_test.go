package landmark

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/storage"
)

// TestEncodeOnlyLandmarkZero confirms the just-landmark-0 case: the
// latest landmark is 0 and the only line is landmark 0 itself (tree size
// 0, expiry 0), which is expired and ends the (empty) active list.
func TestEncodeOnlyLandmarkZero(t *testing.T) {
	s, _, t0 := newTestSeq(t)
	if got, want := string(s.Encode(t0)), "0\n0 0\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if body := requestBody(t, s, "GET"); body != "0\n0 0\n" {
		t.Errorf("served body = %q, want %q", body, "0\n0 0\n")
	}
}

// TestEncodeActiveLandmarks drives the §6.4.3 format: every active
// landmark, newest first, then the newest expired one.
func TestEncodeActiveLandmarks(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		CAID:                 cert.TrustAnchorID("32473.1"),
		LogNumber:            1,
		TimeBetweenLandmarks: time.Hour,
		MaxCertLifetime:      3 * time.Hour,
	}
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	s, err := New(cfg, fs, t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 10; i++ {
		_, ok, err := s.Append(context.Background(), uint64(i*10),
			t0.Add(time.Duration(i)*time.Hour))
		if !ok || err != nil {
			t.Fatal(err)
		}
	}
	// Landmark i expires at t0 + (i+3)h. At t0+10h30m landmarks 8..10 are
	// active and landmark 7 (expired at t0+10h) ends the list.
	now := t0.Add(10*time.Hour + 30*time.Minute)
	exp := func(i int) int64 { return t0.Add(time.Duration(i+3) * time.Hour).Unix() }
	want := "10\n" +
		lineFor(100, exp(10)) + lineFor(90, exp(9)) + lineFor(80, exp(8)) + lineFor(70, exp(7))
	if got := string(s.Encode(now)); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}

	// The body round-trips through ParseList.
	lms, err := ParseList(s.Encode(now), now)
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	if len(lms) != 4 || lms[0].Number != 10 || lms[3].Number != 7 || lms[3].Active(now) || !lms[2].Active(now) {
		t.Errorf("ParseList = %+v", lms)
	}

	// Long after everything expired, only the latest landmark is listed.
	if got, want := string(s.Encode(t0.Add(100*time.Hour))), "10\n"+lineFor(100, exp(10)); got != want {
		t.Errorf("all-expired body = %q, want %q", got, want)
	}
}

func lineFor(size uint64, expiry int64) string {
	return fmt.Sprintf("%d %d\n", size, expiry)
}

// TestParseListRejects exercises §6.4.3's strict-decoding requirement.
func TestParseListRejects(t *testing.T) {
	now := time.Unix(2000, 0)
	cases := map[string]string{
		"no trailing newline":     "1\n10 3000\n0 0",
		"no landmarks":            "1\n",
		"too many lines":          "0\n10 3000\n0 0\n",
		"leading zero":            "01\n10 3000\n0 0\n",
		"extra whitespace":        "1\n10  3000\n0 0\n",
		"trailing space":          "1\n10 3000 \n0 0\n",
		"sign":                    "1\n+10 3000\n0 0\n",
		"sizes not decreasing":    "2\n10 3000\n10 2500\n0 0\n",
		"expiries increasing":     "2\n20 3000\n10 3500\n0 0\n",
		"no expired landmark":     "2\n20 3000\n10 2500\n",
		"bad landmark zero":       "1\n10 3000\n5 0\n",
		"blank line":              "1\n10 3000\n\n",
		"latest beyond 2^48-1":    "281474976710656\n10 3000\n5 0\n",
		"tree size beyond 2^48-1": "1\n281474976710656 3000\n0 0\n",
	}
	for name, body := range cases {
		if _, err := ParseList([]byte(body), now); err == nil {
			t.Errorf("%s: ParseList(%q) succeeded", name, body)
		}
	}
	// A list need not reach landmark 0 when an expired landmark ends it.
	lms, err := ParseList([]byte("7\n30 3000\n20 1000\n"), now)
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	if len(lms) != 2 || lms[0].Number != 7 || lms[1].Number != 6 || lms[1].TreeSize != 20 || !lms[0].Active(now) || lms[1].Active(now) {
		t.Errorf("ParseList = %+v", lms)
	}
}

// TestHandlerHeaders confirms the c2sp.org/mtc-tlog Content-Type and the
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
