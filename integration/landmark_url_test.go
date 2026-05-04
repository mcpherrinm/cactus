package integration

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
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
)

// TestLandmarkURLFormat brings up a tile server with landmark mode
// enabled, allocates several landmarks, hits /landmarks over HTTP,
// parses the §6.3.1 body, and asserts the invariants.
func TestLandmarkURLFormat(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0x77
	}
	sgn, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1.ca")
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: cosigID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seq, err := landmark.New(landmark.Config{
		BaseID:               cert.TrustAnchorID("32473.1.lm"),
		TimeBetweenLandmarks: time.Millisecond,
		MaxCertLifetime:      3 * time.Millisecond, // MaxActive = 4
	}, fs, t0)
	if err != nil {
		t.Fatal(err)
	}

	hsrv := httptest.NewServer(tile.New(l, fs).WithLandmarks(seq).Handler())
	defer hsrv.Close()

	// Allocate 6 landmarks.  MaxActive=4 means only the most recent 4
	// will be served, plus the previous tree size as the floor (5
	// tree-size lines total).
	for i := 1; i <= 6; i++ {
		_, ok, err := seq.Append(context.Background(), uint64(i*100), t0.Add(time.Duration(i)*time.Millisecond))
		if err != nil || !ok {
			t.Fatalf("Append %d: ok=%v err=%v", i, ok, err)
		}
	}

	// Hit /landmarks.
	resp, err := http.Get(hsrv.URL + "/landmarks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.StatusCode; got != 200 {
		t.Fatalf("status = %d", got)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q", cc)
	}
	body, _ := io.ReadAll(resp.Body)

	// Parse: first line is "<last> <num_active>", then num_active+1 tree sizes.
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("body too short: %q", body)
	}
	header := strings.Fields(lines[0])
	if len(header) != 2 {
		t.Fatalf("first line malformed: %q", lines[0])
	}
	last, err := strconv.ParseUint(header[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	numActive, err := strconv.ParseUint(header[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if last != 6 {
		t.Errorf("last_landmark = %d, want 6", last)
	}
	if numActive != 4 {
		t.Errorf("num_active_landmarks = %d, want 4 (capped at MaxActive)", numActive)
	}
	if uint64(len(lines)-1) != numActive+1 {
		t.Errorf("got %d tree-size lines, want %d", len(lines)-1, numActive+1)
	}

	// Tree sizes strictly decreasing.
	prev := uint64(0)
	for i, line := range lines[1:] {
		n, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if i > 0 && n >= prev {
			t.Errorf("not strictly decreasing at line %d: %d -> %d", i, prev, n)
		}
		prev = n
	}
	// First (most recent) tree size = landmark 6 = 600.
	first, _ := strconv.ParseUint(lines[1], 10, 64)
	if first != 600 {
		t.Errorf("most recent tree size = %d, want 600", first)
	}

	// HEAD also works — same headers, no body.
	hreq, _ := http.NewRequest("HEAD", hsrv.URL+"/landmarks", nil)
	hresp, err := http.DefaultClient.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != 200 {
		t.Errorf("HEAD status = %d", hresp.StatusCode)
	}
}

// TestLandmarkURLDisabledWhenSequenceUnset confirms /landmarks 404s
// when WithLandmarks isn't called (i.e. landmark mode is off).
func TestLandmarkURLDisabledWhenSequenceUnset(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()
	resp, err := http.Get(s.tileBase + "/landmarks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when landmarks disabled", resp.StatusCode)
	}
}
