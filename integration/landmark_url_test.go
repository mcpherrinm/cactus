package integration

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
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
)

// TestLandmarkURLFormat brings up a tile server with landmark mode
// enabled, allocates several landmarks, hits /landmarks over HTTP,
// parses the §6.4.3 body, and asserts the invariants.
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
	sgn, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1")
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: cosigID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	// The handler lists landmarks as of the real clock, so allocate
	// them in the recent past: landmark i at now - (7-i)*50m, each
	// expiring 2h later. At "now", landmarks 5 and 6 are active and
	// landmark 4 (expired 30m ago) ends the list.
	now := time.Now()
	allocAt := func(i int) time.Time { return now.Add(-time.Duration(7-i) * 50 * time.Minute) }
	seq, err := landmark.New(landmark.Config{
		CAID:                 cert.TrustAnchorID("32473.1"),
		LogNumber:            1,
		TimeBetweenLandmarks: time.Millisecond,
		MaxCertLifetime:      2 * time.Hour,
	}, fs, allocAt(0))
	if err != nil {
		t.Fatal(err)
	}

	hsrv := httptest.NewServer(tile.New(l, fs).WithLandmarks(seq).Handler())
	defer hsrv.Close()

	for i := 1; i <= 6; i++ {
		_, ok, err := seq.Append(context.Background(), uint64(i*100), allocAt(i))
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

	// §6.4.3: "<latest_landmark>", then "<tree_size> <expiry>" for each
	// active landmark, newest first, and the newest expired one.
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if lines[0] != "6" {
		t.Errorf("latest_landmark line = %q, want 6", lines[0])
	}
	var want []string
	for _, i := range []int{6, 5, 4} {
		want = append(want, fmt.Sprintf("%d %d", i*100, seq.All()[i].Expiry.Unix()))
	}
	if got := lines[1:]; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("landmark lines = %q, want %q", got, want)
	}
	lms, err := landmark.ParseList(body, now)
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	if len(lms) != 3 || !lms[1].Active(now) || lms[2].Active(now) {
		t.Errorf("ParseList = %+v, want landmarks 6 and 5 active, 4 expired", lms)
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
