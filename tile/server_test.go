package tile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"golang.org/x/mod/sumdb/tlog"
)

func newTestServer(t *testing.T) (*httptest.Server, *log.Log) {
	t.Helper()
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x33}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	l, err := log.New(context.Background(), log.Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)

	srv := httptest.NewServer(New(l, fs).Handler())
	t.Cleanup(srv.Close)
	return srv, l
}

func TestCheckpointEndpoint(t *testing.T) {
	srv, l := newTestServer(t)
	resp, err := http.Get(srv.URL + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, l.CurrentCheckpoint().SignedNote) {
		t.Errorf("body != current SignedNote")
	}
}

func TestAppJSEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q, want text/javascript", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, appJS) {
		t.Errorf("body != embedded app.js")
	}
	// index.html must load the embedded script, or the page is dead.
	if !bytes.Contains(indexHTML, []byte(`src="app.js"`)) {
		t.Errorf("index.html does not reference app.js")
	}
}

func TestSubtreeEndpoint(t *testing.T) {
	srv, l := newTestServer(t)
	// Append one entry so a covering subtree gets signed.
	entry := cert.EncodeTBSCertEntry([]byte("x"))
	idem := sha256.Sum256(entry)
	idx, _ := l.Append(context.Background(), entry, idem)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	iss, err := l.Wait(ctx, idx)
	if err != nil {
		t.Fatal(err)
	}
	name := uint64s(iss.Subtree.Start) + "-" + uint64s(iss.Subtree.End)
	resp, err := http.Get(srv.URL + "/subtree/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// TestTilePath checks the c2sp tlog-tiles path layout: hash tiles at
// tile/<L>/<N>, entry (data) tiles at tile/entries/<N>, with the
// x-prefixed 3-digit index encoding and a .p/<W> partial suffix.
func TestTilePath(t *testing.T) {
	full := tilewriter.EntriesPerDataTile
	cases := []struct {
		got, want string
	}{
		{tilewriter.DataTilePath(0, full), "tile/entries/000"},
		{tilewriter.DataTilePath(42, full), "tile/entries/042"},
		{tilewriter.DataTilePath(1000, full), "tile/entries/x001/000"},
		{tilewriter.DataTilePath(1234067, full), "tile/entries/x001/x234/067"},
		{tilewriter.DataTilePath(0, 5), "tile/entries/000.p/5"},
		{tilewriter.TilePath(tlog.Tile{H: tilewriter.TileHeight, L: 0, N: 0, W: full}), "tile/0/000"},
		{tilewriter.TilePath(tlog.Tile{H: tilewriter.TileHeight, L: 1, N: 7, W: full}), "tile/1/007"},
		{tilewriter.TilePath(tlog.Tile{H: tilewriter.TileHeight, L: 0, N: 0, W: 5}), "tile/0/000.p/5"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("tile path = %q, want %q", tc.got, tc.want)
		}
	}
}

func uint64s(n uint64) string {
	if n == 0 {
		return "0"
	}
	var s string
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
