package integration

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/log/tilewriter"
)

// TestHashTileReadPath confirms /tile/<H>/<L>/... serves bytes
// compatible with golang.org/x/mod/sumdb/tlog: a level-0 tile of width
// W has W concatenated 32-byte hashes, each equal to
// tlog.RecordHash(entry_i) for i in [tileN*2^H, tileN*2^H + W).
func TestHashTileReadPath(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()

	// Issue a few entries; we want the first level-0 tile to be
	// partial (W < 256) so we hit the .p/<W> path, which is the more
	// interesting case.
	const n = 5
	entries := make([][]byte, n)
	for i := 0; i < n; i++ {
		der, err := acmeIssueOne(s.acmeBase, fmt.Sprintf("ht%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		// Reconstruct the log entry from the cert (same path the
		// verifier uses) so we know what hash to expect at the
		// corresponding stored index.
		tbs, _, _, err := cert.SplitCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		tbsContents, _, err := cert.RebuildLogEntryFromTBS(tbs, s.logIDDN)
		if err != nil {
			t.Fatal(err)
		}
		// The log stores MerkleTreeCertEntry{type=tbs_cert_entry,data=tbsContents}.
		entries[i] = cert.EncodeTBSCertEntry(tbsContents)
	}

	// Wait for one more flush so all entries are committed.
	time.Sleep(100 * time.Millisecond)

	// The full set is: index 0 (null entry) + n issued entries.
	// Tree size therefore = n+1.
	want := uint64(n + 1)

	// Fetch the level-0 tile width=want.
	url := fmt.Sprintf("%s/tile/%d/0/000.p/%d", s.tileBase, tilewriter.TileHeight, want)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("level-0 tile fetch %s: status=%d", url, resp.StatusCode)
	}
	tileBytes, _ := io.ReadAll(resp.Body)
	if len(tileBytes) != int(want)*tlog.HashSize {
		t.Fatalf("tile size %d, want %d * %d = %d",
			len(tileBytes), want, tlog.HashSize, int(want)*tlog.HashSize)
	}

	// The first hash should equal tlog.RecordHash(null_entry).
	wantNull := tlog.RecordHash(cert.EncodeNullEntry())
	var got tlog.Hash
	copy(got[:], tileBytes[:tlog.HashSize])
	if got != wantNull {
		t.Errorf("hash[0] = %x, want %x (RecordHash of null_entry)", got[:], wantNull[:])
	}

	// Each subsequent hash should be tlog.RecordHash of the
	// corresponding issued entry. Note: certs may be issued in any
	// order under parallelism; here issuance is serial, so index i+1
	// corresponds to entries[i].
	for i, e := range entries {
		var h tlog.Hash
		copy(h[:], tileBytes[(i+1)*tlog.HashSize:(i+2)*tlog.HashSize])
		want := tlog.RecordHash(e)
		if h != want {
			t.Errorf("hash[%d] = %x, want %x", i+1, h[:], want[:])
		}
	}

	// Now also fetch the same tile via tlog.HashFromTile semantics.
	tile := tlog.Tile{H: tilewriter.TileHeight, L: 0, N: 0, W: int(want)}
	for idx := int64(0); idx < int64(want); idx++ {
		stored := tlog.StoredHashIndex(0, idx)
		got, err := tlog.HashFromTile(tile, tileBytes, stored)
		if err != nil {
			t.Errorf("HashFromTile idx=%d: %v", idx, err)
			continue
		}
		var raw tlog.Hash
		copy(raw[:], tileBytes[idx*int64(tlog.HashSize):(idx+1)*int64(tlog.HashSize)])
		if got != raw {
			t.Errorf("HashFromTile(%d) = %x, want %x", idx, got[:], raw[:])
		}
	}

	// Cache-Control on partial tiles must NOT be immutable.
	if cc := resp.Header.Get("Cache-Control"); cc == "" {
		t.Errorf("missing Cache-Control header")
	} else if want := "no-cache"; !contains(cc, want) {
		t.Errorf("partial tile Cache-Control = %q, want to contain %q", cc, want)
	}
}

// contains is a tiny helper to avoid importing strings just for this.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
