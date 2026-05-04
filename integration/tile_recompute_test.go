package integration

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// TestTileBytesRecomputeToSignedRoot is the §9-Definition-of-Done
// "tile bytes recompute to the signed root" check. We:
//
//  1. Issue a handful of certs (so the log grows past trivial sizes).
//  2. Read every persisted data tile from disk via the tile-server HTTP API.
//  3. Replay each entry through tlog.StoredHashes to reconstruct the
//     full Merkle structure independently.
//  4. Compute TreeHash and compare against the size+root from the
//     server's signed checkpoint.
//
// This exercises the tile read path end-to-end and confirms what's on
// disk hashes to what's signed.
func TestTileBytesRecomputeToSignedRoot(t *testing.T) {
	dir := t.TempDir()
	s := bringUp(t, dir)
	defer s.close()

	// Issue several certs.
	const n = 8
	for i := 0; i < n; i++ {
		if _, err := acmeIssueOne(s.acmeBase, fmt.Sprintf("h%d.test", i)); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}

	// Wait for one more flush window so all entries are committed.
	time.Sleep(100 * time.Millisecond)

	// 1) Read the signed checkpoint.
	resp, err := http.Get(s.tileBase + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	signedSize, signedRoot, err := parseCheckpointBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if signedSize == 0 {
		t.Fatal("signed size is 0")
	}

	// 2) Read every data tile.
	entries, err := loadAllEntries(s.tileBase, signedSize)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(entries)) != signedSize {
		t.Fatalf("got %d entries from tiles, signed size is %d", len(entries), signedSize)
	}

	// 3) Replay through tlog.StoredHashes to reconstruct the tree.
	var hashes []tlog.Hash
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hashReader(hashes))
		if err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		hashes = append(hashes, hs...)
	}

	// 4) Compute TreeHash and compare.
	root, err := tlog.TreeHash(int64(signedSize), hashReader(hashes))
	if err != nil {
		t.Fatal(err)
	}
	if tlogx.Hash(root) != signedRoot {
		t.Errorf("recomputed root %x != signed root %x", root[:8], signedRoot[:8])
	}
}

// parseCheckpointBody pulls (size, root) out of the c2sp signed-note
// checkpoint body — same format as log/note.go produces.
func parseCheckpointBody(body []byte) (uint64, tlogx.Hash, error) {
	parts := strings.SplitN(string(body), "\n\n", 2)
	if len(parts) < 1 {
		return 0, tlogx.Hash{}, fmt.Errorf("no body")
	}
	lines := strings.Split(parts[0], "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 3 {
		return 0, tlogx.Hash{}, fmt.Errorf("expected 3 lines, got %d", len(lines))
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, tlogx.Hash{}, err
	}
	rootBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return 0, tlogx.Hash{}, err
	}
	if len(rootBytes) != tlogx.HashSize {
		return 0, tlogx.Hash{}, fmt.Errorf("root size %d", len(rootBytes))
	}
	var root tlogx.Hash
	copy(root[:], rootBytes)
	return size, root, nil
}

// buildDataTilePath mirrors tile/server's dataTilePath. Lives here
// because the tile package's helper isn't exported.
func buildDataTilePath(tileN int64, recordsInTile int) string {
	prefix := "tile/" + strconv.Itoa(tilewriter.TileHeight) + "/data/"
	if recordsInTile == tilewriter.EntriesPerDataTile {
		return prefix + nnnPath(tileN)
	}
	return prefix + nnnPath(tileN) + ".p/" + strconv.Itoa(recordsInTile)
}

// nnnPath formats N in the standard 3-digit-segmented "NNN" tlog
// encoding, matching tlog.Tile.Path.
func nnnPath(n int64) string {
	if n == 0 {
		return "000"
	}
	var parts []string
	for n > 0 {
		parts = append([]string{padDigit(int(n % 1000))}, parts...)
		n /= 1000
	}
	for i := 0; i < len(parts)-1; i++ {
		parts[i] = "x" + parts[i]
	}
	return strings.Join(parts, "/")
}

func padDigit(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

// loadAllEntries fetches every data tile from `tileBase` up to a tree
// of `treeSize` entries and returns the concatenated entry blobs.
func loadAllEntries(tileBase string, treeSize uint64) ([][]byte, error) {
	entries := make([][]byte, 0, treeSize)
	for tileN := uint64(0); tileN*tilewriter.EntriesPerDataTile < treeSize; tileN++ {
		recordsInThisTile := tilewriter.EntriesPerDataTile
		if (tileN+1)*tilewriter.EntriesPerDataTile > treeSize {
			recordsInThisTile = int(treeSize - tileN*tilewriter.EntriesPerDataTile)
		}
		path := buildDataTilePath(int64(tileN), recordsInThisTile)
		resp, err := http.Get(tileBase + "/" + path)
		if err != nil {
			return nil, err
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("tile %s status=%d", path, resp.StatusCode)
		}
		es, err := tilewriter.SplitDataTile(raw)
		if err != nil {
			return nil, fmt.Errorf("split %s: %w", path, err)
		}
		entries = append(entries, es...)
	}
	return entries, nil
}

// hashReader wraps a slice as tlog.HashReader.
type hashReader []tlog.Hash

func (h hashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(h)) {
			return nil, fmt.Errorf("hash index %d out of range [0,%d)", idx, len(h))
		}
		out[i] = h[idx]
	}
	return out, nil
}

// Reference imports so this file is self-contained.
var (
	_ = context.Background
	_ = cactuslog.Issued{}
	_ = cert.MTCProof{}
	_ = signer.AlgECDSAP256SHA256
	_ = storage.New
	_ = binary.BigEndian
)
