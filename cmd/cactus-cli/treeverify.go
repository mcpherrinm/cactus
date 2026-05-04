package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// treeVerify fetches the signed checkpoint, walks every data tile,
// replays records through tlog.StoredHashes, and confirms the
// recomputed root matches the signed one. Output is `OK` on match,
// otherwise an error.
func treeVerify(logURL string) {
	// 1) checkpoint.
	body, err := httpGet(logURL + "/checkpoint")
	if err != nil {
		die("fetch checkpoint: %v", err)
	}
	signedSize, signedRoot, _, err := parseSignedNoteFlat(body)
	if err != nil {
		die("parse checkpoint: %v", err)
	}
	if signedSize == 0 {
		fmt.Println("size: 0; nothing to verify")
		return
	}

	// 2) walk data tiles.
	entries := make([][]byte, 0, signedSize)
	for tileN := uint64(0); tileN*tilewriter.EntriesPerDataTile < signedSize; tileN++ {
		recordsInThisTile := tilewriter.EntriesPerDataTile
		if (tileN+1)*tilewriter.EntriesPerDataTile > signedSize {
			recordsInThisTile = int(signedSize - tileN*tilewriter.EntriesPerDataTile)
		}
		tilePath := dataTilePath(int64(tileN), recordsInThisTile)
		raw, err := httpGet(logURL + "/" + tilePath)
		if err != nil {
			die("fetch %s: %v", tilePath, err)
		}
		es, err := tilewriter.SplitDataTile(raw)
		if err != nil {
			die("parse %s: %v", tilePath, err)
		}
		entries = append(entries, es...)
	}
	if uint64(len(entries)) != signedSize {
		die("got %d entries from tiles, signed size %d", len(entries), signedSize)
	}

	// 3) replay → root.
	var hashes []tlog.Hash
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hr(hashes))
		if err != nil {
			die("replay %d: %v", i, err)
		}
		hashes = append(hashes, hs...)
	}
	root, err := tlog.TreeHash(int64(signedSize), hr(hashes))
	if err != nil {
		die("TreeHash: %v", err)
	}
	got := tlogx.Hash(root)
	if got != signedRoot {
		die("recomputed root %x != signed root %x", got[:8], signedRoot[:8])
	}

	fmt.Printf("size:        %d\n", signedSize)
	fmt.Printf("signed root: %x\n", signedRoot[:])
	fmt.Println("OK — tile bytes recompute to signed root")
}

// prove emits a JSON object with an inclusion proof for index against
// the current checkpoint. Suitable for piping to jq for scripting.
func prove(logURL string, idx uint64) {
	body, err := httpGet(logURL + "/checkpoint")
	if err != nil {
		die("fetch checkpoint: %v", err)
	}
	size, root, _, err := parseSignedNoteFlat(body)
	if err != nil {
		die("parse checkpoint: %v", err)
	}
	if idx >= size {
		die("index %d >= tree size %d", idx, size)
	}

	// Walk all data tiles to rebuild stored hashes (simplest correct
	// implementation; the cost is one full read per `prove` call).
	hashes, entries, err := loadAllHashes(logURL, size)
	if err != nil {
		die("load tree state: %v", err)
	}
	proof, err := tlog.ProveRecord(int64(size), int64(idx), hr(hashes))
	if err != nil {
		die("ProveRecord: %v", err)
	}
	leafHash := tlog.RecordHash(entries[idx])

	out := proveJSON{
		Index:          idx,
		TreeSize:       size,
		Root:           hexs(root[:]),
		LeafHash:       hexs(leafHash[:]),
		InclusionProof: make([]string, 0, len(proof)),
	}
	for _, h := range proof {
		out.InclusionProof = append(out.InclusionProof, hexs(h[:]))
	}
	enc := json.NewEncoder(stdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		die("encode: %v", err)
	}
}

type proveJSON struct {
	Index          uint64   `json:"index"`
	TreeSize       uint64   `json:"tree_size"`
	Root           string   `json:"root_hex"`
	LeafHash       string   `json:"leaf_hash_hex"`
	InclusionProof []string `json:"inclusion_proof_hex"`
}

// loadAllHashes pulls every entry from the data tiles, replays them
// through tlog.StoredHashes, and returns the (hashes, entries) pair.
func loadAllHashes(logURL string, size uint64) ([]tlog.Hash, [][]byte, error) {
	entries := make([][]byte, 0, size)
	for tileN := uint64(0); tileN*tilewriter.EntriesPerDataTile < size; tileN++ {
		recordsInThisTile := tilewriter.EntriesPerDataTile
		if (tileN+1)*tilewriter.EntriesPerDataTile > size {
			recordsInThisTile = int(size - tileN*tilewriter.EntriesPerDataTile)
		}
		raw, err := httpGet(logURL + "/" + dataTilePath(int64(tileN), recordsInThisTile))
		if err != nil {
			return nil, nil, err
		}
		es, err := tilewriter.SplitDataTile(raw)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, es...)
	}
	var hashes []tlog.Hash
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hr(hashes))
		if err != nil {
			return nil, nil, fmt.Errorf("StoredHashes(%d): %w", i, err)
		}
		hashes = append(hashes, hs...)
	}
	return hashes, entries, nil
}

// dataTilePath mirrors tile/server's dataTilePath but uses TileHeight from tilewriter.
func dataTilePath(tileN int64, recordsInTile int) string {
	prefix := "tile/" + strconv.Itoa(tilewriter.TileHeight) + "/data/"
	if recordsInTile == tilewriter.EntriesPerDataTile {
		return prefix + nnnPath(tileN)
	}
	return prefix + nnnPath(tileN) + ".p/" + strconv.Itoa(recordsInTile)
}

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

// hr wraps a slice as tlog.HashReader.
type hr []tlog.Hash

func (h hr) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(h)) {
			return nil, fmt.Errorf("hash index %d out of range [0,%d)", idx, len(h))
		}
		out[i] = h[idx]
	}
	return out, nil
}

func hexs(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexd[x>>4]
		out[i*2+1] = hexd[x&0x0f]
	}
	return string(out)
}
