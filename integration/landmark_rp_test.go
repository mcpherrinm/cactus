package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
	"github.com/letsencrypt/cactus/tlogx"
)

// TestRelyingPartyFastPath simulates the full relying-party verification
// of a landmark-relative cert per §7.4 + §6.3:
//
//  1. Fetch /landmarks to learn the active landmark sequence.
//  2. For each active landmark, compute its §4.5 covering subtrees and
//     fetch the per-subtree hashes from the live tile API. This is the
//     *trusted-subtrees* set the RP would normally have predistributed.
//  3. Fetch a landmark-relative cert.
//  4. Match the cert's MTCProof.subtree against a trusted-subtree
//     hash; if it matches, the cert verifies via the §7.2 fast path
//     with NO cosigner key consulted.
//
// This is the contract that landmark-relative certs are designed to
// support — and the v3 DoD bullet "verifier validates without
// consulting cosigner key".
func TestRelyingPartyFastPath(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0xAA
	}
	sgn, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1.ca")
	baseLM := cert.TrustAnchorID("32473.1.lm")

	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: cosigID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seq, err := landmark.New(landmark.Config{
		BaseID:               baseLM,
		TimeBetweenLandmarks: time.Millisecond,
		MaxCertLifetime:      4 * time.Millisecond, // MaxActive = 5
	}, fs, t0)
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := acme.New(acme.Config{
		Issuer: issuer, ChallengeMode: acme.ChallengeAutoPass,
		Landmarks: seq, SubtreeProof: l.SubtreeProof,
		LogID: logID, LandmarkBaseID: baseLM,
	})
	hAcme := httptest.NewServer(srv.Handler())
	defer hAcme.Close()
	srv.SetExternalURL(hAcme.URL)

	hTile := httptest.NewServer(tile.New(l, fs).WithLandmarks(seq).Handler())
	defer hTile.Close()

	// Issue a few certs.
	const n = 4
	type certCtx struct {
		url     string
		acctKey *ecdsa.PrivateKey
		kid     string
	}
	var certCtxs []certCtx
	var certURLs []string
	for i := 0; i < n; i++ {
		_, certURL, acctKey, kid, err := acmeIssueOneInner(hAcme.URL, fmt.Sprintf("rp%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		certURLs = append(certURLs, certURL)
		certCtxs = append(certCtxs, certCtx{url: certURL, acctKey: acctKey, kid: kid})
	}
	time.Sleep(100 * time.Millisecond)

	// Allocate landmarks covering the issued range.
	cp := l.CurrentCheckpoint()
	if _, ok, err := seq.Append(context.Background(), cp.Size, t0.Add(time.Second)); err != nil || !ok {
		t.Fatal(err)
	}

	// === Begin RP-side simulation: client only knows hTile.URL. ===

	// Step 1: fetch /landmarks.
	resp, err := http.Get(hTile.URL + "/landmarks")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Parse the §6.3.1 format.
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	header := strings.Fields(lines[0])
	last, _ := strconv.ParseUint(header[0], 10, 64)
	numActive, _ := strconv.ParseUint(header[1], 10, 64)
	type lmTuple struct{ number, treeSize uint64 }
	var lms []lmTuple
	for i := uint64(0); i <= numActive; i++ {
		ts, _ := strconv.ParseUint(lines[1+i], 10, 64)
		lms = append(lms, lmTuple{number: last - i, treeSize: ts})
	}
	if len(lms) < 2 {
		t.Fatalf("not enough landmarks: %+v", lms)
	}

	// Step 2: for each landmark (other than zero), compute its §4.5
	// covering subtrees and look up each subtree's hash. We use the
	// tile-served data tiles to recompute the hash — that's what an
	// RP would do (or it could trust pre-distributed hashes).
	hashes, _, err := loadAllStoredHashes(hTile.URL, cp.Size)
	if err != nil {
		t.Fatal(err)
	}
	hr := hashReaderFromSlice(hashes)

	// Build the trusted-subtrees set: { (start, end) : hash }.
	trusted := make(map[[2]uint64]tlogx.Hash)
	// Walk landmarks newest-first; lms[i].treeSize is the upper end.
	// For each, the previous landmark's treeSize (or 0) is the
	// "prev_treeSize" needed for §4.5.
	for i := 0; i < len(lms)-1; i++ {
		prev := lms[i+1].treeSize
		curr := lms[i].treeSize
		if curr <= prev {
			continue
		}
		for _, st := range tlogx.FindSubtrees(prev, curr) {
			h, err := tlogx.SubtreeHash(st.Start, st.End, hr)
			if err != nil {
				t.Fatal(err)
			}
			trusted[[2]uint64{st.Start, st.End}] = h
		}
	}

	// Step 3 & 4: fetch a landmark-relative cert and verify (POST-as-GET).
	for i, ctx := range certCtxs {
		altURL := ctx.url + "/alternate"
		altResp, altBody := postAsGetWithAccept(t, hAcme.URL, altURL, "", ctx.acctKey, ctx.kid)
		if altResp.StatusCode != 200 {
			t.Fatalf("cert %d alt status = %d", i, altResp.StatusCode)
		}
		block, _ := pem.Decode(altBody)
		if block == nil {
			t.Fatalf("cert %d not PEM: %q", i, altBody)
		}
		tbs, _, sigValue, err := cert.SplitCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := cert.ParseMTCProof(sigValue)
		if err != nil {
			t.Fatal(err)
		}
		if len(proof.Signatures) != 0 {
			t.Errorf("cert %d has %d signatures, want 0", i, len(proof.Signatures))
		}
		// The cert's serial is the entry index.
		tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Compute the leaf hash and reconstruct the subtree hash via
		// the inclusion proof.
		leaf := cert.EntryHash(tbsContents)
		gotHash, err := tlogx.EvaluateInclusionProof(
			func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
			proof.Start, proof.End, serial, leaf, proof.InclusionProof,
		)
		if err != nil {
			t.Errorf("cert %d EvaluateInclusionProof: %v", i, err)
			continue
		}
		// Match against the trusted-subtrees set.
		want, ok := trusted[[2]uint64{proof.Start, proof.End}]
		if !ok {
			t.Errorf("cert %d subtree [%d,%d) not in trusted set %v",
				i, proof.Start, proof.End, trustedKeys(trusted))
			continue
		}
		if gotHash != want {
			t.Errorf("cert %d hash mismatch: got %x, want %x", i, gotHash[:8], want[:8])
		}
	}
}

// trustedKeys is a tiny printer for debugging the trusted-subtrees map.
func trustedKeys(m map[[2]uint64]tlogx.Hash) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, fmt.Sprintf("[%d,%d)", k[0], k[1]))
	}
	return out
}
