package integration

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// TestMultiCosignerQuorum stands up one CA plus three stub witnesses
// and drives the §6.3 cosignature collection: the CA fans a sign-subtree
// request out to all three with quorum=2, collects the responses, and
// verifies each.
//
// One witness is *artificially slow* (2s before responding) to
// exercise the best-effort-after-minimum and quorum-met-early paths:
// with quorum=2 and a 1s deadline the slow one must not be waited for.
func TestMultiCosignerQuorum(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	// Issue some certs so the tree is non-trivial.
	for i := 0; i < 3; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("mq%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Three stub witnesses; #2 is deliberately slow.
	stubs := make([]*stubWitness, 3)
	endpoints := make([]cert.MirrorEndpoint, 3)
	for i := range stubs {
		id := cert.TrustAnchorID(fmt.Sprintf("32473.%d", 40+i+1))
		stubs[i] = newStubWitness(t, ca.logID, id, byte(i+1))
		if i == 1 {
			stubs[i].delay = 2 * time.Second
		}
		srv := httptest.NewServer(stubs[i])
		defer srv.Close()
		endpoints[i] = stubs[i].endpoint(srv.URL)
	}

	// Build the request: subtree = [0, 1) (the null entry's leaf), and
	// a consistency proof from there to the CA's checkpoint.
	caSize := ca.log.CurrentCheckpoint().Size
	subtreeStart, subtreeEnd := uint64(0), uint64(1)
	subtreeHash, _, err := ca.log.SubtreeProof(subtreeStart, subtreeEnd, 0)
	if err != nil {
		t.Fatal(err)
	}
	hashes, _, err := loadAllStoredHashes(ca.tileBase, caSize)
	if err != nil {
		t.Fatal(err)
	}
	hr := hashReaderFromSlice(hashes)
	proof, err := tlogx.GenerateConsistencyProof(
		sha256Hash, subtreeStart, subtreeEnd, caSize,
		func(i uint64) (tlogx.Hash, error) {
			hs, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, int64(i))})
			if err != nil {
				return tlogx.Hash{}, err
			}
			return tlogx.Hash(hs[0]), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	mtcSubtree := &cert.MTCSubtree{
		LogID: ca.logID, Start: subtreeStart, End: subtreeEnd, Hash: subtreeHash,
	}
	req := &cert.SubtreeRequest{
		Subtree:          mtcSubtree,
		CACheckpointBody: ca.log.CurrentCheckpoint().SignedNote,
		ConsistencyProof: proof,
	}

	// Quorum=2 with bestEffortAfterMin=false: the slow witness is too
	// late, so we collect only the two fast ones.
	start := time.Now()
	got, err := cert.RequestCosignatures(ctx, req, endpoints, 2, 1*time.Second, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d sigs, want exactly 2 (no best-effort)", len(got))
	}
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("elapsed %v — should have returned as soon as quorum met", elapsed)
	}
	// The slow witness must not be among the collected signatures.
	for _, sig := range got {
		if string(sig.CosignerID) == string(stubs[1].id) {
			t.Errorf("slow witness %q should not have made the quorum", sig.CosignerID)
		}
	}
	// Every returned signature must verify against its witness key.
	for _, sig := range got {
		var key cert.CosignerKey
		for _, ep := range endpoints {
			if string(ep.Key.ID) == string(sig.CosignerID) {
				key = ep.Key
				break
			}
		}
		if len(key.PublicKey) == 0 {
			t.Errorf("returned sig from unknown cosigner %q", sig.CosignerID)
			continue
		}
		msg, err := cert.MarshalSignatureInput(key.ID, mtcSubtree)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.VerifyMTCSignature(key, sig, msg); err != nil {
			t.Errorf("returned sig %q failed to verify: %v", sig.CosignerID, err)
		}
	}
	// All three were asked, even though only two were waited for.
	for i, w := range stubs {
		if n := w.calls.Load(); n != 1 {
			t.Errorf("witness %d served %d requests, want 1", i, n)
		}
	}
	// tlog-tiles: the CA SHOULD identify itself with an operator
	// contact in the User-Agent so mirrors can reach (and not
	// rate-limit) it.
	ua, _ := stubs[0].lastUA.Load().(string)
	if !strings.Contains(ua, "+https://github.com/mcpherrinm/cactus") {
		t.Errorf("witness saw User-Agent %q, want the cactus contact UA", ua)
	}
}

// TestMultiCosignerQuorumNotMet: with a single witness but quorum=2,
// the call returns an error indicating quorum wasn't met.
func TestMultiCosignerQuorumNotMet(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := newStubWitness(t, ca.logID, cert.TrustAnchorID("32473.22"), 0x01)
	srv := httptest.NewServer(w)
	defer srv.Close()

	req := &cert.SubtreeRequest{
		Subtree: &cert.MTCSubtree{
			LogID: ca.logID, Start: 0, End: 1,
			Hash: tlogx.Hash{},
		},
		CACheckpointBody: ca.log.CurrentCheckpoint().SignedNote,
	}
	_, err := cert.RequestCosignatures(ctx, req, []cert.MirrorEndpoint{
		w.endpoint(srv.URL),
	}, 2, 200*time.Millisecond, false)
	if err == nil {
		t.Errorf("expected error when quorum > number of witnesses")
	}
}
