package integration

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
)

// TestEndToEndCAWithThreeCosigners is the CA-side quorum cornerstone:
//   - 1 CA cactus
//   - 3 stub witnesses answering sign-subtree
//   - CA configured with a MirrorRequester that fans out to all three
//     with quorum=2 + WaitForCosigners=3 (CA + 2 witnesses)
//
// Issues a cert and confirms its MTCProof carries the CA's signature
// plus at least two witness cosignatures, each of which is
// independently re-verified against the subtree hash recomputed from
// the log.
//
// The witnesses here are stubs (see stubWitness): cactus no longer
// implements a mirror, so the thing under test is the CA's collection
// client, not witness-side validation.
func TestEndToEndCAWithThreeCosigners(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-cosigner takes a couple seconds")
	}

	// 1) Bring up the CA log + tile server.
	caDir := t.TempDir()
	caFS, err := storage.New(caDir)
	if err != nil {
		t.Fatal(err)
	}
	caSeed := make([]byte, signer.SeedSize)
	caSigner, err := signer.FromSeed(signer.AlgMLDSA44, caSeed)
	if err != nil {
		t.Fatal(err)
	}
	logID := cert.TrustAnchorID("32473.5")
	caCosigID := cert.TrustAnchorID("32473.5")

	// 2) Three stub witnesses, each with its own cosigner identity.
	stubs := make([]*stubWitness, 3)
	endpoints := make([]cert.MirrorEndpoint, 3)
	for i := range stubs {
		id := cert.TrustAnchorID(fmt.Sprintf("32473.%d", 30+i+1))
		stubs[i] = newStubWitness(t, logID, id, byte(0x10+i))
		srv := httptest.NewServer(stubs[i])
		defer srv.Close()
		endpoints[i] = stubs[i].endpoint(srv.URL)
	}

	// The requester needs the log to compute consistency proofs, so
	// forward-declare the pointer the closure captures.
	var caLog *cactuslog.Log
	mirrorRequester := func(ctx context.Context, st *cert.MTCSubtree, caSig cert.MTCSignature) ([]cert.MTCSignature, error) {
		cp := caLog.CurrentCheckpoint()
		if cp.Size == 0 {
			return nil, fmt.Errorf("no checkpoint yet")
		}
		proof, err := caLog.ConsistencyProof(st.Start, st.End, cp.Size)
		if err != nil {
			return nil, err
		}
		return cert.RequestCosignatures(ctx, &cert.SubtreeRequest{
			Subtree:          st,
			CACheckpointBody: cp.SignedNote,
			ConsistencyProof: proof,
		}, endpoints, 2, 2*time.Second, false)
	}

	caLog, err = cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: caCosigID,
		Signer: caSigner, FS: caFS,
		FlushPeriod:      25 * time.Millisecond,
		MirrorRequester:  mirrorRequester,
		WaitForCosigners: 3, // CA + 2 witnesses
	})
	if err != nil {
		t.Fatal(err)
	}
	defer caLog.Stop()
	caTile := httptest.NewServer(tile.New(caLog, caFS).Handler())
	defer caTile.Close()

	// 3) Build an ACME stack on top of the CA log and issue a cert.
	caIssuer, err := ca.New(caLog, "32473.5", 1)
	if err != nil {
		t.Fatal(err)
	}
	acmeSrv, err := acme.New(acme.Config{
		Issuer: caIssuer, ChallengeMode: acme.ChallengeAutoPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	hAcme := httptest.NewServer(acmeSrv.Handler())
	defer hAcme.Close()
	acmeSrv.SetExternalURL(hAcme.URL)

	der, err := acmeIssueOne(hAcme.URL, "three-cosigners.test")
	if err != nil {
		t.Fatal(err)
	}

	// 4) Decode and assert the cert carries the CA sig plus >= 2
	//    witness sigs, and that each witness sig actually verifies.
	_, _, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Signatures) < 3 {
		t.Fatalf("got %d sigs in cert, want >= 3 (CA + 2 witnesses): %+v",
			len(proof.Signatures), proof.Signatures)
	}

	// Recompute the subtree hash the cosigners signed over, straight
	// from the log, so the verification below is independent of
	// whatever the witnesses were handed.
	subtreeHash, _, err := caLog.SubtreeProof(proof.Start, proof.End, proof.Start)
	if err != nil {
		t.Fatal(err)
	}
	subtree := &cert.MTCSubtree{
		LogID: logID, Start: proof.Start, End: proof.End, Hash: subtreeHash,
	}

	caSeen := false
	witnessSeen := 0
	for _, s := range proof.Signatures {
		if string(s.CosignerID) == string(caCosigID) {
			caSeen = true
			continue
		}
		var key cert.CosignerKey
		for _, w := range stubs {
			if string(s.CosignerID) == string(w.id) {
				key = w.key()
			}
		}
		if len(key.PublicKey) == 0 {
			t.Errorf("unrecognised cosigner: %q", s.CosignerID)
			continue
		}
		msg, err := cert.MarshalSignatureInput(key.ID, subtree)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.VerifyMTCSignature(key, s, msg); err != nil {
			t.Errorf("cosignature %q in cert failed to verify: %v", s.CosignerID, err)
			continue
		}
		witnessSeen++
	}
	if !caSeen {
		t.Errorf("CA cosigner missing from cert sigs")
	}
	if witnessSeen < 2 {
		t.Errorf("got %d verified witness sigs in cert, want >= 2", witnessSeen)
	}
	t.Logf("cert has %d signatures (1 CA + %d witness)", len(proof.Signatures), witnessSeen)
}
