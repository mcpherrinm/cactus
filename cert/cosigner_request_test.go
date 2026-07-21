package cert

import (
	"strings"
	"testing"

	"github.com/letsencrypt/cactus/tlogx"
)

// TestBuildSignSubtreeBodyGrammar pins the c2sp.org/tlog-witness
// sign-subtree request grammar:
//
//	subtree <start> <end>
//	<base64 subtree hash>
//	<base64 proof hash>...
//	<blank line>
//	<reference checkpoint>
//
// The regression it guards is a signature line between the subtree hash
// and the proof hashes. An earlier revision of the spec let a client
// prepend its own subtree cosignature there as a DoS gate; C2SP deleted
// it, and a strict mirror now reads that line as a base64 proof hash and
// answers 400. Nothing in a local test suite catches that — only a real
// peer does — so the shape is asserted here.
func TestBuildSignSubtreeBodyGrammar(t *testing.T) {
	var hash tlogx.Hash
	for i := range hash {
		hash[i] = byte(i)
	}
	proof := []tlogx.Hash{hash, hash}
	checkpoint := []byte("oid/1.3.6.1.4.1.32473.1.0.1\n14\nAAAA\n\n— oid/1.3.6.1.4.1.32473.1 sig\n")

	body, err := buildSignSubtreeBody(&SubtreeRequest{
		Subtree: &MTCSubtree{
			LogID: TrustAnchorID("32473.1.0.1"),
			Start: 8, End: 13, Hash: hash,
		},
		CACheckpointBody: checkpoint,
		ConsistencyProof: proof,
	})
	if err != nil {
		t.Fatalf("buildSignSubtreeBody: %v", err)
	}

	head, rest, found := strings.Cut(string(body), "\n\n")
	if !found {
		t.Fatal("no blank line separating the request head from the checkpoint")
	}
	lines := strings.Split(head, "\n")
	// 1 subtree range + 1 subtree hash + 2 proof hashes.
	if len(lines) != 4 {
		t.Fatalf("head has %d lines, want 4:\n%q", len(lines), head)
	}
	if lines[0] != "subtree 8 13" {
		t.Errorf("subtree range line = %q", lines[0])
	}
	for i, l := range lines[1:] {
		if strings.HasPrefix(l, "—") {
			t.Errorf("line %d is a cosignature line (%q); C2SP removed those from the sign-subtree grammar, "+
				"and a strict mirror parses it as a proof hash and answers 400", i+1, l)
		}
	}
	if rest != string(checkpoint) {
		t.Errorf("reference checkpoint was not emitted verbatim:\n got %q\nwant %q", rest, checkpoint)
	}
}

// TestBuildSignSubtreeBodyRequiresCheckpoint documents that the
// reference checkpoint is mandatory. Its *content* requirement — that
// it carry the responding mirror's own cosignature, or the mirror
// answers 403 — is the caller's to satisfy; see
// mirrorpush.Pool.CheckpointWithCosignatures.
func TestBuildSignSubtreeBodyRequiresCheckpoint(t *testing.T) {
	req := &SubtreeRequest{
		Subtree: &MTCSubtree{LogID: TrustAnchorID("32473.1"), Start: 0, End: 1},
	}
	if _, err := buildSignSubtreeBody(req); err == nil {
		t.Error("buildSignSubtreeBody accepted an empty reference checkpoint")
	}
	if _, err := buildSignSubtreeBody(nil); err == nil {
		t.Error("buildSignSubtreeBody accepted a nil request")
	}
}

// TestBuildSignSubtreeBodyRejectsOversizedProof pins the 63-hash limit
// the spec places on consistency proof lines.
func TestBuildSignSubtreeBodyRejectsOversizedProof(t *testing.T) {
	req := &SubtreeRequest{
		Subtree:          &MTCSubtree{LogID: TrustAnchorID("32473.1"), Start: 0, End: 1},
		CACheckpointBody: []byte("cp\n"),
		ConsistencyProof: make([]tlogx.Hash, 64),
	}
	if _, err := buildSignSubtreeBody(req); err == nil {
		t.Error("buildSignSubtreeBody accepted a proof with more than 63 hashes")
	}
}

// TestMarshalSignatureInputTimestamp confirms the timestamp reaches the
// signed bytes, and that the zero-timestamp default is unchanged — MTC
// proofs and sign-subtree both require timestamp 0, and a silent change
// there would invalidate every existing certificate.
func TestMarshalSignatureInputTimestamp(t *testing.T) {
	st := &MTCSubtree{LogID: TrustAnchorID("32473.1.0.1"), Start: 0, End: 14}
	id := TrustAnchorID("32473.1")

	zero, err := MarshalSignatureInput(id, st)
	if err != nil {
		t.Fatal(err)
	}
	explicitZero, err := MarshalSignatureInputAt(id, st, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(zero) != string(explicitZero) {
		t.Error("MarshalSignatureInput is not MarshalSignatureInputAt(..., 0)")
	}

	nonZero, err := MarshalSignatureInputAt(id, st, 1735689600)
	if err != nil {
		t.Fatal(err)
	}
	if string(nonZero) == string(zero) {
		t.Fatal("the timestamp does not affect the signed message")
	}
	if len(nonZero) != len(zero) {
		t.Fatalf("timestamped message is %d bytes, zero-timestamp is %d; the field is fixed-width",
			len(nonZero), len(zero))
	}
	// The timestamp is the u64 immediately after the 12-byte label and
	// the length-prefixed cosigner name.
	off := 12 + 1 + len(OIDName(id))
	want := []byte{0, 0, 0, 0, 0x67, 0x74, 0x85, 0x80} // 1735689600 big-endian
	if got := nonZero[off : off+8]; string(got) != string(want) {
		t.Errorf("timestamp bytes at offset %d = %x, want %x", off, got, want)
	}
	for _, b := range zero[off : off+8] {
		if b != 0 {
			t.Errorf("default timestamp is not zero: %x", zero[off:off+8])
			break
		}
	}
}
