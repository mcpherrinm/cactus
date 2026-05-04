package cert

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/letsencrypt/cactus/tlogx"
)

func TestMTCSubtreeMarshal(t *testing.T) {
	s := &MTCSubtree{
		LogID: TrustAnchorID("32473.1"),
		Start: 0x0102030405060708,
		End:   0x1112131415161718,
		Hash:  tlogx.Hash{0xaa, 0xbb, 0xcc, 0xdd},
	}
	got, err := s.MarshalTLS()
	if err != nil {
		t.Fatal(err)
	}

	// Layout: uint8(len) || logID || uint64 start || uint64 end || hash[32].
	want := []byte{
		byte(len("32473.1")),
	}
	want = append(want, []byte("32473.1")...)
	want = append(want,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	)
	want = append(want, s.Hash[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("MarshalTLS:\n got %x\nwant %x", got, want)
	}
}

func TestMarshalSignatureInputLayout(t *testing.T) {
	st := &MTCSubtree{
		LogID: TrustAnchorID("LogX"),
		Start: 1, End: 2,
		Hash: tlogx.Hash{0x01, 0x02},
	}
	cosigner := TrustAnchorID("CosY")
	got, err := MarshalSignatureInput(cosigner, st)
	if err != nil {
		t.Fatal(err)
	}

	// Must start with the 16-byte fixed label.
	if len(got) < 16 {
		t.Fatal("output too short")
	}
	if string(got[:16]) != SubtreeSignatureLabel {
		t.Errorf("label = %q, want %q", got[:16], SubtreeSignatureLabel)
	}
	if got[16] != byte(len(cosigner)) {
		t.Errorf("cosigner length prefix = %d, want %d", got[16], len(cosigner))
	}
}

func TestMTCProofRoundTrip(t *testing.T) {
	proof := &MTCProof{
		Start: 100,
		End:   132,
		InclusionProof: []tlogx.Hash{
			{0x01}, {0x02}, {0x03}, {0x04}, {0x05},
		},
		Signatures: []MTCSignature{
			{CosignerID: TrustAnchorID("ca-1"), Signature: bytes.Repeat([]byte{0xaa}, 70)},
			{CosignerID: TrustAnchorID("witness-1"), Signature: bytes.Repeat([]byte{0xbb}, 71)},
		},
	}
	enc, err := proof.MarshalTLS()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ParseMTCProof(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec, proof) {
		t.Errorf("round trip mismatch\n got %+v\nwant %+v", dec, proof)
	}
}

func TestMTCProofRejectsInvalidInclusionProofLength(t *testing.T) {
	// Build a body with inclusion_proof length=33 (not multiple of 32).
	bad := []byte{
		// start=0
		0, 0, 0, 0, 0, 0, 0, 0,
		// end=0
		0, 0, 0, 0, 0, 0, 0, 0,
		// inclusion_proof length=33
		0x00, 0x21,
	}
	bad = append(bad, bytes.Repeat([]byte{0xaa}, 33)...)
	// signatures length=0
	bad = append(bad, 0x00, 0x00)

	if _, err := ParseMTCProof(bad); err == nil {
		t.Error("ParseMTCProof: expected error for non-multiple-of-32 inclusion_proof")
	}
}

func TestMTCProofRejectsTrailingBytes(t *testing.T) {
	good := &MTCProof{Start: 0, End: 1}
	enc, err := good.MarshalTLS()
	if err != nil {
		t.Fatal(err)
	}
	enc = append(enc, 0x00)
	if _, err := ParseMTCProof(enc); err == nil {
		t.Error("ParseMTCProof: expected error for trailing bytes")
	}
}

func TestSignatureLabelIs16Bytes(t *testing.T) {
	if len(SubtreeSignatureLabel) != 16 {
		t.Errorf("SubtreeSignatureLabel = %d bytes (%q), want 16", len(SubtreeSignatureLabel), SubtreeSignatureLabel)
	}
	// Per §5.4.1: "mtc-subtree/v1\n\0".
	want := []byte("mtc-subtree/v1\n\x00")
	if !bytes.Equal([]byte(SubtreeSignatureLabel), want) {
		t.Errorf("SubtreeSignatureLabel bytes = %x, want %x", []byte(SubtreeSignatureLabel), want)
	}
}
