package cert

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/letsencrypt/cactus/tlogx"
)

func TestCosignedMessageLayout(t *testing.T) {
	st := &MTCSubtree{
		LogID: TrustAnchorID("32473.1"),
		Start: 0x0102030405060708,
		End:   0x1112131415161718,
		Hash:  tlogx.Hash{0xaa, 0xbb, 0xcc, 0xdd},
	}
	cosigner := TrustAnchorID("32473.2")
	got, err := MarshalSignatureInput(cosigner, st)
	if err != nil {
		t.Fatal(err)
	}

	// §5.3.1 CosignedMessage layout:
	//   label[12] || u8 len||cosigner_name || u64 timestamp ||
	//   u8 len||log_origin || u64 start || u64 end || hash[32].
	cosignerName := "oid/" + string(cosigner)
	logOrigin := "oid/" + string(st.LogID)
	var want []byte
	want = append(want, []byte(SubtreeSignatureLabel)...)
	want = append(want, byte(len(cosignerName)))
	want = append(want, cosignerName...)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 0) // timestamp = 0
	want = append(want, byte(len(logOrigin)))
	want = append(want, logOrigin...)
	want = append(want,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	)
	want = append(want, st.Hash[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("MarshalSignatureInput:\n got %x\nwant %x", got, want)
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

	// Must start with the 12-byte fixed label.
	if len(got) < 12 {
		t.Fatal("output too short")
	}
	if string(got[:12]) != SubtreeSignatureLabel {
		t.Errorf("label = %q, want %q", got[:12], SubtreeSignatureLabel)
	}
	wantName := "oid/" + string(cosigner)
	if got[12] != byte(len(wantName)) {
		t.Errorf("cosigner_name length prefix = %d, want %d", got[12], len(wantName))
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
	// §6.1 layout: extensions<2> || start[6] || end[6] || ip_len[2] || ...
	bad := []byte{
		// extensions length=0
		0x00, 0x00,
		// start (uint48) = 0
		0, 0, 0, 0, 0, 0,
		// end (uint48) = 0
		0, 0, 0, 0, 0, 0,
		// inclusion_proof length=33 (not a multiple of 32)
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

func TestSignatureLabelIs12Bytes(t *testing.T) {
	if len(SubtreeSignatureLabel) != 12 {
		t.Errorf("SubtreeSignatureLabel = %d bytes (%q), want 12", len(SubtreeSignatureLabel), SubtreeSignatureLabel)
	}
	// Per §5.3.1: "subtree/v1\n\0".
	want := []byte("subtree/v1\n\x00")
	if !bytes.Equal([]byte(SubtreeSignatureLabel), want) {
		t.Errorf("SubtreeSignatureLabel bytes = %x, want %x", []byte(SubtreeSignatureLabel), want)
	}
}
