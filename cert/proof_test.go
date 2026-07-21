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
	// Names are "oid/1.3.6.1.4.1." + relative ID (OIDName).
	cosignerName := OIDName(cosigner)
	logOrigin := OIDName(st.LogID)
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
		LogID: TrustAnchorID("32473.7"),
		Start: 1, End: 2,
		Hash: tlogx.Hash{0x01, 0x02},
	}
	cosigner := TrustAnchorID("32473.8")
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
	wantName := OIDName(cosigner)
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
			{CosignerID: TrustAnchorID("32473.1"), Signature: bytes.Repeat([]byte{0xaa}, 70)},
			{CosignerID: TrustAnchorID("32473.10"), Signature: bytes.Repeat([]byte{0xbb}, 71)},
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
	// §6.2 layout: extensions<2> || start[6] || end[6] || ip_len[2] || ...
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

// TestMTCProofCosignerIDIsBinary pins §6.2: the cosigner_id field on the
// wire is the trust anchor ID's binary representation, not ASCII, and the
// in-memory CosignerID round-trips to the canonical relative form.
// (Regression for review finding 1.)
func TestMTCProofCosignerIDIsBinary(t *testing.T) {
	p := &MTCProof{
		Start: 0, End: 1,
		InclusionProof: []tlogx.Hash{{}},
		Signatures: []MTCSignature{
			{CosignerID: TrustAnchorID("32473.1"), Signature: []byte{0xAA, 0xBB}},
		},
	}
	enc, err := p.MarshalTLS()
	if err != nil {
		t.Fatal(err)
	}
	// cosigner_id is uint8-length-prefixed: 0x04 then the 4 binary octets.
	if want := []byte{0x04, 0x81, 0xfd, 0x59, 0x01}; !bytes.Contains(enc, want) {
		t.Errorf("MTCProof %x missing binary cosigner_id field %x", enc, want)
	}
	if bytes.Contains(enc, []byte("32473.1")) {
		t.Error("MTCProof bytes contain ASCII cosigner_id; §6.2 requires binary")
	}
	dec, err := ParseMTCProof(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.Signatures[0].CosignerID) != "32473.1" {
		t.Errorf("parsed CosignerID = %q, want 32473.1", dec.Signatures[0].CosignerID)
	}
}

// TestMTCProofSignaturesSortedByBinary pins the §6.2 ordering: signatures
// are sorted by the *binary* cosigner_id (shorter first, then
// lexicographic), which can differ from ASCII order. "32473.2" (4 binary
// octets) must sort before "32473.130" (5 binary octets) even though
// "32473.130" < "32473.2" as ASCII.
func TestMTCProofSignaturesSortedByBinary(t *testing.T) {
	p := &MTCProof{
		Start: 0, End: 1,
		Signatures: []MTCSignature{
			{CosignerID: TrustAnchorID("32473.130"), Signature: []byte{0x01}},
			{CosignerID: TrustAnchorID("32473.2"), Signature: []byte{0x02}},
		},
	}
	enc, err := p.MarshalTLS()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ParseMTCProof(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.Signatures[0].CosignerID) != "32473.2" ||
		string(dec.Signatures[1].CosignerID) != "32473.130" {
		t.Errorf("order = [%q %q], want [32473.2 32473.130]",
			dec.Signatures[0].CosignerID, dec.Signatures[1].CosignerID)
	}
}

// TestMTCProofExtensionsRoundTrip + TestEntryHashExtSensitiveToExtensions
// pin that the MerkleTreeCertEntry extensions are carried in the MTCProof
// and feed the leaf hash (§7.2 step 8.2). (Regression for review finding 5.)
func TestMTCProofExtensionsRoundTrip(t *testing.T) {
	p := &MTCProof{
		Extensions:     []MerkleTreeCertEntryExtension{{Type: 5, Data: []byte{0xde, 0xad}}},
		Start:          1,
		End:            2,
		InclusionProof: []tlogx.Hash{{0x09}},
	}
	enc, err := p.MarshalTLS()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ParseMTCProof(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec.Extensions, p.Extensions) {
		t.Errorf("Extensions round trip: got %+v want %+v", dec.Extensions, p.Extensions)
	}
}

func TestEntryHashExtSensitiveToExtensions(t *testing.T) {
	tbs := []byte{0x01, 0x02, 0x03}
	withExt, err := EntryHashExt([]MerkleTreeCertEntryExtension{{Type: 1, Data: []byte{0xff}}}, tbs)
	if err != nil {
		t.Fatal(err)
	}
	if EntryHash(tbs) == withExt {
		t.Error("EntryHashExt ignored extensions: hash unchanged")
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
