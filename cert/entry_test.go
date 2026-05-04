package cert

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"reflect"
	"testing"
	"time"
)

func TestEncodeNullEntry(t *testing.T) {
	got := EncodeNullEntry()
	if !bytes.Equal(got, []byte{0x00, 0x00}) {
		t.Errorf("EncodeNullEntry = %x", got)
	}
}

func TestEncodeTBSCertEntry(t *testing.T) {
	got := EncodeTBSCertEntry([]byte{0xAA, 0xBB})
	want := []byte{0x00, 0x01, 0xAA, 0xBB}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeTBSCertEntry = %x, want %x", got, want)
	}
}

func TestEntryHashShape(t *testing.T) {
	tbsContents := []byte{0x01, 0x02, 0x03}
	got := EntryHash(tbsContents)

	// HASH(0x00 || 0x00 0x01 || tbsContents) per §7.2.
	h := sha256.New()
	h.Write([]byte{0x00, 0x00, 0x01, 0x01, 0x02, 0x03})
	want := h.Sum(nil)
	if !bytes.Equal(got[:], want) {
		t.Errorf("EntryHash mismatch:\n got %x\nwant %x", got[:], want)
	}
}

func TestBuildLogIDName(t *testing.T) {
	logID := "32473.1"
	der, err := BuildLogIDName(logID)
	if err != nil {
		t.Fatal(err)
	}
	// Re-decode and check the structure.
	type atv struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}
	var seq []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatalf("unmarshal seq: %v", err)
	}
	if len(seq) != 1 {
		t.Fatalf("want 1 RDN, got %d", len(seq))
	}
	if seq[0].Tag != 17 { // SET
		t.Errorf("RDN tag = %d, want 17", seq[0].Tag)
	}
	var got atv
	if _, err := asn1.Unmarshal(seq[0].Bytes, &got); err != nil {
		t.Fatalf("unmarshal ATV: %v", err)
	}
	if !got.Type.Equal(OIDRDNATrustAnchorID) {
		t.Errorf("ATV oid = %s, want %s", got.Type, OIDRDNATrustAnchorID)
	}
	if got.Value != logID {
		t.Errorf("ATV value = %q, want %q", got.Value, logID)
	}
}

func TestMarshalDERIsParseable(t *testing.T) {
	dn, err := BuildLogIDName("32473.1")
	if err != nil {
		t.Fatal(err)
	}
	subjectDN, err := BuildLogIDName("cactus.test/example")
	if err != nil {
		t.Fatal(err)
	}
	// Minimal AlgorithmIdentifier { OID 1.2.840.10045.2.1 ecPublicKey }.
	algID := []byte{
		0x30, 0x13,
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	}

	e := &TBSCertificateLogEntry{
		Version:                   2,
		IssuerDN:                  dn,
		NotBefore:                 time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:                  time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC),
		SubjectDN:                 subjectDN,
		SubjectPublicKeyAlgorithm: algID,
		SubjectPublicKeyInfoHash:  bytes.Repeat([]byte{0xab}, 32),
	}
	der, err := e.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if der[0] != 0x30 {
		t.Errorf("MarshalDER outer tag = 0x%02x, want 0x30", der[0])
	}
	contents, err := e.MarshalContents()
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip: contents should equal DER minus outer tag+length.
	wrapped := wrapSequence(contents)
	if !bytes.Equal(wrapped, der) {
		t.Errorf("contents+wrap != DER")
	}
}

func TestRoundTripDERLength(t *testing.T) {
	cases := []int{0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000}
	for _, n := range cases {
		body := bytes.Repeat([]byte{0xaa}, n)
		out := wrapSequence(body)
		consumed, contents, err := stripDERHeader(out, 0x30)
		if err != nil {
			t.Errorf("n=%d: %v", n, err)
			continue
		}
		if consumed != len(out) {
			t.Errorf("n=%d: consumed=%d != len=%d", n, consumed, len(out))
		}
		if !bytes.Equal(contents, body) {
			t.Errorf("n=%d: contents mismatch", n)
		}
	}
}

func TestEncodeIntegerBytes(t *testing.T) {
	cases := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x00, 0x80}},
		{255, []byte{0x00, 0xff}},
		{256, []byte{0x01, 0x00}},
		{-1, []byte{0xff}},
		{-128, []byte{0x80}},
		{-129, []byte{0xff, 0x7f}},
	}
	for _, tc := range cases {
		got := encodeIntegerBytes(tc.v)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("encodeIntegerBytes(%d) = %x, want %x", tc.v, got, tc.want)
		}
	}
}

func TestSinglePassEntryHashMatchesEntryHash(t *testing.T) {
	// Build a TBS with a known SPKI, then verify that
	// SinglePassEntryHash(...) matches sha256(0x00 || 0x00 0x01 || tbsContents)
	// when the TBS is reconstructed with subjectPublicKeyInfo replaced by
	// subjectPublicKeyAlgorithm + OCTET STRING(SHA-256(SPKI)).

	// SPKI: minimal AlgorithmIdentifier + a fake BIT STRING(public key).
	algID := []byte{
		0x30, 0x13,
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	}
	bitString := []byte{0x03, 0x04, 0x00, 0xde, 0xad, 0xbe} // BIT STRING with one byte 0xdeadbe (3 bytes)
	spki := []byte{0x30, byte(len(algID) + len(bitString))}
	spki = append(spki, algID...)
	spki = append(spki, bitString...)

	preSPKI := []byte{0xCA, 0xFE} // arbitrary preamble
	postSPKI := []byte{0xBA, 0xBE}

	got := SinglePassEntryHash(preSPKI, spki, postSPKI, sha256.New)

	// Reconstruct expected.
	spkiHash := sha256.Sum256(spki)
	var tbs []byte
	tbs = append(tbs, preSPKI...)
	tbs = append(tbs, 0x04, byte(len(spkiHash)))
	tbs = append(tbs, spkiHash[:]...)
	tbs = append(tbs, postSPKI...)
	want := EntryHash(tbs)
	if !bytes.Equal(got, want[:]) {
		t.Errorf("SinglePassEntryHash mismatch:\n got %x\nwant %x", got, want[:])
	}
}
