package cert

import (
	"encoding/asn1"
	"strings"
	"testing"
)

// buildCertDER assembles a minimal Certificate SEQUENCE whose
// signatureValue BIT STRING carries the given contents and unused-bit
// count. Only the outer framing matters here; the TBSCertificate and
// AlgorithmIdentifier are placeholders.
func buildCertDER(t *testing.T, sigContents []byte, unusedBits int) []byte {
	t.Helper()
	tbs, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	alg, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	// BIT STRING: tag 0x03, length, unused-bits octet, then contents.
	bs := []byte{0x03, byte(len(sigContents) + 1), byte(unusedBits)}
	bs = append(bs, sigContents...)

	body := append(append(append([]byte{}, tbs...), alg...), bs...)
	outer, err := asn1.Marshal(asn1.RawValue{
		Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

// §7.2 step 2: verification must fail if signatureValue is not a whole
// number of octets. encoding/asn1 accepts a non-zero unused-bits count,
// so SplitCertificate has to reject it explicitly — otherwise the proof
// would be parsed out of a partially-used final byte.
func TestSplitCertificateRejectsUnusedBits(t *testing.T) {
	sig := []byte{0xAA, 0xBB, 0xC0}

	// Sanity: with no unused bits the same structure splits cleanly.
	if _, _, got, err := SplitCertificate(buildCertDER(t, sig, 0)); err != nil {
		t.Fatalf("unused=0: SplitCertificate: %v", err)
	} else if string(got) != string(sig) {
		t.Fatalf("unused=0: sigValue = %x, want %x", got, sig)
	}

	// sig ends in 0xC0, so its low 1 and 4 bits are already zero: these
	// are well-formed BIT STRINGs that encoding/asn1 accepts, and only
	// the explicit §7.2 check rejects them.
	for _, unused := range []int{1, 4} {
		_, _, _, err := SplitCertificate(buildCertDER(t, sig, unused))
		if err == nil {
			t.Errorf("unused=%d: SplitCertificate accepted a non-octet-aligned signatureValue", unused)
			continue
		}
		if !strings.Contains(err.Error(), "multiple of 8") {
			t.Errorf("unused=%d: error = %v, want a multiple-of-8 complaint", unused, err)
		}
	}

	// With 7 unused bits the padding bits of 0xC0 are non-zero, so
	// encoding/asn1 rejects it first. Either way it must not verify.
	if _, _, _, err := SplitCertificate(buildCertDER(t, sig, 7)); err == nil {
		t.Error("unused=7: SplitCertificate accepted a malformed BIT STRING")
	}
}
