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

// tlv builds a short-form DER TLV (bodies < 128 bytes only).
func tlv(tag byte, body []byte) []byte {
	return append([]byte{tag, byte(len(body))}, body...)
}

// buildTBSWithTail assembles a minimal TBSCertificate whose optional tail
// carries issuerUniqueID [1] and extensions [3] in caller-chosen order.
func buildTBSWithTail(tailA, tailB []byte) []byte {
	var body []byte
	body = append(body, tlv(0xa0, tlv(0x02, []byte{0x02}))...)                        // version [0] INTEGER 2
	body = append(body, tlv(0x02, []byte{0x01, 0, 0, 0, 0, 0, 0x05})...)              // serialNumber
	algID, _ := asn1.Marshal(struct{ Algorithm asn1.ObjectIdentifier }{OIDAlgMTCProof})
	body = append(body, algID...)                                                     // signature AlgId (id-alg-mtcProof)
	body = append(body, tlv(0x30, nil)...)                                            // issuer
	utc := tlv(0x17, []byte("250101000000Z"))                                         // Time
	body = append(body, tlv(0x30, append(append([]byte{}, utc...), utc...))...)       // validity
	body = append(body, tlv(0x30, nil)...)                                            // subject
	spki := tlv(0x30, append(tlv(0x30, tlv(0x06, []byte{0x2b})), tlv(0x03, []byte{0x00, 0xff})...)) // SPKI
	body = append(body, spki...)
	body = append(body, tailA...)
	body = append(body, tailB...)
	return tlv(0x30, body)
}

// TestRebuildRejectsReorderedTail guards against §12.6 certificate
// malleability: the optional TBS tail fields must be in strict DER order,
// so a tag-reordered (non-DER) encoding cannot rebuild to the same entry.
func TestRebuildRejectsReorderedTail(t *testing.T) {
	uid := tlv(0x81, []byte{0x00, 0xaa}) // issuerUniqueID [1]
	ext := tlv(0xa3, tlv(0x30, tlv(0x30, append(tlv(0x06, []byte{0x55, 0x1d, 0x11}), tlv(0x04, []byte{0x30, 0x00})...)))) // extensions [3]

	if _, _, err := RebuildLogEntryFromTBS(buildTBSWithTail(uid, ext), nil); err != nil {
		t.Fatalf("canonical tail order rejected: %v", err)
	}
	if _, _, err := RebuildLogEntryFromTBS(buildTBSWithTail(ext, uid), nil); err == nil {
		t.Fatal("reordered tail ([3] before [1]) accepted; malleability not closed")
	}
}
