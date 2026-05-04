package cert

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestTBSEntryIsDER asserts that the bytes emitted by
// TBSCertificateLogEntry.MarshalDER use minimum-form length encodings
// at every TLV boundary — the property §12.6 calls "DER, not BER".
//
// We walk the DER recursively and verify each TLV length encoding is
// the shortest legal form per X.690 §10.1 (DER restriction).
func TestTBSEntryIsDER(t *testing.T) {
	dn, _ := BuildLogIDName("32473.1")
	subject, _ := BuildLogIDName("cactus.test/example")
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
		SubjectDN:                 subject,
		SubjectPublicKeyAlgorithm: algID,
		SubjectPublicKeyInfoHash:  bytes.Repeat([]byte{0xab}, 32),
		// Realistic single Extensions SEQUENCE: one extn with OID
		// 1.1 and an empty OCTET STRING.
		Extensions: []byte{
			0x30, 0x07, // SEQUENCE, len 7
			0x30, 0x05, // Extension SEQUENCE, len 5
			0x06, 0x01, 0x01, // OID 1.1
			0x04, 0x00, // empty OCTET STRING
		},
	}
	der, err := e.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := assertDER(der); err != nil {
		t.Errorf("MarshalDER produced non-DER:\n  %v\n  bytes: %x", err, der)
	}

	// Also confirm the body is large enough to exercise long-form
	// length encoding at the outer SEQUENCE — otherwise the test
	// passes trivially.
	if len(der) < 0x80 {
		t.Logf("warning: TBS DER is only %d bytes; long-form length not exercised", len(der))
	}
}

// TestTBSEntryIsDERLongForm builds a TBS with a large enough subject
// DN to push the outer length over 0xFFFF, so the 2-byte long-form
// length is exercised and validated.
func TestTBSEntryIsDERLongForm(t *testing.T) {
	dn, _ := BuildLogIDName("32473.1")
	bigSubject, _ := BuildLogIDName(strings.Repeat("a", 70_000))
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
		SubjectDN:                 bigSubject,
		SubjectPublicKeyAlgorithm: algID,
		SubjectPublicKeyInfoHash:  bytes.Repeat([]byte{0xab}, 32),
	}
	der, err := e.MarshalDER()
	if err != nil {
		t.Fatal(err)
	}
	if err := assertDER(der); err != nil {
		t.Errorf("MarshalDER (long-form) produced non-DER: %v", err)
	}
	if len(der) <= 0xFFFF {
		t.Errorf("expected >0xFFFF-byte TBS to exercise 3-byte long-form length, got %d bytes", len(der))
	}
}

// assertDER walks one TLV at the front of `data` and recurses into
// constructed structures. Returns an error if any length encoding uses
// more octets than necessary.
func assertDER(data []byte) error {
	pos := 0
	for pos < len(data) {
		consumed, contents, constructed, err := parseTLVStrict(data[pos:])
		if err != nil {
			return fmt.Errorf("at offset %d: %w", pos, err)
		}
		if constructed {
			if err := assertDER(contents); err != nil {
				return err
			}
		}
		pos += consumed
	}
	return nil
}

// parseTLVStrict parses one TLV and verifies its length encoding is the
// shortest legal form per X.690 §10.1 (DER restriction).
func parseTLVStrict(data []byte) (consumed int, contents []byte, constructed bool, err error) {
	if len(data) < 2 {
		return 0, nil, false, fmt.Errorf("short TLV (%d bytes)", len(data))
	}
	tag := data[0]
	constructed = tag&0x20 != 0
	hdr := 1

	l := int(data[1])
	hdr++
	switch {
	case l < 0x80:
		// Short form. Always shortest-form-legal.
	case l == 0x80:
		return 0, nil, false, fmt.Errorf("indefinite length (BER, not DER)")
	default:
		nbytes := l & 0x7f
		if nbytes > 4 {
			return 0, nil, false, fmt.Errorf("length-of-length %d > 4", nbytes)
		}
		if len(data) < hdr+nbytes {
			return 0, nil, false, fmt.Errorf("truncated long-form length")
		}
		if data[hdr] == 0 {
			return 0, nil, false, fmt.Errorf("leading-zero length octet (non-minimum)")
		}
		l = 0
		for i := 0; i < nbytes; i++ {
			l = (l << 8) | int(data[hdr+i])
		}
		hdr += nbytes

		// Check the length is NOT representable in fewer bytes — i.e.
		// shortest form. Short form covers 0..127; long-form-1-byte
		// covers 128..255; etc.
		var minBytes int
		switch {
		case l < 0x80:
			minBytes = 0 // short form
		case l <= 0xff:
			minBytes = 1
		case l <= 0xffff:
			minBytes = 2
		case l <= 0xffffff:
			minBytes = 3
		default:
			minBytes = 4
		}
		if minBytes == 0 {
			return 0, nil, false, fmt.Errorf("long-form used for length %d (should be short form)", l)
		}
		if nbytes != minBytes {
			return 0, nil, false, fmt.Errorf("long-form length used %d bytes, minimum is %d (BER, not DER)", nbytes, minBytes)
		}
	}

	if len(data) < hdr+l {
		return 0, nil, false, fmt.Errorf("truncated value (have %d, want %d)", len(data)-hdr, l)
	}
	return hdr + l, data[hdr : hdr+l], constructed, nil
}

// appendDERLengthInline mirrors the appendDERLength helper in entry.go
// but is local to this test file so the test stays self-contained.
func appendDERLengthInline(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n <= 0xff:
		return append(b, 0x81, byte(n))
	case n <= 0xffff:
		return append(b, 0x82, byte(n>>8), byte(n))
	default:
		return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
}

// TestParseTLVStrictRejectsBER pins the parser's job: it must reject
// a DER-style message that has been re-encoded with a non-minimum
// length form.
func TestParseTLVStrictRejectsBER(t *testing.T) {
	// 0x04 0x81 0x05 ... is a 5-byte OCTET STRING in long form, but the
	// minimum form for length=5 is short form (just 0x04 0x05 ...).
	bad := []byte{0x04, 0x81, 0x05, 1, 2, 3, 4, 5}
	if _, _, _, err := parseTLVStrict(bad); err == nil {
		t.Errorf("expected BER-style length to be rejected")
	}
	// Indefinite length (0x80) must be rejected.
	indef := []byte{0x30, 0x80, 0x00, 0x00}
	if _, _, _, err := parseTLVStrict(indef); err == nil {
		t.Errorf("expected indefinite length to be rejected")
	}
}
