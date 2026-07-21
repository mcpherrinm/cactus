package cert

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestTrustAnchorIDBinary pins the binary (RELATIVE-OID) representation
// used on the wire for MTCProof.cosigner_id (§6.2) and the
// trust_anchor_id property (TAI §7). draft-05 §5.1 gives the ground
// truth: trust anchor ID 32473.1 has RELATIVE-OID content octets
// 81 fd 59 01. (Regression for review finding 1.)
func TestTrustAnchorIDBinary(t *testing.T) {
	got, err := TrustAnchorID("32473.1").Binary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x81, 0xfd, 0x59, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("Binary(32473.1) = %x, want %x", got, want)
	}

	// Round-trips for a range of IDs, including derived log/landmark IDs.
	for _, s := range []string{
		"32473.1", "32473.1.0.1", "32473.1.1.8.42", "44363.47.1.99",
		"0", "127", "128", "16383", "16384",
	} {
		id := TrustAnchorID(s)
		bin, err := id.Binary()
		if err != nil {
			t.Fatalf("Binary(%q): %v", id, err)
		}
		back, err := TrustAnchorIDFromBinary(bin)
		if err != nil {
			t.Fatalf("FromBinary(%x): %v", bin, err)
		}
		if string(back) != string(id) {
			t.Errorf("round trip %q -> %x -> %q", id, bin, back)
		}
	}

	// Non-numeric components cannot be a relative OID and MUST error.
	for _, bad := range []string{"", "foo", "32473.ca", "32473..1", "32473.1."} {
		if _, err := TrustAnchorID(bad).Binary(); err == nil {
			t.Errorf("Binary(%q) = nil error, want error", bad)
		}
	}
	// Non-minimal / truncated binary encodings MUST be rejected.
	if _, err := TrustAnchorIDFromBinary([]byte{0x80, 0x01}); err == nil {
		t.Error("FromBinary(non-minimal) = nil error, want error")
	}
	if _, err := TrustAnchorIDFromBinary([]byte{0x81}); err == nil {
		t.Error("FromBinary(truncated) = nil error, want error")
	}
}

// TestOIDName pins the cosigner_name / log_origin ASCII encoding
// (§5.3.1): "oid/1.3.6.1.4.1." + the relative trust anchor ID.
// (Regression for review finding 2.)
func TestOIDName(t *testing.T) {
	if got := OIDName(TrustAnchorID("32473.1")); got != "oid/1.3.6.1.4.1.32473.1" {
		t.Errorf("OIDName(32473.1) = %q, want oid/1.3.6.1.4.1.32473.1", got)
	}
	if got := OIDName(TrustAnchorID("32473.1.0.8")); got != "oid/1.3.6.1.4.1.32473.1.0.8" {
		t.Errorf("OIDName(32473.1.0.8) = %q", got)
	}
}

// TestBuildCANameDN pins the §5.1 distinguished-name encoding: the CA ID
// 32473.1 is a single RDN with attribute type id-rdna-trustAnchorID
// (cactus experimental OID 1.3.6.1.4.1.44363.47.1) and a UTF8String value
// holding the *relative* trust anchor ID "32473.1". The spec gives the
// attribute value bytes as 0c0733323437332e31. (Regression for finding 2.)
func TestBuildCANameDN(t *testing.T) {
	dn, err := BuildCAName("32473.1")
	if err != nil {
		t.Fatal(err)
	}
	const wantHex = "301931173015060a2b0601040182da4b2f010c0733323437332e31"
	if got := hex.EncodeToString(dn); got != wantHex {
		t.Errorf("BuildCAName(32473.1) DER =\n  %s\nwant\n  %s", got, wantHex)
	}
	// The DN must round-trip back to the relative form via parseCANameDN.
	id, err := parseCANameDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	if string(id) != "32473.1" {
		t.Errorf("parseCANameDN = %q, want 32473.1", id)
	}
}
