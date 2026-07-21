package cert

import (
	"bytes"
	"encoding/pem"
	"reflect"
	"testing"
)

// TestPropertyTrustAnchorIDBodyIsBinary pins TAI §7: the trust_anchor_id
// property body is the trust anchor ID's binary representation, not its
// ASCII form. (Regression for review finding 1.)
func TestPropertyTrustAnchorIDBodyIsBinary(t *testing.T) {
	raw, err := BuildPropertyList([]CertificateProperty{
		{Type: PropertyTrustAnchorID, TrustAnchorID: TrustAnchorID("32473.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte{0x81, 0xfd, 0x59, 0x01}) {
		t.Errorf("property list %x missing binary trust anchor ID 81fd5901", raw)
	}
	if bytes.Contains(raw, []byte("32473.1")) {
		t.Error("property list contains ASCII trust anchor ID; TAI §7 requires binary")
	}
}

func TestPropertyListRoundTripStandalone(t *testing.T) {
	props := []CertificateProperty{
		{
			Type:          PropertyTrustAnchorID,
			TrustAnchorID: TrustAnchorID("32473.1"),
		},
	}
	raw, err := BuildPropertyList(props)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePropertyList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, props) {
		t.Errorf("round trip differs:\n got %+v\nwant %+v", got, props)
	}
}

func TestPropertyListRoundTripLandmark(t *testing.T) {
	// draft-05 §8.2: a landmark-relative certificate's property list
	// carries only the individual landmark's trust anchor ID
	// (CA-ID.1.logNumber.L); the additional_trust_anchor_ranges property
	// was removed.
	props := []CertificateProperty{
		{
			Type:          PropertyTrustAnchorID,
			TrustAnchorID: TrustAnchorID("32473.1.1.8.42"),
		},
	}
	raw, err := BuildPropertyList(props)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePropertyList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, props) {
		t.Errorf("round trip differs:\n got %+v\nwant %+v", got, props)
	}
}

func TestBuildPropertyListRejectsEmpty(t *testing.T) {
	if _, err := BuildPropertyList(nil); err == nil {
		t.Error("expected error for empty list")
	}
}

func TestBuildPropertyListRejectsTooLongTAID(t *testing.T) {
	props := []CertificateProperty{
		{
			Type:          PropertyTrustAnchorID,
			TrustAnchorID: make(TrustAnchorID, 256),
		},
	}
	if _, err := BuildPropertyList(props); err == nil {
		t.Error("expected error for too-long trust anchor ID")
	}
}

func TestEncodePEMWithProperties(t *testing.T) {
	certDER := []byte{0x30, 0x03, 0x02, 0x01, 0x01} // tiny dummy
	props := []CertificateProperty{{
		Type: PropertyTrustAnchorID, TrustAnchorID: TrustAnchorID("32473.1"),
	}}
	pl, err := BuildPropertyList(props)
	if err != nil {
		t.Fatal(err)
	}
	body := EncodePEMWithProperties(certDER, pl)

	// Decode both blocks. Per trust-anchor-ids §6.1 the property list
	// comes first and the certificate second.
	rest := body
	block1, rest := pem.Decode(rest)
	if block1 == nil || block1.Type != PEMBlockProperties {
		t.Fatalf("first block bad: %+v", block1)
	}
	block2, _ := pem.Decode(rest)
	if block2 == nil || block2.Type != "CERTIFICATE" {
		t.Fatalf("second block bad: %+v", block2)
	}

	// Property block decodes back to original property list.
	got, err := ParsePropertyList(block1.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, props) {
		t.Errorf("decoded properties differ from original")
	}
}

func TestEncodePEMWithoutProperties(t *testing.T) {
	certDER := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	body := EncodePEMWithProperties(certDER, nil)
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("missing CERTIFICATE block")
	}
	// No second block.
	if block2, _ := pem.Decode(rest); block2 != nil {
		t.Errorf("expected only one block, got %+v", block2)
	}
}
