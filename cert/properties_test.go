package cert

import (
	"encoding/pem"
	"reflect"
	"testing"
)

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
	props := []CertificateProperty{
		{
			Type:          PropertyTrustAnchorID,
			TrustAnchorID: TrustAnchorID("32473.1.lm.42"),
		},
		{
			Type: PropertyAdditionalTAnchorRanges,
			Ranges: []TrustAnchorRange{{
				Base: TrustAnchorID("32473.1.lm"),
				Min:  42,
				Max:  42 + 168, // max_active - 1 for 169-active
			}},
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

func TestBuildPropertyListRejectsBadRange(t *testing.T) {
	props := []CertificateProperty{
		{
			Type: PropertyAdditionalTAnchorRanges,
			Ranges: []TrustAnchorRange{{
				Base: TrustAnchorID("32473.1.lm"),
				Min:  100, Max: 50, // inverted
			}},
		},
	}
	if _, err := BuildPropertyList(props); err == nil {
		t.Error("expected error for inverted range")
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

	// Decode both blocks.
	rest := body
	block1, rest := pem.Decode(rest)
	if block1 == nil || block1.Type != "CERTIFICATE" {
		t.Fatalf("first block bad: %+v", block1)
	}
	block2, _ := pem.Decode(rest)
	if block2 == nil || block2.Type != PEMBlockProperties {
		t.Fatalf("second block bad: %+v", block2)
	}

	// Property block decodes back to original property list.
	got, err := ParsePropertyList(block2.Bytes)
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
