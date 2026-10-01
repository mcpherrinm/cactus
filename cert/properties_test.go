package cert

import (
	"bytes"
	"encoding/base64"
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
	// §9.2: a landmark-relative certificate's property list carries the
	// individual landmark's trust anchor ID (CA-ID.1.logNumber.L), its
	// landmark group pattern (CA-ID.2.logNumber.{L-}), and
	// trust_anchor_negotiation.
	props := []CertificateProperty{
		{Type: PropertyTrustAnchorID, TrustAnchorID: TrustAnchorID("32473.1.1.8.42")},
		{Type: PropertyTrustAnchorGroups, Patterns: []TrustAnchorIDPattern{LandmarkGroupPattern(TrustAnchorID("32473.1"), 8, 42)}},
		{Type: PropertyTrustAnchorNegotiation},
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

// TestPropertyListTAIExample checks the CertificatePropertyList from the
// PEM example in draft-ietf-tls-trust-anchor-ids-06 §7.4: trust_anchor_id
// 32473.1, trust_anchor_groups 2187.2.{100-200} and
// 32473.3.{42-}.{100-200}, and trust_anchor_negotiation.
func TestPropertyListTAIExample(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString("ACoAAAAEgf1ZAQABABoAGAmRC5ELAgJkgUgNgf1Zgf1ZAwMqgGSBSAACAAA=")
	if err != nil {
		t.Fatal(err)
	}
	want := []CertificateProperty{
		{Type: PropertyTrustAnchorID, TrustAnchorID: TrustAnchorID("32473.1")},
		{Type: PropertyTrustAnchorGroups, Patterns: []TrustAnchorIDPattern{
			MustParseTrustAnchorIDPattern("2187.2.{100-200}"),
			MustParseTrustAnchorIDPattern("32473.3.{42-}.{100-200}"),
		}},
		{Type: PropertyTrustAnchorNegotiation},
	}
	got, err := ParsePropertyList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParsePropertyList =\n %+v\nwant\n %+v", got, want)
	}
	enc, err := BuildPropertyList(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, raw) {
		t.Errorf("BuildPropertyList = %x, want %x", enc, raw)
	}
}

// TestParsePropertyListKeepsUnknown checks that an unrecognized property
// type is passed through rather than rejected (TAI §7).
func TestParsePropertyListKeepsUnknown(t *testing.T) {
	raw := []byte{0x00, 0x07, 0x12, 0x34, 0x00, 0x03, 0xaa, 0xbb, 0xcc}
	got, err := ParsePropertyList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != 0x1234 || !bytes.Equal(got[0].Data, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("ParsePropertyList = %+v", got)
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
