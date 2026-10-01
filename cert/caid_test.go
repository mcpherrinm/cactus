package cert

import "testing"

// TestComposeSerialMaxIndex pins §5.2: a log holds at most 2^48-1
// entries, so the largest index is 2^48-2.
func TestComposeSerialMaxIndex(t *testing.T) {
	if s, err := ComposeSerial(1, 1<<48-2); err != nil || s != 1<<49-2 {
		t.Errorf("ComposeSerial(1, 2^48-2) = %d, %v", s, err)
	}
	if _, err := ComposeSerial(1, 1<<48-1); err == nil {
		t.Error("ComposeSerial(1, 2^48-1) succeeded")
	}
}

// TestLandmarkGroupPatterns checks the §8.2.1 example: a CA with ID
// 32473.100 issues a certificate in landmark 42 of log 8, and a relying
// party up to date as of that landmark sends 32473.100.2.8.42, which
// selects every standalone certificate and landmarks 0 through 42 of log 8.
func TestLandmarkGroupPatterns(t *testing.T) {
	caID := TrustAnchorID("32473.100")
	standalone := StandaloneGroupPattern(caID)
	if got := standalone.String(); got != "32473.100.2.{0-}.{0-}" {
		t.Errorf("StandaloneGroupPattern = %s", got)
	}
	landmark42 := LandmarkGroupPattern(caID, 8, 42)
	if got := landmark42.String(); got != "32473.100.2.8.{42-}" {
		t.Errorf("LandmarkGroupPattern = %s", got)
	}
	if got := string(LandmarkID(caID, 8, 42)); got != "32473.100.1.8.42" {
		t.Errorf("LandmarkID = %s", got)
	}

	group := LandmarkGroupID(caID, 8, 42)
	if string(group) != "32473.100.2.8.42" {
		t.Fatalf("LandmarkGroupID = %s", group)
	}
	if !standalone.Contains(group) || !standalone.Contains(LandmarkGroupID(caID, 3, 0)) {
		t.Error("standalone pattern should match every landmark group of the CA")
	}
	if !landmark42.Contains(group) || !LandmarkGroupPattern(caID, 8, 23).Contains(group) {
		t.Error("group 42 should select landmarks up to 42")
	}
	if LandmarkGroupPattern(caID, 8, 43).Contains(group) {
		t.Error("group 42 should not select landmark 43")
	}
	if landmark42.Contains(LandmarkGroupID(caID, 9, 42)) {
		t.Error("log 8's landmark should not match log 9's group")
	}
}

// TestTrustAnchorIDLengthLimit pins the TAI §4 32-byte cap on the binary
// representation.
func TestTrustAnchorIDLengthLimit(t *testing.T) {
	const id = "1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1"
	if _, err := TrustAnchorID(id).Binary(); err != nil {
		t.Errorf("32-byte ID rejected: %v", err)
	}
	if _, err := TrustAnchorID(id + ".1").Binary(); err == nil {
		t.Error("33-byte ID accepted")
	}
}
