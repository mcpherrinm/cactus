package cert

import (
	"bytes"
	"testing"
)

// TestTrustAnchorIDPatternTAIExample checks the example from
// draft-ietf-tls-trust-anchor-ids-06 §5.3.1.
func TestTrustAnchorIDPatternTAIExample(t *testing.T) {
	p, err := ParseTrustAnchorIDPattern("32473.{123-456}.{789-}")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "32473.{123-456}.{789-}" {
		t.Errorf("String = %q", got)
	}
	bin, err := p.Binary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x81, 0xfd, 0x59, 0x81, 0xfd, 0x59, 0x7b, 0x83, 0x48, 0x86, 0x15, 0x80}
	if !bytes.Equal(bin, want) {
		t.Errorf("Binary = %x, want %x", bin, want)
	}
	back, err := TrustAnchorIDPatternFromBinary(bin)
	if err != nil {
		t.Fatal(err)
	}
	if back.String() != p.String() {
		t.Errorf("binary round trip = %s", back)
	}
	for _, id := range []string{"32473.123.789", "32473.300.900", "32473.456.99999"} {
		if !p.Contains(TrustAnchorID(id)) {
			t.Errorf("pattern does not contain %s", id)
		}
	}
	for _, id := range []string{"32473.123", "32473.123.789.0", "32474.123.789", "32473.500.789", "32473.123.700"} {
		if p.Contains(TrustAnchorID(id)) {
			t.Errorf("pattern contains %s", id)
		}
	}
}

func TestTrustAnchorIDPatternRejects(t *testing.T) {
	for _, s := range []string{"", "1..2", "{1-", "{2-1}", "01", "{1}", "a.b", "1.{-2}"} {
		if _, err := ParseTrustAnchorIDPattern(s); err == nil {
			t.Errorf("ParseTrustAnchorIDPattern(%q) succeeded", s)
		}
	}
	for _, b := range [][]byte{
		nil,
		{0x01},             // min without max
		{0x80, 0x01, 0x01}, // non-minimal min
		{0x01, 0x81},       // truncated max
		{0x05, 0x04},       // max below min
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x80}, // overflow
	} {
		if _, err := TrustAnchorIDPatternFromBinary(b); err == nil {
			t.Errorf("TrustAnchorIDPatternFromBinary(%x) succeeded", b)
		}
	}
}
