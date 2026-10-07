package cert

import "testing"

func TestDecodeBase64RejectsNonCanonical(t *testing.T) {
	for _, ok := range []string{"", "AA==", "AAA=", "AAAA", "/w=="} {
		if _, err := DecodeBase64(ok); err != nil {
			t.Errorf("DecodeBase64(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{
		"AB==",   // non-zero padding bits
		"AAB=",   // non-zero padding bits
		"AA",     // missing padding
		"AA\nAA", // embedded newline
		"A A=",   // not base64
	} {
		if _, err := DecodeBase64(bad); err == nil {
			t.Errorf("DecodeBase64(%q) succeeded", bad)
		}
	}
}

func TestParseDecimal(t *testing.T) {
	for in, want := range map[string]uint64{"0": 0, "7": 7, "1234": 1234, "18446744073709551615": 1<<64 - 1} {
		if got, err := ParseDecimal(in); err != nil || got != want {
			t.Errorf("ParseDecimal(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "00", "07", "+7", "-1", " 7", "7 ", "1e3", "18446744073709551616"} {
		if _, err := ParseDecimal(bad); err == nil {
			t.Errorf("ParseDecimal(%q) succeeded", bad)
		}
	}
}
