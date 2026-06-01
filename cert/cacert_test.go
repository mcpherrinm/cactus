package cert

import (
	"reflect"
	"testing"
)

func TestMTCCertificationAuthorityRoundTrip(t *testing.T) {
	// ecdsa-with-SHA256 = 1.2.840.10045.4.3.2
	sigAlg := []int{1, 2, 840, 10045, 4, 3, 2}
	ca := MTCCertificationAuthority{
		LogHash:   OIDDigestSHA256,
		SigAlg:    sigAlg,
		MinSerial: (1 << 48) | 5,
	}
	der, err := ca.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMTCCertificationAuthority(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LogHash.Equal(OIDDigestSHA256) {
		t.Errorf("logHash = %s, want %s", got.LogHash, OIDDigestSHA256)
	}
	if !got.SigAlg.Equal(sigAlg) {
		t.Errorf("sigAlg = %s", got.SigAlg)
	}
	if got.MinSerial != ca.MinSerial {
		t.Errorf("minSerial = %d, want %d", got.MinSerial, ca.MinSerial)
	}
}

func TestInitialRevokedRanges(t *testing.T) {
	ca := MTCCertificationAuthority{MinSerial: (1 << 48) | 3}
	rr := InitialRevokedRanges(ca)
	want := RevokedRanges{{Start: 0, End: (1 << 48) | 3}}
	if !reflect.DeepEqual(rr, want) {
		t.Fatalf("InitialRevokedRanges = %+v, want %+v", rr, want)
	}
	// A serial below minSerial is revoked; the boundary and above are not.
	if !rr.Contains((1 << 48) | 2) {
		t.Errorf("serial below minSerial should be revoked")
	}
	if rr.Contains((1 << 48) | 3) {
		t.Errorf("minSerial itself must not be revoked")
	}
	if rr.Contains((1 << 48) | 9) {
		t.Errorf("serial above minSerial must not be revoked")
	}

	// Zero minSerial → no initial revoked ranges.
	if got := InitialRevokedRanges(MTCCertificationAuthority{MinSerial: 0}); got != nil {
		t.Errorf("zero minSerial: got %+v, want nil", got)
	}
}
