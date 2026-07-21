package cert

import (
	"encoding/asn1"
	"math"
	"math/big"
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
		MaxSerial: (9 << 48) | 7,
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
	if got.MaxSerial != ca.MaxSerial {
		t.Errorf("maxSerial = %d, want %d", got.MaxSerial, ca.MaxSerial)
	}
}

// A draft-04 extension (no maxSerial) must be rejected rather than
// silently parsed with a zero maxSerial, which would revoke everything.
func TestMTCCertificationAuthorityRejectsDraft04(t *testing.T) {
	der, err := asn1.Marshal(struct {
		LogHash   algorithmIdentifier
		SigAlg    algorithmIdentifier
		MinSerial *big.Int
	}{
		LogHash:   algorithmIdentifier{Algorithm: OIDDigestSHA256},
		SigAlg:    algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		MinSerial: big.NewInt(5),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMTCCertificationAuthority(der); err == nil {
		t.Error("draft-04 MTCCertificationAuthority (no maxSerial) parsed without error")
	}
}

func TestMTCCertificationAuthorityRejectsMaxBelowMin(t *testing.T) {
	_, err := MTCCertificationAuthority{
		LogHash:   OIDDigestSHA256,
		SigAlg:    asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		MinSerial: 10,
		MaxSerial: 9,
	}.Marshal()
	if err == nil {
		t.Error("maxSerial below minSerial marshalled without error")
	}
}

func TestInitialRevokedRanges(t *testing.T) {
	ca := MTCCertificationAuthority{MinSerial: (1 << 48) | 3, MaxSerial: math.MaxUint64}
	rr := InitialRevokedRanges(ca)
	// Ranges are closed, so the lower range ends at minSerial-1.
	want := RevokedRanges{{Start: 0, End: (1 << 48) | 2}}
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

	// No bounds at all → no initial revoked ranges.
	if got := InitialRevokedRanges(MTCCertificationAuthority{MinSerial: 0, MaxSerial: math.MaxUint64}); got != nil {
		t.Errorf("unbounded CA: got %+v, want nil", got)
	}
}

// §7.1's upper revoked range is [maxSerial+1, 2^64). The exclusive end
// is not representable in a uint64, so the closed-range encoding must
// still revoke the very last serial, 2^64-1.
func TestInitialRevokedRangesUpperBound(t *testing.T) {
	const maxSerial = (3 << 48) | 7
	ca := MTCCertificationAuthority{MinSerial: 0, MaxSerial: maxSerial}
	rr := InitialRevokedRanges(ca)
	want := RevokedRanges{{Start: maxSerial + 1, End: math.MaxUint64}}
	if !reflect.DeepEqual(rr, want) {
		t.Fatalf("InitialRevokedRanges = %+v, want %+v", rr, want)
	}
	if rr.Contains(maxSerial) {
		t.Errorf("maxSerial itself must not be revoked")
	}
	if !rr.Contains(maxSerial + 1) {
		t.Errorf("serial just above maxSerial must be revoked")
	}
	// The regression this encoding exists to prevent.
	if !rr.Contains(math.MaxUint64) {
		t.Errorf("serial 2^64-1 must be revoked")
	}
}

// Both bounds together, as a relying party would see them.
func TestInitialRevokedRangesBothBounds(t *testing.T) {
	ca := MTCCertificationAuthority{MinSerial: 100, MaxSerial: 200}
	rr := InitialRevokedRanges(ca)
	if len(rr) != 2 {
		t.Fatalf("got %d ranges, want 2: %+v", len(rr), rr)
	}
	for _, s := range []uint64{0, 99, 201, math.MaxUint64} {
		if !rr.Contains(s) {
			t.Errorf("serial %d should be revoked", s)
		}
	}
	for _, s := range []uint64{100, 150, 200} {
		if rr.Contains(s) {
			t.Errorf("serial %d should not be revoked", s)
		}
	}
}
