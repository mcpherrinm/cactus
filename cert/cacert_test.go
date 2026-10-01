package cert

import (
	"bytes"
	"encoding/asn1"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestMTCCertificationAuthorityRoundTrip(t *testing.T) {
	// ecdsa-with-SHA256 = 1.2.840.10045.4.3.2
	sigAlg := []int{1, 2, 840, 10045, 4, 3, 2}
	ca := MTCCertificationAuthority{
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

// A draft-05 extension (with the logHash field draft-06 removed) must be
// rejected rather than misparsed: its first field is an
// AlgorithmIdentifier where sigAlg is expected, and it has an extra
// trailing INTEGER.
func TestMTCCertificationAuthorityRejectsDraft05(t *testing.T) {
	der, err := asn1.Marshal(struct {
		LogHash   algorithmIdentifier
		SigAlg    algorithmIdentifier
		MinSerial *big.Int
		MaxSerial *big.Int
	}{
		LogHash:   algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		SigAlg:    algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		MinSerial: big.NewInt(1 << 48),
		MaxSerial: new(big.Int).SetUint64(math.MaxUint64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMTCCertificationAuthority(der); err == nil {
		t.Error("draft-05 MTCCertificationAuthority (with logHash) parsed without error")
	}
}

func TestMTCCertificationAuthorityRejectsMaxBelowMin(t *testing.T) {
	_, err := MTCCertificationAuthority{
		SigAlg:    asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		MinSerial: 10 << 48,
		MaxSerial: 9 << 48,
	}.Marshal()
	if err == nil {
		t.Error("maxSerial below minSerial marshalled without error")
	}
}

// §5.5 constrains both serial bounds to (mtcMinSerial..mtcMaxSerial):
// no serial below 2^48 (log number 0) is valid.
func TestMTCCertificationAuthoritySerialBelowMin(t *testing.T) {
	sigAlg := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	if _, err := (MTCCertificationAuthority{SigAlg: sigAlg, MinSerial: 0, MaxSerial: math.MaxUint64}).Marshal(); err == nil {
		t.Error("minSerial 0 marshalled without error")
	}
	der, err := asn1.Marshal(mtcCertificationAuthorityASN1{
		SigAlg:    algorithmIdentifier{Algorithm: sigAlg},
		MinSerial: big.NewInt(1<<48 - 1),
		MaxSerial: new(big.Int).SetUint64(math.MaxUint64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMTCCertificationAuthority(der); err == nil {
		t.Error("minSerial 2^48-1 parsed without error")
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

// TestPrefixURLsExtension pins the c2sp.org/mtc-tlog
// id-mtcTlogPrefixURLs encoding (SEQUENCE OF IA5String) and checks it
// round-trips through a CA certificate into the relying-party config.
func TestPrefixURLsExtension(t *testing.T) {
	der, err := MarshalPrefixURLs([]string{"https://a.test", "b"})
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x30, 0x13, 0x16, 0x0e}, append([]byte("https://a.test"), 0x16, 0x01, 'b')...)
	if !bytes.Equal(der, want) {
		t.Errorf("MarshalPrefixURLs = %x, want %x", der, want)
	}
	for _, bad := range [][]string{nil, {""}, {"https://ä.test"}} {
		if _, err := MarshalPrefixURLs(bad); err == nil {
			t.Errorf("MarshalPrefixURLs(%q) succeeded", bad)
		}
	}
	if _, err := ParsePrefixURLs([]byte{0x30, 0x00}); err == nil {
		t.Error("ParsePrefixURLs accepted an empty SEQUENCE")
	}

	spki, err := MarshalCosignerSPKI(AlgMLDSA44, make([]byte, 1312))
	if err != nil {
		t.Fatal(err)
	}
	sigAlg, err := SigAlgOID(AlgMLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	in := CACertificateInput{
		CAID:         TrustAnchorID("32473.1"),
		CosignerSPKI: spki,
		SigAlg:       sigAlg,
		MinSerial:    MTCMinSerial,
		MaxSerial:    MTCMaxSerial,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	caDER, err := BuildCACertificate(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFromCACertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrefixURLs != nil {
		t.Errorf("PrefixURLs = %q without the extension", cfg.PrefixURLs)
	}

	in.PrefixURLs = []string{"https://ca.test/mtc"}
	if caDER, err = BuildCACertificate(in); err != nil {
		t.Fatal(err)
	}
	if cfg, err = ConfigFromCACertificate(caDER); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.PrefixURLs, in.PrefixURLs) {
		t.Errorf("PrefixURLs = %q, want %q", cfg.PrefixURLs, in.PrefixURLs)
	}
}
