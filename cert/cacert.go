package cert

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// This file implements the draft-04 §5.5 "Representing Certification
// Authorities" X.509 extension and the relying-party configuration a
// CA certificate carries (§7.1).

// OIDDigestSHA256 is id-sha256 (NIST), used as the logHash algorithm
// identifier for a CA whose issuance logs hash with SHA-256.
var OIDDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// algorithmIdentifier is a PKIX AlgorithmIdentifier with optional
// parameters (RFC 5280 §4.1.1.2).
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// mtcCertificationAuthorityASN1 mirrors the §5.5 / Appendix A SEQUENCE:
//
//	MTCCertificationAuthority ::= SEQUENCE {
//	    logHash   AlgorithmIdentifier{DIGEST-ALGORITHM, {...}},
//	    sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
//	    minSerial INTEGER
//	}
type mtcCertificationAuthorityASN1 struct {
	LogHash   algorithmIdentifier
	SigAlg    algorithmIdentifier
	MinSerial *big.Int
}

// MTCCertificationAuthority is the decoded content of the critical
// id-pe-mtcCertificationAuthority extension (§5.5). It carries the
// parameters a relying party needs to derive its configuration (§7.1):
// the hash algorithm all of the CA's logs use, the CA cosigner's
// signature algorithm, and the minimum valid serial number.
type MTCCertificationAuthority struct {
	// LogHash is the algorithm identifier of the hash used by all the
	// CA's issuance logs (e.g. id-sha256).
	LogHash asn1.ObjectIdentifier
	// SigAlg is the CA cosigner's PKIX signature algorithm identifier.
	SigAlg asn1.ObjectIdentifier
	// MinSerial is the smallest serial number the CA will not have
	// pruned; serials in [0, MinSerial) are treated as revoked (§7.1).
	MinSerial uint64
}

// Marshal returns the DER encoding of the MTCCertificationAuthority
// extension value (the bytes that go inside the extension's OCTET
// STRING). Both algorithm identifiers are emitted with absent
// parameters.
func (m MTCCertificationAuthority) Marshal() ([]byte, error) {
	if len(m.LogHash) == 0 {
		return nil, fmt.Errorf("cert: MTCCertificationAuthority logHash unset")
	}
	if len(m.SigAlg) == 0 {
		return nil, fmt.Errorf("cert: MTCCertificationAuthority sigAlg unset")
	}
	v := mtcCertificationAuthorityASN1{
		LogHash:   algorithmIdentifier{Algorithm: m.LogHash},
		SigAlg:    algorithmIdentifier{Algorithm: m.SigAlg},
		MinSerial: new(big.Int).SetUint64(m.MinSerial),
	}
	return asn1.Marshal(v)
}

// ParseMTCCertificationAuthority decodes the DER of an
// MTCCertificationAuthority extension value.
func ParseMTCCertificationAuthority(der []byte) (MTCCertificationAuthority, error) {
	var v mtcCertificationAuthorityASN1
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return MTCCertificationAuthority{}, fmt.Errorf("cert: parse MTCCertificationAuthority: %w", err)
	}
	if len(rest) != 0 {
		return MTCCertificationAuthority{}, fmt.Errorf("cert: %d trailing bytes after MTCCertificationAuthority", len(rest))
	}
	if v.MinSerial == nil || v.MinSerial.Sign() < 0 {
		return MTCCertificationAuthority{}, fmt.Errorf("cert: MTCCertificationAuthority minSerial missing or negative")
	}
	if !v.MinSerial.IsUint64() {
		return MTCCertificationAuthority{}, fmt.Errorf("cert: MTCCertificationAuthority minSerial %s does not fit in uint64", v.MinSerial)
	}
	return MTCCertificationAuthority{
		LogHash:   v.LogHash.Algorithm,
		SigAlg:    v.SigAlg.Algorithm,
		MinSerial: v.MinSerial.Uint64(),
	}, nil
}

// RevokedRange is a half-open range [Start, End) of certificate serial
// numbers (§7.5). Because a serial number packs a log number and an
// entry index, a single range can revoke entries within a log or whole
// logs at once.
type RevokedRange struct {
	Start, End uint64
}

// RevokedRanges is a relying party's list of revoked serial-number
// ranges (§7.5).
type RevokedRanges []RevokedRange

// InitialRevokedRanges returns the revoked ranges implied by a CA
// certificate's minSerial (§7.1): serials in [0, minSerial) are
// revoked. Relying parties may extend this list out-of-band.
func InitialRevokedRanges(ca MTCCertificationAuthority) RevokedRanges {
	if ca.MinSerial == 0 {
		return nil
	}
	return RevokedRanges{{Start: 0, End: ca.MinSerial}}
}

// Contains reports whether serial falls in any revoked range.
func (r RevokedRanges) Contains(serial uint64) bool {
	for _, rr := range r {
		if serial >= rr.Start && serial < rr.End {
			return true
		}
	}
	return false
}
