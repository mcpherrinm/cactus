package cert

import (
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OIDAlgUnsigned is id-alg-unsigned from [RFC9925] ("Unsigned X.509
// Certificates"). A CA certificate representing a trust anchor SHOULD
// NOT be self-signed (§5.5); cactus emits it as an unsigned certificate:
// signatureAlgorithm is id-alg-unsigned with absent parameters and the
// signatureValue is a zero-length BIT STRING.
var OIDAlgUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}

// X.509 v3 extension OIDs used by a CA certificate (§5.5 / RFC 5280).
var (
	oidExtSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
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

// mtcMaxSerial is the §5.5 / Appendix A bound on serial numbers: 2^64-1,
// the largest serial this protocol can express.
const mtcMaxSerial = math.MaxUint64

// mtcCertificationAuthorityASN1 mirrors the §5.5 / Appendix A SEQUENCE:
//
//	MTCCertificationAuthority ::= SEQUENCE {
//	    logHash   AlgorithmIdentifier{DIGEST-ALGORITHM, {...}},
//	    sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
//	    minSerial INTEGER (0..mtcMaxSerial),
//	    maxSerial INTEGER (0..mtcMaxSerial)
//	}
//
// maxSerial is new in draft-05. Because it is a required field, -04 and
// -05 encodings are mutually unparseable: a -05 parser rejects a -04
// extension as truncated, and a -04 parser rejects a -05 one as having
// trailing data. Any previously issued CA certificate must be reissued.
type mtcCertificationAuthorityASN1 struct {
	LogHash   algorithmIdentifier
	SigAlg    algorithmIdentifier
	MinSerial *big.Int
	MaxSerial *big.Int
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
	// MaxSerial is the largest serial number the CA will issue; serials
	// in [MaxSerial+1, 2^64) are treated as revoked (§7.1). Because a
	// serial packs a log number and an entry index (§5.2.3), an upper
	// bound on serials is also an upper bound on log numbers, which a
	// relying party can use to bound its monitoring scope (§7.5).
	MaxSerial uint64
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
	if m.MaxSerial < m.MinSerial {
		return nil, fmt.Errorf("cert: MTCCertificationAuthority maxSerial %d below minSerial %d", m.MaxSerial, m.MinSerial)
	}
	v := mtcCertificationAuthorityASN1{
		LogHash:   algorithmIdentifier{Algorithm: m.LogHash},
		SigAlg:    algorithmIdentifier{Algorithm: m.SigAlg},
		MinSerial: new(big.Int).SetUint64(m.MinSerial),
		MaxSerial: new(big.Int).SetUint64(m.MaxSerial),
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
	minSerial, err := serialBound("minSerial", v.MinSerial)
	if err != nil {
		return MTCCertificationAuthority{}, err
	}
	maxSerial, err := serialBound("maxSerial", v.MaxSerial)
	if err != nil {
		return MTCCertificationAuthority{}, err
	}
	if maxSerial < minSerial {
		return MTCCertificationAuthority{}, fmt.Errorf("cert: MTCCertificationAuthority maxSerial %d below minSerial %d", maxSerial, minSerial)
	}
	return MTCCertificationAuthority{
		LogHash:   v.LogHash.Algorithm,
		SigAlg:    v.SigAlg.Algorithm,
		MinSerial: minSerial,
		MaxSerial: maxSerial,
	}, nil
}

// serialBound range-checks one of the INTEGER (0..mtcMaxSerial) serial
// bounds from the §5.5 SEQUENCE.
func serialBound(name string, v *big.Int) (uint64, error) {
	if v == nil || v.Sign() < 0 {
		return 0, fmt.Errorf("cert: MTCCertificationAuthority %s missing or negative", name)
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("cert: MTCCertificationAuthority %s %s exceeds %d", name, v, uint64(mtcMaxSerial))
	}
	return v.Uint64(), nil
}

// RevokedRange is a closed range [Start, End] of certificate serial
// numbers (§7.5). Because a serial number packs a log number and an
// entry index, a single range can revoke entries within a log or whole
// logs at once.
//
// The range is closed rather than half-open so that the upper revoked
// range from §7.1, [maxSerial+1, 2^64), is representable: a half-open
// uint64 range cannot express an exclusive end of 2^64, and clamping it
// to 2^64-1 would silently leave the largest serial unrevoked.
type RevokedRange struct {
	Start, End uint64
}

// RevokedRanges is a relying party's list of revoked serial-number
// ranges (§7.5).
type RevokedRanges []RevokedRange

// InitialRevokedRanges returns the revoked ranges implied by a CA
// certificate's minSerial and maxSerial (§7.1): serials in
// [0, minSerial) and [maxSerial+1, 2^64) are revoked. Either range is
// omitted when it is empty. Relying parties may extend this list
// out-of-band.
func InitialRevokedRanges(ca MTCCertificationAuthority) RevokedRanges {
	var out RevokedRanges
	if ca.MinSerial > 0 {
		out = append(out, RevokedRange{Start: 0, End: ca.MinSerial - 1})
	}
	if ca.MaxSerial < mtcMaxSerial {
		out = append(out, RevokedRange{Start: ca.MaxSerial + 1, End: mtcMaxSerial})
	}
	return out
}

// Contains reports whether serial falls in any revoked range.
func (r RevokedRanges) Contains(serial uint64) bool {
	for _, rr := range r {
		if serial >= rr.Start && serial <= rr.End {
			return true
		}
	}
	return false
}

// CACertificateInput carries the fields needed to build a §5.5 CA
// certificate. The certificate identifies a Merkle Tree Certificate CA
// so a relying party can derive its configuration (§7.1).
type CACertificateInput struct {
	// CAID is the CA's CA ID (§5.1) in canonical relative form. It is
	// the certificate's subject (and issuer) and its subjectKeyId.
	CAID TrustAnchorID
	// CosignerSPKI is the DER SubjectPublicKeyInfo of the CA cosigner
	// (§5.4) — the certificate's subjectPublicKeyInfo.
	CosignerSPKI []byte
	// LogHash is the hash algorithm used by all of the CA's logs (the
	// MTCCertificationAuthority.logHash, e.g. OIDDigestSHA256).
	LogHash asn1.ObjectIdentifier
	// SigAlg is the CA cosigner's PKIX signature algorithm OID
	// (MTCCertificationAuthority.sigAlg).
	SigAlg asn1.ObjectIdentifier
	// MinSerial is the minimum valid serial number (§5.2.3 / §7.1).
	MinSerial uint64
	// MaxSerial is the maximum valid serial number (§7.1 / §7.5).
	MaxSerial           uint64
	NotBefore, NotAfter time.Time
}

// pkixExtension is one X.509 v3 extension. asn1.Marshal of this struct
// yields an Extension SEQUENCE { extnID, critical, extnValue }; Value is
// emitted as the extnValue OCTET STRING.
type pkixExtension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// BuildCACertificate builds the §5.5 X.509 representation of a Merkle
// Tree Certificate CA as an *unsigned* certificate ([RFC9925]): the
// subject and issuer are the CA ID DN (§5.1), the subjectPublicKeyInfo
// is the CA cosigner key, and the extensions carry a critical
// id-pe-mtcCertificationAuthority (§5.5), a critical basicConstraints
// with cA=TRUE, a critical keyUsage asserting keyCertSign, and a
// subjectKeyId set to the CA ID's binary representation. The
// signatureAlgorithm is id-alg-unsigned and the signatureValue is a
// zero-length BIT STRING.
func BuildCACertificate(in CACertificateInput) ([]byte, error) {
	if len(in.CAID) == 0 {
		return nil, fmt.Errorf("cert: CA certificate needs a CA ID")
	}
	if len(in.CosignerSPKI) == 0 {
		return nil, fmt.Errorf("cert: CA certificate needs a cosigner SPKI")
	}
	dn, err := BuildCAName(string(in.CAID))
	if err != nil {
		return nil, err
	}
	binID, err := in.CAID.Binary()
	if err != nil {
		return nil, fmt.Errorf("cert: CA ID: %w", err)
	}

	mtcExtVal, err := MTCCertificationAuthority{
		LogHash:   in.LogHash,
		SigAlg:    in.SigAlg,
		MinSerial: in.MinSerial,
		MaxSerial: in.MaxSerial,
	}.Marshal()
	if err != nil {
		return nil, err
	}
	bcVal, err := asn1.Marshal(struct {
		CA bool `asn1:"optional"`
	}{CA: true})
	if err != nil {
		return nil, err
	}
	// keyUsage with only keyCertSign (bit 5) set.
	kuVal, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
	if err != nil {
		return nil, err
	}
	skiVal, err := asn1.Marshal(binID) // SubjectKeyIdentifier ::= OCTET STRING
	if err != nil {
		return nil, err
	}
	extsDER, err := asn1.Marshal([]pkixExtension{
		{ID: oidExtBasicConstraints, Critical: true, Value: bcVal},
		{ID: oidExtKeyUsage, Critical: true, Value: kuVal},
		{ID: OIDExtMTCCertificationAuthority, Critical: true, Value: mtcExtVal},
		{ID: oidExtSubjectKeyID, Value: skiVal},
	})
	if err != nil {
		return nil, err
	}

	algID, err := asn1.Marshal(struct{ Algorithm asn1.ObjectIdentifier }{Algorithm: OIDAlgUnsigned})
	if err != nil {
		return nil, err
	}
	validityDER, err := encodeValidity(in.NotBefore, in.NotAfter)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	// version [0] EXPLICIT INTEGER (v3 = 2)
	b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
		c.AddASN1Int64(2)
	})
	b.AddASN1BigInt(big.NewInt(1)) // serialNumber (cosmetic for an unsigned cert)
	b.AddBytes(algID)              // signature AlgorithmIdentifier (id-alg-unsigned)
	b.AddBytes(dn)                 // issuer = CA ID DN (self-issued name)
	b.AddBytes(validityDER)        // validity
	b.AddBytes(dn)                 // subject = CA ID DN
	b.AddBytes(in.CosignerSPKI)    // subjectPublicKeyInfo
	// extensions [3] EXPLICIT Extensions
	b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
		c.AddBytes(extsDER)
	})
	tbsBody, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	tbsCert := wrapSequence(tbsBody)

	var outer cryptobyte.Builder
	outer.AddBytes(tbsCert)
	outer.AddBytes(algID)
	outer.AddASN1BitString(nil) // zero-length signatureValue (unsigned, RFC 9925)
	outerBody, err := outer.Bytes()
	if err != nil {
		return nil, err
	}
	return wrapSequence(outerBody), nil
}
