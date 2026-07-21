package cert

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/letsencrypt/cactus/tlogx"
)

// This file implements the draft-05 §7 relying-party side: deriving a
// relying party's configuration from a CA certificate (§7.1) and the
// full certificate-signature verification procedure (§7.2), including
// revoked-range (§7.5) and trusted-subtree (§7.4) handling.

// TrustedSubtreeKey identifies a trusted subtree (§7.4). The match key
// per §7.2 step 11 is (log_number, start, end) — not (start, end) alone,
// since the same interval can recur across a CA's logs.
type TrustedSubtreeKey struct {
	LogNumber  uint16
	Start, End uint64
}

// RelyingPartyConfig is everything a relying party needs to verify a
// Merkle Tree Certificate from one CA (§7.1).
type RelyingPartyConfig struct {
	// CAID is the CA's CA ID (§5.1), canonical relative form.
	CAID TrustAnchorID
	// CADN is the DER of the CA ID distinguished name; an incoming
	// certificate's issuer MUST equal it.
	CADN []byte
	// LogHash is the hash algorithm used by all of the CA's logs.
	// cactus only implements SHA-256.
	LogHash asn1.ObjectIdentifier
	// Cosigners are the cosigner keys the relying party knows, keyed by
	// cosigner ID. It MUST include the CA cosigner (ID == CAID).
	Cosigners []CosignerKey
	// RequiredCosigners lists the cosigner IDs that MUST all produce a
	// valid signature for a standalone certificate to verify (§7.3). If
	// empty, the CA cosigner (CAID) alone is required.
	RequiredCosigners []TrustAnchorID
	// RevokedRanges are revoked serial-number ranges (§7.5), seeded from
	// the CA certificate's minSerial and optionally extended out-of-band.
	RevokedRanges RevokedRanges
	// TrustedSubtrees is the optional predistributed set (§7.4) enabling
	// the landmark-relative fast path.
	TrustedSubtrees map[TrustedSubtreeKey]tlogx.Hash
}

// ErrRevoked is returned by VerifyCertificate when the serial number
// falls in a revoked range (§7.5).
var ErrRevoked = errors.New("cert: serial number is revoked")

// ConfigFromCACertificate derives a RelyingPartyConfig from a §5.5 CA
// certificate (§7.1): the CA ID from the subject, the log hash and CA
// cosigner signature algorithm from the id-pe-mtcCertificationAuthority
// extension, the CA cosigner key from the subjectPublicKeyInfo, and the
// initial revoked range [0, minSerial). The CA cosigner ID is the CA ID.
// Relying parties may then extend RevokedRanges, TrustedSubtrees, and
// Cosigners out-of-band.
func ConfigFromCACertificate(caCertDER []byte) (RelyingPartyConfig, error) {
	subjectDN, spki, exts, err := parseCACertificate(caCertDER)
	if err != nil {
		return RelyingPartyConfig{}, err
	}
	mtcExt, ok := exts[OIDExtMTCCertificationAuthority.String()]
	if !ok {
		return RelyingPartyConfig{}, fmt.Errorf("cert: CA certificate missing id-pe-mtcCertificationAuthority extension")
	}
	ca, err := ParseMTCCertificationAuthority(mtcExt)
	if err != nil {
		return RelyingPartyConfig{}, err
	}
	// Verification is SHA-256-only, so reject (fail closed) a CA cert
	// that advertises any other log hash rather than silently verifying
	// it as SHA-256.
	if !ca.LogHash.Equal(OIDDigestSHA256) {
		return RelyingPartyConfig{}, fmt.Errorf("cert: unsupported log hash %v (only id-sha256 is supported)", ca.LogHash)
	}
	caID, err := parseCANameDN(subjectDN)
	if err != nil {
		return RelyingPartyConfig{}, fmt.Errorf("cert: CA certificate subject: %w", err)
	}
	cosigner, err := cosignerKeyFromSPKI(caID, spki, ca.SigAlg)
	if err != nil {
		return RelyingPartyConfig{}, err
	}
	return RelyingPartyConfig{
		CAID:              caID,
		CADN:              subjectDN,
		LogHash:           ca.LogHash,
		Cosigners:         []CosignerKey{cosigner},
		RequiredCosigners: []TrustAnchorID{caID},
		RevokedRanges:     InitialRevokedRanges(ca),
	}, nil
}

// VerifyCertificate runs the §7.2 certificate-signature verification for
// a Merkle Tree Certificate issued by the CA described by cfg. It
// returns nil if the certificate verifies. This replaces only the
// signature-verification portion of X.509 path validation; callers must
// still check expiry and other constraints.
func VerifyCertificate(certDER []byte, cfg RelyingPartyConfig) error {
	tbs, sigAlg, sigValue, err := SplitCertificate(certDER)
	if err != nil {
		return err
	}
	// Step 1: signatureAlgorithm MUST be id-alg-mtcProof, parameters absent.
	if err := checkMTCProofAlgID(sigAlg); err != nil {
		return err
	}
	// Step 2: decode the MTCProof.
	proof, err := ParseMTCProof(sigValue)
	if err != nil {
		return err
	}
	// Steps 3 & 7: rebuild the log entry and read the serial. Passing
	// cfg.CADN checks the issuer is this CA.
	tbsContents, serial, err := RebuildLogEntryFromTBS(tbs, cfg.CADN)
	if err != nil {
		return err
	}
	// Step 4: revoked ranges (§7.5).
	if cfg.RevokedRanges.Contains(serial) {
		return ErrRevoked
	}
	// Step 5: split the serial, rejecting a zero log number.
	logNumber, index, err := SplitSerial(serial)
	if err != nil {
		return err
	}
	// Step 6: derive the log ID from the CA ID and log number.
	logID, err := LogID(cfg.CAID, logNumber)
	if err != nil {
		return err
	}
	// Steps 8 & 9: build the entry hash, taking the extensions from the
	// MTCProof (§7.2 step 8.2), and evaluate the inclusion proof.
	leaf, err := EntryHashExt(proof.Extensions, tbsContents)
	if err != nil {
		return err
	}
	expected, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		proof.Start, proof.End, index, leaf, proof.InclusionProof,
	)
	if err != nil {
		return fmt.Errorf("cert: evaluate inclusion proof: %w", err)
	}
	// Step 11: trusted-subtree fast path, keyed on (log_number, start, end).
	if cfg.TrustedSubtrees != nil {
		if want, ok := cfg.TrustedSubtrees[TrustedSubtreeKey{LogNumber: logNumber, Start: proof.Start, End: proof.End}]; ok {
			if want == expected {
				return nil
			}
			return ErrSubtreeMismatch
		}
	}
	// Step 12: verify a sufficient set of cosignatures.
	return verifyCosignatures(cfg, logID, proof, expected)
}

// verifyCosignatures checks that every required cosigner has a valid
// signature in the proof (§7.2 step 12, §7.3). Unrecognized cosigners
// are ignored.
func verifyCosignatures(cfg RelyingPartyConfig, logID TrustAnchorID, proof *MTCProof, subtreeHash tlogx.Hash) error {
	required := cfg.RequiredCosigners
	if len(required) == 0 {
		required = []TrustAnchorID{cfg.CAID}
	}
	keys := make(map[string]CosignerKey, len(cfg.Cosigners))
	for _, k := range cfg.Cosigners {
		keys[string(k.ID)] = k
	}
	sigs := make(map[string]MTCSignature, len(proof.Signatures))
	for _, s := range proof.Signatures {
		sigs[string(s.CosignerID)] = s
	}
	subtree := &MTCSubtree{LogID: logID, Start: proof.Start, End: proof.End, Hash: subtreeHash}
	for _, id := range required {
		key, ok := keys[string(id)]
		if !ok {
			return fmt.Errorf("cert: no configured key for required cosigner %q", id)
		}
		sig, ok := sigs[string(id)]
		if !ok {
			return fmt.Errorf("cert: certificate missing required cosignature from %q", id)
		}
		msg, err := MarshalSignatureInput(id, subtree)
		if err != nil {
			return err
		}
		if err := VerifyMTCSignature(key, sig, msg); err != nil {
			return fmt.Errorf("cert: cosignature from %q: %w", id, err)
		}
	}
	return nil
}

// checkMTCProofAlgID verifies an AlgorithmIdentifier is id-alg-mtcProof
// with absent parameters (§7.2 step 1).
func checkMTCProofAlgID(der []byte) error {
	var alg algorithmIdentifier
	if _, err := asn1.Unmarshal(der, &alg); err != nil {
		return fmt.Errorf("cert: parse signatureAlgorithm: %w", err)
	}
	if !alg.Algorithm.Equal(OIDAlgMTCProof) {
		return fmt.Errorf("cert: signatureAlgorithm %v is not id-alg-mtcProof", alg.Algorithm)
	}
	if len(alg.Parameters.FullBytes) != 0 {
		return errors.New("cert: id-alg-mtcProof parameters must be absent")
	}
	return nil
}

// cosignerKeyFromSPKI builds a CosignerKey for a CA cosigner from the CA
// certificate's subjectPublicKeyInfo and the sigAlg OID. The PublicKey is
// the raw FIPS 204 ML-DSA key carried in the SPKI BIT STRING.
func cosignerKeyFromSPKI(id TrustAnchorID, spki []byte, sigAlg asn1.ObjectIdentifier) (CosignerKey, error) {
	alg, err := algFromSigAlgOID(sigAlg)
	if err != nil {
		return CosignerKey{}, err
	}
	// crypto/x509 cannot parse ML-DSA SPKIs, and ML-DSA keys are the raw
	// FIPS 204 key bytes carried in the SPKI BIT STRING. Extract that BIT
	// STRING so VerifyMTCSignature (via the crypto/mldsa verifier) gets the
	// same raw key encoding signer.Signer emits.
	raw, err := rawKeyFromSPKI(spki, sigAlg)
	if err != nil {
		return CosignerKey{}, fmt.Errorf("cert: extract ML-DSA key: %w", err)
	}
	return CosignerKey{ID: id, Algorithm: alg, PublicKey: raw}, nil
}

// rawKeyFromSPKI extracts the subjectPublicKey BIT STRING contents from a
// DER SubjectPublicKeyInfo (SEQUENCE { AlgorithmIdentifier, BIT STRING }).
// For ML-DSA (which crypto/x509 cannot parse) the raw key bytes are
// exactly the BIT STRING value. It enforces RFC 9881 §3: the SPKI
// AlgorithmIdentifier OID MUST equal wantOID and its parameters MUST be
// absent.
func rawKeyFromSPKI(spki []byte, wantOID asn1.ObjectIdentifier) ([]byte, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(spki, &seq); err != nil {
		return nil, err
	}
	var algID asn1.RawValue
	rest, err := asn1.Unmarshal(seq.Bytes, &algID)
	if err != nil {
		return nil, err
	}
	// AlgorithmIdentifier ::= SEQUENCE { algorithm OID }, parameters absent.
	var algOID asn1.ObjectIdentifier
	algRest, err := asn1.Unmarshal(algID.Bytes, &algOID)
	if err != nil {
		return nil, fmt.Errorf("cert: parse SPKI algorithm: %w", err)
	}
	if len(algRest) != 0 {
		return nil, errors.New("cert: SPKI algorithm identifier has unexpected parameters")
	}
	if !algOID.Equal(wantOID) {
		return nil, fmt.Errorf("cert: SPKI algorithm %v does not match expected %v", algOID, wantOID)
	}
	var bits asn1.BitString
	if _, err := asn1.Unmarshal(rest, &bits); err != nil {
		return nil, err
	}
	if bits.BitLength%8 != 0 {
		return nil, fmt.Errorf("cert: SPKI key bit length %d not a whole number of bytes", bits.BitLength)
	}
	return bits.RightAlign(), nil
}

// PKIX signature algorithm OIDs cactus maps to its internal enum:
// id-ml-dsa-44/65/87 (NIST FIPS 204), per RFC 9881.
var (
	oidSigMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidSigMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidSigMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

func algFromSigAlgOID(oid asn1.ObjectIdentifier) (SignatureAlgorithm, error) {
	switch {
	case oid.Equal(oidSigMLDSA44):
		return AlgMLDSA44, nil
	case oid.Equal(oidSigMLDSA65):
		return AlgMLDSA65, nil
	case oid.Equal(oidSigMLDSA87):
		return AlgMLDSA87, nil
	default:
		return AlgUnknown, fmt.Errorf("cert: unsupported CA cosigner sigAlg %v", oid)
	}
}

// SigAlgOID returns the PKIX signature-algorithm OID for a cactus
// SignatureAlgorithm, suitable for the MTCCertificationAuthority.sigAlg
// field of a CA certificate.
func SigAlgOID(alg SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
	switch alg {
	case AlgMLDSA44:
		return oidSigMLDSA44, nil
	case AlgMLDSA65:
		return oidSigMLDSA65, nil
	case AlgMLDSA87:
		return oidSigMLDSA87, nil
	default:
		return nil, fmt.Errorf("cert: no PKIX sigAlg OID for algorithm 0x%04x", uint16(alg))
	}
}

// MarshalCosignerSPKI returns the DER SubjectPublicKeyInfo for a CA
// cosigner public key, suitable for CACertificateInput.CosignerSPKI.
//
// ML-DSA public keys (signer.Signer.PublicKey) are the raw FIPS 204 key
// bytes, wrapped here in an SPKI carrying the ML-DSA algorithm OID (RFC
// 9881) with absent parameters and the key in the BIT STRING — the exact
// shape cosignerKeyFromSPKI/rawKeyFromSPKI expect on the relying-party side.
func MarshalCosignerSPKI(alg SignatureAlgorithm, pub []byte) ([]byte, error) {
	oid, err := SigAlgOID(alg)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm struct{ Algorithm asn1.ObjectIdentifier }
		PublicKey asn1.BitString
	}
	spki.Algorithm.Algorithm = oid
	spki.PublicKey = asn1.BitString{Bytes: pub, BitLength: len(pub) * 8}
	return asn1.Marshal(spki)
}

// parseCACertificate extracts the subject DN, subjectPublicKeyInfo, and
// extensions (by OID string) from a CA certificate's DER.
func parseCACertificate(der []byte) (subjectDN, spki []byte, exts map[string][]byte, err error) {
	tbs, _, _, err := SplitCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &outer); err != nil {
		return nil, nil, nil, err
	}
	body := outer.Bytes
	// version[0], serialNumber, signature, issuer, validity, subject, SPKI, ...
	skip := func(name string) error {
		var rv asn1.RawValue
		body, err = asn1.Unmarshal(body, &rv)
		if err != nil {
			return fmt.Errorf("cert: CA cert %s: %w", name, err)
		}
		return nil
	}
	take := func(name string) ([]byte, error) {
		var rv asn1.RawValue
		body, err = asn1.Unmarshal(body, &rv)
		if err != nil {
			return nil, fmt.Errorf("cert: CA cert %s: %w", name, err)
		}
		return rv.FullBytes, nil
	}
	if err := skip("version"); err != nil {
		return nil, nil, nil, err
	}
	if err := skip("serialNumber"); err != nil {
		return nil, nil, nil, err
	}
	if err := skip("signature"); err != nil {
		return nil, nil, nil, err
	}
	if err := skip("issuer"); err != nil {
		return nil, nil, nil, err
	}
	if err := skip("validity"); err != nil {
		return nil, nil, nil, err
	}
	if subjectDN, err = take("subject"); err != nil {
		return nil, nil, nil, err
	}
	if spki, err = take("subjectPublicKeyInfo"); err != nil {
		return nil, nil, nil, err
	}
	exts = map[string][]byte{}
	for len(body) > 0 {
		var rv asn1.RawValue
		body, err = asn1.Unmarshal(body, &rv)
		if err != nil {
			return nil, nil, nil, err
		}
		if rv.Class != asn1.ClassContextSpecific || rv.Tag != 3 {
			continue // issuerUniqueID/subjectUniqueID — ignore
		}
		var extSeq asn1.RawValue
		if _, err := asn1.Unmarshal(rv.Bytes, &extSeq); err != nil {
			return nil, nil, nil, fmt.Errorf("cert: CA cert extensions: %w", err)
		}
		rest := extSeq.Bytes
		for len(rest) > 0 {
			var e pkixExtension
			rest, err = asn1.Unmarshal(rest, &e)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("cert: CA cert extension: %w", err)
			}
			exts[e.ID.String()] = e.Value
		}
	}
	return subjectDN, spki, exts, nil
}

// parseCANameDN extracts the canonical relative TrustAnchorID from a CA
// ID distinguished name as built by BuildCAName: a single RDN with a
// single AttributeTypeAndValue of type id-rdna-trustAnchorID (cactus
// experimental OID) and a UTF8String value.
func parseCANameDN(dn []byte) (TrustAnchorID, error) {
	// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName(SET) OF
	// AttributeTypeAndValue(SEQUENCE). BuildCAName emits exactly one of
	// each, so we descend explicitly rather than via slice decoding.
	var rdnSeq asn1.RawValue
	if _, err := asn1.Unmarshal(dn, &rdnSeq); err != nil {
		return nil, err
	}
	if rdnSeq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("cert: CA DN is not a SEQUENCE (tag %d)", rdnSeq.Tag)
	}
	var rdn asn1.RawValue
	if _, err := asn1.Unmarshal(rdnSeq.Bytes, &rdn); err != nil {
		return nil, err
	}
	if rdn.Tag != asn1.TagSet {
		return nil, fmt.Errorf("cert: CA DN RDN is not a SET (tag %d)", rdn.Tag)
	}
	var atv struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}
	if _, err := asn1.Unmarshal(rdn.Bytes, &atv); err != nil {
		return nil, err
	}
	if !atv.Type.Equal(OIDRDNATrustAnchorID) {
		return nil, fmt.Errorf("cert: CA DN attribute type %v is not id-rdna-trustAnchorID", atv.Type)
	}
	if atv.Value == "" {
		return nil, errors.New("cert: CA DN has empty trust anchor ID")
	}
	return TrustAnchorID(atv.Value), nil
}
