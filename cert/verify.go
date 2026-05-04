package cert

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// SplitCertificate decomposes a Certificate DER into the
// TBSCertificate, the signatureAlgorithm AlgorithmIdentifier, and the
// signatureValue BIT STRING contents (i.e. without the unused-bits
// byte). The §7.2 verifier needs to peek at signatureAlgorithm before
// touching anything else.
func SplitCertificate(der []byte) (tbs, sigAlg, sigValue []byte, err error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, nil, errors.New("cert: trailing bytes after Certificate")
	}
	body := outer.Bytes
	var tbsRV asn1.RawValue
	body, err = asn1.Unmarshal(body, &tbsRV)
	if err != nil {
		return nil, nil, nil, err
	}
	var algRV asn1.RawValue
	body, err = asn1.Unmarshal(body, &algRV)
	if err != nil {
		return nil, nil, nil, err
	}
	var sigBS asn1.BitString
	rest2, err := asn1.Unmarshal(body, &sigBS)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(rest2) != 0 {
		return nil, nil, nil, errors.New("cert: trailing bytes after Certificate body")
	}
	return tbsRV.FullBytes, algRV.FullBytes, sigBS.Bytes, nil
}

// RebuildLogEntryFromTBS reconstructs the contents-octet form of a
// TBSCertificateLogEntry from a cert's TBSCertificate per §7.2 step 4.
//
// The substitution it performs: replace the SubjectPublicKeyInfo field
// with subjectPublicKeyAlgorithm + OCTET STRING(HASH(SPKI)).
//
// Returns the rebuilt log entry contents and the cert's serial number.
// expectedIssuer, if non-nil, is checked against the cert's issuer DN.
func RebuildLogEntryFromTBS(tbs []byte, expectedIssuer []byte) ([]byte, uint64, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &outer); err != nil {
		return nil, 0, err
	}
	body := outer.Bytes

	// version [0] EXPLICIT INTEGER
	var ver asn1.RawValue
	body, err := asn1.Unmarshal(body, &ver)
	if err != nil {
		return nil, 0, err
	}

	// serialNumber INTEGER. RFC 5280 §4.1.2.2 allows up to 20 octets; for
	// cactus the serial is the log index, so we accept anything that
	// fits in a uint64 (including the 9-byte 0x00 || 8-byte form needed
	// for the high bit set).
	var serialRaw asn1.RawValue
	body, err = asn1.Unmarshal(body, &serialRaw)
	if err != nil {
		return nil, 0, err
	}
	var serialBig *big.Int
	if _, err := asn1.Unmarshal(serialRaw.FullBytes, &serialBig); err != nil {
		return nil, 0, err
	}
	if serialBig.Sign() < 0 {
		return nil, 0, errors.New("cert: negative serialNumber")
	}
	if !serialBig.IsUint64() {
		return nil, 0, fmt.Errorf("cert: serialNumber %s does not fit in uint64", serialBig)
	}
	serial := serialBig.Uint64()

	// signature AlgorithmIdentifier — drop.
	var sigAlg asn1.RawValue
	body, err = asn1.Unmarshal(body, &sigAlg)
	if err != nil {
		return nil, 0, err
	}
	_ = sigAlg

	// issuer Name
	var issuer asn1.RawValue
	body, err = asn1.Unmarshal(body, &issuer)
	if err != nil {
		return nil, 0, err
	}
	if expectedIssuer != nil && !bytes.Equal(issuer.FullBytes, expectedIssuer) {
		return nil, 0, fmt.Errorf("cert: issuer mismatch")
	}

	// validity Validity
	var validity asn1.RawValue
	body, err = asn1.Unmarshal(body, &validity)
	if err != nil {
		return nil, 0, err
	}

	// subject Name
	var subject asn1.RawValue
	body, err = asn1.Unmarshal(body, &subject)
	if err != nil {
		return nil, 0, err
	}

	// subjectPublicKeyInfo — replace with algorithm + OCTET STRING(HASH(spki)).
	var spki asn1.RawValue
	body, err = asn1.Unmarshal(body, &spki)
	if err != nil {
		return nil, 0, err
	}
	var spkiAlg asn1.RawValue
	if _, err := asn1.Unmarshal(spki.Bytes, &spkiAlg); err != nil {
		return nil, 0, err
	}
	spkiHash := sha256.Sum256(spki.FullBytes)
	hashOctet, err := asn1.Marshal(spkiHash[:])
	if err != nil {
		return nil, 0, err
	}

	// Parse the optional tail fields in order:
	//   issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL
	//   subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL
	//   extensions      [3] EXPLICIT Extensions OPTIONAL
	// Each is identified by its ASN.1 context-specific tag class (0x80
	// bit) and tag number. The MTC log entry preserves whichever are
	// present so §7.2 verification stays exact.
	var issuerUniqueID, subjectUniqueID, extensions asn1.RawValue
	for len(body) > 0 {
		var rv asn1.RawValue
		body, err = asn1.Unmarshal(body, &rv)
		if err != nil {
			return nil, 0, err
		}
		if rv.Class != asn1.ClassContextSpecific {
			return nil, 0, fmt.Errorf("cert: unexpected TBS field with class=%d tag=%d", rv.Class, rv.Tag)
		}
		switch rv.Tag {
		case 1:
			if issuerUniqueID.FullBytes != nil {
				return nil, 0, errors.New("cert: duplicate issuerUniqueID")
			}
			issuerUniqueID = rv
		case 2:
			if subjectUniqueID.FullBytes != nil {
				return nil, 0, errors.New("cert: duplicate subjectUniqueID")
			}
			subjectUniqueID = rv
		case 3:
			if extensions.FullBytes != nil {
				return nil, 0, errors.New("cert: duplicate extensions")
			}
			extensions = rv
		default:
			return nil, 0, fmt.Errorf("cert: unknown TBS context-specific tag %d", rv.Tag)
		}
	}

	var contents []byte
	contents = append(contents, ver.FullBytes...)
	contents = append(contents, issuer.FullBytes...)
	contents = append(contents, validity.FullBytes...)
	contents = append(contents, subject.FullBytes...)
	contents = append(contents, spkiAlg.FullBytes...)
	contents = append(contents, hashOctet...)
	if len(issuerUniqueID.FullBytes) > 0 {
		contents = append(contents, issuerUniqueID.FullBytes...)
	}
	if len(subjectUniqueID.FullBytes) > 0 {
		contents = append(contents, subjectUniqueID.FullBytes...)
	}
	if len(extensions.FullBytes) > 0 {
		contents = append(contents, extensions.FullBytes...)
	}
	return contents, serial, nil
}
