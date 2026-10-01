package cert

import (
	"encoding/asn1"
	"fmt"
)

// tagRelativeOID is the ASN.1 universal tag for RELATIVE-OID (X.680),
// which encoding/asn1 does not model natively.
const tagRelativeOID = 13

// BuildCAName returns the DER encoding of a Name (RFC 5280 §4.1.2.4)
// representing the CA's CA ID per §5.1 of the draft. The CA ID is the
// issuer of every certificate the CA produces (and the subject of the
// CA certificate, §5.5). The Name has a single RDN holding a single
// id-rdna-trustAnchorID attribute whose value is a RELATIVE-OID with the
// trust anchor ID; its content octets are the ID's binary
// representation. The CA ID 32473.1 thus yields, in RFC 4514 syntax,
// 1.3.6.1.5.5.7.25.3=#0d0481fd5901.
//
// Result shape:
//
//	Name ::= CHOICE { rdnSequence RDNSequence }
//	RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//	RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//	AttributeTypeAndValue ::= SEQUENCE { type OID, value RELATIVE-OID }
func BuildCAName(caID string) ([]byte, error) {
	if caID == "" {
		return nil, fmt.Errorf("caID empty")
	}
	bin, err := TrustAnchorID(caID).Binary()
	if err != nil {
		return nil, err
	}
	// AttributeTypeAndValue { OIDRDNATrustAnchorID, RELATIVE-OID(caID) }
	type atv struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	atvBytes, err := asn1.Marshal(atv{
		Type:  OIDRDNATrustAnchorID,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: tagRelativeOID, Bytes: bin},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal AttributeTypeAndValue: %w", err)
	}

	// RelativeDistinguishedName: SET OF the above.
	rdn := asn1.RawValue{Tag: 17, IsCompound: true, Class: 0, Bytes: atvBytes}
	rdnBytes, err := asn1.Marshal(rdn)
	if err != nil {
		return nil, fmt.Errorf("marshal RDN: %w", err)
	}

	// RDNSequence: SEQUENCE OF RDN.
	seq := asn1.RawValue{Tag: 16, IsCompound: true, Class: 0, Bytes: rdnBytes}
	return asn1.Marshal(seq)
}
