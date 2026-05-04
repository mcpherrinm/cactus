package cert

import (
	"encoding/asn1"
	"fmt"
)

// BuildLogIDName returns the DER encoding of a Name (RFC 5280 §4.1.2.4)
// representing the issuance log's log ID per §5.2 of the draft. For
// initial experimentation, the value is encoded as a UTF8String
// containing the trust anchor ID's ASCII representation.
//
// Result shape:
//
//	Name ::= CHOICE { rdnSequence RDNSequence }
//	RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//	RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//	AttributeTypeAndValue ::= SEQUENCE { type OID, value UTF8String }
func BuildLogIDName(logID string) ([]byte, error) {
	if logID == "" {
		return nil, fmt.Errorf("logID empty")
	}
	// AttributeTypeAndValue { OIDRDNATrustAnchorID, UTF8String(logID) }
	type atv struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}
	atvBytes, err := asn1.Marshal(atv{Type: OIDRDNATrustAnchorID, Value: logID})
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
