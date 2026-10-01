package cert

import (
	"encoding/pem"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/cryptobyte"
)

// CertificatePropertyType codes mirror the trust-anchor-ids
// CertificatePropertyType registry (TAI §7, §12.3).
type CertificatePropertyType uint16

const (
	PropertyTrustAnchorID          CertificatePropertyType = 0
	PropertyTrustAnchorGroups      CertificatePropertyType = 1
	PropertyTrustAnchorNegotiation CertificatePropertyType = 2
)

// CertificateProperty is one entry in the property list. Which field is
// meaningful depends on Type.
type CertificateProperty struct {
	Type CertificatePropertyType
	// TrustAnchorID is the trust_anchor_id property's value (TAI §7.1).
	TrustAnchorID TrustAnchorID
	// Patterns is the trust_anchor_groups property's value (TAI §7.2):
	// patterns matching the IDs of trust anchor groups containing the
	// issuer.
	Patterns []TrustAnchorIDPattern
	// Data is the raw body of a property type this package does not
	// interpret; ParsePropertyList fills it in and ignores the type.
	Data []byte
	// trust_anchor_negotiation (TAI §7.3) has an empty body.
}

// BuildPropertyList builds the TLS-presentation-language encoding of a
// CertificatePropertyList containing the given properties. Entries are
// emitted in ascending Type order, with duplicate types rejected, per
// TAI §7 ("entries MUST be sorted numerically by type and MUST NOT
// contain values with a duplicate type").
//
// On-wire layout:
//
//	uint16 length-prefixed list of CertificateProperty
//	  CertificateProperty:
//	    uint16 type
//	    uint16 length-prefixed body
//	      type=0 trust_anchor_id          → raw binary representation
//	                                          (TAI §4, §7.1)
//	      type=1 trust_anchor_groups      → TrustAnchorIDPatternList
//	                                          (TAI §5.3.1, §7.2)
//	      type=2 trust_anchor_negotiation → empty (TAI §7.3)
func BuildPropertyList(props []CertificateProperty) ([]byte, error) {
	if len(props) == 0 {
		return nil, errors.New("cert: empty property list")
	}
	sorted := make([]CertificateProperty, len(props))
	copy(sorted, props)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Type < sorted[j].Type
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Type == sorted[i-1].Type {
			return nil, fmt.Errorf("cert: duplicate property type %d", sorted[i].Type)
		}
	}
	var b cryptobyte.Builder
	var inner []byte
	for _, p := range sorted {
		body, err := encodeProperty(p)
		if err != nil {
			return nil, err
		}
		var pb cryptobyte.Builder
		pb.AddUint16(uint16(p.Type))
		pb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(body) })
		raw, err := pb.Bytes()
		if err != nil {
			return nil, err
		}
		inner = append(inner, raw...)
	}
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(inner) })
	return b.Bytes()
}

func encodeProperty(p CertificateProperty) ([]byte, error) {
	switch p.Type {
	case PropertyTrustAnchorID:
		if len(p.TrustAnchorID) == 0 {
			return nil, errors.New("cert: trust_anchor_id property has empty value")
		}
		// Per TAI §7.1, the property body is the binary representation
		// of the trust anchor ID (TAI §4) — the same encoding as
		// MTCProof.cosigner_id, not the ASCII form — with no inner length
		// prefix (the outer uint16 already bounds the body). Binary
		// enforces the TAI §4 32-byte limit.
		bin, err := p.TrustAnchorID.Binary()
		if err != nil {
			return nil, fmt.Errorf("cert: trust_anchor_id property: %w", err)
		}
		return bin, nil

	case PropertyTrustAnchorGroups:
		// TAI §7.2:
		//	opaque TrustAnchorIDPattern<0..2^8-1>;
		//	TrustAnchorIDPattern TrustAnchorIDPatternList<1..2^16-1>;
		// The property body is the list, with its own uint16 prefix.
		if len(p.Patterns) == 0 {
			return nil, errors.New("cert: trust_anchor_groups property has no patterns")
		}
		var b cryptobyte.Builder
		var perr error
		b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
			for _, pat := range p.Patterns {
				bin, err := pat.Binary()
				if err != nil {
					perr = err
					return
				}
				if len(bin) > 0xff {
					perr = fmt.Errorf("cert: trust anchor ID pattern %s is %d bytes, over 255", pat, len(bin))
					return
				}
				list.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(bin) })
			}
		})
		if perr != nil {
			return nil, perr
		}
		return b.Bytes()

	case PropertyTrustAnchorNegotiation:
		return nil, nil

	default:
		return nil, fmt.Errorf("cert: unknown property type %d", p.Type)
	}
}

// ParsePropertyList is the inverse of BuildPropertyList; included so
// tests can round-trip the encoding.
func ParsePropertyList(data []byte) ([]CertificateProperty, error) {
	s := cryptobyte.String(data)
	var listBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&listBytes) {
		return nil, errors.New("cert: short property list")
	}
	if !s.Empty() {
		return nil, fmt.Errorf("cert: %d trailing bytes after property list", len(s))
	}
	var props []CertificateProperty
	var prevType uint16
	first := true
	for !listBytes.Empty() {
		var t uint16
		if !listBytes.ReadUint16(&t) {
			return nil, errors.New("cert: short property type")
		}
		if !first {
			if t < prevType {
				return nil, fmt.Errorf("cert: property type %d out of order (after %d)", t, prevType)
			}
			if t == prevType {
				return nil, fmt.Errorf("cert: duplicate property type %d", t)
			}
		}
		prevType = t
		first = false
		var body cryptobyte.String
		if !listBytes.ReadUint16LengthPrefixed(&body) {
			return nil, errors.New("cert: short property body")
		}
		p := CertificateProperty{Type: CertificatePropertyType(t)}
		switch p.Type {
		case PropertyTrustAnchorID:
			// Body is the binary representation (TAI §4); decode to the
			// canonical relative ASCII form.
			id, err := TrustAnchorIDFromBinary(body)
			if err != nil {
				return nil, fmt.Errorf("cert: trust_anchor_id property: %w", err)
			}
			p.TrustAnchorID = id
		case PropertyTrustAnchorGroups:
			var list cryptobyte.String
			if !body.ReadUint16LengthPrefixed(&list) || !body.Empty() || list.Empty() {
				return nil, errors.New("cert: malformed trust_anchor_groups property")
			}
			for !list.Empty() {
				var raw cryptobyte.String
				if !list.ReadUint8LengthPrefixed(&raw) {
					return nil, errors.New("cert: malformed trust_anchor_groups property")
				}
				pat, err := TrustAnchorIDPatternFromBinary(raw)
				if err != nil {
					return nil, fmt.Errorf("cert: trust_anchor_groups property: %w", err)
				}
				p.Patterns = append(p.Patterns, pat)
			}
		case PropertyTrustAnchorNegotiation:
			if !body.Empty() {
				return nil, errors.New("cert: trust_anchor_negotiation property must be empty")
			}
		default:
			// Unknown property type: pass the body through unparsed but
			// don't reject (TAI §7: authenticating parties MUST ignore
			// unrecognized types).
			p.Data = append([]byte(nil), body...)
		}
		props = append(props, p)
	}
	return props, nil
}

// PEMBlockProperties is the type label used for the
// CertificatePropertyList PEM block, fixed by TAI §7.4.
const PEMBlockProperties = "CERTIFICATE PROPERTIES"

// EncodePEMWithProperties returns the body for the
// `application/pem-certificate-chain-with-properties` content type.
// Per TAI §7.4 the first PEM element MUST be the encoded
// CertificatePropertyList and the second MUST be the end-entity
// certificate, so the CERTIFICATE PROPERTIES block is emitted first.
//
// If propertyList is nil the function returns just the cert PEM.
func EncodePEMWithProperties(certDER, propertyList []byte) []byte {
	var out []byte
	if propertyList != nil {
		out = pem.EncodeToMemory(&pem.Block{
			Type:  PEMBlockProperties,
			Bytes: propertyList,
		})
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	return out
}
