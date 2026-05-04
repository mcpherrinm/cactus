package cert

import (
	"encoding/pem"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/cryptobyte"
)

// CertificatePropertyType codes mirror trust-anchor-ids §6 + the MTC
// draft's §8.1 extension. The 0/1 codepoints used here are best-effort
// against an unstable spec; see PROJECT_PLAN §8 Risk 9.
type CertificatePropertyType uint16

const (
	PropertyTrustAnchorID           CertificatePropertyType = 0
	PropertyAdditionalTAnchorRanges CertificatePropertyType = 1
)

// TrustAnchorRange is the §8.1 struct: a base ID plus an inclusive
// [min, max] range of integers that may be appended to it.
type TrustAnchorRange struct {
	Base     TrustAnchorID
	Min, Max uint64
}

// CertificateProperty is one entry in the property list.
type CertificateProperty struct {
	Type CertificatePropertyType
	// Exactly one of these is populated.
	TrustAnchorID TrustAnchorID
	Ranges        []TrustAnchorRange
}

// BuildPropertyList builds the TLS-presentation-language encoding of a
// CertificatePropertyList containing the given properties. Entries are
// emitted in ascending Type order, with duplicate types rejected, per
// trust-anchor-ids §6 ("entries MUST be sorted numerically by type and
// MUST NOT contain values with a duplicate type").
//
// On-wire layout:
//
//	uint16 length-prefixed list of CertificateProperty
//	  CertificateProperty:
//	    uint16 type
//	    uint16 length-prefixed body
//	      type=0 trust_anchor_id   →  raw binary representation
//	                                   (see trust-anchor-ids §3, §6)
//	      type=1 additional_ranges →  uint16 length-prefixed list of:
//	                                    TrustAnchorRange = uint8 base‖uint64 min‖uint64 max
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
		// trust-anchor-ids §4.1: TrustAnchorID is opaque<1..2^8-1>, so a
		// trust anchor ID is always ≤255 bytes regardless of where it
		// appears.
		if len(p.TrustAnchorID) > 0xff {
			return nil, fmt.Errorf("cert: trust_anchor_id %d > 255 bytes", len(p.TrustAnchorID))
		}
		// Per trust-anchor-ids §6, the property body is the raw binary
		// representation of the trust anchor ID — no inner length prefix
		// (the outer uint16 already bounds the body).
		return append([]byte(nil), p.TrustAnchorID...), nil

	case PropertyAdditionalTAnchorRanges:
		if len(p.Ranges) == 0 {
			return nil, errors.New("cert: additional_trust_anchor_ranges property has zero ranges")
		}
		var b cryptobyte.Builder
		var rangesErr error
		b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
			for _, r := range p.Ranges {
				if len(r.Base) == 0 || len(r.Base) > 0xff {
					rangesErr = fmt.Errorf("cert: range base length %d invalid", len(r.Base))
					return
				}
				if r.Min > r.Max {
					rangesErr = fmt.Errorf("cert: range min %d > max %d", r.Min, r.Max)
					return
				}
				c.AddUint8LengthPrefixed(func(d *cryptobyte.Builder) {
					d.AddBytes(r.Base)
				})
				c.AddUint64(r.Min)
				c.AddUint64(r.Max)
			}
		})
		if rangesErr != nil {
			return nil, rangesErr
		}
		return b.Bytes()

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
			// Body is the entire raw binary representation.
			p.TrustAnchorID = TrustAnchorID(append([]byte(nil), body...))
		case PropertyAdditionalTAnchorRanges:
			var rangesBytes cryptobyte.String
			if !body.ReadUint16LengthPrefixed(&rangesBytes) {
				return nil, errors.New("cert: short additional_trust_anchor_ranges")
			}
			for !rangesBytes.Empty() {
				var baseBytes cryptobyte.String
				if !rangesBytes.ReadUint8LengthPrefixed(&baseBytes) {
					return nil, errors.New("cert: short range base")
				}
				var min, max uint64
				if !rangesBytes.ReadUint64(&min) || !rangesBytes.ReadUint64(&max) {
					return nil, errors.New("cert: short range min/max")
				}
				p.Ranges = append(p.Ranges, TrustAnchorRange{
					Base: TrustAnchorID(append([]byte(nil), baseBytes...)),
					Min:  min, Max: max,
				})
			}
			if !body.Empty() {
				return nil, fmt.Errorf("cert: trailing bytes in property type %d", t)
			}
		default:
			// Unknown property type: pass the body through unparsed but
			// don't reject (extensibility).
		}
		props = append(props, p)
	}
	return props, nil
}

// PEMBlockProperties is the type label used for the cactus
// CertificatePropertyList PEM block. The "MTC " prefix is intentional
// — it scopes our experimental layout away from any well-known PEM
// types — and we'll switch to whatever the trust-anchor-ids draft
// pins down once that spec settles.
const PEMBlockProperties = "MTC PROPERTIES"

// EncodePEMWithProperties returns the body for the
// `application/pem-certificate-chain-with-properties` content type:
// a PEM CERTIFICATE block followed by an MTC PROPERTIES block.
//
// If propertyList is nil the function returns just the cert PEM.
func EncodePEMWithProperties(certDER, propertyList []byte) []byte {
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if propertyList != nil {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  PEMBlockProperties,
			Bytes: propertyList,
		})...)
	}
	return out
}
