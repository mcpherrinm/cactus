package cert

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// This file centralizes the three on-wire encodings of a trust anchor ID
// used by Merkle Tree Certificates, all derived from one canonical
// in-memory form.
//
// Canonical form: cactus stores a TrustAnchorID as the *relative*
// trust-anchor-ID ASCII (Section 3 of draft-ietf-tls-trust-anchor-ids),
// e.g. "32473.1" — the dotted-decimal OID arcs *relative to the
// 1.3.6.1.4.1 base*. From this single form we derive:
//
//   - the cosigner_name / log_origin: "oid/1.3.6.1.4.1."+<rel ASCII> (§5.3.1)
//   - the binary representation: DER content octets of the
//     RELATIVE-OID, used in the CA ID DN attribute value (§5.1),
//     MTCProof.cosigner_id (§6.2), the trust_anchor_id certificate
//     property, and the CA cert subjectKeyId.

// TrustAnchorOIDBase is the absolute OID prefix that every Merkle Tree
// Certificate trust anchor ID is relative to (§5.3.1 fixes the 16-byte
// ASCII prefix "oid/1.3.6.1.4.1."). Trust anchor IDs are expressed
// relative to this base.
const TrustAnchorOIDBase = "1.3.6.1.4.1"

// OIDNamePrefix is the four-byte ASCII prefix of a cosigner_name /
// log_origin (§5.3.1). It precedes the full dotted-decimal OID.
const OIDNamePrefix = "oid/"

// Binary returns the trust anchor ID's binary representation per Section
// 3 of draft-ietf-tls-trust-anchor-ids: the DER content octets of the
// RELATIVE-OID (X.690 §8.20), i.e. each arc base-128 encoded with the
// high bit set on every octet but the last of the arc, concatenated.
// This is the form draft-07 §6.2 requires for MTCProof.cosigner_id and
// TAI §7.1 requires for the trust_anchor_id certificate property.
//
// For example, TrustAnchorID("32473.1").Binary() == {0x81,0xfd,0x59,0x01}.
//
// It returns an error if the ID is not a non-empty dotted-decimal string
// of non-negative integers (a trust anchor ID is a relative OID, so
// non-numeric components such as "foo" cannot be represented on the
// wire), or if the binary representation exceeds the
// MaxTrustAnchorIDLen bytes TAI §4 allows. Arcs may be arbitrarily large
// (TAI §4); in practice the length limit bounds them.
func (id TrustAnchorID) Binary() ([]byte, error) {
	s := string(id)
	if s == "" {
		return nil, fmt.Errorf("cert: empty trust anchor ID")
	}
	var out []byte
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return nil, fmt.Errorf("cert: trust anchor ID %q has empty arc", s)
		}
		v, ok := new(big.Int).SetString(part, 10)
		if !ok || strings.TrimLeft(part, "0123456789") != "" {
			return nil, fmt.Errorf("cert: trust anchor ID %q arc %q is not a non-negative integer", s, part)
		}
		out = appendBase128Big(out, v)
	}
	if len(out) > MaxTrustAnchorIDLen {
		return nil, fmt.Errorf("cert: trust anchor ID %q is %d bytes, over the %d-byte limit", s, len(out), MaxTrustAnchorIDLen)
	}
	return out, nil
}

// MaxTrustAnchorIDLen is the longest binary representation a trust
// anchor ID may have (draft-ietf-tls-trust-anchor-ids-06 §4). cactus
// enforces it on IDs it produces; parsers stay lenient up to the
// opaque<1..2^8-1> bound of MTCProof.cosigner_id.
const MaxTrustAnchorIDLen = 32

// TrustAnchorIDFromBinary is the inverse of Binary: it decodes the DER
// content octets of a RELATIVE-OID into the canonical relative-ASCII
// TrustAnchorID. It rejects non-minimal (leading 0x80) and truncated
// (trailing continuation) encodings, but not large arcs: OID components
// may be arbitrarily large (TAI §4), and §7.2 requires a relying party to
// ignore cosigners it doesn't recognize, so an unusual cosigner ID must
// not make the whole MTCProof unparseable.
func TrustAnchorIDFromBinary(b []byte) (TrustAnchorID, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("cert: empty binary trust anchor ID")
	}
	var arcs []string
	for len(b) > 0 {
		if b[0] == 0x80 {
			return nil, fmt.Errorf("cert: non-minimal base-128 encoding in trust anchor ID")
		}
		end := 0
		for end < len(b) && b[end]&0x80 != 0 {
			end++
		}
		if end == len(b) {
			return nil, fmt.Errorf("cert: truncated base-128 encoding in trust anchor ID")
		}
		arc, rest := b[:end+1], b[end+1:]
		if len(arc) <= 9 { // at most 63 bits
			var v uint64
			for _, c := range arc {
				v = v<<7 | uint64(c&0x7f)
			}
			arcs = append(arcs, strconv.FormatUint(v, 10))
		} else {
			v := new(big.Int)
			for _, c := range arc {
				v.Lsh(v, 7).Or(v, big.NewInt(int64(c&0x7f)))
			}
			arcs = append(arcs, v.String())
		}
		b = rest
	}
	return TrustAnchorID(strings.Join(arcs, ".")), nil
}

// appendBase128Big is appendBase128 for an arbitrarily large v >= 0.
func appendBase128Big(dst []byte, v *big.Int) []byte {
	if v.IsUint64() {
		return appendBase128(dst, v.Uint64())
	}
	var digits []byte // little-endian base-128 digits
	v = new(big.Int).Set(v)
	mask := big.NewInt(0x7f)
	for v.Sign() > 0 {
		digits = append(digits, byte(new(big.Int).And(v, mask).Uint64()))
		v.Rsh(v, 7)
	}
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if i > 0 {
			c |= 0x80
		}
		dst = append(dst, c)
	}
	return dst
}

// appendBase128 appends v to dst as a base-128, big-endian, minimal-
// length integer with the continuation bit (0x80) set on every octet
// but the last (X.690 §8.19.2, used for OID/RELATIVE-OID arcs).
func appendBase128(dst []byte, v uint64) []byte {
	var buf [10]byte
	n := len(buf)
	n--
	buf[n] = byte(v & 0x7f)
	for v >>= 7; v > 0; v >>= 7 {
		n--
		buf[n] = byte(v&0x7f) | 0x80
	}
	return append(dst, buf[n:]...)
}
