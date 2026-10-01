package cert

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file implements trust anchor ID patterns
// (draft-ietf-tls-trust-anchor-ids-06 §5.3.1). A certificate's
// trust_anchor_groups property lists patterns matching the IDs of the
// trust anchor groups that contain its issuer, which is how draft-07 §8.2.1
// tells an authenticating party which landmark groups select a
// certificate.

// PatternRange is one component of a trust anchor ID pattern: it matches
// an OID component v with Min <= v <= Max, or Min <= v if Unbounded.
type PatternRange struct {
	Min, Max  uint64
	Unbounded bool
}

// TrustAnchorIDPattern is a sequence of component ranges. It contains a
// trust anchor ID with the same number of components, each within the
// corresponding range.
type TrustAnchorIDPattern []PatternRange

// patternInfinity is the one-byte binary encoding of an unbounded max.
const patternInfinity = 0x80

// ParseTrustAnchorIDPattern parses the text representation (TAI §5.3.1),
// e.g. "32473.{123-456}.{789-}". A component is a decimal integer v
// (min = max = v), "{min-max}", or "{min-}" (unbounded max).
func ParseTrustAnchorIDPattern(s string) (TrustAnchorIDPattern, error) {
	if s == "" {
		return nil, errors.New("cert: empty trust anchor ID pattern")
	}
	var out TrustAnchorIDPattern
	for _, part := range strings.Split(s, ".") {
		r, err := parsePatternRange(part)
		if err != nil {
			return nil, fmt.Errorf("cert: trust anchor ID pattern %q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parsePatternRange(part string) (PatternRange, error) {
	parseInt := func(s string) (uint64, error) {
		// The decimal representation has no sign and no leading zeros.
		if s == "" || (len(s) > 1 && s[0] == '0') || s[0] == '+' {
			return 0, fmt.Errorf("bad integer %q", s)
		}
		return strconv.ParseUint(s, 10, 64)
	}
	inner, ok := strings.CutPrefix(part, "{")
	if !ok {
		v, err := parseInt(part)
		return PatternRange{Min: v, Max: v}, err
	}
	inner, ok = strings.CutSuffix(inner, "}")
	if !ok {
		return PatternRange{}, fmt.Errorf("unterminated range %q", part)
	}
	lo, hi, ok := strings.Cut(inner, "-")
	if !ok {
		return PatternRange{}, fmt.Errorf("range %q missing '-'", part)
	}
	minV, err := parseInt(lo)
	if err != nil {
		return PatternRange{}, err
	}
	if hi == "" {
		return PatternRange{Min: minV, Unbounded: true}, nil
	}
	maxV, err := parseInt(hi)
	if err != nil {
		return PatternRange{}, err
	}
	if maxV < minV {
		return PatternRange{}, fmt.Errorf("range %q has max below min", part)
	}
	return PatternRange{Min: minV, Max: maxV}, nil
}

// MustParseTrustAnchorIDPattern is ParseTrustAnchorIDPattern for
// patterns built from already-validated components; it panics on error.
func MustParseTrustAnchorIDPattern(s string) TrustAnchorIDPattern {
	p, err := ParseTrustAnchorIDPattern(s)
	if err != nil {
		panic(err)
	}
	return p
}

// String returns the text representation (TAI §5.3.1).
func (p TrustAnchorIDPattern) String() string {
	parts := make([]string, len(p))
	for i, r := range p {
		switch {
		case r.Unbounded:
			parts[i] = fmt.Sprintf("{%d-}", r.Min)
		case r.Min == r.Max:
			parts[i] = strconv.FormatUint(r.Min, 10)
		default:
			parts[i] = fmt.Sprintf("{%d-%d}", r.Min, r.Max)
		}
	}
	return strings.Join(parts, ".")
}

// Binary returns the byte-string representation (TAI §5.3.1): each
// component's min, then max, base-128 encoded as in an OID arc, with an
// unbounded max encoded as the single byte 0x80.
func (p TrustAnchorIDPattern) Binary() ([]byte, error) {
	if len(p) == 0 {
		return nil, errors.New("cert: empty trust anchor ID pattern")
	}
	var out []byte
	for _, r := range p {
		out = appendBase128(out, r.Min)
		if r.Unbounded {
			out = append(out, patternInfinity)
		} else {
			out = appendBase128(out, r.Max)
		}
	}
	return out, nil
}

// TrustAnchorIDPatternFromBinary is the inverse of Binary. It rejects
// non-minimal and truncated integers, values that overflow a uint64, and
// a max below its min.
func TrustAnchorIDPatternFromBinary(b []byte) (TrustAnchorIDPattern, error) {
	if len(b) == 0 {
		return nil, errors.New("cert: empty trust anchor ID pattern")
	}
	var out TrustAnchorIDPattern
	for len(b) > 0 {
		var r PatternRange
		var err error
		if r.Min, b, err = readBase128(b); err != nil {
			return nil, fmt.Errorf("cert: trust anchor ID pattern min: %w", err)
		}
		if len(b) > 0 && b[0] == patternInfinity {
			r.Unbounded = true
			b = b[1:]
		} else {
			if r.Max, b, err = readBase128(b); err != nil {
				return nil, fmt.Errorf("cert: trust anchor ID pattern max: %w", err)
			}
			if r.Max < r.Min {
				return nil, fmt.Errorf("cert: trust anchor ID pattern range {%d-%d} has max below min", r.Min, r.Max)
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// readBase128 removes one minimally encoded base-128 integer from b.
func readBase128(b []byte) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, errors.New("missing value")
	}
	if b[0] == 0x80 {
		return 0, nil, errors.New("non-minimal encoding")
	}
	var v uint64
	for i, c := range b {
		if v > (1<<64-1)>>7 {
			return 0, nil, errors.New("value overflows uint64")
		}
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("truncated value")
}

// Contains reports whether the pattern contains the trust anchor ID
// (TAI §5.3.1). An ID that is not a valid relative OID is never
// contained.
func (p TrustAnchorIDPattern) Contains(id TrustAnchorID) bool {
	parts := strings.Split(string(id), ".")
	if len(parts) != len(p) {
		return false
	}
	for i, part := range parts {
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil || v < p[i].Min || (!p[i].Unbounded && v > p[i].Max) {
			return false
		}
	}
	return true
}
