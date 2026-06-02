package cert

import "fmt"

// This file implements the draft-04 §5.1 Certification Authority
// identifier model. A CA has a single CA ID (a trust anchor ID). All
// other identifiers — log IDs, landmark IDs, landmark group IDs — are
// derived from it by appending OID components. cactus stores trust
// anchor IDs in the relative dotted-decimal form (e.g. "44363.47.1.99",
// the arcs below the 1.3.6.1.4.1 enterprise base), so derivation is
// string concatenation of dotted components. See TrustAnchorID and
// OIDName for how the form maps to the wire and to "oid/" names.

// MaxLogNumber is the largest permitted log number (§5.2: at most
// 2^16-1). Log numbers start at 1. The ceiling is enforced by the
// uint16 type used for log numbers throughout (config and LogID).
const MaxLogNumber = 1<<16 - 1

// LogID derives an issuance log's log ID from the CA ID and log number
// per §5.2: logID = CA-ID ‖ 0 ‖ logNumber. logNumber MUST be in
// [1, MaxLogNumber]; the upper bound holds by construction (uint16).
func LogID(caID TrustAnchorID, logNumber uint16) (TrustAnchorID, error) {
	if logNumber == 0 {
		return nil, fmt.Errorf("cert: log number must be >= 1")
	}
	return TrustAnchorID(fmt.Sprintf("%s.0.%d", string(caID), logNumber)), nil
}

// LandmarkID derives the trust anchor ID of a single landmark per
// §6.3.1 / §8.2: CA-ID ‖ 1 ‖ logNumber ‖ landmarkNumber.
func LandmarkID(caID TrustAnchorID, logNumber uint16, landmarkNumber uint64) TrustAnchorID {
	return TrustAnchorID(fmt.Sprintf("%s.1.%d.%d", string(caID), logNumber, landmarkNumber))
}

// LandmarkGroupID derives the trust anchor group ID for a single-log
// landmark group per §8.2.1: CA-ID ‖ 2 ‖ logNumber ‖ landmarkNumber.
// The group contains the CA ID plus each active landmark of the log.
func LandmarkGroupID(caID TrustAnchorID, logNumber uint16, landmarkNumber uint64) TrustAnchorID {
	return TrustAnchorID(fmt.Sprintf("%s.2.%d.%d", string(caID), logNumber, landmarkNumber))
}

// serialIndexBits is the width of the entry-index portion of a serial
// number (§6.1). The log number occupies the bits above it.
const serialIndexBits = 48

// ComposeSerial builds a certificate serial number from a log number
// and an entry index per §6.1: serial = (logNumber << 48) | index.
// index MUST fit in 48 bits.
func ComposeSerial(logNumber uint16, index uint64) (uint64, error) {
	if index > maxUint48 {
		return 0, fmt.Errorf("cert: entry index %d exceeds 2^48-1", index)
	}
	return uint64(logNumber)<<serialIndexBits | index, nil
}

// SplitSerial decomposes a serial number into its log number and entry
// index per §6.1. It rejects a zero log number (§7.2).
func SplitSerial(serial uint64) (logNumber uint16, index uint64, err error) {
	logNumber = uint16(serial >> serialIndexBits)
	index = serial & maxUint48
	if logNumber == 0 {
		return 0, 0, fmt.Errorf("cert: serial %d has zero log number", serial)
	}
	return logNumber, index, nil
}
