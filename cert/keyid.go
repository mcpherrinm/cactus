package cert

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Signed-note signature-type identifier bytes, assigned by
// c2sp.org/signed-note ("Signature types"). Only the ones cactus emits
// are listed.
const (
	// sigTypeMLDSA44 is signed-note type 0x06, "Timestamped ML-DSA-44
	// (sub)tree cosignatures", specified by c2sp.org/tlog-cosignature.
	sigTypeMLDSA44 = 0x06
	// sigTypeUnassigned is signed-note type 0xff, reserved for signature
	// types without an assigned identifier byte; it MUST be followed by a
	// longer, collision-resistant identifier. cactus uses it for the
	// experimental ML-DSA-65/87 cosigners, which c2sp does not (yet)
	// assign. These are NOT permitted on the witness sign-subtree path.
	sigTypeUnassigned = 0xff
)

// FIPS 204 raw public-key sizes, by ML-DSA parameter set. Used to
// reject mis-sized keys before they flow into a key-ID computation.
const (
	pubKeyLenMLDSA44 = 1312
	pubKeyLenMLDSA65 = 1952
	pubKeyLenMLDSA87 = 2592
)

// expectedPubKeyLen returns the raw FIPS 204 public-key length for alg,
// or (0, false) if alg has no ML-DSA key size.
func expectedPubKeyLen(alg SignatureAlgorithm) (int, bool) {
	switch alg {
	case AlgMLDSA44:
		return pubKeyLenMLDSA44, true
	case AlgMLDSA65:
		return pubKeyLenMLDSA65, true
	case AlgMLDSA87:
		return pubKeyLenMLDSA87, true
	default:
		return 0, false
	}
}

// timestampedSigTimestampLen is the width of the big-endian u64
// timestamp that prefixes a c2sp.org/tlog-cosignature
// timestamped_signature.
const timestampedSigTimestampLen = 8

// MarshalTimestampedSignature returns the c2sp.org/tlog-cosignature
// timestamped_signature wire form: an 8-byte big-endian timestamp
// followed by the algorithm-specific signature. This is the value that
// follows the 4-byte key ID in a signed-note signature line. For MTC
// (sub)tree cosignatures the timestamp is zero.
func MarshalTimestampedSignature(timestamp uint64, sig []byte) []byte {
	out := make([]byte, timestampedSigTimestampLen+len(sig))
	binary.BigEndian.PutUint64(out[:timestampedSigTimestampLen], timestamp)
	copy(out[timestampedSigTimestampLen:], sig)
	return out
}

// ParseTimestampedSignature splits a timestamped_signature into its
// timestamp and the underlying signature bytes.
func ParseTimestampedSignature(b []byte) (timestamp uint64, sig []byte, err error) {
	if len(b) < timestampedSigTimestampLen {
		return 0, nil, errors.New("cert: timestamped_signature too short for timestamp")
	}
	return binary.BigEndian.Uint64(b[:timestampedSigTimestampLen]), b[timestampedSigTimestampLen:], nil
}

// CosignatureKeyID computes the 4-byte c2sp signed-note key ID for a
// cosigner's signature line, per c2sp.org/signed-note. The key ID is a
// short identifier (not a strong hash); verifiers match it together with
// the key name and ignore non-matching signatures.
//
// pub is the cosigner's raw FIPS 204 ML-DSA public key (as
// signer.Signer.PublicKey / CosignerKey.PublicKey carry it).
//
//   - ML-DSA-44: SHA-256(name || 0x0A || 0x06 || 1312-byte raw key)[:4],
//     per c2sp.org/tlog-cosignature.
//   - ML-DSA-65/87: the signed-note 0xff escape with a "ml-dsa-NN"
//     identifier and the raw key.
func CosignatureKeyID(name string, alg SignatureAlgorithm, pub []byte) ([4]byte, error) {
	var out [4]byte
	if want, ok := expectedPubKeyLen(alg); ok && len(pub) != want {
		return out, fmt.Errorf("cert: public key for algorithm 0x%04x is %d bytes, want %d", uint16(alg), len(pub), want)
	}
	h := sha256.New()
	switch alg {
	case AlgMLDSA44:
		h.Write([]byte(name))
		h.Write([]byte{0x0A, sigTypeMLDSA44})
		h.Write(pub)
	case AlgMLDSA65:
		h.Write([]byte(name))
		h.Write([]byte{0x0A, sigTypeUnassigned})
		h.Write([]byte("ml-dsa-65"))
		h.Write(pub)
	case AlgMLDSA87:
		h.Write([]byte(name))
		h.Write([]byte{0x0A, sigTypeUnassigned})
		h.Write([]byte("ml-dsa-87"))
		h.Write(pub)
	default:
		return out, fmt.Errorf("cert: no c2sp signed-note key ID for algorithm 0x%04x", uint16(alg))
	}
	copy(out[:], h.Sum(nil)[:4])
	return out, nil
}
