package cert

import (
	"crypto/sha256"
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
