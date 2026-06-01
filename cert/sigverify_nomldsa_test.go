//go:build !go1.27

package cert

import (
	"bytes"
	"testing"
)

// On a pre-1.27 toolchain (no crypto/mldsa), ML-DSA cosignatures cannot be
// verified and VerifyMTCSignature reports the specific sentinel error.
func TestVerifyMTCSignatureUnsupportedReturnsSpecificError(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{AlgMLDSA44, AlgMLDSA65, AlgMLDSA87} {
		key := CosignerKey{ID: TrustAnchorID("x"), Algorithm: alg, PublicKey: bytes.Repeat([]byte{0}, 16)}
		err := VerifyMTCSignature(key, MTCSignature{CosignerID: TrustAnchorID("x")}, nil)
		if err != ErrUnsupportedAlgorithm {
			t.Errorf("alg 0x%04x: err = %v, want ErrUnsupportedAlgorithm", uint16(alg), err)
		}
	}
}
