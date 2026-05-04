package signer

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// marshalPKIXPublicKey wraps x509.MarshalPKIXPublicKey. Kept as a separate
// file so the import is co-located with this small helper.
func marshalPKIXPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
