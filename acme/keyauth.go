package acme

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// keyAuthorization returns the RFC 8555 §8.1 keyAuthorization for the
// given token and account JWK: token + "." + base64url(SHA-256(JWK)).
func keyAuthorization(token string, jwkBytes []byte) (string, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
		return "", fmt.Errorf("parse stored JWK: %w", err)
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("thumbprint: %w", err)
	}
	return token + "." + base64.RawURLEncoding.EncodeToString(tp), nil
}
