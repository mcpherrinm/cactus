package acme

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// AcceptedJWSAlgs is the set of signature algorithms cactus accepts on
// ACME requests. Constrained to the ACME-mandated set.
var AcceptedJWSAlgs = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
}

// ParsedJWS is the result of verifying an ACME request body.
type ParsedJWS struct {
	Payload    []byte
	Nonce      string
	URL        string
	KID        string           // header.kid for already-existing accounts
	JWK        *jose.JSONWebKey // header.jwk for new-account
	Thumbprint string           // SHA-256 thumbprint of the verified key
}

// ParseAndVerify validates the ACME JWS request body. If accountKey is
// nil, the JWS is verified against the embedded jwk (used for
// new-account); otherwise it is verified against accountKey (used for
// every other request).
func ParseAndVerify(body []byte, accountKey *jose.JSONWebKey) (*ParsedJWS, error) {
	jws, err := jose.ParseSigned(string(body), AcceptedJWSAlgs)
	if err != nil {
		return nil, fmt.Errorf("acme: parse JWS: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("acme: JWS must have exactly one signature, got %d", len(jws.Signatures))
	}
	sig := jws.Signatures[0]
	hdr := sig.Protected
	hasJWK := hdr.JSONWebKey != nil
	hasKID := hdr.KeyID != ""
	if hasJWK == hasKID {
		return nil, errors.New("acme: protected header must have exactly one of jwk and kid")
	}

	var verifyKey interface{}
	var jwkOut *jose.JSONWebKey
	if hasJWK {
		if accountKey != nil {
			return nil, errors.New("acme: jwk header used with existing account key")
		}
		jwkOut = hdr.JSONWebKey
		verifyKey = hdr.JSONWebKey.Key
	} else {
		if accountKey == nil {
			return nil, errors.New("acme: kid header but no account key provided to verifier")
		}
		verifyKey = accountKey.Key
	}

	payload, err := jws.Verify(verifyKey)
	if err != nil {
		return nil, fmt.Errorf("acme: verify JWS: %w", err)
	}

	out := &ParsedJWS{
		Payload: payload,
		Nonce:   hdr.Nonce,
		KID:     hdr.KeyID,
		JWK:     jwkOut,
	}
	// URL and other extras come from `extra` headers in go-jose.
	if v, ok := hdr.ExtraHeaders["url"]; ok {
		if s, ok := v.(string); ok {
			out.URL = s
		}
	}

	// Compute the JWK thumbprint to use as the account ID.
	var thumbKey *jose.JSONWebKey
	if hasJWK {
		thumbKey = hdr.JSONWebKey
	} else {
		thumbKey = accountKey
	}
	tp, err := thumbKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("acme: thumbprint: %w", err)
	}
	out.Thumbprint = base64.RawURLEncoding.EncodeToString(tp)
	return out, nil
}

// EmptyPayloadOK returns true if the JWS payload is the ACME
// "POST-as-GET" empty body.
func EmptyPayloadOK(payload []byte) bool {
	if len(payload) == 0 {
		return true
	}
	var v struct{}
	return json.Unmarshal(payload, &v) == nil && len(payload) == 2
}
