package cert

import (
	"errors"
	"fmt"

	"github.com/letsencrypt/cactus/tlogx"
	"golang.org/x/crypto/cryptobyte"
)

// TrustAnchorID is the TrustAnchorID value from
// draft-ietf-tls-trust-anchor-ids §4.1, encoded on the wire as
// `opaque TrustAnchorID<1..2^8-1>`. Cactus uses the relative-OID-as-
// ASCII representation for v1 (e.g. "32473.1"); the binary
// representation defined by the trust-anchor-ids draft is used wherever
// the TLS presentation language requires it.
type TrustAnchorID []byte

// MTCSubtree mirrors the TLS-presentation struct from §5.4.1:
//
//	struct {
//	    TrustAnchorID log_id;
//	    uint64 start;
//	    uint64 end;
//	    HashValue hash;
//	} MTCSubtree;
type MTCSubtree struct {
	LogID      TrustAnchorID
	Start, End uint64
	Hash       tlogx.Hash
}

// MarshalTLS returns the TLS-presentation encoding of the subtree.
func (s *MTCSubtree) MarshalTLS() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) {
		c.AddBytes(s.LogID)
	})
	b.AddUint64(s.Start)
	b.AddUint64(s.End)
	b.AddBytes(s.Hash[:])
	return b.Bytes()
}

// MTCSubtreeSignatureInput is the §5.4.1 signing message:
//
//	struct {
//	    uint8 label[16] = "mtc-subtree/v1\n\0";
//	    TrustAnchorID cosigner_id;
//	    MTCSubtree subtree;
//	} MTCSubtreeSignatureInput;
//
// MarshalSignatureInput returns the bytes a cosigner signs.
func MarshalSignatureInput(cosignerID TrustAnchorID, subtree *MTCSubtree) ([]byte, error) {
	subtreeBytes, err := subtree.MarshalTLS()
	if err != nil {
		return nil, err
	}
	if len(SubtreeSignatureLabel) != 16 {
		return nil, fmt.Errorf("internal: SubtreeSignatureLabel is %d bytes", len(SubtreeSignatureLabel))
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte(SubtreeSignatureLabel))
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) {
		c.AddBytes(cosignerID)
	})
	b.AddBytes(subtreeBytes)
	return b.Bytes()
}

// MTCSignature mirrors the §6.1 struct:
//
//	struct {
//	    TrustAnchorID cosigner_id;
//	    opaque signature<0..2^16-1>;
//	} MTCSignature;
type MTCSignature struct {
	CosignerID TrustAnchorID
	Signature  []byte
}

// MTCProof is the §6.1 signatureValue contents — emitted raw into the
// X.509 BIT STRING with no ASN.1 wrapping:
//
//	struct {
//	    uint64 start;
//	    uint64 end;
//	    HashValue inclusion_proof<0..2^16-1>;
//	    MTCSignature signatures<0..2^16-1>;
//	} MTCProof;
//
// Per §6.1, `inclusion_proof<0..2^16-1>` is a length-prefixed byte
// vector containing concatenated HashValues; the verifier slices into
// HASH_SIZE pieces.
type MTCProof struct {
	Start, End     uint64
	InclusionProof []tlogx.Hash
	Signatures     []MTCSignature
}

// MarshalTLS encodes the proof in the on-wire format. The output is
// what gets placed (verbatim, no further ASN.1) into the certificate's
// signatureValue BIT STRING per §6.1.
func (p *MTCProof) MarshalTLS() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint64(p.Start)
	b.AddUint64(p.End)

	// inclusion_proof<0..2^16-1>: length prefix counts bytes (concatenated hashes).
	var ipErr error
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		total := len(p.InclusionProof) * tlogx.HashSize
		if total > 0xffff {
			ipErr = fmt.Errorf("inclusion_proof too long: %d nodes * %d bytes", len(p.InclusionProof), tlogx.HashSize)
			return
		}
		for _, h := range p.InclusionProof {
			c.AddBytes(h[:])
		}
	})
	if ipErr != nil {
		return nil, ipErr
	}

	// signatures<0..2^16-1>: outer length-prefix wraps the concatenated
	// MTCSignature encodings.
	var sigErr error
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for i, s := range p.Signatures {
			if len(s.CosignerID) > 0xff {
				sigErr = fmt.Errorf("signatures[%d]: cosigner_id %d > 255 bytes", i, len(s.CosignerID))
				return
			}
			if len(s.Signature) > 0xffff {
				sigErr = fmt.Errorf("signatures[%d]: signature %d > 65535 bytes", i, len(s.Signature))
				return
			}
			c.AddUint8LengthPrefixed(func(d *cryptobyte.Builder) {
				d.AddBytes(s.CosignerID)
			})
			c.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) {
				d.AddBytes(s.Signature)
			})
		}
	})
	if sigErr != nil {
		return nil, sigErr
	}
	return b.Bytes()
}

// ParseMTCProof decodes a proof emitted by MarshalTLS. It enforces that
// inclusion_proof bytes are a multiple of HashSize and that the
// signatures vector is fully consumed.
func ParseMTCProof(data []byte) (*MTCProof, error) {
	s := cryptobyte.String(data)
	var p MTCProof
	if !s.ReadUint64(&p.Start) {
		return nil, errors.New("MTCProof: short read start")
	}
	if !s.ReadUint64(&p.End) {
		return nil, errors.New("MTCProof: short read end")
	}

	var ipBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ipBytes) {
		return nil, errors.New("MTCProof: short read inclusion_proof length")
	}
	if len(ipBytes)%tlogx.HashSize != 0 {
		return nil, fmt.Errorf("MTCProof: inclusion_proof length %d not multiple of %d", len(ipBytes), tlogx.HashSize)
	}
	for len(ipBytes) > 0 {
		var h tlogx.Hash
		if !ipBytes.CopyBytes(h[:]) {
			return nil, errors.New("MTCProof: inclusion_proof copy failed")
		}
		p.InclusionProof = append(p.InclusionProof, h)
	}

	var sigBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&sigBytes) {
		return nil, errors.New("MTCProof: short read signatures")
	}
	for len(sigBytes) > 0 {
		var sig MTCSignature
		var idBytes cryptobyte.String
		if !sigBytes.ReadUint8LengthPrefixed(&idBytes) {
			return nil, errors.New("MTCProof: short read cosigner_id")
		}
		sig.CosignerID = append([]byte(nil), idBytes...)
		var sigData cryptobyte.String
		if !sigBytes.ReadUint16LengthPrefixed(&sigData) {
			return nil, errors.New("MTCProof: short read signature")
		}
		sig.Signature = append([]byte(nil), sigData...)
		p.Signatures = append(p.Signatures, sig)
	}
	if !s.Empty() {
		return nil, fmt.Errorf("MTCProof: %d trailing bytes", len(s))
	}
	return &p, nil
}
