// Package cert deals with the X.509 / TLS encodings used by Merkle Tree
// certificates per draft-ietf-plants-merkle-tree-certs-03.
package cert

import "encoding/asn1"

// Experimental OIDs locked in for v1, per §13 and §5.2 of the draft.
// These will move to IANA-assigned arcs once the draft progresses;
// callers should consume the named symbols, not the raw arcs.
var (
	// OIDAlgMTCProof — id-alg-mtcProof, used as TBSCertificate.signature
	// and Certificate.signatureAlgorithm. Parameters MUST be omitted.
	OIDAlgMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}

	// OIDRDNATrustAnchorID — the experimental id-rdna-trustAnchorID arc.
	// In v1 the attribute value is encoded as a UTF8String containing the
	// log ID's ASCII representation (per §5.2 "For initial experimentation").
	OIDRDNATrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
)

// SubtreeSignatureLabel is the 16-byte fixed prefix from §5.4.1:
//
//	mtc-subtree/v1\n\0
//
// concatenated with the cosigner ID and MTCSubtree to form the signing
// message MTCSubtreeSignatureInput.
const SubtreeSignatureLabel = "mtc-subtree/v1\n\x00"

// CertChainContentType is the ACME content type from §9 the server
// returns when downloading a Merkle Tree certificate.
const CertChainContentType = "application/pem-certificate-chain-with-properties"

// LegacyCertChainContentType is the fallback content type for ACME
// clients that do not advertise support for Merkle Tree certificates.
const LegacyCertChainContentType = "application/pem-certificate-chain"
