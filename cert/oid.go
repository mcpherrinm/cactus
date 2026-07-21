// Package cert deals with the X.509 / TLS encodings used by Merkle Tree
// certificates per draft-ietf-plants-merkle-tree-certs-04.
package cert

import "encoding/asn1"

// Experimental OIDs locked in for v1, per §13 and §5.1 of the draft.
// These will move to IANA-assigned arcs once the draft progresses;
// callers should consume the named symbols, not the raw arcs.
var (
	// OIDAlgMTCProof — id-alg-mtcProof, used as TBSCertificate.signature
	// and Certificate.signatureAlgorithm. Parameters MUST be omitted.
	OIDAlgMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}

	// OIDRDNATrustAnchorID — the experimental id-rdna-trustAnchorID arc.
	// In v1 the attribute value is encoded as a UTF8String containing the
	// CA ID's ASCII representation (per §5.1 "For initial experimentation").
	OIDRDNATrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}

	// OIDExtMTCCertificationAuthority — the experimental
	// id-pe-mtcCertificationAuthority arc (draft-05 §5.5 / §13.3). The
	// IANA-track value is {iso(1) ... pkix(7) pe(1) TBD}; until assignment
	// cactus uses this private-enterprise placeholder.
	OIDExtMTCCertificationAuthority = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}
)

// SubtreeSignatureLabel is the 12-byte fixed prefix from §5.3.1:
//
//	subtree/v1\n\0
//
// It is the first field of the CosignedMessage a cosigner signs. The
// label is designed for domain separation (§12.8): it does not begin
// with the DER SEQUENCE tag 0x30, so subtree signatures cannot collide
// with TBSCertificate / TBSCertList / OCSP ResponseData signing inputs.
const SubtreeSignatureLabel = "subtree/v1\n\x00"

// CertChainContentType is the ACME content type from §9 the server
// returns when downloading a Merkle Tree certificate.
const CertChainContentType = "application/pem-certificate-chain-with-properties"

// LegacyCertChainContentType is the fallback content type for ACME
// clients that do not advertise support for Merkle Tree certificates.
const LegacyCertChainContentType = "application/pem-certificate-chain"
