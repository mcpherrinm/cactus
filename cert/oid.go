// Package cert deals with the X.509 / TLS encodings used by Merkle Tree
// certificates per draft-ietf-plants-merkle-tree-certs-07.
package cert

import "encoding/asn1"

// PKIX OIDs allocated to draft-07 (§13.1). Earlier drafts used
// experimental arcs under 1.3.6.1.4.1.44363.47, which cactus no longer
// emits or accepts.
var (
	// OIDAlgMTCProof is id-alg-mtcProof {id-pkix algorithms(6) 67} (§6.2,
	// §13.1.2), used as TBSCertificate.signature and
	// Certificate.signatureAlgorithm. Parameters MUST be omitted.
	OIDAlgMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 67}

	// OIDRDNATrustAnchorID is id-rdna-trustAnchorID {id-pkix rdna(25) 3}
	// (§5.1, §13.1.4). The attribute value is a RELATIVE-OID holding the
	// trust anchor ID.
	OIDRDNATrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}

	// OIDExtMTCCertificationAuthoritySHA256 is
	// id-pe-mtcCertificationAuthority-SHA256 {id-pe 38} (§5.5, §13.1.3),
	// the Merkle Tree CA extension type for CAs whose logs hash with
	// SHA-256. Since draft-06 the extension type, not a field of the
	// extension, identifies the tree hash.
	OIDExtMTCCertificationAuthoritySHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 38}
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
