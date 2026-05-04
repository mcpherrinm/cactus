// Package ca turns validated ACME orders into Merkle Tree certificates.
//
// The Validator (Phase 3.1) checks a CSR matches an order and produces
// the inputs needed to build a TBSCertificateLogEntry. The Issuer
// (Phase 3.2) drives the log Append/Wait round-trip and assembles the
// final X.509 certificate per §6.1.
package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/letsencrypt/cactus/cert"
)

// OrderInput carries the relevant ACME order state. It is the
// validator's job to confirm the CSR is consistent with this.
type OrderInput struct {
	// AuthorizedDNSNames is the set of names the order has validated.
	// SAN dNSName entries in the CSR MUST all be members.
	AuthorizedDNSNames []string

	// AuthorizedIPs is the set of IP addresses the order has validated
	// (for completeness; usually empty in cactus tests).
	AuthorizedIPs []net.IP

	// NotBefore / NotAfter define the validity window the issuer will
	// stamp on the certificate. If zero, the issuer applies a default.
	NotBefore, NotAfter time.Time
}

// Validated is the result of Validator.Validate. It carries the
// pre-computed pieces needed to build both the
// TBSCertificateLogEntry and the X.509 TBSCertificate.
type Validated struct {
	Subject               []byte // DER of subject Name
	SubjectPublicKeyInfo  []byte // DER of SubjectPublicKeyInfo
	SubjectPublicKeyAlgID []byte // DER of the AlgorithmIdentifier inside SPKI
	Extensions            []byte // DER of the *contents* of Extensions SEQUENCE (i.e. just the inner SEQUENCEs concatenated; see x509Builder)
	NotBefore, NotAfter   time.Time
}

// Validator turns a CSR + order into a Validated.
type Validator struct {
	// DefaultLifetime is the validity window applied when the order
	// does not pin a NotBefore/NotAfter.
	DefaultLifetime time.Duration

	// Now returns "now"; mocked in tests.
	Now func() time.Time
}

// NewValidator returns a Validator with sensible defaults.
func NewValidator() *Validator {
	return &Validator{
		DefaultLifetime: 7 * 24 * time.Hour,
		Now:             time.Now,
	}
}

// ErrBadCSR is returned by Validate when the CSR is malformed or its
// identifiers don't match the order. ACME callers should map this to
// the `urn:ietf:params:acme:error:badCSR` problem type (RFC 8555 §7.4).
var ErrBadCSR = errors.New("badCSR")

// Validate checks csr against order and returns a Validated.
func (v *Validator) Validate(csr *x509.CertificateRequest, order OrderInput) (*Validated, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: csr signature: %v", ErrBadCSR, err)
	}

	// Every dNSName in the CSR's SAN must have been authorized.
	authorized := make(map[string]struct{}, len(order.AuthorizedDNSNames))
	for _, n := range order.AuthorizedDNSNames {
		authorized[strings.ToLower(n)] = struct{}{}
	}
	for _, n := range csr.DNSNames {
		if _, ok := authorized[strings.ToLower(n)]; !ok {
			return nil, fmt.Errorf("%w: CSR DNSName %q not authorized by order", ErrBadCSR, n)
		}
	}

	authorizedIPs := make(map[string]struct{}, len(order.AuthorizedIPs))
	for _, ip := range order.AuthorizedIPs {
		authorizedIPs[ip.String()] = struct{}{}
	}
	for _, ip := range csr.IPAddresses {
		if _, ok := authorizedIPs[ip.String()]; !ok {
			return nil, fmt.Errorf("%w: CSR IPAddress %s not authorized by order", ErrBadCSR, ip)
		}
	}

	if len(csr.DNSNames)+len(csr.IPAddresses) == 0 {
		return nil, fmt.Errorf("%w: CSR has no SAN entries", ErrBadCSR)
	}

	notBefore := order.NotBefore
	notAfter := order.NotAfter
	if notBefore.IsZero() {
		notBefore = v.Now().UTC()
	}
	if notAfter.IsZero() {
		notAfter = notBefore.Add(v.DefaultLifetime)
	}
	if !notAfter.After(notBefore) {
		return nil, errors.New("validity window has zero or negative duration")
	}

	subjectDER := csr.RawSubject
	if len(subjectDER) == 0 {
		// Synthesize an empty Name (an RDN sequence with no entries).
		subjectDER = []byte{0x30, 0x00}
	}

	// Extract the SPKI's algorithm portion. csr.RawSubjectPublicKeyInfo
	// is the full DER. Inside, the first child is the AlgorithmIdentifier.
	spkiDER := csr.RawSubjectPublicKeyInfo
	algID, err := extractFirstElement(spkiDER)
	if err != nil {
		return nil, fmt.Errorf("extract SPKI algorithm: %w", err)
	}

	extensions, err := buildExtensionsFromCSR(csr)
	if err != nil {
		return nil, fmt.Errorf("build extensions: %w", err)
	}

	return &Validated{
		Subject:               subjectDER,
		SubjectPublicKeyInfo:  spkiDER,
		SubjectPublicKeyAlgID: algID,
		Extensions:            extensions,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}, nil
}

// BuildLogEntry returns the TBSCertificateLogEntry's contents-octet
// encoding (i.e. without the outer SEQUENCE header), plus the full DER
// of the entry. The contents-octet form is what gets carried in
// MerkleTreeCertEntry.tbs_cert_entry_data per §5.3.
func BuildLogEntry(v *Validated, issuerDN []byte) (*cert.TBSCertificateLogEntry, []byte, []byte, error) {
	if len(v.SubjectPublicKeyInfo) == 0 {
		return nil, nil, nil, errors.New("SubjectPublicKeyInfo missing")
	}
	if len(issuerDN) == 0 {
		return nil, nil, nil, errors.New("issuer DN missing")
	}
	spkiHash := sha256.Sum256(v.SubjectPublicKeyInfo)

	entry := &cert.TBSCertificateLogEntry{
		Version:                   2, // X.509 v3
		IssuerDN:                  issuerDN,
		NotBefore:                 v.NotBefore,
		NotAfter:                  v.NotAfter,
		SubjectDN:                 v.Subject,
		SubjectPublicKeyAlgorithm: v.SubjectPublicKeyAlgID,
		SubjectPublicKeyInfoHash:  spkiHash[:],
		Extensions:                v.Extensions,
	}
	der, err := entry.MarshalDER()
	if err != nil {
		return nil, nil, nil, err
	}
	contents, err := entry.MarshalContents()
	if err != nil {
		return nil, nil, nil, err
	}
	return entry, der, contents, nil
}

// extractFirstElement returns the first ASN.1 element of a SEQUENCE,
// preserving its DER encoding (header + body). data is the full DER of
// the parent SEQUENCE.
func extractFirstElement(data []byte) ([]byte, error) {
	var inner asn1.RawValue
	rest, err := asn1.Unmarshal(data, &inner)
	if err != nil {
		return nil, err
	}
	_ = rest
	if !inner.IsCompound {
		return nil, errors.New("expected outer SEQUENCE")
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(inner.Bytes, &first); err != nil {
		return nil, err
	}
	return first.FullBytes, nil
}

// buildExtensionsFromCSR returns the DER of the EXPLICIT [3] Extensions
// wrapper for a CSR's extensions. We re-emit each extension verbatim
// from the CSR (which preserves DER from the request), filtering out
// any that don't belong on a leaf cert (none currently filtered).
//
// The returned bytes are the *value contents* of the EXPLICIT [3]
// wrapper — i.e. the SEQUENCE-of-Extension DER itself, ready to be
// dropped into TBSCertificateLogEntry.Extensions or
// TBSCertificate.extensions.
func buildExtensionsFromCSR(csr *x509.CertificateRequest) ([]byte, error) {
	if len(csr.Extensions) == 0 {
		return nil, nil
	}
	// Sort by OID for determinism.
	exts := make([]pkix_Extension, 0, len(csr.Extensions))
	for _, e := range csr.Extensions {
		exts = append(exts, pkix_Extension{
			ID:       e.Id,
			Critical: e.Critical,
			Value:    e.Value,
		})
	}
	sort.Slice(exts, func(i, j int) bool {
		return oidLess(exts[i].ID, exts[j].ID)
	})

	// Marshal each Extension and concatenate, then wrap in SEQUENCE.
	var inner []byte
	for _, e := range exts {
		der, err := asn1.Marshal(e)
		if err != nil {
			return nil, err
		}
		inner = append(inner, der...)
	}
	return wrapSequence(inner), nil
}

// pkix_Extension is asn1.Marshal-friendly, identical to pkix.Extension
// but defined locally so we can keep the dependency graph tight.
type pkix_Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

func oidLess(a, b asn1.ObjectIdentifier) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// wrapSequence wraps body in a DER SEQUENCE.
func wrapSequence(body []byte) []byte {
	var hdr []byte
	hdr = append(hdr, 0x30)
	hdr = appendDERLength(hdr, len(body))
	return append(hdr, body...)
}

func appendDERLength(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n <= 0xff:
		return append(b, 0x81, byte(n))
	case n <= 0xffff:
		return append(b, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(b, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}
