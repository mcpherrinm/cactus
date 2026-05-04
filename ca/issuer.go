package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// LogAPI is the subset of *log.Log the issuer needs. Defined as an
// interface so tests can substitute a fake.
type LogAPI interface {
	Append(ctx context.Context, entry []byte, idemKey [32]byte) (uint64, error)
	Wait(ctx context.Context, index uint64) (cactuslog.Issued, error)
}

// Issuer turns a CSR + ACME order into a Merkle Tree certificate per
// §6.1 of the draft.
type Issuer struct {
	Validator *Validator
	Log       LogAPI

	// LogIDDN is the precomputed DER-encoded log ID Name (§5.2). It's
	// used both as the TBSCertificateLogEntry.issuer and the
	// TBSCertificate.issuer.
	LogIDDN []byte
}

// New returns an Issuer configured with the given log ID. logID is the
// trust anchor ID's ASCII representation (e.g. "32473.1") — see §5.2.
func New(log LogAPI, logID string) (*Issuer, error) {
	if log == nil {
		return nil, errors.New("ca: log required")
	}
	dn, err := cert.BuildLogIDName(logID)
	if err != nil {
		return nil, fmt.Errorf("ca: log ID DN: %w", err)
	}
	return &Issuer{
		Validator: NewValidator(),
		Log:       log,
		LogIDDN:   dn,
	}, nil
}

// Issue submits a CSR + order to the log and returns the assembled
// X.509 certificate as DER bytes.
func (i *Issuer) Issue(ctx context.Context, csr *x509.CertificateRequest, order OrderInput) ([]byte, error) {
	v, err := i.Validator.Validate(csr, order)
	if err != nil {
		return nil, fmt.Errorf("ca: validate: %w", err)
	}
	_, _, tbsContents, err := BuildLogEntry(v, i.LogIDDN)
	if err != nil {
		return nil, fmt.Errorf("ca: build log entry: %w", err)
	}

	entry := cert.EncodeTBSCertEntry(tbsContents)
	idemKey := sha256.Sum256(tbsContents)

	idx, err := i.Log.Append(ctx, entry, idemKey)
	if err != nil {
		return nil, fmt.Errorf("ca: log append: %w", err)
	}
	issued, err := i.Log.Wait(ctx, idx)
	if err != nil {
		return nil, fmt.Errorf("ca: log wait: %w", err)
	}
	if issued.Index != idx {
		return nil, fmt.Errorf("ca: index mismatch: %d vs %d", issued.Index, idx)
	}
	if len(issued.Signatures) == 0 {
		return nil, errors.New("ca: log returned no cosigner signatures")
	}

	// Build MTCProof.
	proof := &cert.MTCProof{
		Start:          issued.Subtree.Start,
		End:            issued.Subtree.End,
		InclusionProof: issued.InclusionProof,
		Signatures:     issued.Signatures,
	}
	proofBytes, err := proof.MarshalTLS()
	if err != nil {
		return nil, fmt.Errorf("ca: marshal proof: %w", err)
	}

	derCert, err := assembleCertificate(certInputs{
		serialNumber:         idx,
		issuerDN:             i.LogIDDN,
		notBefore:            v.NotBefore,
		notAfter:             v.NotAfter,
		subjectDN:            v.Subject,
		subjectPublicKeyInfo: v.SubjectPublicKeyInfo,
		extensions:           v.Extensions,
		mtcProof:             proofBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("ca: assemble cert: %w", err)
	}
	return derCert, nil
}

// certInputs gathers the bytes needed to build a Merkle Tree cert. The
// X.509 wrapper has signature/algorithm = id-alg-mtcProof and
// signatureValue = a BIT STRING whose body is the MTCProof bytes.
type certInputs struct {
	serialNumber         uint64
	issuerDN             []byte
	notBefore, notAfter  time.Time
	subjectDN            []byte
	subjectPublicKeyInfo []byte
	extensions           []byte
	mtcProof             []byte
}

func assembleCertificate(in certInputs) ([]byte, error) {
	algID, err := encodeMTCProofAlgID()
	if err != nil {
		return nil, err
	}

	// Build TBSCertificate body.
	var b cryptobyte.Builder

	// version [0] EXPLICIT INTEGER (v3 = 2)
	b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
		c.AddASN1Int64(2)
	})

	// serialNumber INTEGER (RFC 5280 §4.1.2.2: positive, ≤20 octets)
	b.AddASN1BigInt(new(big.Int).SetUint64(in.serialNumber))

	// signature AlgorithmIdentifier (id-alg-mtcProof, params absent)
	b.AddBytes(algID)

	// issuer Name
	b.AddBytes(in.issuerDN)

	// validity Validity
	validityDER, err := encodeValidity(in.notBefore, in.notAfter)
	if err != nil {
		return nil, err
	}
	b.AddBytes(validityDER)

	// subject Name
	b.AddBytes(in.subjectDN)

	// subjectPublicKeyInfo SubjectPublicKeyInfo
	b.AddBytes(in.subjectPublicKeyInfo)

	// extensions [3] EXPLICIT Extensions OPTIONAL
	if len(in.extensions) > 0 {
		b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
			c.AddBytes(in.extensions)
		})
	}

	tbsBody, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	tbsCert := wrapSequence(tbsBody)

	// Outer Certificate.
	var outer cryptobyte.Builder
	outer.AddBytes(tbsCert)
	outer.AddBytes(algID)

	// signatureValue BIT STRING whose body is the MTCProof bytes,
	// prefixed by the unused-bits byte (0).
	outer.AddASN1BitString(in.mtcProof)

	outerBody, err := outer.Bytes()
	if err != nil {
		return nil, err
	}
	return wrapSequence(outerBody), nil
}

// encodeMTCProofAlgID returns the DER for AlgorithmIdentifier with
// algorithm = id-alg-mtcProof and parameters absent.
func encodeMTCProofAlgID() ([]byte, error) {
	type algID struct {
		Algorithm asn1.ObjectIdentifier
	}
	return asn1.Marshal(algID{Algorithm: cert.OIDAlgMTCProof})
}

// encodeValidity returns the DER for an RFC 5280 Validity SEQUENCE.
// §4.1.2.5: dates through 2049 MUST be UTCTime, dates 2050+ MUST be
// GeneralizedTime.
func encodeValidity(notBefore, notAfter time.Time) ([]byte, error) {
	nb, err := encodeRFC5280Time(notBefore)
	if err != nil {
		return nil, err
	}
	na, err := encodeRFC5280Time(notAfter)
	if err != nil {
		return nil, err
	}
	return wrapSequence(append(nb, na...)), nil
}

func encodeRFC5280Time(t time.Time) ([]byte, error) {
	t = t.UTC()
	year := t.Year()
	if year < 1950 || year > 9999 {
		return nil, fmt.Errorf("validity year %d out of range", year)
	}
	if year < 2050 {
		s := fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ",
			year%100, t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second())
		out := []byte{0x17}
		out = appendDERLength(out, len(s))
		return append(out, s...), nil
	}
	s := fmt.Sprintf("%04d%02d%02d%02d%02d%02dZ",
		year, t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	out := []byte{0x18}
	out = appendDERLength(out, len(s))
	return append(out, s...), nil
}
