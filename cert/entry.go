package cert

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/letsencrypt/cactus/tlogx"
	"golang.org/x/crypto/cryptobyte"
)

// TBSCertificateLogEntry is the §5.2.1 ASN.1 SEQUENCE that the log
// stores. It mirrors the TBSCertificate structure of RFC 5280 with a
// few key substitutions:
//
//   - issuer is the CA ID DN (§5.1);
//   - subjectPublicKeyAlgorithm and subjectPublicKeyInfoHash replace
//     subjectPublicKeyInfo;
//   - signature/signatureValue are absent — they are conveyed via the
//     surrounding MerkleTreeCertEntry/Merkle proof.
//
// The struct here is defined explicitly rather than via Marshal-tagged
// reflection: encoding/asn1's RFC 5280 mapping is somewhat awkward
// (e.g. Validity, Name) and we want byte-exact DER for §12.6 strictness.
type TBSCertificateLogEntry struct {
	// Version is the X.509 version, 0 = v1, 2 = v3. We always emit v3 to
	// match standard ACME issuance, even though the LogEntry itself is
	// neutral on this; the X.509 cert built from it must match anyway.
	Version int

	// IssuerDN is the DER encoding of the Name (RFC 5280 §4.1.2.4) for
	// the CA ID, as built by BuildCAName.
	IssuerDN []byte

	NotBefore, NotAfter time.Time

	// SubjectDN is the DER encoding of the subject Name.
	SubjectDN []byte

	// SubjectPublicKeyAlgorithm is the DER of the AlgorithmIdentifier
	// from the cert's SubjectPublicKeyInfo.
	SubjectPublicKeyAlgorithm []byte

	// SubjectPublicKeyInfoHash is HASH(DER(SubjectPublicKeyInfo)) — the
	// hash output is stored raw (e.g. 32 bytes for SHA-256).
	SubjectPublicKeyInfoHash []byte

	// IssuerUniqueID, SubjectUniqueID, Extensions are encoded with the
	// IMPLICIT [1], [2] and EXPLICIT [3] tags from the ASN.1 module.
	IssuerUniqueID  []byte // raw bit string contents, nil if absent
	SubjectUniqueID []byte // raw bit string contents, nil if absent
	Extensions      []byte // DER of the Extensions SEQUENCE, nil if absent
}

// MerkleTreeCertEntryType matches the TLS-presentation enum from §5.2.1.
type MerkleTreeCertEntryType uint16

const (
	EntryTypeNullEntry    MerkleTreeCertEntryType = 0
	EntryTypeTBSCertEntry MerkleTreeCertEntryType = 1
)

// MerkleTreeCertEntryExtensionType is the §5.2.1 entry-extension type
// registry. No values are defined yet; the registry exists so future
// drafts can add entry-level extension fields.
type MerkleTreeCertEntryExtensionType uint16

// MerkleTreeCertEntryExtension is one entry-level extension (§5.2.1):
//
//	struct {
//	    MerkleTreeCertEntryExtensionType extension_type;
//	    opaque extension_data<0..2^16-1>;
//	} MerkleTreeCertEntryExtension;
type MerkleTreeCertEntryExtension struct {
	Type MerkleTreeCertEntryExtensionType
	Data []byte
}

// marshalEntryExtensions encodes the concatenated extensions of a
// MerkleTreeCertEntry's `extensions<0..2^16-1>` vector body (i.e.
// without the outer uint16 length prefix). §5.2.1 requires entries to
// be sorted ascending by extension_type with no duplicate types.
func marshalEntryExtensions(exts []MerkleTreeCertEntryExtension) ([]byte, error) {
	for i := 1; i < len(exts); i++ {
		if exts[i].Type < exts[i-1].Type {
			return nil, fmt.Errorf("cert: entry extensions not sorted (type %d after %d)", exts[i].Type, exts[i-1].Type)
		}
		if exts[i].Type == exts[i-1].Type {
			return nil, fmt.Errorf("cert: duplicate entry extension type %d", exts[i].Type)
		}
	}
	var inner []byte
	for _, e := range exts {
		if len(e.Data) > 0xffff {
			return nil, fmt.Errorf("cert: entry extension data %d > 65535 bytes", len(e.Data))
		}
		var eb cryptobyte.Builder
		eb.AddUint16(uint16(e.Type))
		eb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(e.Data) })
		raw, err := eb.Bytes()
		if err != nil {
			return nil, err
		}
		inner = append(inner, raw...)
	}
	return inner, nil
}

// parseEntryExtensions decodes the body of an `extensions<0..2^16-1>`
// vector (without the outer uint16 length prefix), enforcing the
// §5.2.1 ascending-order + no-duplicates rules.
func parseEntryExtensions(body cryptobyte.String) ([]MerkleTreeCertEntryExtension, error) {
	var out []MerkleTreeCertEntryExtension
	for !body.Empty() {
		var t uint16
		if !body.ReadUint16(&t) {
			return nil, errors.New("short entry extension type")
		}
		var data cryptobyte.String
		if !body.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("short entry extension data")
		}
		if n := len(out); n > 0 {
			if MerkleTreeCertEntryExtensionType(t) < out[n-1].Type {
				return nil, fmt.Errorf("entry extensions out of order (type %d)", t)
			}
			if MerkleTreeCertEntryExtensionType(t) == out[n-1].Type {
				return nil, fmt.Errorf("duplicate entry extension type %d", t)
			}
		}
		out = append(out, MerkleTreeCertEntryExtension{
			Type: MerkleTreeCertEntryExtensionType(t),
			Data: append([]byte(nil), data...),
		})
	}
	return out, nil
}

// encodeEntryExtensionsVector returns the full `extensions<0..2^16-1>`
// vector (uint16 length prefix + body) for prepending to a
// MerkleTreeCertEntry. cactus emits an empty vector today.
func encodeEntryExtensionsVector(exts []MerkleTreeCertEntryExtension) ([]byte, error) {
	body, err := marshalEntryExtensions(exts)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2+len(body))
	out[0] = byte(len(body) >> 8)
	out[1] = byte(len(body))
	copy(out[2:], body)
	return out, nil
}

// EncodeNullEntry returns the §5.2.1 MerkleTreeCertEntry serialization
// for a null entry: an empty extensions vector followed by the
// null_entry type. Any index MAY be a null entry (draft-04 relaxed the
// earlier "index 0 must be null" rule).
func EncodeNullEntry() []byte {
	return []byte{0x00, 0x00, 0x00, 0x00} // empty extensions + type=null_entry
}

// EncodeTBSCertEntry returns MerkleTreeCertEntry { extensions={}, type=1,
// data } where data is the contents octets of the TBSCertificateLogEntry
// DER (i.e. the SEQUENCE's value, excluding identifier+length). cactus
// always emits an empty extensions vector.
func EncodeTBSCertEntry(tbsContents []byte) []byte {
	out := make([]byte, 4+len(tbsContents))
	// extensions<0..2^16-1>: empty.
	out[0], out[1] = 0x00, 0x00
	// type = tbs_cert_entry (0x0001).
	out[2] = byte(EntryTypeTBSCertEntry >> 8)
	out[3] = byte(EntryTypeTBSCertEntry)
	copy(out[4:], tbsContents)
	return out
}

// MarshalContents returns the contents octets of the
// TBSCertificateLogEntry's DER encoding (i.e. without the outer
// SEQUENCE identifier+length). This is exactly the format §5.2.1 specifies
// goes into MerkleTreeCertEntry.tbs_cert_entry_data, and is what the
// log's Merkle leaves cover.
func (e *TBSCertificateLogEntry) MarshalContents() ([]byte, error) {
	full, err := e.MarshalDER()
	if err != nil {
		return nil, err
	}
	// Strip outer SEQUENCE tag + length.
	_, contents, err := stripDERHeader(full, 0x30)
	if err != nil {
		return nil, fmt.Errorf("strip outer SEQUENCE: %w", err)
	}
	return contents, nil
}

// MarshalDER returns the full DER encoding of the
// TBSCertificateLogEntry, as a SEQUENCE.
func (e *TBSCertificateLogEntry) MarshalDER() ([]byte, error) {
	var b derBuilder

	// version [0] EXPLICIT Version DEFAULT v1
	if e.Version != 0 {
		var inner derBuilder
		inner.WriteASN1Int(e.Version)
		b.WriteExplicit(0, inner.Bytes())
	}
	// issuer Name
	b.WriteRaw(e.IssuerDN)
	// validity Validity
	validity, err := encodeValidity(e.NotBefore, e.NotAfter)
	if err != nil {
		return nil, err
	}
	b.WriteRaw(validity)
	// subject Name
	b.WriteRaw(e.SubjectDN)
	// subjectPublicKeyAlgorithm AlgorithmIdentifier
	b.WriteRaw(e.SubjectPublicKeyAlgorithm)
	// subjectPublicKeyInfoHash OCTET STRING
	b.WriteASN1OctetString(e.SubjectPublicKeyInfoHash)
	// issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL
	if e.IssuerUniqueID != nil {
		b.WriteImplicitBitString(1, e.IssuerUniqueID)
	}
	// subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL
	if e.SubjectUniqueID != nil {
		b.WriteImplicitBitString(2, e.SubjectUniqueID)
	}
	// extensions [3] EXPLICIT Extensions{{CertExtensions}} OPTIONAL
	if e.Extensions != nil {
		b.WriteExplicit(3, e.Extensions)
	}
	return wrapSequence(b.Bytes()), nil
}

// EntryHash implements the §7.2 single-pass hash for a tbs_cert_entry
// with an empty extensions vector (the only form cactus emits):
//
//	HASH(0x00 || 0x00 0x00 || 0x00 0x01 || tbsContents-with-SPKI-replaced-by-its-hash)
//
// where the leading 0x00 is the RFC 9162 leaf prefix, 0x00 0x00 is the
// empty MerkleTreeCertEntry.extensions vector (§5.2.1), 0x00 0x01 is the
// tbs_cert_entry type, and tbsContents is the contents octets of
// TBSCertificateLogEntry (as encoded by MarshalContents). Use
// EntryHashExt to supply non-empty extensions.
//
// In the certificate-verification path, the verifier rebuilds
// TBSCertificateLogEntry from the X.509 TBSCertificate by replacing the
// SubjectPublicKeyInfo OCTET STRING-of-SPKI with hash-of-SPKI, and takes
// the extensions from the MTCProof. We expose the same hash here so
// issuance and verification can share the implementation.
func EntryHash(tbsContents []byte) tlogx.Hash {
	h, _ := EntryHashExt(nil, tbsContents)
	return h
}

// EntryHashExt is EntryHash with an explicit extensions vector. The
// extensions are written (as the §5.2.1 length-prefixed vector) between
// the RFC 9162 leaf prefix and the entry type, matching the §7.2 verify
// step "write the extensions field from the MTCProof to the hash".
func EntryHashExt(exts []MerkleTreeCertEntryExtension, tbsContents []byte) (tlogx.Hash, error) {
	extVec, err := encodeEntryExtensionsVector(exts)
	if err != nil {
		return tlogx.Hash{}, err
	}
	h := sha256.New()
	h.Write([]byte{0x00})       // RFC 9162 leaf prefix
	h.Write(extVec)             // MerkleTreeCertEntry.extensions<0..2^16-1>
	h.Write([]byte{0x00, 0x01}) // MerkleTreeCertEntryType=tbs_cert_entry, big-endian uint16
	h.Write(tbsContents)
	var out tlogx.Hash
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SinglePassEntryHash implements the alternate single-pass procedure
// described at the end of §7.2: hash the TBSCertificate contents
// directly, substituting subjectPublicKeyInfo with HASH(spki) wrapped in
// an OCTET STRING. preSPKI is the TBSCertificate contents up to (but
// not including) the subjectPublicKeyInfo field; spkiDER is the full
// DER of subjectPublicKeyInfo; postSPKI is the rest of the TBS contents
// after subjectPublicKeyInfo.
//
// Note: this assumes HashSize <= 127 so the OCTET STRING length is one
// octet (per the §7.2 algorithm).
func SinglePassEntryHash(preSPKI, spkiDER, postSPKI []byte, hashFn func() hash.Hash) []byte {
	if hashFn == nil {
		hashFn = sha256.New
	}
	hh := hashFn()
	// Hash of the SPKI alone, used to substitute for it in the entry hash.
	spkiHasher := hashFn()
	spkiHasher.Write(spkiDER)
	spkiHash := spkiHasher.Sum(nil)
	if len(spkiHash) > 127 {
		// Should never happen with SHA-256/384/512, but guard the
		// length-octet shortcut from §7.2.
		panic("SinglePassEntryHash: HASH_SIZE > 127 not supported")
	}

	// RFC 9162 leaf prefix.
	hh.Write([]byte{0x00})
	// MerkleTreeCertEntry.extensions<0..2^16-1>: empty in cactus.
	hh.Write([]byte{0x00, 0x00})
	// MerkleTreeCertEntryType = tbs_cert_entry (0x0001).
	hh.Write([]byte{0x00, 0x01})

	// In TBSCertificateLogEntry, the field at the SPKI position is
	// `subjectPublicKeyInfoHash OCTET STRING`. Its DER is 0x04 || length
	// || hash, but in the §5.3-defined contents-octets representation
	// the algorithm ID stays as subjectPublicKeyAlgorithm — that's
	// already in `preSPKI`'s caller logic. Here we substitute the
	// SubjectPublicKeyInfo's BIT STRING value in spkiDER with HASH(spki).
	hh.Write(preSPKI)
	hh.Write([]byte{0x04, byte(len(spkiHash))})
	hh.Write(spkiHash)
	hh.Write(postSPKI)
	return hh.Sum(nil)
}

// ----- DER helpers -----------------------------------------------------

type derBuilder struct {
	buf []byte
}

func (b *derBuilder) Bytes() []byte { return b.buf }

func (b *derBuilder) WriteRaw(p []byte) { b.buf = append(b.buf, p...) }

func (b *derBuilder) WriteASN1Int(v int) {
	body := encodeIntegerBytes(int64(v))
	b.buf = append(b.buf, 0x02)
	b.buf = appendDERLength(b.buf, len(body))
	b.buf = append(b.buf, body...)
}

func (b *derBuilder) WriteASN1OctetString(p []byte) {
	b.buf = append(b.buf, 0x04)
	b.buf = appendDERLength(b.buf, len(p))
	b.buf = append(b.buf, p...)
}

func (b *derBuilder) WriteImplicitBitString(tagNumber int, body []byte) {
	// IMPLICIT [n] applied to a UniqueIdentifier (BIT STRING). Tag class
	// = context-specific (0b10), primitive (0b0), tag number n.
	tag := byte(0x80 | tagNumber)
	// BIT STRING contents start with the unused-bits byte. We treat
	// the input as already including that byte.
	b.buf = append(b.buf, tag)
	b.buf = appendDERLength(b.buf, len(body))
	b.buf = append(b.buf, body...)
}

func (b *derBuilder) WriteExplicit(tagNumber int, body []byte) {
	// EXPLICIT [n] = a constructed context-specific tag wrapping body.
	tag := byte(0xa0 | tagNumber) // constructed bit set
	b.buf = append(b.buf, tag)
	b.buf = appendDERLength(b.buf, len(body))
	b.buf = append(b.buf, body...)
}

// wrapSequence wraps b in an outer DER SEQUENCE (tag 0x30).
func wrapSequence(b []byte) []byte {
	out := make([]byte, 0, 1+5+len(b))
	out = append(out, 0x30)
	out = appendDERLength(out, len(b))
	out = append(out, b...)
	return out
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

func encodeIntegerBytes(v int64) []byte {
	// Minimal-length two's complement, as DER requires.
	if v == 0 {
		return []byte{0x00}
	}
	var raw [9]byte
	for i := 0; i < 8; i++ {
		raw[i] = byte(v >> (56 - i*8))
	}
	// Strip leading 0x00 / 0xff bytes that don't change the value.
	i := 0
	for i < 7 {
		if v >= 0 && raw[i] == 0x00 && raw[i+1]&0x80 == 0 {
			i++
		} else if v < 0 && raw[i] == 0xff && raw[i+1]&0x80 != 0 {
			i++
		} else {
			break
		}
	}
	return raw[i:8]
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
	body := append(nb, na...)
	return wrapSequence(body), nil
}

func encodeRFC5280Time(t time.Time) ([]byte, error) {
	t = t.UTC()
	year := t.Year()
	if year < 1950 || year > 9999 {
		return nil, fmt.Errorf("validity year %d out of range", year)
	}
	if year < 2050 {
		// UTCTime: YYMMDDHHMMSSZ, tag 0x17.
		s := fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ",
			year%100, t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second())
		out := []byte{0x17}
		out = appendDERLength(out, len(s))
		out = append(out, s...)
		return out, nil
	}
	// GeneralizedTime: YYYYMMDDHHMMSSZ, tag 0x18.
	s := fmt.Sprintf("%04d%02d%02d%02d%02d%02dZ",
		year, t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	out := []byte{0x18}
	out = appendDERLength(out, len(s))
	out = append(out, s...)
	return out, nil
}

// stripDERHeader returns the contents bytes of a DER TLV whose tag
// matches `wantTag`. Returns the consumed length so callers can
// continue parsing.
func stripDERHeader(b []byte, wantTag byte) (consumed int, contents []byte, err error) {
	if len(b) < 2 {
		return 0, nil, errors.New("der: short input")
	}
	if b[0] != wantTag {
		return 0, nil, fmt.Errorf("der: unexpected tag 0x%02x, want 0x%02x", b[0], wantTag)
	}
	hdr := 1
	l := int(b[1])
	hdr++
	if l&0x80 != 0 {
		nbytes := l & 0x7f
		if nbytes == 0 || nbytes > 4 {
			return 0, nil, fmt.Errorf("der: bad length octets 0x%02x", b[1])
		}
		if len(b) < hdr+nbytes {
			return 0, nil, errors.New("der: truncated length")
		}
		l = 0
		for i := 0; i < nbytes; i++ {
			l = (l << 8) | int(b[hdr+i])
		}
		hdr += nbytes
	}
	if len(b) < hdr+l {
		return 0, nil, errors.New("der: truncated value")
	}
	return hdr + l, b[hdr : hdr+l], nil
}
