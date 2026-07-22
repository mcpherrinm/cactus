package cert

import (
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/cactus/tlogx"
)

// TrustAnchorID is the TrustAnchorID value from
// draft-ietf-tls-trust-anchor-ids §4.1, encoded on the wire as
// `opaque TrustAnchorID<1..2^8-1>`. cactus stores it in its canonical
// relative-OID ASCII form (e.g. "32473.1"); see trustanchorid.go for
// the DN, "oid/" name, and binary (wire) representations derived from
// it. On the wire (MTCProof.cosigner_id, §6.2) the binary form from
// TrustAnchorID.Binary is used; in memory cactus keeps the relative
// ASCII so cosigner IDs compare and log identically everywhere else.
type TrustAnchorID []byte

// MTCSubtree is an internal carrier for the (log ID, [start, end),
// subtree hash) tuple a cosigner signs. In draft-05 there is no
// standalone MTCSubtree wire struct; these fields are folded into the
// CosignedMessage (§5.3.1) produced by MarshalSignatureInput.
type MTCSubtree struct {
	LogID      TrustAnchorID
	Start, End uint64
	Hash       tlogx.Hash
}

// OIDName renders a trust anchor ID as the ASCII OID name used in a
// CosignedMessage's cosigner_name / log_origin fields (§5.3.1): the
// 16-byte ASCII string "oid/1.3.6.1.4.1." followed by the trust anchor
// ID's relative dotted-decimal ASCII representation. cactus stores
// TrustAnchorID values in their canonical relative form (e.g.
// "32473.1"), so this re-attaches the fixed 1.3.6.1.4.1 base: the
// example trust anchor ID 32473.1 yields "oid/1.3.6.1.4.1.32473.1".
func OIDName(id TrustAnchorID) string {
	return OIDNamePrefix + TrustAnchorOIDBase + "." + string(id)
}

// MarshalSignatureInput returns the bytes a cosigner signs: the §5.3.1
// CosignedMessage for the given subtree, with timestamp = 0 — the value
// required for Merkle Tree Certificate proofs (§6.2) and, equivalently,
// for c2sp.org/tlog-witness `sign-subtree` responses, whose timestamp
// "MUST be zero".
//
//	struct {
//	    uint8 label[12] = "subtree/v1\n\0";
//	    opaque cosigner_name<1..2^8-1>;   // OIDName(cosigner ID)
//	    uint64 timestamp;                  // 0 for MTC proofs
//	    opaque log_origin<1..2^8-1>;       // OIDName(log ID)
//	    uint64 start;
//	    uint64 end;
//	    HashValue subtree_hash;
//	} CosignedMessage;
//
// Use MarshalSignatureInputAt for the other flavour of cosignature: a
// *checkpoint* cosignature (c2sp.org/tlog-witness `add-checkpoint`, and
// the `add-entries` 200 response of c2sp.org/tlog-mirror), where the
// timestamp MUST NOT be zero.
func MarshalSignatureInput(cosignerID TrustAnchorID, subtree *MTCSubtree) ([]byte, error) {
	return MarshalSignatureInputAt(cosignerID, subtree, 0)
}

// MarshalSignatureInputAt is MarshalSignatureInput with an explicit
// CosignedMessage timestamp.
//
// The two callers want opposite things and the spec is strict about it:
//
//   - Subtree cosignatures (MTC §6.2, tlog-witness `sign-subtree`) MUST
//     carry timestamp 0, and start/end are the subtree's own bounds.
//   - Checkpoint cosignatures (tlog-witness `add-checkpoint`,
//     tlog-mirror `add-entries`) MUST carry a non-zero timestamp — it is
//     the cosigner's freshness assertion — and cover the whole tree, so
//     start MUST be 0 and end is the checkpoint's tree size.
//
// Neither rule is enforced here: the timestamp is an input to the
// signature, and both signing and verification have to reproduce
// whatever value is on the wire. Callers enforce the rules before
// trusting a signature (see mirrorpush.VerifyCosignatures).
func MarshalSignatureInputAt(cosignerID TrustAnchorID, subtree *MTCSubtree, timestamp uint64) ([]byte, error) {
	return MarshalCosignedMessage(OIDName(cosignerID), OIDName(subtree.LogID),
		timestamp, subtree.Start, subtree.End, subtree.Hash)
}

// MarshalCosignedMessage builds the §5.3.1 CosignedMessage from its raw
// string components. It exists for logs whose checkpoint origin is not
// an oid/-derived name — a c2sp.org/tlog-cosignature log_origin is just
// the checkpoint origin, and real-world MTC logs (e.g. Cloudflare's
// bootstrap CA) use plain hostname-path origins that TrustAnchorID
// cannot represent. Callers with trust anchor IDs on both sides should
// use MarshalSignatureInput / MarshalSignatureInputAt instead.
func MarshalCosignedMessage(cosignerName, logOrigin string, timestamp, start, end uint64, hash tlogx.Hash) ([]byte, error) {
	if len(SubtreeSignatureLabel) != 12 {
		return nil, fmt.Errorf("internal: SubtreeSignatureLabel is %d bytes", len(SubtreeSignatureLabel))
	}
	if len(cosignerName) < 1 || len(cosignerName) > 0xff {
		return nil, fmt.Errorf("cert: cosigner_name length %d out of range", len(cosignerName))
	}
	if len(logOrigin) < 1 || len(logOrigin) > 0xff {
		return nil, fmt.Errorf("cert: log_origin length %d out of range", len(logOrigin))
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte(SubtreeSignatureLabel))
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes([]byte(cosignerName)) })
	b.AddUint64(timestamp)
	b.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes([]byte(logOrigin)) })
	b.AddUint64(start)
	b.AddUint64(end)
	b.AddBytes(hash[:])
	return b.Bytes()
}

// MTCSignature mirrors the §6.2 struct:
//
//	struct {
//	    TrustAnchorID cosigner_id;
//	    opaque signature<0..2^16-1>;
//	} MTCSignature;
type MTCSignature struct {
	CosignerID TrustAnchorID
	Signature  []byte
}

// MTCProof is the §6.2 signatureValue contents — emitted raw into the
// X.509 BIT STRING with no ASN.1 wrapping:
//
//	struct {
//	    MerkleTreeCertEntryExtension extensions<0..2^16-1>;
//	    uint48 start;
//	    uint48 end;
//	    HashValue inclusion_proof<0..2^16-1>;
//	    MTCSignature signatures<0..2^16-1>;
//	} MTCProof;
//
// Per §6.2, `inclusion_proof<0..2^16-1>` is a length-prefixed byte
// vector containing concatenated HashValues; the verifier slices into
// HASH_SIZE pieces. `extensions` MUST equal the log entry's extensions
// (§5.2.1); `start`/`end` are 48-bit big-endian, capping the log index
// at 2^48-1. The `signatures` vector MUST be sorted by cosigner_id
// (shorter byte strings first, then lexicographically) with no
// duplicate cosigner_id values.
type MTCProof struct {
	Extensions     []MerkleTreeCertEntryExtension
	Start, End     uint64
	InclusionProof []tlogx.Hash
	Signatures     []MTCSignature
}

// maxUint48 is the largest value a uint48 field can hold.
const maxUint48 = 1<<48 - 1

func addUint48(b *cryptobyte.Builder, v uint64) {
	b.AddBytes([]byte{
		byte(v >> 40), byte(v >> 32), byte(v >> 24),
		byte(v >> 16), byte(v >> 8), byte(v),
	})
}

func readUint48(s *cryptobyte.String, v *uint64) bool {
	var buf [6]byte
	if !s.CopyBytes(buf[:]) {
		return false
	}
	*v = uint64(buf[0])<<40 | uint64(buf[1])<<32 | uint64(buf[2])<<24 |
		uint64(buf[3])<<16 | uint64(buf[4])<<8 | uint64(buf[5])
	return true
}

// MarshalTLS encodes the proof in the on-wire format. The output is
// what gets placed (verbatim, no further ASN.1) into the certificate's
// signatureValue BIT STRING per §6.2.
func (p *MTCProof) MarshalTLS() ([]byte, error) {
	if p.Start > maxUint48 || p.End > maxUint48 {
		return nil, fmt.Errorf("MTCProof: start/end exceed uint48 (%d, %d)", p.Start, p.End)
	}
	var b cryptobyte.Builder

	// extensions<0..2^16-1>: empty in cactus today, but always present.
	extBytes, err := marshalEntryExtensions(p.Extensions)
	if err != nil {
		return nil, err
	}
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(extBytes) })

	addUint48(&b, p.Start)
	addUint48(&b, p.End)

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
	// MTCSignature encodings. Per §6.2 each cosigner_id is the trust
	// anchor ID's *binary* representation (TAI §3), and the list MUST be
	// sorted by cosigner_id (shorter byte strings first, then
	// lexicographic) with no duplicates. We convert the in-memory
	// (relative-ASCII) IDs to binary, then sort/dedup on those bytes.
	type wireSig struct {
		id  []byte // binary cosigner_id
		sig []byte
	}
	wsigs := make([]wireSig, 0, len(p.Signatures))
	for _, s := range p.Signatures {
		bin, err := s.CosignerID.Binary()
		if err != nil {
			return nil, fmt.Errorf("MTCProof: cosigner_id %q: %w", s.CosignerID, err)
		}
		if len(bin) < 1 || len(bin) > 0xff {
			return nil, fmt.Errorf("MTCProof: cosigner_id binary length %d out of range [1,255]", len(bin))
		}
		if len(s.Signature) > 0xffff {
			return nil, fmt.Errorf("MTCProof: signature %d > 65535 bytes", len(s.Signature))
		}
		wsigs = append(wsigs, wireSig{id: bin, sig: s.Signature})
	}
	sort.SliceStable(wsigs, func(i, j int) bool {
		return cosignerIDLess(wsigs[i].id, wsigs[j].id)
	})
	for i := 1; i < len(wsigs); i++ {
		if string(wsigs[i].id) == string(wsigs[i-1].id) {
			return nil, fmt.Errorf("MTCProof: duplicate cosigner_id %x", wsigs[i].id)
		}
	}
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, s := range wsigs {
			c.AddUint8LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(s.id) })
			c.AddUint16LengthPrefixed(func(d *cryptobyte.Builder) { d.AddBytes(s.sig) })
		}
	})
	return b.Bytes()
}

// ParseMTCProof decodes a proof emitted by MarshalTLS. It enforces that
// inclusion_proof bytes are a multiple of HashSize and that the
// signatures vector is fully consumed.
func ParseMTCProof(data []byte) (*MTCProof, error) {
	s := cryptobyte.String(data)
	var p MTCProof

	var extBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extBytes) {
		return nil, errors.New("MTCProof: short read extensions")
	}
	exts, err := parseEntryExtensions(extBytes)
	if err != nil {
		return nil, fmt.Errorf("MTCProof: %w", err)
	}
	p.Extensions = exts

	if !readUint48(&s, &p.Start) {
		return nil, errors.New("MTCProof: short read start")
	}
	if !readUint48(&s, &p.End) {
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
	var prevBin []byte
	for len(sigBytes) > 0 {
		var idBytes cryptobyte.String
		if !sigBytes.ReadUint8LengthPrefixed(&idBytes) {
			return nil, errors.New("MTCProof: short read cosigner_id")
		}
		if len(idBytes) == 0 {
			return nil, errors.New("MTCProof: empty cosigner_id")
		}
		// §6.2 ordering/uniqueness is checked over the binary cosigner_id
		// bytes as read from the wire.
		if prevBin != nil {
			if string(prevBin) == string(idBytes) {
				return nil, fmt.Errorf("MTCProof: duplicate cosigner_id %x", []byte(idBytes))
			}
			if cosignerIDLess(idBytes, prevBin) {
				return nil, errors.New("MTCProof: signatures not sorted by cosigner_id")
			}
		}
		prevBin = append([]byte(nil), idBytes...)
		// Decode the binary cosigner_id back to the canonical relative
		// ASCII so it compares against configured cosigner IDs.
		id, err := TrustAnchorIDFromBinary(idBytes)
		if err != nil {
			return nil, fmt.Errorf("MTCProof: %w", err)
		}
		var sigData cryptobyte.String
		if !sigBytes.ReadUint16LengthPrefixed(&sigData) {
			return nil, errors.New("MTCProof: short read signature")
		}
		p.Signatures = append(p.Signatures, MTCSignature{
			CosignerID: id,
			Signature:  append([]byte(nil), sigData...),
		})
	}
	if !s.Empty() {
		return nil, fmt.Errorf("MTCProof: %d trailing bytes", len(s))
	}
	return &p, nil
}

// cosignerIDLess orders cosigner_id byte strings as §6.2 requires:
// shorter strings sort first; equal-length strings sort
// lexicographically. It operates on the binary cosigner_id bytes.
func cosignerIDLess(a, b []byte) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return string(a) < string(b)
}
