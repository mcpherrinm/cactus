package mirrorpush

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/letsencrypt/cactus/tlogx"
)

// EntriesPerPackage is the entry-package alignment mandated by
// c2sp.org/tlog-mirror: "The interval determines a fixed canonical
// sequence of entry packages, aligned at multiples of 256." The value
// is not a tunable — it is chosen to coincide with the entry bundle
// size of c2sp.org/tlog-tiles (1 << TileHeight), so a mirror can commit
// exactly one bundle per authenticated package.
const EntriesPerPackage = 256

// MaxPackagesPerRequest is the per-request package cap clients SHOULD
// observe ("at most 32 entry packages (8192 entries)"), so bodies stay
// under the request size limits of common hosting platforms. Beyond it
// the client sends a strict prefix of the canonical sequence and
// completes the upload via the 202 loop.
const MaxPackagesPerRequest = 32

// MaxProofHashes is the per-package proof cap: num_hashes is a single
// byte and "MUST be at most 63".
const MaxProofHashes = 63

// maxOriginLen is the ceiling implied by the uint16 log_origin_size
// header field. cactus origins are ~40 bytes, so this only ever fires
// on a caller bug.
const maxOriginLen = 0xffff

// Package is one element of the canonical entry-package sequence.
//
// It carries two distinct ranges, and conflating them is the single
// easiest way to produce an add-entries request that a mirror rejects
// with a 422 that looks like a Merkle bug:
//
//   - [Start, End) is what goes on the wire. For package 0 of an upload
//     whose upload_start is not 256-aligned, Start is upload_start, so
//     the package transmits fewer than 256 entries.
//   - [ProofStart, End) is what the subtree consistency proof is
//     computed over. ProofStart is always rounded_start + i*256, i.e.
//     the *aligned* bundle boundary, even when Start is past it. The
//     mirror already holds the entries in [ProofStart, Start) — that is
//     precisely why it advertised a next entry inside the bundle — and
//     reconstructs the subtree hash from its own storage plus the
//     entries we send.
//
// [ProofStart, End) is always a valid subtree per MTC §4.1: ProofStart
// is a multiple of 256 and End-Start is at most 256, so ProofStart is
// necessarily a multiple of bit_ceil(End-ProofStart).
type Package struct {
	Start, End uint64
	ProofStart uint64
}

// maxMaterialisedPackages bounds CanonicalSequence's allocation.
//
// The protocol places no limit on an upload interval, and the header
// fields are uint64, so a hostile or corrupt header can describe
// 2^55 packages. Anything that materialises the sequence eagerly from
// untrusted values is an out-of-memory bug waiting to happen, so
// CanonicalSequence refuses absurd intervals and the parser below never
// materialises the sequence at all — it walks it lazily, bounded by the
// bytes actually present. This cap (a quarter of a billion entries) is
// far past any real upload; a client hits the 32-package request cap
// long before.
const maxMaterialisedPackages = 1 << 20

// NumPackages returns the number of packages in the canonical sequence
// for [uploadStart, uploadEnd).
func NumPackages(uploadStart, uploadEnd uint64) (uint64, error) {
	if uploadStart > uploadEnd {
		return 0, fmt.Errorf("mirrorpush: upload_start %d > upload_end %d", uploadStart, uploadEnd)
	}
	if uploadStart == uploadEnd {
		return 0, nil
	}
	roundedStart := uploadStart - uploadStart%EntriesPerPackage
	roundedEnd := uploadEnd
	if r := uploadEnd % EntriesPerPackage; r != 0 {
		// Rounding up cannot overflow in practice: log indices are
		// capped at 2^48-1 (MTC §5.2), far below the wrap point.
		roundedEnd = uploadEnd - r + EntriesPerPackage
	}
	return (roundedEnd - roundedStart) / EntriesPerPackage, nil
}

// PackageAt returns package i of the canonical sequence for
// [uploadStart, uploadEnd). It is the single definition of the
// arithmetic; everything else in this file goes through it.
func PackageAt(uploadStart, uploadEnd, i uint64) Package {
	roundedStart := uploadStart - uploadStart%EntriesPerPackage
	lo := roundedStart + i*EntriesPerPackage
	return Package{
		Start:      max(uploadStart, lo),
		End:        min(uploadEnd, lo+EntriesPerPackage),
		ProofStart: lo,
	}
}

// CanonicalSequence derives the full canonical sequence of entry
// packages for the upload interval [uploadStart, uploadEnd), per
// c2sp.org/tlog-mirror.
//
// The sequence is a pure function of the two header values, which is
// the point: nothing about package boundaries or counts is transmitted,
// so sender and receiver must derive an identical sequence from the
// header alone. An empty interval yields an empty sequence.
func CanonicalSequence(uploadStart, uploadEnd uint64) ([]Package, error) {
	n, err := NumPackages(uploadStart, uploadEnd)
	if err != nil {
		return nil, err
	}
	if n > maxMaterialisedPackages {
		return nil, fmt.Errorf("mirrorpush: canonical sequence for [%d,%d) has %d packages, refusing to materialise more than %d",
			uploadStart, uploadEnd, n, maxMaterialisedPackages)
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]Package, 0, n)
	for i := uint64(0); i < n; i++ {
		out = append(out, PackageAt(uploadStart, uploadEnd, i))
	}
	return out, nil
}

// Header is the fixed-size preamble of an add-entries request body.
type Header struct {
	Origin      string
	UploadStart uint64
	UploadEnd   uint64
	// Ticket is the opaque mirror-supplied resume token, in its RAW
	// form. Note the asymmetry, which is easy to get backwards: the
	// ticket travels base64-encoded in the mirror-info body of a 202 or
	// 409 response, but raw and length-prefixed here. ParseMirrorInfo
	// decodes on receipt so everything downstream of it — including
	// this field — deals only in raw bytes.
	Ticket []byte
}

// PackageData is the transmitted content of one entry package: the
// entries in [Package.Start, Package.End) and the subtree consistency
// proof from the subtree [Package.ProofStart, Package.End) to the log
// checkpoint of size upload_end.
type PackageData struct {
	Entries [][]byte
	Proof   []tlogx.Hash
}

// BuildAddEntries assembles an add-entries request body: the header,
// then the given packages concatenated with neither a package count nor
// per-package length prefixes.
//
// pkgs MUST be a prefix of CanonicalSequence(h.UploadStart, h.UploadEnd)
// — the spec permits a strict prefix (that is how oversized uploads and
// the 32-package cap work) but not a subset or a reordering. That is
// checked here rather than trusted, because the failure mode on the
// wire is a mirror rejecting a structurally fine-looking body.
func BuildAddEntries(h Header, pkgs []PackageData) ([]byte, error) {
	if len(h.Origin) == 0 || len(h.Origin) > maxOriginLen {
		return nil, fmt.Errorf("mirrorpush: log_origin length %d out of range [1,%d]", len(h.Origin), maxOriginLen)
	}
	if len(h.Ticket) > 0xffff {
		return nil, fmt.Errorf("mirrorpush: ticket length %d exceeds uint16", len(h.Ticket))
	}
	n, err := NumPackages(h.UploadStart, h.UploadEnd)
	if err != nil {
		return nil, err
	}
	if uint64(len(pkgs)) > n {
		return nil, fmt.Errorf("mirrorpush: %d packages but the canonical sequence has %d", len(pkgs), n)
	}

	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Origin)))
	b = append(b, h.Origin...)
	b = binary.BigEndian.AppendUint64(b, h.UploadStart)
	b = binary.BigEndian.AppendUint64(b, h.UploadEnd)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Ticket)))
	b = append(b, h.Ticket...)

	for i, p := range pkgs {
		cp := PackageAt(h.UploadStart, h.UploadEnd, uint64(i))
		want := cp.End - cp.Start
		if uint64(len(p.Entries)) != want {
			return nil, fmt.Errorf("mirrorpush: package %d has %d entries, canonical sequence says %d for [%d,%d)",
				i, len(p.Entries), want, cp.Start, cp.End)
		}
		if len(p.Proof) > MaxProofHashes {
			return nil, fmt.Errorf("mirrorpush: package %d proof has %d hashes, max %d", i, len(p.Proof), MaxProofHashes)
		}
		for j, e := range p.Entries {
			if len(e) > 0xffff {
				return nil, fmt.Errorf("mirrorpush: package %d entry %d is %d bytes, exceeds uint16 framing", i, j, len(e))
			}
			b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
			b = append(b, e...)
		}
		b = append(b, byte(len(p.Proof)))
		for _, h := range p.Proof {
			b = append(b, h[:]...)
		}
	}
	return b, nil
}

// ParseAddEntries is the inverse of BuildAddEntries: it recovers the
// header, re-derives the canonical sequence from that header alone, and
// reads back exactly as many packages as the body contains.
//
// cactus is a client and never serves add-entries, so this exists to
// pin the framing: a build/parse round trip proves that a receiver
// which knows nothing but the header can segment the body the same way
// the sender did. It is also the fuzz entry point.
//
// The returned Package slice is the prefix of the canonical sequence
// that the body actually covers, so pkgs[i] describes data[i].
func ParseAddEntries(body []byte) (h Header, pkgs []Package, data []PackageData, err error) {
	s := body
	readUint16 := func() (uint16, bool) {
		if len(s) < 2 {
			return 0, false
		}
		v := binary.BigEndian.Uint16(s)
		s = s[2:]
		return v, true
	}
	readUint64 := func() (uint64, bool) {
		if len(s) < 8 {
			return 0, false
		}
		v := binary.BigEndian.Uint64(s)
		s = s[8:]
		return v, true
	}
	readN := func(n int) ([]byte, bool) {
		if n < 0 || len(s) < n {
			return nil, false
		}
		v := s[:n]
		s = s[n:]
		return v, true
	}

	originLen, ok := readUint16()
	if !ok {
		return h, nil, nil, errors.New("mirrorpush: short read log_origin_size")
	}
	if originLen == 0 {
		// A zero-length origin is framing-legal but cannot name a log,
		// and BuildAddEntries refuses to emit one. Rejecting it here
		// keeps the parser and the builder accepting exactly the same
		// set of bodies, which is the property the framing fuzz target
		// checks.
		return h, nil, nil, errors.New("mirrorpush: zero-length log_origin")
	}
	origin, ok := readN(int(originLen))
	if !ok {
		return h, nil, nil, errors.New("mirrorpush: short read log_origin")
	}
	h.Origin = string(origin)
	if h.UploadStart, ok = readUint64(); !ok {
		return h, nil, nil, errors.New("mirrorpush: short read upload_start")
	}
	if h.UploadEnd, ok = readUint64(); !ok {
		return h, nil, nil, errors.New("mirrorpush: short read upload_end")
	}
	ticketLen, ok := readUint16()
	if !ok {
		return h, nil, nil, errors.New("mirrorpush: short read ticket_size")
	}
	ticket, ok := readN(int(ticketLen))
	if !ok {
		return h, nil, nil, errors.New("mirrorpush: short read ticket")
	}
	if ticketLen > 0 {
		h.Ticket = append([]byte(nil), ticket...)
	}

	// The sequence is walked lazily rather than materialised: the
	// header is untrusted here, and an interval describing billions of
	// packages must cost nothing beyond the bytes actually received.
	// Each package consumes at least one byte, so the loop is bounded
	// by the body length.
	n, err := NumPackages(h.UploadStart, h.UploadEnd)
	if err != nil {
		return h, nil, nil, err
	}
	for i := uint64(0); len(s) > 0; i++ {
		if i >= n {
			return h, nil, nil, fmt.Errorf("mirrorpush: %d trailing bytes after the canonical sequence", len(s))
		}
		cp := PackageAt(h.UploadStart, h.UploadEnd, i)
		var pd PackageData
		for j := cp.Start; j < cp.End; j++ {
			n, ok := readUint16()
			if !ok {
				return h, nil, nil, fmt.Errorf("mirrorpush: package %d: short read entry length", i)
			}
			e, ok := readN(int(n))
			if !ok {
				return h, nil, nil, fmt.Errorf("mirrorpush: package %d: short read entry", i)
			}
			pd.Entries = append(pd.Entries, append([]byte(nil), e...))
		}
		nh, ok := readN(1)
		if !ok {
			return h, nil, nil, fmt.Errorf("mirrorpush: package %d: short read num_hashes", i)
		}
		if int(nh[0]) > MaxProofHashes {
			return h, nil, nil, fmt.Errorf("mirrorpush: package %d: num_hashes %d exceeds %d", i, nh[0], MaxProofHashes)
		}
		for k := 0; k < int(nh[0]); k++ {
			hb, ok := readN(tlogx.HashSize)
			if !ok {
				return h, nil, nil, fmt.Errorf("mirrorpush: package %d: short read proof hash %d", i, k)
			}
			pd.Proof = append(pd.Proof, tlogx.Hash(hb))
		}
		pkgs = append(pkgs, cp)
		data = append(data, pd)
	}
	return h, pkgs, data, nil
}
