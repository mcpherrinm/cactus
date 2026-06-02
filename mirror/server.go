package mirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/tlogx"
)

// ServerConfig configures the mirror's sign-subtree HTTP endpoint.
type ServerConfig struct {
	// Follower owns the local mirror state.
	Follower *Follower
	// Signer is the mirror's own cosigner key (separate from the
	// upstream CA's). Used to sign the §5.3.1 input.
	Signer signer.Signer
	// CosignerID is the mirror's trust anchor ID.
	CosignerID cert.TrustAnchorID
	// RequireCASignatureOnSubtree is the default DoS mitigation per
	// [tlog-cosignature]: only honour requests that already carry
	// the upstream CA's signature on the subtree note.
	RequireCASignatureOnSubtree bool
	// UpstreamCAKey is required when RequireCASignatureOnSubtree.
	UpstreamCAKey *cert.CosignerKey
	// Metrics are optional; nil-safe.
	Metrics ServerMetrics
}

// ServerMetrics are optional Prometheus instruments the Server
// updates. Each is nil-safe.
type ServerMetrics struct {
	Requests        CounterVec // labels: result
	RequestDuration Observer
}

// CounterVec / Observer mirror the metrics.* interfaces.
type CounterVec interface {
	WithLabelValues(...string) Counter
}

// Observer mirrors metrics.Observer.
type Observer interface{ Observe(float64) }

// Server handles POST /sign-subtree requests.
type Server struct {
	cfg ServerConfig
}

// NewServer constructs a Server. Returns an error on invalid config.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Follower == nil {
		return nil, errors.New("mirror: ServerConfig.Follower required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("mirror: ServerConfig.Signer required")
	}
	if len(cfg.CosignerID) == 0 {
		return nil, errors.New("mirror: ServerConfig.CosignerID required")
	}
	// The c2sp.org/tlog-witness sign-subtree response is an ML-DSA-44
	// cosignature (c2sp.org/tlog-cosignature defines no ECDSA cosignature
	// type), so the witness key MUST be ML-DSA-44.
	if cert.SignatureAlgorithm(cfg.Signer.Algorithm()) != cert.AlgMLDSA44 {
		return nil, fmt.Errorf("mirror: witness Signer must be ML-DSA-44, got %s", cfg.Signer.Algorithm())
	}
	if cfg.RequireCASignatureOnSubtree {
		if cfg.UpstreamCAKey == nil {
			return nil, errors.New("mirror: UpstreamCAKey required when RequireCASignatureOnSubtree")
		}
		if cfg.UpstreamCAKey.Algorithm != cert.AlgMLDSA44 {
			return nil, fmt.Errorf("mirror: UpstreamCAKey must be ML-DSA-44 for subtree cosignatures, got 0x%04x",
				uint16(cfg.UpstreamCAKey.Algorithm))
		}
	}
	return &Server{cfg: cfg}, nil
}

// Handler returns the HTTP handler. Mount it at the desired path
// (typically /sign-subtree on the mirror's listener).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

// MaxRequestBytes caps the sign-subtree request body. A subtree note
// (a few hundred bytes), a checkpoint note (a few hundred bytes), and
// up to 63 base64 hashes (~3 KiB) is well under 16 KiB.
const MaxRequestBytes = 16 * 1024

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	result := "ok"
	defer func() {
		if s.cfg.Metrics.Requests != nil {
			s.cfg.Metrics.Requests.WithLabelValues(result).Add(1)
		}
		if s.cfg.Metrics.RequestDuration != nil {
			s.cfg.Metrics.RequestDuration.Observe(time.Since(start).Seconds())
		}
	}()
	if r.Method != http.MethodPost {
		result = "method_not_allowed"
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		result = "bad_body"
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	parsed, err := s.parseRequest(body)
	if err != nil {
		result = "parse_error"
		http.Error(w, "parse request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 1) Range validity (c2sp.org/tlog-witness): start < end and end <=
	// the reference checkpoint size, else 400.
	if parsed.start >= parsed.end || parsed.end > parsed.checkpointSize {
		result = "bad_range"
		http.Error(w, "invalid subtree range", http.StatusBadRequest)
		return
	}

	// 2) Origin: the reference checkpoint MUST be for the log we mirror,
	// else 404 (unknown checkpoint origin).
	wantOrigin := cert.OIDName(s.cfg.Follower.cfg.Upstream.LogID)
	if parsed.checkpointOrigin != wantOrigin {
		result = "unknown_origin"
		http.Error(w, "unknown checkpoint origin", http.StatusNotFound)
		return
	}

	// 3) DoS mitigation: a valid CA subtree cosignature must be present.
	// A missing/invalid gate cosignature is an authorization failure, so
	// it returns 403 (distinct from the 400 used for a malformed body).
	if s.cfg.RequireCASignatureOnSubtree {
		if err := s.verifyCAOnSubtree(parsed); err != nil {
			result = "ca_sig_error"
			http.Error(w, "CA signature on subtree: "+err.Error(), http.StatusForbidden)
			return
		}
	}

	// 4) Stateful checkpoint check: compare to our verified upstream
	// state. If the requester's checkpoint is not ours, return 409 with
	// our current checkpoint (c2sp.org/tlog-witness).
	currentSize, currentRoot, currentNote := s.cfg.Follower.Current()
	if parsed.checkpointSize != currentSize || parsed.checkpointRoot != currentRoot {
		result = "checkpoint_conflict"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(currentNote)
		return
	}

	// 5) Verify the subtree consistency proof against the checkpoint.
	// A failed Merkle proof is 422 (c2sp.org/tlog-witness).
	if err := tlogx.VerifyConsistencyProof(
		sha256Hash, parsed.start, parsed.end, currentSize, parsed.proof,
		parsed.subtreeHash, currentRoot,
	); err != nil {
		result = "consistency_error"
		http.Error(w, "consistency proof: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// 6) Cross-check the requester's claimed subtree hash against our
	// local copy. Already implicit in step 5, but explicit here catches a
	// different class of bug (hash mismatch with no proof).
	localHash, err := s.cfg.Follower.SubtreeHash(parsed.start, parsed.end)
	if err != nil {
		result = "subtree_hash_error"
		http.Error(w, "subtree hash: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if localHash != parsed.subtreeHash {
		result = "subtree_hash_mismatch"
		http.Error(w, "subtree hash mismatch", http.StatusBadRequest)
		return
	}

	// 7) Sign the §5.3.1 CosignedMessage.
	subtree := &cert.MTCSubtree{
		LogID: s.cfg.Follower.cfg.Upstream.LogID,
		Start: parsed.start, End: parsed.end, Hash: parsed.subtreeHash,
	}
	msg, err := cert.MarshalSignatureInput(s.cfg.CosignerID, subtree)
	if err != nil {
		http.Error(w, "marshal sig input: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sig, err := s.cfg.Signer.Sign(rand.Reader, msg)
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 8) Emit the c2sp.org/signed-note signature line: em-dash, key
	// name, base64(keyID || timestamped_signature), with the ML-DSA-44
	// cosignature key ID and the u64-timestamp wrapper (timestamp 0 for
	// MTC subtree cosignatures) from c2sp.org/tlog-cosignature.
	keyName := cert.OIDName(s.cfg.CosignerID)
	keyID, err := cert.CosignatureKeyID(keyName,
		cert.SignatureAlgorithm(s.cfg.Signer.Algorithm()), s.cfg.Signer.PublicKey())
	if err != nil {
		http.Error(w, "key id: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sigWithID := append(append([]byte(nil), keyID[:]...), cert.MarshalTimestampedSignature(0, sig)...)
	line := fmt.Sprintf("%s %s %s\n", emDash, keyName, base64.StdEncoding.EncodeToString(sigWithID))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(line))
}

// ParseSignSubtreeRequestForFuzz exposes the request parser for fuzz
// testing. Returns the error (or nil) but discards the parsed body —
// the fuzz target only cares that this never panics.
func ParseSignSubtreeRequestForFuzz(body []byte) error {
	s := Server{}
	_, err := s.parseRequest(body)
	return err
}

// parsedRequest carries everything the handler needs to make a decision.
type parsedRequest struct {
	start, end       uint64
	subtreeHash      tlogx.Hash
	subtreeCosigs    []noteSignature // 0..8 subtree cosignature lines
	proof            []tlogx.Hash
	checkpointNote   *signedNote
	checkpointOrigin string
	checkpointSize   uint64
	checkpointRoot   tlogx.Hash
}

// parseRequest parses a c2sp.org/tlog-witness sign-subtree request body:
//
//	subtree <start> <end>
//	<base64 subtree hash>
//	[— <key> <sig>]            (0..8 subtree cosignature lines)
//	<base64 proof hash>        (0..63 consistency-proof lines)
//	...
//	<empty line>
//	<reference checkpoint>
//
// parseCanonicalDecimal parses an unsigned ASCII decimal with no leading
// zeros, as the c2sp.org/tlog-witness and tlog-checkpoint formats require
// (strconv.ParseUint alone would accept "007").
func parseCanonicalDecimal(s string) (uint64, error) {
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("non-canonical decimal %q (leading zero)", s)
	}
	return strconv.ParseUint(s, 10, 64)
}

func (s *Server) parseRequest(body []byte) (*parsedRequest, error) {
	r := bufio.NewReader(bytes.NewReader(body))

	// Subtree range line.
	rangeLine, err := readLine(r)
	if err != nil {
		return nil, fmt.Errorf("subtree range line: %w", err)
	}
	fields := strings.Split(rangeLine, " ")
	if len(fields) != 3 || fields[0] != "subtree" {
		return nil, fmt.Errorf("malformed subtree range line %q", rangeLine)
	}
	start, err := parseCanonicalDecimal(fields[1])
	if err != nil {
		return nil, fmt.Errorf("subtree start: %w", err)
	}
	end, err := parseCanonicalDecimal(fields[2])
	if err != nil {
		return nil, fmt.Errorf("subtree end: %w", err)
	}

	// Subtree hash line.
	hashLine, err := readLine(r)
	if err != nil {
		return nil, fmt.Errorf("subtree hash line: %w", err)
	}
	hashBytes, err := base64.StdEncoding.DecodeString(hashLine)
	if err != nil {
		return nil, fmt.Errorf("subtree hash b64: %w", err)
	}
	if len(hashBytes) != tlogx.HashSize {
		return nil, fmt.Errorf("subtree hash %d bytes, want %d", len(hashBytes), tlogx.HashSize)
	}
	var subtreeHash tlogx.Hash
	copy(subtreeHash[:], hashBytes)

	// Subtree cosignature lines (0..8), then consistency-proof lines
	// (0..63), terminated by an empty line before the checkpoint.
	// Cosignature lines start with the em-dash; proof lines are bare
	// base64 hashes. Cosignatures MUST precede proof lines.
	var cosigs []noteSignature
	var proof []tlogx.Hash
	sawProof := false
	for {
		line, err := readLine(r)
		if err == io.EOF {
			return nil, errors.New("request ended before checkpoint")
		}
		if err != nil {
			return nil, fmt.Errorf("subtree section: %w", err)
		}
		if line == "" {
			break // empty line: end of subtree section.
		}
		if strings.HasPrefix(line, emDash+" ") {
			if sawProof {
				return nil, errors.New("subtree cosignature line after proof line")
			}
			if len(cosigs) >= 8 {
				return nil, errors.New("more than 8 subtree cosignature lines")
			}
			ns, err := parseNoteSignatureLine(line)
			if err != nil {
				return nil, fmt.Errorf("subtree cosignature: %w", err)
			}
			cosigs = append(cosigs, ns)
			continue
		}
		// Otherwise a consistency-proof hash.
		sawProof = true
		if len(proof) >= 63 {
			return nil, errors.New("more than 63 proof lines")
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("proof line b64: %w", err)
		}
		if len(raw) != tlogx.HashSize {
			return nil, fmt.Errorf("proof line %d bytes, want %d", len(raw), tlogx.HashSize)
		}
		var h tlogx.Hash
		copy(h[:], raw)
		proof = append(proof, h)
	}

	// Reference checkpoint: a full signed checkpoint note.
	checkpointNote, err := readSignedNote(r)
	if err != nil {
		return nil, fmt.Errorf("checkpoint note: %w", err)
	}
	// c2sp.org/tlog-witness: at most 8 checkpoint signatures.
	if len(checkpointNote.sigs) > 8 {
		return nil, fmt.Errorf("checkpoint has %d signatures, max 8", len(checkpointNote.sigs))
	}
	if len(checkpointNote.body) != 3 {
		return nil, fmt.Errorf("checkpoint note has %d body lines, want 3", len(checkpointNote.body))
	}
	cpSize, err := parseCanonicalDecimal(checkpointNote.body[1])
	if err != nil {
		return nil, fmt.Errorf("checkpoint size: %w", err)
	}
	cpRootBytes, err := base64.StdEncoding.DecodeString(checkpointNote.body[2])
	if err != nil {
		return nil, fmt.Errorf("checkpoint root b64: %w", err)
	}
	if len(cpRootBytes) != tlogx.HashSize {
		return nil, fmt.Errorf("checkpoint root %d bytes, want %d", len(cpRootBytes), tlogx.HashSize)
	}
	var cpRoot tlogx.Hash
	copy(cpRoot[:], cpRootBytes)

	return &parsedRequest{
		start: start, end: end,
		subtreeHash:      subtreeHash,
		subtreeCosigs:    cosigs,
		proof:            proof,
		checkpointNote:   checkpointNote,
		checkpointOrigin: checkpointNote.body[0],
		checkpointSize:   cpSize,
		checkpointRoot:   cpRoot,
	}, nil
}

// verifyCAOnSubtree checks the upstream CA's subtree cosignature among
// the request's subtree cosignature lines. The CA's signature is over
// the §5.3.1 CosignedMessage for [start, end), with hash = the
// requester's claimed hash. The key ID MUST match the c2sp.org/signed-
// note ML-DSA-44 key ID for the CA key.
func (s *Server) verifyCAOnSubtree(p *parsedRequest) error {
	wantKey := cert.OIDName(s.cfg.UpstreamCAKey.ID)
	wantKeyID, err := cert.CosignatureKeyID(wantKey,
		s.cfg.UpstreamCAKey.Algorithm, s.cfg.UpstreamCAKey.PublicKey)
	if err != nil {
		return err
	}
	var rawSig []byte
	for _, c := range p.subtreeCosigs {
		if c.keyName != wantKey {
			continue
		}
		if len(c.sigBytes) < 4 || [4]byte(c.sigBytes[:4]) != wantKeyID {
			continue // same name, different key ID: ignore.
		}
		ts, sig, perr := cert.ParseTimestampedSignature(c.sigBytes[4:])
		if perr != nil {
			return fmt.Errorf("CA subtree cosignature: %w", perr)
		}
		// Subtree cosignatures MUST carry a zero timestamp
		// (c2sp.org/tlog-witness / tlog-cosignature).
		if ts != 0 {
			return fmt.Errorf("CA subtree cosignature has non-zero timestamp %d", ts)
		}
		rawSig = sig
		break
	}
	if rawSig == nil {
		return fmt.Errorf("no subtree cosignature from %q", wantKey)
	}

	// The signed message is CosignedMessage. We need the
	// log_id, which is the upstream's log ID; we have it on Follower.
	subtree := &cert.MTCSubtree{
		LogID: s.cfg.Follower.cfg.Upstream.LogID,
		Start: p.start, End: p.end, Hash: p.subtreeHash,
	}
	msg, err := cert.MarshalSignatureInput(s.cfg.UpstreamCAKey.ID, subtree)
	if err != nil {
		return err
	}
	return cert.VerifyMTCSignature(*s.cfg.UpstreamCAKey, cert.MTCSignature{
		CosignerID: s.cfg.UpstreamCAKey.ID,
		Signature:  rawSig,
	}, msg)
}

// sha256Hash matches the helper used in tlogx.
func sha256Hash(b []byte) tlogx.Hash {
	return tlogx.Hash(sha256.Sum256(b))
}

// silence unused
var (
	_ = context.Background
)
