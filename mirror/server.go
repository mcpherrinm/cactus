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
	// upstream CA's). Used to sign the §5.4.1 input.
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
	if cfg.RequireCASignatureOnSubtree && cfg.UpstreamCAKey == nil {
		return nil, errors.New("mirror: UpstreamCAKey required when RequireCASignatureOnSubtree")
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

	// 1) DoS mitigation: subtree note must carry the CA's signature.
	if s.cfg.RequireCASignatureOnSubtree {
		if err := s.verifyCAOnSubtree(parsed); err != nil {
			result = "ca_sig_error"
			http.Error(w, "CA signature on subtree: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 2) Stateful checkpoint check: compare to our verified upstream
	// state. If the requester's checkpoint is older than ours, return
	// 409 with our current checkpoint (Appendix C.2).
	currentSize, currentRoot, currentNote := s.cfg.Follower.Current()
	if parsed.checkpointSize != currentSize || parsed.checkpointRoot != currentRoot {
		result = "checkpoint_conflict"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write(currentNote)
		return
	}

	// 3) Verify consistency proof: subtree → checkpoint.
	if err := tlogx.VerifyConsistencyProof(
		sha256Hash, parsed.start, parsed.end, currentSize, parsed.proof,
		parsed.subtreeHash, currentRoot,
	); err != nil {
		result = "consistency_error"
		http.Error(w, "consistency proof: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 4) Cross-check the requester's claimed subtree hash against
	// our local copy. Already implicit in step 3, but explicit here
	// catches a different class of bug (hash mismatch with no proof).
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

	// 5) Sign the §5.4.1 MTCSubtreeSignatureInput.
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

	// 6) Emit the signature line per [tlog-cosignature]: em-dash,
	// key name, base64(keyID || signature). Use the §C.1 subtree key
	// ID derivation: SHA-256(keyName || 0x0A || 0xFF || "mtc-subtree/v1")[:4].
	keyName := "oid/" + string(s.cfg.CosignerID)
	keyID := subtreeKeyID(keyName)
	sigWithID := append(append([]byte(nil), keyID[:]...), sig...)
	line := fmt.Sprintf("%s %s %s\n", emDash, keyName, base64.StdEncoding.EncodeToString(sigWithID))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(line))
}

// subtreeKeyID computes the §C.1 keyID for a subtree signature.
func subtreeKeyID(keyName string) [4]byte {
	buf := append([]byte(keyName), 0x0A, 0xFF)
	buf = append(buf, []byte("mtc-subtree/v1")...)
	sum := sha256.Sum256(buf)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
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
	subtreeNote    *signedNote
	subtreeOrigin  string
	start, end     uint64
	subtreeHash    tlogx.Hash
	checkpointNote *signedNote
	checkpointSize uint64
	checkpointRoot tlogx.Hash
	proof          []tlogx.Hash
}

func (s *Server) parseRequest(body []byte) (*parsedRequest, error) {
	r := bufio.NewReader(bytes.NewReader(body))
	subtreeNote, err := readSignedNote(r)
	if err != nil {
		return nil, fmt.Errorf("subtree note: %w", err)
	}
	if len(subtreeNote.body) != 3 {
		return nil, fmt.Errorf("subtree note has %d body lines, want 3", len(subtreeNote.body))
	}
	startEnd := strings.Fields(subtreeNote.body[1])
	if len(startEnd) != 2 {
		return nil, fmt.Errorf("subtree note body[1] %q not %q-shaped", subtreeNote.body[1], "<start> <end>")
	}
	start, err := strconv.ParseUint(startEnd[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("subtree start: %w", err)
	}
	end, err := strconv.ParseUint(startEnd[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("subtree end: %w", err)
	}
	hashBytes, err := base64.StdEncoding.DecodeString(subtreeNote.body[2])
	if err != nil {
		return nil, fmt.Errorf("subtree hash b64: %w", err)
	}
	if len(hashBytes) != tlogx.HashSize {
		return nil, fmt.Errorf("subtree hash %d bytes, want %d", len(hashBytes), tlogx.HashSize)
	}
	var subtreeHash tlogx.Hash
	copy(subtreeHash[:], hashBytes)

	checkpointNote, err := readSignedNote(r)
	if err != nil {
		return nil, fmt.Errorf("checkpoint note: %w", err)
	}
	if len(checkpointNote.body) != 3 {
		return nil, fmt.Errorf("checkpoint note has %d body lines, want 3", len(checkpointNote.body))
	}
	cpSize, err := strconv.ParseUint(checkpointNote.body[1], 10, 64)
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

	// Remaining lines are consistency proof hashes (max 63 per §C.2).
	var proof []tlogx.Hash
	for {
		line, err := readLine(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("proof: %w", err)
		}
		if line == "" {
			continue
		}
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

	return &parsedRequest{
		subtreeNote:   subtreeNote,
		subtreeOrigin: subtreeNote.body[0],
		start:         start, end: end,
		subtreeHash:    subtreeHash,
		checkpointNote: checkpointNote,
		checkpointSize: cpSize,
		checkpointRoot: cpRoot,
		proof:          proof,
	}, nil
}

// verifyCAOnSubtree checks the upstream CA's signature on the subtree
// note. The CA's signature is over the §5.4.1 MTCSubtreeSignatureInput
// for [start, end), with hash = the requester's claimed hash.
func (s *Server) verifyCAOnSubtree(p *parsedRequest) error {
	wantKey := "oid/" + string(s.cfg.UpstreamCAKey.ID)
	caSig, ok := p.subtreeNote.signatureFor(wantKey)
	if !ok {
		return fmt.Errorf("subtree note missing %q signature", wantKey)
	}
	if len(caSig.sigBytes) < 5 {
		return errors.New("subtree note CA sig too short")
	}
	rawSig := caSig.sigBytes[4:]

	// The signed message is MTCSubtreeSignatureInput. We need the
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
