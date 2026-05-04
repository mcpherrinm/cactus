package cert

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/cactus/tlogx"
)

// MirrorEndpoint identifies one mirror the CA is configured to ask
// for a sign-subtree cosignature.
type MirrorEndpoint struct {
	// URL is the mirror's sign-subtree endpoint (e.g.
	// "https://mirror-1.example/sign-subtree").
	URL string
	// Key is the mirror's cosigner identity + public key. Used to
	// verify the response signature with VerifyMTCSignature.
	Key CosignerKey
}

// CosignerRequestMetrics are optional Prometheus instruments updated
// by RequestCosignatures. Each is nil-safe.
type CosignerRequestMetrics struct {
	Requests       CounterVec // labels: mirror_id, result
	QuorumFailures Counter
}

// CounterVec / Counter mirror the metrics.* interfaces, declared
// locally so cert/ doesn't import metrics.
type CounterVec interface {
	WithLabelValues(...string) Counter
}

// Counter mirrors metrics.Counter.
type Counter interface{ Add(float64) }

// SubtreeRequest carries the inputs for a single round of multi-mirror
// cosignature collection.
type SubtreeRequest struct {
	// Subtree is the §5.4.1 MTCSubtree being signed (log_id, start,
	// end, hash). The mirrors will sign MTCSubtreeSignatureInput for
	// these values.
	Subtree *MTCSubtree
	// CACheckpointBody is the bytes of a signed-note checkpoint the
	// CA is presenting (typically the CA's own latest signed-note).
	// In stateful mode mirrors use it only to compare (size, root)
	// to their own verified state; the signatures inside are
	// inspected by mirrors that run in stateless mode.
	CACheckpointBody []byte
	// ConsistencyProof is the §4.4 subtree consistency proof from
	// (start, end, hash) up to the checkpoint root.
	ConsistencyProof []tlogx.Hash
	// CASignature, if non-nil, is included in the subtree note as a
	// signature line. Mirrors with `RequireCASignatureOnSubtree` set
	// will only honour the request if this is present and verifies.
	CASignature *MTCSignature
	// CACosignerID is the trust anchor ID of the CA cosigner that
	// produced CASignature. Used only when CASignature != nil.
	CACosignerID TrustAnchorID
}

// RequestCosignatures fans the request out to all configured mirrors
// in parallel, collects valid signatures with the given timeout, and
// returns once at least `quorum` valid signatures have arrived (or
// the deadline expires).
//
// Returns an error iff fewer than `quorum` valid signatures were
// gathered. Per-mirror failures (HTTP errors, parse failures,
// signature-verify failures) are silently dropped so that issuance
// degrades gracefully when one mirror is offline; the function's
// error report is intentionally coarse.
//
// If `bestEffortAfterMin` is true and the quorum has been reached,
// the function continues waiting until the deadline to gather as
// many extra valid signatures as possible. If false, it returns as
// soon as the quorum is met.
func RequestCosignatures(
	ctx context.Context,
	req *SubtreeRequest,
	mirrors []MirrorEndpoint,
	quorum int,
	deadline time.Duration,
	bestEffortAfterMin bool,
) ([]MTCSignature, error) {
	return RequestCosignaturesWithMetrics(ctx, req, mirrors, quorum, deadline, bestEffortAfterMin, CosignerRequestMetrics{})
}

// RequestCosignaturesWithMetrics is RequestCosignatures with optional
// Prometheus instruments. Use this overload from production callers
// that want per-mirror request counters.
func RequestCosignaturesWithMetrics(
	ctx context.Context,
	req *SubtreeRequest,
	mirrors []MirrorEndpoint,
	quorum int,
	deadline time.Duration,
	bestEffortAfterMin bool,
	mx CosignerRequestMetrics,
) ([]MTCSignature, error) {
	if quorum < 0 {
		return nil, errors.New("cert: negative quorum")
	}
	if len(mirrors) < quorum {
		if mx.QuorumFailures != nil {
			mx.QuorumFailures.Add(1)
		}
		return nil, fmt.Errorf("cert: %d mirrors but quorum is %d", len(mirrors), quorum)
	}
	if quorum == 0 {
		return nil, nil
	}

	body, err := buildSignSubtreeBody(req)
	if err != nil {
		return nil, fmt.Errorf("cert: build request body: %w", err)
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	results := make(chan MTCSignature, len(mirrors))
	var wg sync.WaitGroup
	for _, m := range mirrors {
		wg.Add(1)
		go func(m MirrorEndpoint) {
			defer wg.Done()
			sig, err := requestOne(deadlineCtx, m, body, req.Subtree)
			if mx.Requests != nil {
				result := "ok"
				if err != nil {
					result = "error"
				}
				mx.Requests.WithLabelValues(string(m.Key.ID), result).Add(1)
			}
			if err != nil {
				return
			}
			select {
			case results <- sig:
			case <-deadlineCtx.Done():
			}
		}(m)
	}

	// Drain results until quorum / deadline / all mirrors finished.
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	var collected []MTCSignature
	for {
		select {
		case sig := <-results:
			collected = append(collected, sig)
			if len(collected) >= quorum && !bestEffortAfterMin {
				return collected, nil
			}
		case <-finished:
			// All goroutines done.
			if len(collected) >= quorum {
				return collected, nil
			}
			if mx.QuorumFailures != nil {
				mx.QuorumFailures.Add(1)
			}
			return collected, fmt.Errorf("cert: quorum %d not met (got %d)", quorum, len(collected))
		case <-deadlineCtx.Done():
			if len(collected) >= quorum {
				return collected, nil
			}
			if mx.QuorumFailures != nil {
				mx.QuorumFailures.Add(1)
			}
			return collected, fmt.Errorf("cert: quorum %d not met by deadline (got %d)", quorum, len(collected))
		}
	}
}

func requestOne(ctx context.Context, m MirrorEndpoint, body []byte, subtree *MTCSubtree) (MTCSignature, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(body))
	if err != nil {
		return MTCSignature{}, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return MTCSignature{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return MTCSignature{}, err
	}
	if resp.StatusCode != 200 {
		return MTCSignature{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, respBody)
	}

	// Response: one or more signature lines starting with em-dash.
	// We expect exactly one matching the configured mirror key.
	wantKey := "oid/" + string(m.Key.ID)
	prefix := "— " + wantKey + " "
	for _, line := range strings.Split(strings.TrimRight(string(respBody), "\n"), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, prefix))
		if err != nil {
			return MTCSignature{}, fmt.Errorf("decode sig: %w", err)
		}
		if len(raw) < 5 {
			return MTCSignature{}, errors.New("sig too short")
		}
		// Drop the §C.1 keyID prefix.
		rawSig := raw[4:]
		// Verify against MTCSubtreeSignatureInput.
		msg, err := MarshalSignatureInput(m.Key.ID, subtree)
		if err != nil {
			return MTCSignature{}, err
		}
		sig := MTCSignature{CosignerID: m.Key.ID, Signature: rawSig}
		if err := VerifyMTCSignature(m.Key, sig, msg); err != nil {
			return MTCSignature{}, fmt.Errorf("verify: %w", err)
		}
		return sig, nil
	}
	return MTCSignature{}, errors.New("no matching signature line in response")
}

// buildSignSubtreeBody assembles the §C.2 request body.
func buildSignSubtreeBody(req *SubtreeRequest) ([]byte, error) {
	if req == nil || req.Subtree == nil {
		return nil, errors.New("nil request")
	}
	if len(req.CACheckpointBody) == 0 {
		return nil, errors.New("empty CACheckpointBody")
	}

	var b bytes.Buffer
	// Subtree note: <log origin>\n<start> <end>\n<base64 hash>\n\n
	// followed by zero or more signature lines, then a blank line
	// (§C.2 inter-section separator).
	b.WriteString("oid/" + string(req.Subtree.LogID) + "\n")
	fmt.Fprintf(&b, "%d %d\n", req.Subtree.Start, req.Subtree.End)
	b.WriteString(base64.StdEncoding.EncodeToString(req.Subtree.Hash[:]) + "\n")
	b.WriteString("\n") // body/sigs delimiter
	if req.CASignature != nil {
		caKey := "oid/" + string(req.CACosignerID)
		// The wire signature blob must include a §C.1 keyID prefix.
		keyID := mtcSubtreeKeyID(caKey)
		blob := append(append([]byte(nil), keyID[:]...), req.CASignature.Signature...)
		fmt.Fprintf(&b, "— %s %s\n", caKey, base64.StdEncoding.EncodeToString(blob))
	}
	b.WriteString("\n") // §C.2 inter-section blank line

	// Cosigned checkpoint: paste verbatim. Must end with the
	// signed-note `body\n\n[sigs]\n` shape and be followed by a
	// blank line for the §C.2 separator.
	b.Write(req.CACheckpointBody)
	if !bytes.HasSuffix(req.CACheckpointBody, []byte("\n")) {
		b.WriteString("\n")
	}
	if !bytes.HasSuffix(req.CACheckpointBody, []byte("\n\n")) {
		b.WriteString("\n")
	}

	// Consistency proof lines: each one base64 hash on its own line.
	for _, h := range req.ConsistencyProof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	return b.Bytes(), nil
}

// mtcSubtreeKeyID computes the §C.1 keyID for a subtree signature.
// Duplicates the helper in mirror/server.go but local to this package
// so we don't have a dependency cycle.
func mtcSubtreeKeyID(keyName string) [4]byte {
	buf := append([]byte(keyName), 0x0A, 0xFF)
	buf = append(buf, []byte("mtc-subtree/v1")...)
	return [4]byte(sha256First4(buf))
}

func sha256First4(b []byte) [4]byte {
	// Localised hash to avoid pulling crypto/sha256 into multiple
	// public files. We accept a tiny bit of helper duplication.
	h := newSHA256()
	h.Write(b)
	sum := h.Sum(nil)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
}
