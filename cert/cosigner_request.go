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
	// Subtree is the §5.3.1 MTCSubtree being signed (log_id, start,
	// end, hash). The mirrors will sign CosignedMessage for
	// these values.
	Subtree *MTCSubtree
	// CACheckpointBody is the bytes of the *reference checkpoint*: a
	// signed-note checkpoint that MUST already carry a cosignature
	// from the responding mirror's own key.
	//
	// c2sp.org/tlog-witness sign-subtree: "The witness MUST verify that
	// the checkpoint includes a valid cosignature from one of its own
	// keys. If the witness can't verify the checkpoint, it MUST respond
	// with a 403 Forbidden." The CA's own signature alone is therefore
	// not enough — a strict mirror rejects it.
	//
	// A mirror's cosignature over a checkpoint is only ever produced by
	// the c2sp.org/tlog-mirror add-entries 200 response, so the caller
	// has to push entries first and feed the resulting cosigned
	// checkpoint back in here. See package mirrorpush, whose
	// Pool.CheckpointWithCosignatures does exactly that. Because a
	// signed note may carry many signature lines and each mirror
	// ignores lines that aren't its own, one body with every mirror's
	// cosignature appended satisfies all of them at once — which is
	// what lets this function keep fanning a single body out.
	CACheckpointBody []byte
	// ConsistencyProof is the §4.4 subtree consistency proof from
	// (start, end, hash) up to the checkpoint root.
	ConsistencyProof []tlogx.Hash
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
	// The witness sign-subtree path is ML-DSA-44 only (c2sp.org/tlog-
	// cosignature has no ECDSA cosignature type); reject other keys up
	// front rather than emitting a request we could never verify.
	if m.Key.Algorithm != AlgMLDSA44 {
		return MTCSignature{}, fmt.Errorf("cert: mirror %q must be ML-DSA-44, got 0x%04x",
			m.Key.ID, uint16(m.Key.Algorithm))
	}
	wantKey := OIDName(m.Key.ID)
	wantKeyID, err := CosignatureKeyID(wantKey, m.Key.Algorithm, m.Key.PublicKey)
	if err != nil {
		return MTCSignature{}, err
	}

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

	// Response: one or more c2sp.org/signed-note signature lines. We
	// accept the one whose key name AND key ID match the configured
	// mirror key, ignoring all others (per signed-note).
	prefix := "— " + wantKey + " "
	for _, line := range strings.Split(strings.TrimRight(string(respBody), "\n"), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, prefix))
		if err != nil {
			return MTCSignature{}, fmt.Errorf("decode sig: %w", err)
		}
		if len(raw) < 4 {
			return MTCSignature{}, errors.New("sig too short for key ID")
		}
		if [4]byte(raw[:4]) != wantKeyID {
			continue // same name, different key ID: not our key.
		}
		ts, rawSig, err := ParseTimestampedSignature(raw[4:])
		if err != nil {
			return MTCSignature{}, err
		}
		// Subtree cosignatures MUST carry a zero timestamp
		// (c2sp.org/tlog-witness / tlog-cosignature).
		if ts != 0 {
			return MTCSignature{}, fmt.Errorf("cert: mirror cosignature has non-zero timestamp %d", ts)
		}
		// Verify against the §5.3.1 CosignedMessage.
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

// buildSignSubtreeBody assembles the c2sp.org/tlog-witness sign-subtree
// request body:
//
//	subtree <start> <end>
//	<base64 subtree hash>
//	<base64 consistency-proof hash>        (0..63 lines)
//	...
//	<empty line>
//	<reference checkpoint, a full signed checkpoint>
//
// Note there is no CA cosignature line. An earlier revision of
// c2sp.org/tlog-witness allowed the client to prepend a subtree
// cosignature of its own as a DoS gate; C2SP has since deleted it from
// the grammar, which now runs subtree-range / subtree-hash / proof
// lines / blank / checkpoint. A strict mirror parses the first
// non-"subtree" line as base64 proof hash, so emitting a "— ..." line
// there is a 400.
func buildSignSubtreeBody(req *SubtreeRequest) ([]byte, error) {
	if req == nil || req.Subtree == nil {
		return nil, errors.New("nil request")
	}
	if len(req.CACheckpointBody) == 0 {
		return nil, errors.New("empty CACheckpointBody")
	}
	if len(req.ConsistencyProof) > 63 {
		return nil, fmt.Errorf("cert: consistency proof has %d hashes, max 63", len(req.ConsistencyProof))
	}

	var b bytes.Buffer
	// Subtree range + hash.
	fmt.Fprintf(&b, "subtree %d %d\n", req.Subtree.Start, req.Subtree.End)
	b.WriteString(base64.StdEncoding.EncodeToString(req.Subtree.Hash[:]) + "\n")

	// Consistency proof lines: each one base64 hash on its own line.
	for _, h := range req.ConsistencyProof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}

	// Empty line, then the reference checkpoint verbatim.
	b.WriteString("\n")
	b.Write(req.CACheckpointBody)
	if !bytes.HasSuffix(req.CACheckpointBody, []byte("\n")) {
		b.WriteString("\n")
	}

	return b.Bytes(), nil
}
