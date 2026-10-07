package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/tlogx"
)

// mldsaCosigner builds an ML-DSA-44 cosigner (the only MTC cosigner
// algorithm) from a one-byte seed fill, returning the signer and its
// CosignerKey.
func mldsaCosigner(t *testing.T, id cert.TrustAnchorID, seedByte byte) (signer.Signer, cert.CosignerKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{seedByte}, signer.SeedSize)
	s, err := signer.FromSeed(signer.AlgMLDSA44, seed)
	if err != nil {
		t.Fatalf("ML-DSA-44 signer: %v", err)
	}
	return s, cert.CosignerKey{
		ID:        id,
		Algorithm: cert.AlgMLDSA44,
		PublicKey: s.PublicKey(),
	}
}

// sha256Hash is the tlogx hash function used to build consistency
// proofs in tests.
func sha256Hash(b []byte) tlogx.Hash {
	return tlogx.Hash(sha256.Sum256(b))
}

// stubWitness is a test-only c2sp.org/tlog-witness sign-subtree
// responder. It exists so the integration tests can exercise the
// *CA-side* cosignature-collection client (cert.RequestCosignatures)
// without cactus itself implementing a mirror.
//
// It performs almost no verification: it parses the subtree range and
// hash out of the request and signs whatever it is handed, ignoring the
// consistency proof. It does enforce the c2sp.org/tlog-witness@v1.1.0
// rule that the request's checkpoint carries exactly one note signature,
// its own (else 403), because that is a rule the CA-side client must
// follow; use cosign to give a reference checkpoint that signature.
// Otherwise witness-side validation is not what these tests are about —
// they assert that the CA fans out, collects a quorum, verifies the
// responses, and embeds them in issued certs.
type stubWitness struct {
	id     cert.TrustAnchorID
	signer signer.Signer
	logID  cert.TrustAnchorID

	// delay, if non-zero, is slept before responding. Used to make one
	// witness artificially slow so quorum-timing paths are exercised.
	delay time.Duration

	// calls counts served requests.
	calls atomic.Int64

	// lastUA records the most recent request's User-Agent, so tests can
	// assert the CA identifies itself per tlog-tiles.
	lastUA atomic.Value // string
}

// newStubWitness builds a stub witness signing for logID under the
// cosigner identity id, keyed from a one-byte seed fill.
func newStubWitness(t *testing.T, logID, id cert.TrustAnchorID, seedByte byte) *stubWitness {
	t.Helper()
	s, _ := mldsaCosigner(t, id, seedByte)
	return &stubWitness{id: id, signer: s, logID: logID}
}

// key is the stub's cosigner key, for cert.MirrorEndpoint and for
// verifying the signatures it returns.
func (w *stubWitness) key() cert.CosignerKey {
	return cert.CosignerKey{
		ID:        w.id,
		Algorithm: cert.AlgMLDSA44,
		PublicKey: w.signer.PublicKey(),
	}
}

// endpoint builds a cert.MirrorEndpoint pointing at url.
func (w *stubWitness) endpoint(url string) cert.MirrorEndpoint {
	return cert.MirrorEndpoint{URL: url, Key: w.key()}
}

// cosign returns note with the stub's checkpoint cosignature line
// appended, standing in for the cosigned checkpoint a real mirror hands
// back from add-entries.
func (w *stubWitness) cosign(t *testing.T, note []byte) []byte {
	t.Helper()
	text, _, ok := strings.Cut(string(note), "\n\n")
	lines := strings.Split(text, "\n")
	if !ok || len(lines) != 3 {
		t.Fatalf("cosign: malformed checkpoint %q", note)
	}
	size, err := cert.ParseDecimal(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	root, err := cert.DecodeBase64(lines[2])
	if err != nil || len(root) != 32 {
		t.Fatalf("cosign: bad root: %v", err)
	}
	const ts = 1790000000
	msg, err := cert.MarshalSignatureInputAt(w.id, &cert.MTCSubtree{
		LogID: cert.TrustAnchorID(strings.TrimPrefix(lines[0], cert.OIDNamePrefix+cert.TrustAnchorOIDBase+".")),
		Start: 0, End: size, Hash: tlogx.Hash(root),
	}, ts)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := w.signer.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	name := cert.OIDName(w.id)
	keyID, err := cert.CosignatureKeyID(name, cert.AlgMLDSA44, w.signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	blob := append(keyID[:], cert.MarshalCheckpointCosignature(ts, sig)...)
	out := append([]byte(nil), note...)
	return fmt.Appendf(out, "— %s %s\n", name, base64.StdEncoding.EncodeToString(blob))
}

// cosignAll applies each witness's cosign to note.
func cosignAll(t *testing.T, note []byte, ws ...*stubWitness) []byte {
	t.Helper()
	for _, w := range ws {
		note = w.cosign(t, note)
	}
	return note
}

// ServeHTTP implements the sign-subtree POST. The response is the
// c2sp.org/tlog-witness@v1.1.0 form, a base64 subtree cosignature and a
// newline, which requestOne in cert/cosigner_request.go parses.
func (w *stubWitness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.calls.Add(1)
	w.lastUA.Store(r.Header.Get("User-Agent"))
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	if r.Method != http.MethodPost {
		http.Error(rw, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(rw, "read body", http.StatusBadRequest)
		return
	}

	// The checkpoint follows the first blank line, and must carry
	// exactly one note signature, from this witness.
	head, checkpoint, ok := strings.Cut(string(body), "\n\n")
	if !ok {
		http.Error(rw, "no checkpoint", http.StatusBadRequest)
		return
	}
	_, sigs, _ := strings.Cut(checkpoint, "\n\n")
	sigLines := strings.Split(strings.TrimSuffix(sigs, "\n"), "\n")
	name := cert.OIDName(w.id)
	if len(sigLines) != 1 || !strings.HasPrefix(sigLines[0], "— "+name+" ") {
		http.Error(rw, "checkpoint must carry exactly one signature, ours", http.StatusForbidden)
		return
	}

	// Line 1: "subtree <start> <end>". Line 2: base64 32-byte hash.
	// The proof hashes after that are intentionally ignored.
	lines := strings.Split(head, "\n")
	if len(lines) < 2 {
		http.Error(rw, "short request", http.StatusBadRequest)
		return
	}
	var start, end uint64
	if _, err := fmt.Sscanf(lines[0], "subtree %d %d", &start, &end); err != nil {
		http.Error(rw, "bad subtree line", http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(raw) != 32 {
		http.Error(rw, "bad subtree hash", http.StatusBadRequest)
		return
	}

	msg, err := cert.MarshalSignatureInput(w.id, &cert.MTCSubtree{
		LogID: w.logID, Start: start, End: end, Hash: tlogx.Hash(raw),
	})
	if err != nil {
		http.Error(rw, "marshal signature input", http.StatusInternalServerError)
		return
	}
	sig, err := w.signer.Sign(nil, msg)
	if err != nil {
		http.Error(rw, "sign", http.StatusInternalServerError)
		return
	}

	// A subtree cosignature is the bare signature: no key name, key ID,
	// or timestamp.
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(rw, "%s\n", base64.StdEncoding.EncodeToString(sig))
}
