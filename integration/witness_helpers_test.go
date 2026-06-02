package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/tlogx"
)

// startFollower runs f.Run(ctx) in the background and registers a
// cleanup that waits for the goroutine to exit. The caller's deferred
// cancel() stops the follower when the test returns; this cleanup then
// blocks until the follower has actually stopped, so its in-flight tile
// writes can't race the t.TempDir RemoveAll (which is registered earlier
// and thus runs after this one, LIFO).
func startFollower(t *testing.T, ctx context.Context, f *mirror.Follower) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); _ = f.Run(ctx) }()
	t.Cleanup(func() { <-done })
}

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

// buildSignSubtreeRequest assembles a c2sp.org/tlog-witness sign-subtree
// request body with no subtree cosignature lines:
//
//	subtree <start> <end>
//	<base64 hash>
//	<base64 proof hash>...
//	<empty line>
//	<reference checkpoint>
func buildSignSubtreeRequest(t *testing.T, start, end uint64,
	subtreeHash tlogx.Hash, cpBody []byte, proof []tlogx.Hash) []byte {
	t.Helper()
	return buildSignSubtreeRequestWithCASig(t, cert.TrustAnchorID(""), cert.AlgMLDSA44, nil,
		start, end, subtreeHash, nil, cpBody, proof)
}

// buildSignSubtreeRequestWithCASig assembles a sign-subtree request body,
// optionally including a single subtree cosignature line for the CA key.
// If caSig is nil, no cosignature line is emitted (caKey/caAlg/caPub are
// then ignored).
func buildSignSubtreeRequestWithCASig(
	t *testing.T,
	caCosignerID cert.TrustAnchorID, caAlg cert.SignatureAlgorithm, caPub []byte,
	start, end uint64, subtreeHash tlogx.Hash,
	caSig []byte,
	cpBody []byte, proof []tlogx.Hash,
) []byte {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "subtree %d %d\n", start, end)
	b.WriteString(base64.StdEncoding.EncodeToString(subtreeHash[:]) + "\n")
	if caSig != nil {
		caKey := cert.OIDName(caCosignerID)
		keyID, err := cert.CosignatureKeyID(caKey, caAlg, caPub)
		if err != nil {
			t.Fatalf("CA key ID: %v", err)
		}
		blob := append(append([]byte(nil), keyID[:]...), caSig...)
		fmt.Fprintf(&b, "— %s %s\n", caKey, base64.StdEncoding.EncodeToString(blob))
	}
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	b.WriteString("\n") // empty line before the checkpoint
	b.Write(cpBody)
	if !bytes.HasSuffix(cpBody, []byte("\n")) {
		b.WriteString("\n")
	}
	return b.Bytes()
}
