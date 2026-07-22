package pollinate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/tlogx"
)

// buildTestNote assembles a checkpoint note for origin at (size, root)
// signed by the given ML-DSA-44 cosigner, the way cactus's log and a
// conforming mirror produce them.
func buildTestNote(t *testing.T, sgn signer.Signer, signerID cert.TrustAnchorID, origin string, size uint64, root tlogx.Hash, ts uint64) []byte {
	t.Helper()
	name := cert.OIDName(signerID)
	msg, err := cert.MarshalCosignedMessage(name, origin, ts, 0, size, root)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sgn.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := cert.CosignatureKeyID(name, cert.AlgMLDSA44, sgn.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	blob := append(append([]byte(nil), keyID[:]...), cert.MarshalTimestampedSignature(ts, sig)...)
	return fmt.Appendf(nil, "%s\n%d\n%s\n\n— %s %s\n",
		origin, size, base64.StdEncoding.EncodeToString(root[:]),
		name, base64.StdEncoding.EncodeToString(blob))
}

func TestParseAndVerifyNote(t *testing.T) {
	sgn, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{7}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	id := cert.TrustAnchorID("32473.9")
	origin := "oid/1.3.6.1.4.1.32473.9.0.1"
	root := sha256Hash([]byte("root"))

	for _, ts := range []uint64{0, 1752000000} {
		data := buildTestNote(t, sgn, id, origin, 42, root, ts)
		n, err := ParseNote(data)
		if err != nil {
			t.Fatal(err)
		}
		if n.Origin != origin || n.Size != 42 || n.Root != root {
			t.Fatalf("parsed %q %d %x", n.Origin, n.Size, n.Root[:4])
		}
		if !bytes.Equal(n.Raw, data) {
			t.Fatal("Raw is not the verbatim note")
		}
		if err := n.VerifySignature(id, sgn.PublicKey()); err != nil {
			t.Fatalf("ts=%d: %v", ts, err)
		}
	}
}

func TestVerifyNoteRejects(t *testing.T) {
	sgn, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{7}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	other, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{8}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	id := cert.TrustAnchorID("32473.9")
	origin := "oid/1.3.6.1.4.1.32473.9.0.1"
	root := sha256Hash([]byte("root"))
	data := buildTestNote(t, sgn, id, origin, 42, root, 0)

	n, err := ParseNote(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.VerifySignature(id, other.PublicKey()); err == nil {
		t.Error("verified with the wrong key")
	}
	if err := n.VerifySignature(cert.TrustAnchorID("32473.10"), sgn.PublicKey()); err == nil {
		t.Error("verified under the wrong signer ID")
	}

	// A tampered size must fail even though the signature line is intact.
	tampered := bytes.Replace(data, []byte("\n42\n"), []byte("\n43\n"), 1)
	n2, err := ParseNote(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.VerifySignature(id, sgn.PublicKey()); err == nil {
		t.Error("verified a tampered note")
	}
}

// TestParseNoteNonOIDOrigin pins down that origins outside the
// oid/-derived namespace parse fine — Cloudflare's bootstrap CA uses a
// hostname-path origin, and pollinate must follow such logs too.
func TestParseNoteNonOIDOrigin(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	sig := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 12))
	data := fmt.Sprintf("bootstrap-mtca.cloudflareresearch.com/logs/shard3\n228999041\n%s\n\n— host.example/k %s\n", root, sig)
	n, err := ParseNote([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if n.Origin != "bootstrap-mtca.cloudflareresearch.com/logs/shard3" || n.Size != 228999041 {
		t.Fatalf("parsed %q %d", n.Origin, n.Size)
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != "host.example/k" {
		t.Fatalf("sigs = %+v", n.Sigs)
	}
}

func TestParseNoteRejectsMalformed(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for name, in := range map[string]string{
		"no separator": "origin\n5\n" + root + "\n",
		"two lines":    "origin\n5\n\nsigs\n",
		"bad size":     "origin\nfive\n" + root + "\n\n— a " + base64.StdEncoding.EncodeToString(make([]byte, 8)) + "\n",
		"short root":   "origin\n5\nAAAA\n\n— a AAAAAAAA\n",
		"bad sig line": "origin\n5\n" + root + "\n\nnot a sig\n",
		"short sig":    "origin\n5\n" + root + "\n\n— a " + base64.StdEncoding.EncodeToString([]byte{1, 2}) + "\n",
		"empty origin": "\n5\n" + root + "\n\n— a AAAAAAAA\n",
	} {
		if _, err := ParseNote([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if !strings.HasPrefix("— x", "— ") {
		t.Fatal("sanity: em dash prefix")
	}
}
