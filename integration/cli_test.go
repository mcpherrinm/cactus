package integration

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// buildCLI compiles cactus-cli into a temp file and returns the path.
// Done once per test invocation (lazy via TestMain would be cleaner;
// for a small test suite this is fine).
func buildCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "cactus-cli")
	cmd := exec.Command("go", "build", "-o", bin, "../cmd/cactus-cli")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build cactus-cli: %v", err)
	}
	return bin
}

// TestCLITreeShow brings up a stack, shells out to `cactus-cli tree
// show`, and asserts the output contains the expected fields.
func TestCLITreeShow(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()

	bin := buildCLI(t)
	out, err := exec.Command(bin, "tree", "show", s.tileBase).CombinedOutput()
	if err != nil {
		t.Fatalf("cactus-cli tree show: %v\nout=%s", err, out)
	}
	str := string(out)
	for _, want := range []string{"origin: oid/32473.1", "size:", "root:"} {
		if !strings.Contains(str, want) {
			t.Errorf("output missing %q:\n%s", want, str)
		}
	}
}

// TestCLICertVerify drives the full ACME flow, then runs `cactus-cli
// cert verify` against the resulting cert and the live log. This is
// the literal §9-Definition-of-Done check that "every cert verifies
// against the live log via cactus-cli".
func TestCLICertVerify(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()

	der, err := acmeIssueOne(s.acmeBase, "cli.test")
	if err != nil {
		t.Fatal(err)
	}

	pemPath := filepath.Join(t.TempDir(), "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	bin := buildCLI(t)
	cmd := exec.Command(bin, "cert", "verify", pemPath, s.tileBase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cactus-cli cert verify: %v\nout=%s", err, out)
	}
	if !strings.Contains(string(out), "OK\n") {
		t.Errorf("expected OK in output:\n%s", out)
	}
}

// TestCLITreeVerify issues a few certs, then runs `cactus-cli tree
// verify` to confirm the tile bytes recompute to the signed root.
func TestCLITreeVerify(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()
	for i := 0; i < 4; i++ {
		if _, err := acmeIssueOne(s.acmeBase, fmt.Sprintf("tv%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	bin := buildCLI(t)
	out, err := exec.Command(bin, "tree", "verify", s.tileBase).CombinedOutput()
	if err != nil {
		t.Fatalf("cactus-cli tree verify: %v\nout=%s", err, out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Errorf("missing OK:\n%s", out)
	}
}

// TestCLIProve runs `cactus-cli prove`, parses the JSON, and feeds
// the emitted (proof, root, leaf hash) through tlog.CheckRecord — i.e.
// confirms the emitted proof is actually a working RFC-9162 inclusion
// proof, not just well-shaped bytes.
func TestCLIProve(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()
	if _, err := acmeIssueOne(s.acmeBase, "prove.test"); err != nil {
		t.Fatal(err)
	}
	bin := buildCLI(t)
	// Index 1 is the entry we just issued (index 0 is the null entry).
	out, err := exec.Command(bin, "prove", s.tileBase, "1").CombinedOutput()
	if err != nil {
		t.Fatalf("cactus-cli prove: %v\nout=%s", err, out)
	}
	var got proveOutput
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("parse JSON: %v\nout=%s", err, out)
	}
	if got.Index != 1 {
		t.Errorf("Index = %d, want 1", got.Index)
	}
	if got.TreeSize < 2 {
		t.Errorf("TreeSize = %d, want >= 2", got.TreeSize)
	}
	if len(got.Root) != 64 || len(got.LeafHash) != 64 {
		t.Fatalf("hex hashes wrong length: root=%d leaf=%d", len(got.Root), len(got.LeafHash))
	}

	// Decode hex into tlog.Hash values.
	var rootHash, leafHash tlog.Hash
	mustHex(t, got.Root, rootHash[:])
	mustHex(t, got.LeafHash, leafHash[:])
	proof := make([]tlog.Hash, len(got.InclusionProof))
	for i, h := range got.InclusionProof {
		if len(h) != 64 {
			t.Fatalf("inclusion proof[%d] length = %d, want 64", i, len(h))
		}
		mustHex(t, h, proof[i][:])
	}

	// CheckRecord verifies that leafHash at index `got.Index` is in a
	// tree of size `got.TreeSize` with root `rootHash`, given `proof`.
	if err := tlog.CheckRecord(proof, int64(got.TreeSize), rootHash, int64(got.Index), leafHash); err != nil {
		t.Errorf("tlog.CheckRecord: %v", err)
	}
}

// mustHex decodes hex string s into dst. dst is assumed to be the
// right length.
func mustHex(t *testing.T, s string, dst []byte) {
	t.Helper()
	if _, err := hexDecode(s, dst); err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
}

func hexDecode(s string, dst []byte) (int, error) {
	if len(s) != 2*len(dst) {
		return 0, fmt.Errorf("hex length %d != 2*%d", len(s), len(dst))
	}
	for i := 0; i < len(dst); i++ {
		hi, err := unhex(s[2*i])
		if err != nil {
			return i, err
		}
		lo, err := unhex(s[2*i+1])
		if err != nil {
			return i, err
		}
		dst[i] = hi<<4 | lo
	}
	return len(dst), nil
}

func unhex(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return 10 + c - 'a', nil
	case 'A' <= c && c <= 'F':
		return 10 + c - 'A', nil
	default:
		return 0, fmt.Errorf("bad hex char %q", c)
	}
}

type proveOutput struct {
	Index          uint64   `json:"index"`
	TreeSize       uint64   `json:"tree_size"`
	Root           string   `json:"root_hex"`
	LeafHash       string   `json:"leaf_hash_hex"`
	InclusionProof []string `json:"inclusion_proof_hex"`
}
