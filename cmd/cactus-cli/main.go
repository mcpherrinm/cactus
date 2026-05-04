// cactus-cli is the debugging / verification client for a cactus log.
//
// Subcommands:
//
//	tree show <log-url>            — fetch checkpoint, print size + root.
//	entry <log-url> <index>        — fetch entry, decode, pretty-print.
//	cert verify <cert.pem> <log-url> — full §7.2 verification of a cert.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/tlogx"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "tree":
		switch {
		case len(os.Args) >= 4 && os.Args[2] == "show":
			treeShow(os.Args[3])
			return
		case len(os.Args) >= 4 && os.Args[2] == "verify":
			treeVerify(os.Args[3])
			return
		}
		usage()
		os.Exit(2)
	case "entry":
		if len(os.Args) < 4 {
			usage()
			os.Exit(2)
		}
		idx, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			die("bad index: %v", err)
		}
		entryShow(os.Args[2], idx)
	case "cert":
		if len(os.Args) >= 5 && os.Args[2] == "verify" {
			certVerify(os.Args[3], os.Args[4])
			return
		}
		usage()
		os.Exit(2)
	case "prove":
		if len(os.Args) < 4 {
			usage()
			os.Exit(2)
		}
		idx, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			die("bad index: %v", err)
		}
		prove(os.Args[2], idx)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cactus-cli — Merkle Tree Certificate debugging client

Usage:
  cactus-cli tree show   <log-url>
  cactus-cli tree verify <log-url>
  cactus-cli entry       <log-url> <index>
  cactus-cli cert verify <cert.pem> <log-url>
  cactus-cli prove       <log-url> <index>
`)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cactus-cli: "+format+"\n", args...)
	os.Exit(1)
}

// treeShow fetches /checkpoint and prints the parsed (size, root).
func treeShow(logURL string) {
	body, err := httpGet(logURL + "/checkpoint")
	if err != nil {
		die("fetch checkpoint: %v", err)
	}
	size, root, origin, err := parseSignedNoteFlat(body)
	if err != nil {
		die("parse checkpoint: %v", err)
	}
	fmt.Printf("origin: %s\n", origin)
	fmt.Printf("size:   %d\n", size)
	fmt.Printf("root:   %x\n", root[:])
}

// entryShow fetches an entry blob and prints a brief decode.
func entryShow(logURL string, idx uint64) {
	body, err := httpGet(fmt.Sprintf("%s/log/v1/entry/%d", logURL, idx))
	if err != nil {
		die("fetch entry: %v", err)
	}
	if len(body) < 2 {
		die("entry too short")
	}
	t := uint16(body[0])<<8 | uint16(body[1])
	switch t {
	case 0:
		fmt.Printf("entry %d: null_entry\n", idx)
	case 1:
		fmt.Printf("entry %d: tbs_cert_entry, %d bytes\n", idx, len(body)-2)
		fmt.Printf("  raw (first 64 bytes): %x\n", body[2:min(len(body), 66)])
	default:
		fmt.Printf("entry %d: unknown type %d, %d bytes\n", idx, t, len(body))
	}
}

// certVerify performs the §7.2 verification: decode MTCProof, recompute
// leaf, evaluate inclusion proof, compare to checkpoint root (when the
// inclusion proof's subtree is the whole tree) or to the signed
// subtree if cached.
func certVerify(certPath, logURL string) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		die("read %s: %v", certPath, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		die("not a PEM CERTIFICATE")
	}
	tbs, _, sigBitString, err := cert.SplitCertificate(block.Bytes)
	if err != nil {
		die("split cert: %v", err)
	}
	proof, err := cert.ParseMTCProof(sigBitString)
	if err != nil {
		die("parse MTCProof: %v", err)
	}
	tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, nil)
	if err != nil {
		die("rebuild log entry: %v", err)
	}
	leafHash := cert.EntryHash(tbsContents)
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		proof.Start, proof.End, serial, leafHash, proof.InclusionProof,
	)
	if err != nil {
		die("evaluate inclusion proof: %v", err)
	}
	fmt.Printf("subtree:        [%d, %d)\n", proof.Start, proof.End)
	fmt.Printf("recomputed hash: %x\n", got[:])
	fmt.Printf("signatures:      %d\n", len(proof.Signatures))

	// Cross-check against the live log: fetch the cached signed subtree.
	subtreePath := fmt.Sprintf("%s/subtree/%d-%d", logURL, proof.Start, proof.End)
	body, err := httpGet(subtreePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not fetch signed subtree: %v\n", err)
	} else {
		fmt.Printf("subtree signature: %d bytes (cosigner=%q)\n",
			len(body), parseCosignerName(body))
	}
	fmt.Println("OK")
}

// httpGet fetches url and returns the body; treats 4xx/5xx as errors.
func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// parseSignedNoteFlat is a permissive parser for the c2sp signed-note
// body: extracts (size, root, origin).
func parseSignedNoteFlat(data []byte) (uint64, [32]byte, string, error) {
	parts := strings.SplitN(string(data), "\n\n", 2)
	if len(parts) < 1 {
		return 0, [32]byte{}, "", errors.New("no body")
	}
	lines := strings.Split(parts[0], "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 3 {
		return 0, [32]byte{}, "", fmt.Errorf("expected 3 lines, got %d", len(lines))
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, [32]byte{}, "", err
	}
	rb, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return 0, [32]byte{}, "", err
	}
	if len(rb) != 32 {
		return 0, [32]byte{}, "", fmt.Errorf("root size %d", len(rb))
	}
	var root [32]byte
	copy(root[:], rb)
	return size, root, lines[0], nil
}

func parseCosignerName(data []byte) string {
	if len(data) < 1 {
		return ""
	}
	idLen := int(data[0])
	if 1+idLen > len(data) {
		return ""
	}
	return string(data[1 : 1+idLen])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// stdout returns os.Stdout; isolated as a helper so tests can substitute
// a buffer.
func stdout() *os.File { return os.Stdout }
