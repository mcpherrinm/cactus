// cactus-cli is the debugging / verification client for a cactus log.
//
// Subcommands:
//
//	tree show <log-url>            — fetch checkpoint, print size + root.
//	entry <log-url> <index>        — fetch entry, decode, pretty-print.
//	cert verify <cert.pem> <log-url> — full §7.2 verification of a cert.
//	cert text <cert.pem>           — print a text representation of a cert.
//	cert landmark-relative <cert.pem> <log-url> — convert a standalone
//	                                 cert to its landmark-relative form.
package main

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
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
		switch {
		case len(os.Args) >= 5 && os.Args[2] == "verify":
			certVerify(os.Args[3], os.Args[4])
			return
		case len(os.Args) >= 4 && os.Args[2] == "text":
			certText(os.Args[3])
			return
		case len(os.Args) >= 5 && os.Args[2] == "landmark-relative":
			certLandmarkRelative(os.Args[3], os.Args[4])
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
  cactus-cli tree show          <log-url>
  cactus-cli tree verify        <log-url>
  cactus-cli entry              <log-url> <index>
  cactus-cli cert verify        <cert.pem> <log-url>
  cactus-cli cert text          <cert.pem>
  cactus-cli cert landmark-relative <cert.pem> <log-url>
  cactus-cli prove              <log-url> <index>
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
	// MerkleTreeCertEntry (§5.2.1): extensions<0..2^16-1> then uint16 type
	// then the type-specific data. The leading uint16 is the extensions
	// vector length, NOT the type.
	if len(body) < 2 {
		die("entry too short")
	}
	extLen := int(body[0])<<8 | int(body[1])
	if len(body) < 2+extLen+2 {
		die("entry too short (ext_len=%d, %d bytes)", extLen, len(body))
	}
	rest := body[2+extLen:]
	t := uint16(rest[0])<<8 | uint16(rest[1])
	data := rest[2:]
	switch t {
	case 0:
		fmt.Printf("entry %d: null_entry\n", idx)
	case 1:
		fmt.Printf("entry %d: tbs_cert_entry, %d bytes\n", idx, len(data))
		e, err := cert.ParseTBSCertificateLogEntry(data)
		if err != nil {
			fmt.Printf("  (decode failed: %v)\n", err)
			fmt.Printf("  raw (first 64 bytes): %x\n", data[:min(len(data), 64)])
			break
		}
		printLogEntry(e)
	default:
		fmt.Printf("entry %d: unknown type %d, %d bytes\n", idx, t, len(data))
	}
}

// printLogEntry pretty-prints the decoded fields of a TBSCertificateLogEntry.
func printLogEntry(e *cert.TBSCertificateLogEntry) {
	fmt.Printf("  version:    v%d\n", e.Version+1)
	fmt.Printf("  issuer:     %s\n", formatDN(e.IssuerDN))
	fmt.Printf("  not before: %s\n", e.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Printf("  not after:  %s\n", e.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Printf("  subject:    %s\n", formatDN(e.SubjectDN))
	fmt.Printf("  spki alg:   %s\n", formatAlgID(e.SubjectPublicKeyAlgorithm))
	fmt.Printf("  spki hash:  %x (sha-256)\n", e.SubjectPublicKeyInfoHash)
	if e.IssuerUniqueID != nil {
		fmt.Printf("  issuerUID:  %x\n", e.IssuerUniqueID)
	}
	if e.SubjectUniqueID != nil {
		fmt.Printf("  subjectUID: %x\n", e.SubjectUniqueID)
	}
	if e.Extensions != nil {
		fmt.Printf("  extensions:\n")
		for _, line := range formatExtensions(e.Extensions) {
			fmt.Printf("    %s\n", line)
		}
	}
}

// attrNames maps the AttributeType OIDs cactus may emit in a Name to
// short labels. Unknown OIDs fall back to dotted notation.
var attrNames = map[string]string{
	cert.OIDRDNATrustAnchorID.String(): "trustAnchorID",
	"2.5.4.3":                          "CN",
	"2.5.4.6":                          "C",
	"2.5.4.10":                         "O",
	"2.5.4.11":                         "OU",
}

// formatDN renders a DER-encoded Name (RDNSequence) as "type=value, …".
func formatDN(der []byte) string {
	if len(der) == 0 {
		return "(empty)"
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		return fmt.Sprintf("<unparseable: %x>", der)
	}
	if len(rdns) == 0 {
		return "(empty)"
	}
	var parts []string
	for _, rdn := range rdns {
		for _, atv := range rdn {
			name := atv.Type.String()
			if n, ok := attrNames[name]; ok {
				name = n
			}
			parts = append(parts, fmt.Sprintf("%s=%v", name, atv.Value))
		}
	}
	return strings.Join(parts, ", ")
}

// formatAlgID renders an AlgorithmIdentifier as its OID (named if known).
func formatAlgID(der []byte) string {
	var alg struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &alg); err != nil {
		return fmt.Sprintf("<unparseable: %x>", der)
	}
	oid := alg.Algorithm.String()
	if name, ok := algNames[oid]; ok {
		return fmt.Sprintf("%s (%s)", name, oid)
	}
	return oid
}

// algNames maps SPKI algorithm OIDs to friendly names.
var algNames = map[string]string{
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"1.2.840.10045.2.1":       "ecPublicKey",
	"1.2.840.113549.1.1.1":    "rsaEncryption",
}

// extOIDNames maps certificate extension OIDs to short labels.
var extOIDNames = map[string]string{
	"2.5.29.15": "keyUsage",
	"2.5.29.17": "subjectAltName",
	"2.5.29.19": "basicConstraints",
	"2.5.29.37": "extKeyUsage",
}

// formatExtensions decodes a DER Extensions SEQUENCE into one display
// line per extension.
func formatExtensions(der []byte) []string {
	var exts []pkix.Extension
	if _, err := asn1.Unmarshal(der, &exts); err != nil {
		return []string{fmt.Sprintf("<unparseable: %x>", der)}
	}
	var lines []string
	for _, ext := range exts {
		oid := ext.Id.String()
		name := extOIDNames[oid]
		label := oid
		if name != "" {
			label = fmt.Sprintf("%s %s", oid, name)
		}
		if ext.Critical {
			label += " (critical)"
		}
		if name == "subjectAltName" {
			if sans := formatSAN(ext.Value); sans != "" {
				label += "  " + sans
			}
		}
		lines = append(lines, label)
	}
	return lines
}

// formatSAN extracts the dNSName entries from a SubjectAltName extension
// value (the GeneralNames SEQUENCE), the common case for cactus leaves.
func formatSAN(der []byte) string {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return ""
	}
	var names []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			break
		}
		// dNSName is [2] IMPLICIT IA5String.
		if gn.Class == asn1.ClassContextSpecific && gn.Tag == 2 {
			names = append(names, "DNS:"+string(gn.Bytes))
		}
	}
	return strings.Join(names, ", ")
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
	// draft-04 §6.1: serial = (log_number << 48) | index.
	logNumber, index, err := cert.SplitSerial(serial)
	if err != nil {
		die("decode serial: %v", err)
	}
	// §7.2 step 8.2: the MerkleTreeCertEntry's extensions come from the
	// MTCProof, not the X.509 cert. Feed them into the leaf hash so a
	// proof carrying entry extensions hashes correctly.
	leafHash, err := cert.EntryHashExt(proof.Extensions, tbsContents)
	if err != nil {
		die("entry hash: %v", err)
	}
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		proof.Start, proof.End, index, leafHash, proof.InclusionProof,
	)
	if err != nil {
		die("evaluate inclusion proof: %v", err)
	}
	fmt.Printf("log number:     %d\n", logNumber)
	fmt.Printf("entry index:    %d\n", index)
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
