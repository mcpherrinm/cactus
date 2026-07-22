package main

import (
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/tlogx"
)

// certText prints a human-readable view of a Merkle Tree Certificate:
// the X.509 / log-entry fields, the decoded serial (log number +
// index), and the MTCProof carried in the signatureValue. It works on
// both standalone certs (cosigner-signed subtree) and landmark-relative
// certs (no signatures), and on either a bare CERTIFICATE PEM or the
// trust-anchor-ids `…-with-properties` form.
func certText(certPath string) {
	der, props, err := readCertPEM(certPath)
	if err != nil {
		die("read %s: %v", certPath, err)
	}
	tbs, _, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		die("split cert: %v", err)
	}
	tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, nil)
	if err != nil {
		die("rebuild log entry: %v", err)
	}
	logNumber, index, err := cert.SplitSerial(serial)
	if err != nil {
		die("decode serial: %v", err)
	}
	e, err := cert.ParseTBSCertificateLogEntry(tbsContents)
	if err != nil {
		die("parse TBS log entry: %v", err)
	}
	proof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		die("parse MTCProof: %v", err)
	}

	fmt.Println("Merkle Tree Certificate")
	fmt.Printf("  serial:     %d (log number %d, entry index %d)\n", serial, logNumber, index)
	printLogEntry(e)

	form := "landmark-relative (no signatures)"
	if len(proof.Signatures) > 0 {
		form = "standalone (cosigner-signed subtree)"
	}
	fmt.Println("  MTC proof:")
	fmt.Printf("    form:            %s\n", form)
	fmt.Printf("    subtree:         [%d, %d)\n", proof.Start, proof.End)
	fmt.Printf("    inclusion proof: %d node(s)\n", len(proof.InclusionProof))
	fmt.Printf("    signatures:      %d\n", len(proof.Signatures))
	for _, sig := range proof.Signatures {
		fmt.Printf("      - cosigner %s (%d-byte signature)\n", string(sig.CosignerID), len(sig.Signature))
	}
	if len(proof.Extensions) > 0 {
		fmt.Printf("    entry extensions: %d\n", len(proof.Extensions))
	}
	for _, p := range props {
		if p.Type == cert.PropertyTrustAnchorID {
			fmt.Printf("  trust anchor id: %s\n", string(p.TrustAnchorID))
		}
	}
}

// certLandmarkRelative converts a standalone certificate into the
// equivalent landmark-relative certificate (§6.4.4): same TBS, but a new
// MTCProof whose inclusion proof climbs from the entry to a covering
// subtree of the smallest landmark containing the entry, with the
// cosigner signatures dropped. The log's /landmarks and tile endpoints
// are read from logURL to pick the landmark and build the proof.
func certLandmarkRelative(certPath, logURL string) {
	der, props, err := readCertPEM(certPath)
	if err != nil {
		die("read %s: %v", certPath, err)
	}
	tbs, _, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		die("split cert: %v", err)
	}
	origProof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		die("parse MTCProof: %v", err)
	}
	if len(origProof.Signatures) == 0 {
		die("input certificate is already landmark-relative (no signatures)")
	}
	// BuildLandmarkRelativeCert emits a proof with no entry extensions,
	// so a cert whose entry carries extensions can't be converted
	// without losing them (the leaf hash would no longer reconstruct).
	if len(origProof.Extensions) > 0 {
		die("entry carries %d extension(s); landmark-relative conversion would drop them", len(origProof.Extensions))
	}

	tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, nil)
	if err != nil {
		die("rebuild log entry: %v", err)
	}
	logNumber, index, err := cert.SplitSerial(serial)
	if err != nil {
		die("decode serial: %v", err)
	}

	// Pick the covering landmark from the §6.4.1 list.
	body, err := httpGet(logURL + "/landmarks")
	if err != nil {
		die("fetch landmarks: %v", err)
	}
	lms, err := parseLandmarks(body)
	if err != nil {
		die("parse landmarks: %v", err)
	}
	lmNum, lmSize, prevSize, ok := coveringLandmark(lms, index)
	if !ok {
		die("no active landmark covers entry index %d (entry too new, or older than the active window)", index)
	}

	// Choose the §4.5 covering subtree of [prevSize, lmSize) containing
	// the entry, then build its hash + inclusion proof from the tiles.
	var chosen tlogx.Subtree
	for _, st := range tlogx.FindSubtrees(prevSize, lmSize) {
		if index >= st.Start && index < st.End {
			chosen = st
			break
		}
	}
	if chosen.End == 0 {
		die("internal: no covering subtree for index %d in landmark %d [%d,%d)", index, lmNum, prevSize, lmSize)
	}

	// Rebuild stored hashes from the current tree; subtree hashes and
	// proofs for [start,end) are stable regardless of the (larger)
	// total size, and only the current partial tile is guaranteed to be
	// fetchable.
	cpBody, err := httpGet(logURL + "/checkpoint")
	if err != nil {
		die("fetch checkpoint: %v", err)
	}
	curSize, _, _, err := parseSignedNoteFlat(cpBody)
	if err != nil {
		die("parse checkpoint: %v", err)
	}
	if curSize < lmSize {
		die("checkpoint size %d < landmark tree size %d", curSize, lmSize)
	}
	hashes, _, err := loadAllHashes(logURL, curSize)
	if err != nil {
		die("load tree state: %v", err)
	}
	subtreeHash, err := tlogx.SubtreeHash(chosen.Start, chosen.End, hr(hashes))
	if err != nil {
		die("subtree hash: %v", err)
	}
	proof, err := tlogx.GenerateInclusionProof(chosen.Start, chosen.End, index, hr(hashes))
	if err != nil {
		die("inclusion proof: %v", err)
	}

	// Self-check: the inclusion proof must reconstruct the subtree hash
	// from the entry's leaf so we never emit a cert that won't verify.
	leafHash, err := cert.EntryHashExt(nil, tbsContents)
	if err != nil {
		die("entry hash: %v", err)
	}
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		chosen.Start, chosen.End, index, leafHash, proof,
	)
	if err != nil {
		die("verify inclusion proof: %v", err)
	}
	if got != subtreeHash {
		die("self-check failed: inclusion proof does not reconstruct subtree hash")
	}

	out, err := cert.BuildLandmarkRelativeCert(der, nil,
		cert.MTCSubtree{Start: chosen.Start, End: chosen.End, Hash: subtreeHash}, proof)
	if err != nil {
		die("build landmark-relative cert: %v", err)
	}

	// If the input named the CA via a trust_anchor_id property (§8.1),
	// emit the matching landmark trust anchor id (§8.2) so the output is
	// a faithful with-properties cert; otherwise emit bare PEM.
	if caTAID, ok := caTrustAnchorID(props); ok {
		lmTAID := cert.LandmarkID(caTAID, logNumber, lmNum)
		pl, err := cert.BuildPropertyList([]cert.CertificateProperty{
			{Type: cert.PropertyTrustAnchorID, TrustAnchorID: lmTAID},
		})
		if err != nil {
			die("build properties: %v", err)
		}
		_, _ = os.Stdout.Write(cert.EncodePEMWithProperties(out, pl))
	} else {
		_ = pem.Encode(stdout(), &pem.Block{Type: "CERTIFICATE", Bytes: out})
	}
	fmt.Fprintf(os.Stderr, "landmark-relative: landmark %d, subtree [%d,%d), %d-node inclusion proof\n",
		lmNum, chosen.Start, chosen.End, len(proof))
}

// readCertPEM reads a PEM file holding either a bare CERTIFICATE or the
// trust-anchor-ids `-with-properties` pair (CERTIFICATE PROPERTIES then
// CERTIFICATE). It returns the cert DER and any parsed properties.
func readCertPEM(path string) (der []byte, props []cert.CertificateProperty, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if der == nil {
				der = block.Bytes
			}
		case cert.PEMBlockProperties:
			props, err = cert.ParsePropertyList(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse property list: %w", err)
			}
		}
	}
	if der == nil {
		return nil, nil, errors.New("no CERTIFICATE block found")
	}
	return der, props, nil
}

// caTrustAnchorID returns the trust_anchor_id property value (the CA ID
// for a standalone cert, §8.1) if present.
func caTrustAnchorID(props []cert.CertificateProperty) (cert.TrustAnchorID, bool) {
	for _, p := range props {
		if p.Type == cert.PropertyTrustAnchorID {
			return p.TrustAnchorID, true
		}
	}
	return nil, false
}

// landmarkEntry is one (number, treeSize) pair from the §6.4.1 list.
type landmarkEntry struct {
	number   uint64
	treeSize uint64
}

// parseLandmarks decodes the §6.4.1 landmark list:
//
//	<last> <num_active>\n
//	<treeSize of landmark last>\n
//	<treeSize of landmark last-1>\n
//	… (num_active + 1 size lines, strictly decreasing)
//
// It returns the entries in descending Number order (newest first).
func parseLandmarks(body []byte) ([]landmarkEntry, error) {
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, errors.New("empty landmark list")
	}
	hdr := strings.Fields(lines[0])
	if len(hdr) != 2 {
		return nil, fmt.Errorf("bad header %q", lines[0])
	}
	last, err := strconv.ParseUint(hdr[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad last %q: %w", hdr[0], err)
	}
	numActive, err := strconv.ParseUint(hdr[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad num_active %q: %w", hdr[1], err)
	}
	if numActive > last {
		return nil, fmt.Errorf("num_active %d > last %d", numActive, last)
	}
	sizeLines := lines[1:]
	if uint64(len(sizeLines)) != numActive+1 {
		return nil, fmt.Errorf("expected %d size lines, got %d", numActive+1, len(sizeLines))
	}
	out := make([]landmarkEntry, 0, len(sizeLines))
	for i := uint64(0); i <= numActive; i++ {
		ts, err := strconv.ParseUint(strings.TrimSpace(sizeLines[i]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad tree size %q: %w", sizeLines[i], err)
		}
		out = append(out, landmarkEntry{number: last - i, treeSize: ts})
	}
	return out, nil
}

// coveringLandmark finds the smallest-numbered landmark whose tree size
// is strictly greater than index (§6.4.4), and its predecessor's tree
// size (the lower bound of the landmark's entry range). It needs the
// predecessor to be present in the list, which the §6.4.1 format
// guarantees for every active landmark by including one extra older
// size line.
func coveringLandmark(desc []landmarkEntry, index uint64) (num, size, prev uint64, ok bool) {
	// Walk ascending by number (the list is descending).
	for i := len(desc) - 1; i >= 0; i-- {
		if desc[i].treeSize > index {
			if i == len(desc)-1 {
				// Oldest entry in the list: its predecessor's tree
				// size is outside the published window, so we can't
				// bound the landmark's range.
				return 0, 0, 0, false
			}
			return desc[i].number, desc[i].treeSize, desc[i+1].treeSize, true
		}
	}
	return 0, 0, 0, false
}
