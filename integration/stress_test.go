//go:build stress

// Bulk issuance stress test. Gated behind the `stress` build tag because
// it issues hundreds of certificates and takes far longer than the rest
// of the suite, which is meant to stay fast enough to run on every save.
//
//	gotip test -tags=stress -run TestBulkIssuanceStress -timeout 30m ./integration/
//	make stress
//
// Size and concurrency are tunable so the same test can be a quick smoke
// run locally and a heavier soak in CI:
//
//	CACTUS_STRESS_CERTS=2000 CACTUS_STRESS_CONCURRENCY=128 make stress
package integration

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// Defaults. 800 is the floor this test is specified to cover; it is well
// past the 256-entry tile boundary and the 100-cert TestParallelIssuance
// case, so it exercises multi-tile growth and partial-tile handling
// under concurrent load.
const (
	defaultStressCerts       = 800
	defaultStressConcurrency = 64
)

func envInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		t.Fatalf("%s=%q: want a positive integer", name, v)
	}
	return n
}

// TestBulkIssuanceStress issues a large batch of certificates
// concurrently through the full ACME flow and then checks the log is
// internally consistent.
//
// The load itself is not the interesting part — the assertions after it
// are. In particular the set of assigned log indices must be exactly
// {0, ..., n-1}: the log is a single writer with no cross-process
// locking, so a concurrency bug there shows up as a duplicated or
// skipped index rather than as an error any individual request would
// see. Checking only that every request returned 200, or only that the
// tree ends at the right size, would miss a swap of two entries or a
// double-assigned index that happens to leave the count intact.
func TestBulkIssuanceStress(t *testing.T) {
	n := envInt(t, "CACTUS_STRESS_CERTS", defaultStressCerts)
	concurrency := envInt(t, "CACTUS_STRESS_CONCURRENCY", defaultStressConcurrency)
	if concurrency > n {
		concurrency = n
	}
	t.Logf("issuing %d certificates, %d in flight", n, concurrency)

	s := bringUp(t, t.TempDir())
	defer s.close()

	type result struct {
		index uint64
		err   error
	}
	results := make([]result, n)

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	start := time.Now()
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			der, err := acmeIssueOne(s.acmeBase, fmt.Sprintf("stress%d.example.test", i))
			if err != nil {
				results[i] = result{err: fmt.Errorf("issue: %w", err)}
				return
			}
			// Full §7.2 verification against the live log: rebuild the
			// log entry from the certificate, recompute the leaf hash,
			// and evaluate the inclusion proof.
			if err := verifyAgainstLog(der, s); err != nil {
				results[i] = result{err: fmt.Errorf("verify: %w", err)}
				return
			}
			idx, err := certLogIndex(der, s)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			results[i] = result{index: idx}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Report failures in bulk rather than one t.Error per certificate,
	// which would bury the summary under hundreds of lines.
	var failures []string
	for i, r := range results {
		if r.err != nil {
			if len(failures) < 20 {
				failures = append(failures, fmt.Sprintf("  cert %d: %v", i, r.err))
			}
		}
	}
	if len(failures) > 0 {
		nFailed := 0
		for _, r := range results {
			if r.err != nil {
				nFailed++
			}
		}
		t.Fatalf("%d/%d certificates failed; first %d:\n%s",
			nFailed, n, len(failures), joinLines(failures))
	}

	t.Logf("issued and verified %d certificates in %s (%.0f certs/sec)",
		n, elapsed.Round(time.Millisecond), float64(n)/elapsed.Seconds())

	// Every index in [0, n) assigned exactly once. This is the assertion
	// that a concurrency bug in the sequencer would actually trip.
	seen := make([]int, n)
	for i, r := range results {
		if r.index >= uint64(n) {
			t.Fatalf("cert %d got log index %d, outside [0,%d)", i, r.index, n)
		}
		seen[r.index]++
	}
	for idx, count := range seen {
		switch {
		case count == 0:
			t.Errorf("log index %d was never assigned", idx)
		case count > 1:
			t.Errorf("log index %d was assigned to %d certificates", idx, count)
		}
	}
	if t.Failed() {
		t.Fatalf("log index assignment is not a permutation of [0,%d)", n)
	}

	// The tree must end at exactly n entries.
	cp := s.log.CurrentCheckpoint()
	if cp.Size != uint64(n) {
		t.Errorf("checkpoint size = %d, want %d", cp.Size, n)
	}

	// And the published tiles must still recompute to the signed root:
	// replay every entry through tlog.StoredHashes and compare. This
	// catches a tile written inconsistently under concurrent flushes,
	// which the per-certificate inclusion proofs above would not,
	// because those are served from the same in-memory hashes.
	entries, err := loadAllEntries(s.tileBase, cp.Size)
	if err != nil {
		t.Fatalf("load entry tiles: %v", err)
	}
	if uint64(len(entries)) != cp.Size {
		t.Fatalf("entry tiles hold %d entries, want %d", len(entries), cp.Size)
	}
	var hashes []tlog.Hash
	hr := hashReader(nil)
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hr)
		if err != nil {
			t.Fatalf("StoredHashes(%d): %v", i, err)
		}
		hashes = append(hashes, hs...)
		hr = hashReader(hashes)
	}
	root, err := tlog.TreeHash(int64(cp.Size), hr)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if tlogx.Hash(root) != cp.Root {
		t.Errorf("root recomputed from tiles = %x, signed checkpoint says %x", root, cp.Root)
	}
}

// certLogIndex extracts the log index a certificate was assigned, from
// the serial number packed as (log_number << 48) | index.
func certLogIndex(der []byte, s *stack) (uint64, error) {
	tbs, _, _, err := cert.SplitCertificate(der)
	if err != nil {
		return 0, err
	}
	_, serial, err := cert.RebuildLogEntryFromTBS(tbs, s.logIDDN)
	if err != nil {
		return 0, err
	}
	_, index, err := cert.SplitSerial(serial)
	if err != nil {
		return 0, err
	}
	return index, nil
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
