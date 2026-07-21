# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

cactus is a Go ACME server that issues **Merkle Tree certificates** per
[draft-ietf-plants-merkle-tree-certs-05], for **testing only** (not a production CA).
Read [MTC.md](MTC.md) for how MTC works (why certs have no real signature, what the
inclusion proof proves, how landmarks and mirrors fit) and [README.md](README.md) for
operating details and the full config reference.

## Toolchain (non-obvious, important)

cactus is **ML-DSA-44 only** and uses Go's built-in `crypto/mldsa`, so it **requires
Go 1.27+** (`go.mod` declares `go 1.27`). There are no build tags — an older toolchain
simply won't compile. Until 1.27 ships, build and test with **`gotip`** (a 1.27-devel
toolchain). The `Makefile` defaults `GO ?= gotip`; override with `make GO=go` once a
1.27 release is installed. ECDSA support has been removed.

## Commands

```sh
make build              # builds bin/cactus, bin/cactus-cli, bin/cactus-keygen
make test               # gotip test ./...
make test-race          # gotip test -race ./...
make vet                # gotip vet ./...
make integration        # gotip test -race -count=1 -tags=integration ./integration/...
make stress             # bulk issuance stress test (800 certs, `stress` build tag)

# Single test / package:
gotip test ./log/...
gotip test -run TestParallelIssuance -tags=integration ./integration/...

# Fuzz targets:
gotip test -fuzz=FuzzParseMTCProof -fuzztime=30s ./cert/...
gotip test -fuzz=FuzzAddEntriesFraming -fuzztime=30s ./mirrorpush/...

# Local stack: cactus + Sunlight as a c2sp.org/tlog-mirror (see docker/README.md).
make docker-up          # cross-build binaries with gotip, build images, start
make docker-logs
make docker-down        # also deletes volumes, and therefore key material
```

Integration tests live in `./integration/` and are **not** build-tagged, so plain
`gotip test ./...` runs them; they take ~10s. The one exception is
`stress_test.go`, which *is* tagged (`stress`) so hundreds of issuances stay out of
the default suite — `make stress`, or
`CACTUS_STRESS_CERTS=5000 CACTUS_STRESS_CONCURRENCY=128 make stress` for a soak. (`make integration` passes
`-tags=integration`, which currently selects nothing extra — it exists to run them
under `-race -count=1`.) Some of them compile and run the actual `cactus` binary
over HTTP.

## Architecture

One binary (`cmd/cactus`) brings up whichever subsystems the JSON config asks for — there
is no fixed mode enum. The two composable concerns are **CA** (`acme` + `log` +
`ca_cosigner`) and **CA-side mirror quorum collection** (`ca_cosigner_quorum.mirrors[]`),
which requests cosignatures from external mirrors. cactus does not itself act as a
mirror; mirroring is push-based against an external tlog-mirror (Sunlight).

Cert issuance data flow (CSR → verifiable bytes on disk):

1. **`acme/`** — RFC 8555 server with the draft §9 cert-download extensions. Validates
   the order, then calls the CA issuer.
2. **`ca/`** — turns a CSR into a standalone X.509 cert whose `signatureAlgorithm` is
   `id-alg-mtcProof` and whose `signatureValue` is an `MTCProof` blob (inclusion proof +
   cosigner signatures). Builds the log entry and waits on the log.
3. **`log/`** — the single-writer issuance log. `Log.Append` assigns an index
   immediately; `Log.Wait` blocks until the entry is in a published checkpoint **and** a
   covering signed subtree (§4.5) exists. A sequencer flushes pooled entries every
   `checkpoint_period_ms`, writes tiles, and signs a new checkpoint (c2sp signed-note).
   In CA-quorum mode, each flush fires parallel `sign-subtree` requests to configured
   mirrors and `Wait` blocks for `1 + min_signatures` cosignatures.
4. **`tile/`** — read-path HTTP server with a tlog-tiles-compatible layout
   (`/<lognum>/checkpoint`, `/<lognum>/tile/…`, `/<lognum>/landmarks`).

Supporting packages: **`cert/`** holds the wire types (`TBSCertificateLogEntry`,
`MTCProof`, `CosignedMessage`, `CertificatePropertyList`) and the multi-mirror
sign-subtree request client. **`mirrorpush/`** is the c2sp.org/tlog-mirror push
client: it replicates the log to external mirrors (`add-checkpoint`, `add-entries`)
and retains the mirror-cosigned checkpoint that `sign-subtree` then requires. **`tlogx/`** extends `x/mod/sumdb/tlog` with the §4 subtree primitives
(consistency, inclusion, covering subtrees). **`signer/`** is the ML-DSA cosigner
abstraction. **`landmark/`** allocates §6.4 landmark sequences and serves `/landmarks`.
**`storage/`** is on-disk K/V using atomic-rename writes.

**Single-writer assumption**: the log has no locks or shared-state coordination across
processes — single-writer is enforced by documentation, not by code. See
[docs/threat-model.md](docs/threat-model.md), [docs/disk-layout.md](docs/disk-layout.md).

## IDs are derived, not independent

The **CA ID** (`ca_cosigner.id`, e.g. `44363.47.1.99`, the arcs *below* the `1.3.6.1.4.1` enterprise base) is load-bearing: draft
§5.4 requires the CA cosigner ID to equal the CA ID, so this one value identifies the CA,
seeds the issuer DN, and roots all derived IDs — the log ID is `<CA-ID>.0.<lognum>` and
landmark trust-anchor IDs are `<CA-ID>.1.<lognum>.L`. There is no separate `base_id`.

## cactus-cli (debugging / verification)

```
cactus-cli tree show|verify <log-url>       # checkpoint vs. recomputed root from tiles
cactus-cli entry <log-url> <index>          # decode one §5.2.1 entry
cactus-cli cert verify <cert.pem> <log-url> # full §7.2 verification, prints OK
cactus-cli prove <log-url> <index>          # JSON inclusion proof
```

[draft-ietf-plants-merkle-tree-certs-05]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-05.txt
