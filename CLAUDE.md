# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

cactus is a Go ACME server that issues **Merkle Tree certificates** per
[draft-ietf-plants-merkle-tree-certs-04], for **testing only** (not a production CA).
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

# Single test / package:
gotip test ./log/...
gotip test -run TestParallelIssuance -tags=integration ./integration/...

# Fuzz targets:
gotip test -fuzz=FuzzParseMTCProof -fuzztime=30s ./cert/...
gotip test -fuzz=FuzzParseSignSubtreeRequest -fuzztime=30s ./mirror/...
```

Integration tests live in `./integration/` behind the `integration` build tag; some of
them compile and run the actual `cactus` binary over HTTP.

## Architecture

One binary (`cmd/cactus`) brings up whichever subsystems the JSON config asks for — there
is no fixed mode enum. The three composable concerns are **CA** (`acme` + `log` +
`ca_cosigner`), **CA-side mirror quorum collection** (`ca_cosigner_quorum.mirrors[]`), and
**mirror operating mode** (`mirror.enabled`). The config validator enforces hygiene rules
— notably, CA and mirror cosigner keys in the same binary must differ.

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
`MTCProof`, `MTCSubtreeSignatureInput`, `CertificatePropertyList`) and the multi-mirror
request client. **`tlogx/`** extends `x/mod/sumdb/tlog` with the §4 subtree primitives
(consistency, inclusion, covering subtrees). **`signer/`** is the ML-DSA cosigner
abstraction. **`landmark/`** allocates §6.3 landmark sequences and serves `/landmarks`.
**`mirror/`** is the upstream follower plus the `/sign-subtree` server. **`storage/`** is
on-disk K/V using atomic-rename writes.

**Single-writer assumption**: the log has no locks or shared-state coordination across
processes — single-writer is enforced by documentation, not by code. See
[docs/threat-model.md](docs/threat-model.md), [docs/disk-layout.md](docs/disk-layout.md).

## IDs are derived, not independent

The **CA ID** (`ca_cosigner.id`, e.g. `1.3.6.1.4.1.44363.47.1.99`) is load-bearing: draft
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

[draft-ietf-plants-merkle-tree-certs-04]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.txt
