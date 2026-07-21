# cactus

A Go ACME server that issues **Merkle Tree certificates** per
[draft-ietf-plants-merkle-tree-certs-05][draft], intended for
**testing environments only**.

> ⚠ This is *not* a production CA. There is no fsync ladder, no
> shared-state coordination, and the single-writer assumption is
> enforced by documentation rather than by locks. See
> [docs/threat-model.md](docs/threat-model.md) before running it
> anywhere it could be reached.

For a tutorial introduction to *how Merkle Tree certificates work*
(why a cert has no real signature, what the inclusion proof is
proving, how landmarks and mirrors fit), read [MTC.md](MTC.md). The
rest of this README is about cactus itself: what it does, how to
operate it, and where to look in the code.

---

## Contents

1. [What it does](#what-it-does)
2. [What it does not do](#what-it-does-not-do)
3. [Quickstart](#quickstart)
4. [Local stack with a real mirror](#local-stack-with-a-real-mirror)
5. [Operating modes](#operating-modes)
6. [Issuing your first cert](#issuing-your-first-cert)
7. [Verifying certs with the CLI](#verifying-certs-with-the-cli)
8. [Configuration reference](#configuration-reference)
9. [Observability](#observability)
10. [Layout of the codebase](#layout-of-the-codebase)
11. [Tests](#tests)
12. [Status](#status)

---

## What it does

- Runs an **ACME server** (RFC 8555) extended with the §9
  cert-download negotiation from the draft, including
  `application/pem-certificate-chain-with-properties` with a real
  `CertificatePropertyList`.
- Maintains a CA-operated **issuance log** with on-disk tiles, signed
  checkpoints (c2sp signed-note format), and signed §4.5 covering
  subtrees.
- Issues **standalone X.509 certificates** (§6.2) whose
  `signatureAlgorithm` is `id-alg-mtcProof` and whose `signatureValue`
  body is an `MTCProof` blob carrying an inclusion proof + cosigner
  signatures.
- Supports **landmark-relative certificates** (§6.3). Allocates
  landmarks per §6.3.2 and serves a `/landmarks` endpoint per §6.3.1.
  The standalone cert advertises the signature-free landmark-relative
  form as a `rel="acme-optional-alternate"` URL (an optional, non-blocking substitute
  that returns HTTP 202 until a covering landmark exists). The same form
  is also derivable from the log with `cactus-cli cert landmark-relative`.
- Acts as a **CA cosigner** using ML-DSA-44 (requires a Go 1.27+ build).
- **Collects cosignatures from a configured set of external mirrors**
  ([tlog-witness], [tlog-cosignature]) in parallel, with quorum +
  per-mirror timeout + best-effort-after-minimum semantics.

## What it does not do

- **Act as a mirror or witness itself.** cactus only ever *requests*
  cosignatures; mirroring is push-based against an external
  [tlog-mirror] (Sunlight). There is no follower and no `/sign-subtree`
  server.
- **Witness-only cosigners** (§7.3).
- **Log pruning** (§5.2.3).
- **Real DNS-01 challenges.** `auto-pass` and `http-01` are
  supported; DNS-01 is not.
- **Revoked ranges** (§7.5) beyond a stub list in config.

---

## Quickstart

```sh
# 0. Clone & build.
git clone https://github.com/letsencrypt/cactus
cd cactus
make build              # produces ./bin/cactus, cactus-cli, cactus-keygen

# 1. Pick a data directory.
export DATA_DIR=/tmp/cactus
mkdir -p "$DATA_DIR/keys"

# 2. Write a config.json — start from config-example.json. The
#    example writes to /tmp/cactus-data; substitute your DATA_DIR.
cp config-example.json config.json
sed -i "s|/tmp/cactus-data|$DATA_DIR|" config.json

# 3. Run the server. On first start it generates the CA cosigner
#    seed at $DATA_DIR/keys/ca-cosigner.seed (mode 0600). To inspect
#    or pre-generate one yourself, use ./bin/cactus-keygen -o <path>.
./bin/cactus -config config.json
```

You'll see structured JSON logs on stdout. The default
config-example listens on:

- `:14000` — ACME (HTTP, plaintext for tests)
- `:14080` — monitoring read-path. The monitoring base URL is the **CA
  prefix**; each issuance log is served as a tiled transparency log under
  `/<log number>/` (`/<log number>/checkpoint`, `/<log number>/tile/…`,
  `/<log number>/landmarks`), per the MTC-with-tlog profile. The
  CA-level `/ca-certificate` lives at the root.
- `127.0.0.1:14090` — Prometheus metrics + pprof

Once it's up (log number `1` in the example config):

```sh
curl http://localhost:14000/directory     # ACME directory
curl http://localhost:14080/1/checkpoint   # current signed-note checkpoint
curl http://localhost:14090/metrics        # Prometheus metrics
```

Stop it with `Ctrl-C` (SIGINT) or `kill -TERM` — graceful shutdown
drains the pool, writes a final checkpoint, and closes listeners.

---

## Local stack with a real mirror

The quickstart above runs cactus alone, so issued certificates carry
only the CA's own cosignature. To see the full picture — the log
replicated to a mirror, and that mirror's cosignature inside an issued
certificate — use the compose stack in [`docker/`](docker/README.md):

```sh
make docker-up      # cactus + Sunlight (tlog-mirror) + skylight
make docker-logs
make docker-down    # deletes volumes, and therefore key material
```

It runs [Sunlight](https://github.com/FiloSottile/sunlight) as a
c2sp.org/tlog-mirror and ML-DSA-44 cosigner, and handles the key
exchange in both directions. cactus pushes its log to the mirror
(`mirror_push`), the mirror cosigns the resulting checkpoint, and that
cosigned checkpoint is what makes `sign-subtree` work — so certificates
issued against the stack verify with two cosignatures.

Because cactus needs Go 1.27 and no `golang:1.27` image exists yet, the
cactus image is built from binaries cross-compiled on the host with
`gotip`; `make docker-up` does that first. `docker/README.md` covers
that and the several non-obvious things Sunlight needs in order to run
as a mirror.

---

## Operating modes

The same binary can run either of two concerns, determined by which
top-level config blocks are populated:

| Concern | Adds | Set |
|---|---|---|
| **CA** (default) | Issuance log + ACME server + landmark-relative certs | `acme`, `log`, `ca_cosigner` |
| **CA-side mirror collection** | Multi-mirror cosignatures during issuance | `ca_cosigner_quorum.mirrors[]` |
| **Mirror push** | Replicating the log to c2sp.org/tlog-mirror mirrors | `mirror_push.targets[]` |

Landmark-relative cert support is always on; only its cadence is
tunable (see `landmarks` below).

Cactus operating modes are not enumerated; the binary just brings up
whichever subsystems the config asks for.

---

## Issuing your first cert

Use any RFC 8555 ACME client. With `lego`:

```sh
lego --server http://localhost:14000/directory \
     --email you@example.com \
     --domains example.test \
     --accept-tos \
     --pem \
     --path ./certs run
```

Or hand-rolled with `cactus-cli` for inspection (run *after*
issuing at least one cert; entries are §5.2.1 MerkleTreeCertEntry
blobs):

```sh
# After issuance, find the cert's index in the log:
curl http://localhost:14080/1/checkpoint
# (parse the second body line — that's the tree size)

# Show the most recent entry, where N = (tree size - 1).
# The log base URL is the monitoring base + "/<log number>":
./bin/cactus-cli entry http://localhost:14080/1 N

# Verify the issued cert end-to-end:
./bin/cactus-cli cert verify ./certs/example.test.crt http://localhost:14080/1
```

The cert verify path runs the full §7.2 procedure: split the
certificate, decode the MTCProof, recompute the leaf hash from the
TBS (substituting the public key with its hash), evaluate the
inclusion proof, and compare against the live log's subtree hash.
On match it prints `OK`.

---

## Verifying certs with the CLI

```
cactus-cli tree show   <log-url>            # checkpoint origin/size/root
cactus-cli tree verify <log-url>            # walk tiles, recompute root, compare
cactus-cli entry       <log-url> <index>    # fetch + decode one entry
cactus-cli cert verify <cert.pem> <log-url> # full §7.2 verification
cactus-cli prove       <log-url> <index>    # JSON inclusion proof for scripting
```

`tree verify` is the gut check that the on-disk tile bytes really
add up to the signed root: it walks every data tile, replays each
entry through `tlog.StoredHashes`, and compares the computed
`TreeHash` to the signed-note checkpoint. Used by monitors that want
to be sure the log isn't lying about what it has.

`prove` emits a JSON object that's easy to pipe to `jq`:

```sh
./bin/cactus-cli prove http://localhost:14080 1 | jq .
{
  "index": 1,
  "tree_size": 2,
  "root_hex": "...",
  "leaf_hash_hex": "...",
  "inclusion_proof_hex": ["..."]
}
```

---

## Configuration reference

A complete config is in [config-example.json](config-example.json).
The blocks below are the load-bearing ones.

### `log`

```json
"log": {
  "number": 1,
  "shortname": "cactus-test",
  "hash": "sha256",
  "checkpoint_period_ms": 1000,
  "pool_size": 256
}
```

`number` is the issuance log's log number (1–65535, §5.2); the log ID
is derived as `<ca_cosigner.id>.0.<number>` and the issuer DN is the
CA ID. `checkpoint_period_ms` is how often the sequencer flushes pooled
entries and signs a new checkpoint; lower = lower issuance latency, more
signatures per second.

### `ca_cosigner`

```json
"ca_cosigner": {
  "id": "1.3.6.1.4.1.44363.47.1.99",
  "algorithm": "mldsa-44",
  "seed_path": "keys/ca-cosigner.seed"
}
```

`id` is the **CA ID** (§5.1): draft §5.4 requires the CA cosigner's
ID to equal the CA ID, so this one value identifies the CA, seeds the
issuer DN, and roots all derived log / landmark IDs.

`algorithm` **must be `mldsa-44`** (the validator rejects anything else).
The MTC-with-tlog profile requires every MTC cosigner — including the CA
cosigner that signs checkpoints — to use an ML-DSA-44 key and produce
ML-DSA-44 [tlog-cosignature] signed messages, since that is currently the
only algorithm available in both X.509 and C2SP in a subtree-capable
form. ML-DSA-44 is the only cosigner algorithm cactus implements (with
`mldsa-65`/`mldsa-87` available for experiments). It uses Go's built-in
`crypto/mldsa`, so **cactus requires a Go 1.27+ build** (until 1.27
ships, a `gotip` 1.27-devel toolchain works); there are no build tags,
and an older toolchain simply won't compile cactus.

### `acme`

```json
"acme": {
  "listen": ":14000",
  "external_url": "http://localhost:14000",
  "challenge_mode": "auto-pass"
}
```

`challenge_mode` is `auto-pass` (every authorization is instantly
valid; for tests) or `http-01` (real fetch of
`http://identifier/.well-known/acme-challenge/<token>`).

### `landmarks` (tuning only)

```json
"landmarks": {
  "time_between_landmarks_ms": 3600000,
  "max_cert_lifetime_ms": 604800000
}
```

Landmarks are always on; this block only tunes the cadence and the
max cert lifetime (both optional, with the defaults shown). The
§6.3.1 list is always served at `/landmarks`. Landmark trust anchor
IDs are derived from the CA ID and log number (`CA-ID.1.logNumber.L`,
§6.3.1) — there's no separate `base_id`. Defaults: 1-hour landmark
cadence, 7-day max cert lifetime ⇒ `max_active_landmarks =
ceil(168) + 1 = 169` ⇒ ~10 KiB of relying party state per CA. See
§6.3.1 of the draft.

### `ca_cosigner_quorum` (optional, CA-side mirror requests)

```json
"ca_cosigner_quorum": {
  "mirrors": [
    {
      "id": "example.mirror.1",
      "url": "https://mirror-1.example/sign-subtree",
      "algorithm": "mldsa-44",
      "public_key_path": "keys/mirror-1.pub.pem"
    }
  ],
  "min_signatures": 1,
  "request_timeout_ms": 2000,
  "best_effort_after_minimum": true,
  "mirror_retry_deadline_ms": 5000
}
```

When set, every flush fires a parallel sign-subtree request to all
listed mirrors; the issuance waits for at least `min_signatures`
mirror sigs to arrive before `Wait` returns. The retry deadline lets
the requester poll-and-retry while mirrors catch up to the new
checkpoint (mirrors can't sign a subtree until they've verified the
checkpoint that contains it).

Note that a mirror will only answer `sign-subtree` if the reference
checkpoint in the request already carries **that mirror's own
cosignature** (c2sp.org/tlog-witness; otherwise it responds 403). The
only place such a cosignature is produced is the `add-entries` success
response, so `ca_cosigner_quorum` against a real c2sp mirror requires
`mirror_push` to be configured for the same mirror. Against a witness
that does not enforce the rule, `ca_cosigner_quorum` works alone.

### `mirror_push` (optional, c2sp.org/tlog-mirror push client)

```json
"mirror_push": {
  "targets": [
    {
      "id": "example.mirror.1",
      "submission_prefix": "https://mirror-1.example",
      "monitoring_prefix": "https://mirror-1.example/mon",
      "algorithm": "mldsa-44",
      "public_key_path": "keys/mirror-1.pub.pem"
    }
  ],
  "request_timeout_ms": 30000,
  "push_timeout_ms": 300000,
  "disable_gzip": false
}
```

When set, every flush pushes the new checkpoint and any new entries to
each target, in parallel and best effort:

1. `POST <submission_prefix>/add-checkpoint` moves the mirror's pending
   checkpoint to ours, with an RFC 6962 tree consistency proof.
2. `POST <submission_prefix>/add-entries` uploads the entries the mirror
   is missing as 256-aligned packages, each carrying a draft §4.4
   subtree consistency proof. Uploads are capped at 32 packages (8192
   entries) per request and continue via the 202 loop.
3. The `200` response carries the mirror's checkpoint cosignature, which
   is retained and folded into the reference checkpoint that
   `ca_cosigner_quorum` presents to `sign-subtree`.

`monitoring_prefix` is optional and only used to guess a starting index
for a mirror cactus has no state for; the mirror corrects any guess.
Resume state (next entry, pending size, and the mirror's opaque ticket)
is persisted under `<data_dir>/mirrorpush/`.

A `422` from `add-entries` is treated as fatal and is **not** retried:
it means the mirror could not verify a consistency proof against its
pending checkpoint, which is an integrity signal rather than a
transient error.

With no targets configured the subsystem is entirely inert.

---

## Observability

cactus emits structured JSON logs (slog) on stdout. Every line carries
`time`, `level`, `msg`, plus event-specific fields like `request_id`.

Prometheus metrics on `127.0.0.1:14090/metrics`:

| Metric | Labels | Type |
|---|---|---|
| `cactus_acme_orders_total` | `status` | Counter |
| `cactus_log_entries_total` | | Counter |
| `cactus_log_checkpoints_total` | | Counter |
| `cactus_pool_flush_size` | | Histogram |
| `cactus_signature_duration_seconds` | `alg` | Histogram |
| `cactus_ca_mirror_request_total` | `mirror_id`, `result` | Counter |
| `cactus_ca_quorum_failures_total` | | Counter |

Plus stdlib Go runtime metrics (goroutines, GC, etc.) and pprof
under `/debug/pprof` on the same listener.

---

## Layout of the codebase

```
cactus/
├── cmd/
│   ├── cactus/         main server binary
│   ├── cactus-cli/     debugging client (tree show, entry, cert verify, prove)
│   └── cactus-keygen/  cosigner seed generator (-pub / -vkey / -from-vkey)
├── acme/      RFC 8555 ACME server with §9 extensions
├── ca/        Issuer (CSR → X.509 cert via id-alg-mtcProof)
├── cert/      TBSCertificateLogEntry, MTCProof, CosignedMessage,
│              CertificatePropertyList, multi-mirror sign-subtree client
├── mirrorpush/ c2sp.org/tlog-mirror push client (add-checkpoint, add-entries)
├── landmark/  §6.4 landmark sequence allocator + /landmarks handler
├── log/       issuance log (single-writer, signed checkpoints + subtrees)
├── signer/    cosigner abstraction (ML-DSA-44/65/87, Go 1.27+)
├── storage/   on-disk K/V (atomic-rename writes)
├── tile/      read-path HTTP server (tlog-tiles compatible layout)
├── tlogx/     §4 subtree primitives extending x/mod/sumdb/tlog
├── metrics/   Prometheus instruments
├── config/    JSON config loader
├── docs/      threat-model, disk-layout, test-instance
├── docker/    compose stack: cactus + Sunlight as a tlog-mirror
└── integration/ end-to-end tests
```

A reading guide is in [MTC.md](MTC.md) — it suggests an order
through the packages that mirrors how a cert flows from "ACME order"
to "verifiable bytes on disk".

---

## Tests

cactus requires **Go 1.27+** (built-in `crypto/mldsa`). Until 1.27 ships,
use a `gotip` 1.27-devel toolchain; an older `go` won't compile cactus.

```sh
gotip test -race -count=1 ./...
gotip test -fuzz=FuzzParseMTCProof -fuzztime=30s ./cert/...
make integration                                       # `gotip test -race -count=1 -tags=integration ./integration/...`
make stress                                            # bulk issuance stress test (see below)
```

The cornerstone tests:

- `integration.TestParallelIssuance` — 100 certs issued in parallel,
  each independently re-verified end-to-end via §7.2.
- `integration.TestRestartContinuesIssuance` — 50 + restart + 50,
  with the pre-restart certs still verifying against the now-larger
  tree.
- `integration.TestLandmarkRelativeCertConstruction` — landmark-relative
  cert verification *without* consulting any cosigner key, using only
  the public `/landmarks` + tile-served subtree hashes.
- `integration.TestEndToEndCAWithThreeCosigners` — a CA plus three
  stub witnesses, `quorum=2`. Issued cert lands with 1 CA + 2
  cosigner sigs, each independently verifiable.
- `integration.TestMultiCosignerQuorum` — quorum collection against
  three stub witnesses, one deliberately slow, asserting the CA
  returns as soon as the minimum is met.
- `integration.TestCactusBinaryStartsAndServes` — actually runs the
  binary, drives it over HTTP.

### Bulk issuance stress test

`integration.TestBulkIssuanceStress` issues 800 certificates
concurrently through the full ACME flow, verifies each against the log,
and then checks the log is internally consistent. It sits behind the
`stress` build tag so it stays out of the default suite:

```sh
make stress
CACTUS_STRESS_CERTS=5000 CACTUS_STRESS_CONCURRENCY=128 make stress
```

The load is not the point; the post-conditions are. The log is a single
writer with no cross-process locking, so a sequencing bug shows up as a
duplicated or skipped index rather than as an error any one request
would see — the test therefore asserts the assigned indices are exactly
a permutation of `[0, n)`, not merely that every request succeeded and
the tree ended at the right size. It also replays the published entry
tiles through `tlog.StoredHashes` and compares the recomputed root to
the signed checkpoint, which catches a tile written inconsistently under
concurrent flushes (the per-certificate inclusion proofs would not,
since those are served from the same in-memory hashes).

---

## Status

Working draft; APIs may shift to track the upstream IETF and c2sp
specs.

[draft]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-05.txt
[tlog-mirror]: https://github.com/C2SP/C2SP/blob/main/tlog-mirror.md
[tlog-cosignature]: https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md
[tlog-witness]: https://github.com/C2SP/C2SP/blob/main/tlog-witness.md
