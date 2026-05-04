# cactus

A Go ACME server that issues **Merkle Tree certificates** per
[draft-ietf-plants-merkle-tree-certs-03][draft], intended for
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
4. [Operating modes](#operating-modes)
5. [Issuing your first cert](#issuing-your-first-cert)
6. [Verifying certs with the CLI](#verifying-certs-with-the-cli)
7. [Configuration reference](#configuration-reference)
8. [Observability](#observability)
9. [Layout of the codebase](#layout-of-the-codebase)
10. [Tests](#tests)
11. [Status](#status)

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
- Issues **landmark-relative certificates** (§6.3) alongside the
  standalone ones. Allocates landmarks per §6.3.2, serves a
  `/landmarks` endpoint per §6.3.1, and switches the §9 alternate URL
  from a `503` stub to a real signature-less cert once a covering
  landmark exists.
- Acts as a **CA cosigner** using ECDSA-P256 (or ML-DSA-44/65 if built
  with `-tags mldsa`).
- Optionally **runs as a cosigning mirror** for an external upstream
  log ([tlog-mirror], [tlog-cosignature]). In mirror mode cactus
  follows an upstream via tlog-tiles, verifies consistency, and
  exposes a `/sign-subtree` endpoint that signs §5.4.1 inputs with
  its own cosigner key.
- In CA mode, **collects cosignatures from a configured set of
  external mirrors** in parallel, with quorum + per-mirror timeout +
  best-effort-after-minimum semantics.

## What it does not do

- **Witness-only cosigners** (§7.3). Mirror cosigners are in scope;
  pure witnesses are a future addition.
- **Log pruning** (§5.6.1).
- **Real DNS-01 challenges.** `auto-pass` and `http-01` are
  supported; DNS-01 is not.
- **Revocation by index** (§7.5) beyond a stub list in config.

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for the full design and
[TODO.md](TODO.md) for an iteration log.

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
- `:14080` — monitoring read-path (`/checkpoint`, tiles, entries)
- `127.0.0.1:14090` — Prometheus metrics + pprof

Once it's up:

```sh
curl http://localhost:14000/directory   # ACME directory
curl http://localhost:14080/checkpoint  # current signed-note checkpoint
curl http://localhost:14090/metrics     # Prometheus metrics
```

Stop it with `Ctrl-C` (SIGINT) or `kill -TERM` — graceful shutdown
drains the pool, writes a final checkpoint, and closes listeners.

---

## Operating modes

The same binary can run in any combination of three concerns,
determined by which top-level config blocks are populated and
`enabled`:

| Concern | Adds | Set |
|---|---|---|
| **CA** (default) | Issuance log + ACME server | `acme`, `log`, `ca_cosigner` |
| **Landmarks** | Landmark-relative cert support | `landmarks.enabled = true` |
| **CA-side mirror collection** | Multi-mirror cosignatures during issuance | `ca_cosigner_quorum.mirrors[]` |
| **Mirror operating mode** | Follow an upstream + serve `/sign-subtree` | `mirror.enabled = true` (and `mirror.upstream`) |

Cactus operating modes are not enumerated; the binary just brings up
whichever subsystems the config asks for. The validator does enforce
some hygiene rules — chiefly, mirror + CA modes in the same binary
must use distinct cosigner keys.

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
issuing at least one cert; index 0 is the §5.3 null entry):

```sh
# After issuance, find the cert's index in the log:
curl http://localhost:14080/checkpoint
# (parse the second body line — that's the tree size)

# Show the most recent entry, where N = (tree size - 1):
./bin/cactus-cli entry http://localhost:14080 N

# Verify the issued cert end-to-end:
./bin/cactus-cli cert verify ./certs/example.test.crt http://localhost:14080
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
  "id": "1.3.6.1.4.1.44363.47.1.99",
  "shortname": "cactus-test",
  "hash": "sha256",
  "checkpoint_period_ms": 1000,
  "pool_size": 256
}
```

`id` is the log's trust anchor ID — the OID-shaped name in the §5.2
issuer DN. `checkpoint_period_ms` is how often the sequencer flushes
pooled entries and signs a new checkpoint; lower = lower issuance
latency, more signatures per second.

### `ca_cosigner`

```json
"ca_cosigner": {
  "id": "1.3.6.1.4.1.44363.47.1.99.ca",
  "algorithm": "ecdsa-p256-sha256",
  "seed_path": "keys/ca-cosigner.seed"
}
```

Use `ecdsa-p256-sha256` in default builds; `mldsa-44` and `mldsa-65`
are available with `-tags mldsa`.

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

### `landmarks` (optional)

```json
"landmarks": {
  "enabled": true,
  "base_id": "1.3.6.1.4.1.44363.47.1.99.lm",
  "time_between_landmarks_ms": 3600000,
  "max_cert_lifetime_ms": 604800000,
  "landmark_url_path": "/landmarks"
}
```

Defaults: 1-hour landmark cadence, 7-day max cert lifetime ⇒
`max_active_landmarks = ceil(168) + 1 = 169` ⇒ ~10 KiB of relying
party state per CA. See §6.3.1 of the draft.

### `mirror` (optional, mirror mode)

```json
"mirror": {
  "enabled": true,
  "cosigner_id": "1.3.6.1.4.1.44363.47.2.1.mirror",
  "seed_path": "keys/mirror-cosigner.seed",
  "algorithm": "ecdsa-p256-sha256",
  "upstream": {
    "tile_url": "https://upstream.example/log",
    "log_id": "1.3.6.1.4.1.44363.47.1.99",
    "ca_cosigner_id": "1.3.6.1.4.1.44363.47.1.99.ca",
    "ca_cosigner_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "poll_interval_ms": 1000
  },
  "sign_subtree_listen": ":14081",
  "sign_subtree_path": "/sign-subtree",
  "require_ca_signature_on_subtree": true
}
```

The mirror's cosigner ID + seed must differ from the CA's (the
validator rejects shared keys). `require_ca_signature_on_subtree`
is the [tlog-cosignature] DoS gate — keep it on if the
`/sign-subtree` listener is publicly reachable.

### `ca_cosigner_quorum` (optional, CA-side mirror requests)

```json
"ca_cosigner_quorum": {
  "mirrors": [
    {
      "id": "example.mirror.1",
      "url": "https://mirror-1.example/sign-subtree",
      "algorithm": "ecdsa-p256-sha256",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
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
| `cactus_mirror_upstream_checkpoint_size` | | Gauge |
| `cactus_mirror_consistency_failures_total` | | Counter |
| `cactus_mirror_signsubtree_requests_total` | `result` | Counter |
| `cactus_mirror_signsubtree_duration_seconds` | | Histogram |
| `cactus_ca_mirror_request_total` | `mirror_id`, `result` | Counter |
| `cactus_ca_quorum_failures_total` | | Counter |

Plus stdlib Go runtime metrics (goroutines, GC, etc.) and pprof
under `/debug/pprof` on the same listener.

---

## Layout of the codebase

```
cactus/
├── cmd/
│   ├── cactus/         main server binary (CA / mirror / both)
│   ├── cactus-cli/     debugging client (tree show, entry, cert verify, prove)
│   └── cactus-keygen/  fresh seed generator
├── acme/      RFC 8555 ACME server with §9 extensions
├── ca/        Issuer (CSR → X.509 cert via id-alg-mtcProof)
├── cert/      TBSCertificateLogEntry, MTCProof, MTCSubtreeSignatureInput,
│              CertificatePropertyList, multi-mirror request client
├── landmark/  §6.3 landmark sequence allocator + /landmarks handler
├── log/       issuance log (single-writer, signed checkpoints + subtrees)
├── mirror/    follower + sign-subtree HTTP server
├── signer/    cosigner abstraction (ECDSA + optional ML-DSA via -tags mldsa)
├── storage/   on-disk K/V (atomic-rename writes)
├── tile/      read-path HTTP server (tlog-tiles compatible layout)
├── tlogx/     §4 subtree primitives extending x/mod/sumdb/tlog
├── metrics/   Prometheus instruments
├── config/    JSON config loader
├── docs/      threat-model, disk-layout
└── integration/ end-to-end tests
```

A reading guide is in [MTC.md](MTC.md) — it suggests an order
through the packages that mirrors how a cert flows from "ACME order"
to "verifiable bytes on disk".

---

## Tests

```sh
go test -race -count=1 ./...                          # default build
go test -tags mldsa -count=1 ./...                    # also ML-DSA cosigner
go test -fuzz=FuzzParseMTCProof -fuzztime=30s ./cert/...
go test -fuzz=FuzzParseSignSubtreeRequest -fuzztime=30s ./mirror/...
make integration                                       # `go test -race -count=1 -tags=integration ./integration/...`
```

The cornerstone tests:

- `integration.TestParallelIssuance` — 100 certs issued in parallel,
  each independently re-verified end-to-end via §7.2.
- `integration.TestRestartContinuesIssuance` — 50 + restart + 50,
  with the pre-restart certs still verifying against the now-larger
  tree.
- `integration.TestRelyingPartyFastPath` — landmark-relative cert
  verification *without* consulting any cosigner key, using only
  the public `/landmarks` + tile-served subtree hashes.
- `integration.TestEndToEndCAWithThreeMirrors` — a CA, three
  mirror followers + servers, `quorum=2`. Issued cert lands with
  1 CA + 2 mirror sigs, each independently verifiable.
- `integration.TestMirrorRestartResume` — mirror restart picks up
  where it left off without re-fetching everything.
- `integration.TestCactusBinaryStartsAndServes` and
  `integration.TestCactusBinaryMirrorMode` — actually run the
  binary, drive it over HTTP.

---

## Status

§9 Definition of Done v1 + v2 + v3 all met (see [PROJECT_PLAN.md][plan]
and [TODO.md][todo]). Working draft; APIs may shift to track the
upstream IETF and c2sp specs.

[draft]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-03.txt
[tlog-mirror]: https://github.com/C2SP/C2SP/blob/main/tlog-mirror.md
[tlog-cosignature]: https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md
[plan]: PROJECT_PLAN.md
[todo]: TODO.md
