# Running a standalone test instance (CA + one witness cosigner)

This describes a single-process cactus deployment that issues
certificates carrying **the CA cosignature plus one witness
cosignature**, so an ACME client can request standalone and
landmark-relative certificates and you can verify them against the log.

A single cactus process is always a full CA (issuance log + ACME server
+ CA cosigner). The `mirror` block adds **one** witness/mirror cosigner
in the same process, and `ca_cosigner_quorum` makes the CA collect that
witness's cosignature — over loopback — for every subtree it signs. With
`min_signatures: 1`, each issued standalone certificate ends up with two
cosignatures: the CA's and the witness's.

> **This is not real transparency.** A witness operated by the CA on the
> same host proves nothing a relying party should trust — independence is
> the whole point of a witness. This setup exists to exercise the
> cosignature wire formats and the relying-party verification paths on a
> public *test* instance. See [threat-model.md](threat-model.md).

The sample config is [`config-witness-example.json`](../config-witness-example.json).

## How the pieces wire together

```
                ┌──────────────────────── one cactus process ───────────────────────┐
   ACME client ─┼─▶ :14000  ACME  ──▶ issuance log ──▶ CA cosigner (id 44363.47.1.99)│
                │                              │  signs each subtree                  │
                │   :14080  monitoring (tiles, checkpoint, /landmarks)                │
                │      ▲                       │  CA quorum requester                 │
                │      │ follows               ▼  POST /sign-subtree                  │
                │   witness follower ──▶ :14081 witness cosigner (id 44363.47.2.1)    │
                └─────────────────────────────────────────────────────────────────────┘
```

- The witness **follows** the CA's own log over loopback
  (`mirror.upstream.tile_url` = `http://127.0.0.1:14080/1`) and verifies
  the CA's checkpoint cosignatures.
- On each checkpoint the CA's quorum requester sends a `sign-subtree`
  request — including its own CA cosignature — to the witness over
  loopback (`ca_cosigner_quorum.mirrors[0].url` =
  `http://127.0.0.1:14081/sign-subtree`). `require_ca_signature_on_subtree`
  can stay `true`: the CA supplies that cosignature.
- All identifiers use the **relative** trust-anchor-ID form (the arcs
  below the `1.3.6.1.4.1` enterprise base). The log ID is the CA ID with
  `.0.<log number>` appended, e.g. `44363.47.1.99.0.1`.

## Setup

```sh
# 0. Build (cactus needs Go 1.27 / gotip; see README).
make build                      # ./bin/cactus, cactus-cli, cactus-keygen

# 1. Pick a data dir and create the keys dir.
export DATA_DIR=/tmp/cactus-data
mkdir -p "$DATA_DIR/keys"

# 2. Generate two distinct cosigner seeds — one for the CA, one for the
#    witness. They MUST differ (the config validator enforces this).
./bin/cactus-keygen -o "$DATA_DIR/keys/ca-cosigner.seed"
./bin/cactus-keygen -o "$DATA_DIR/keys/witness-cosigner.seed"

# 3. Start from the sample config and point it at $DATA_DIR.
cp config-witness-example.json config.json
sed -i "s|/tmp/cactus-data|$DATA_DIR|" config.json

# 4. Fill in the two public keys. `-pub` prints the PEM block whose body
#    is the raw public key — exactly what the config fields take.
#    - ca_cosigner.seed  -> mirror.upstream.ca_cosigner_key_pem
#    - witness seed       -> ca_cosigner_quorum.mirrors[0].public_key_pem
./bin/cactus-keygen -pub -o "$DATA_DIR/keys/ca-cosigner.seed"
./bin/cactus-keygen -pub -o "$DATA_DIR/keys/witness-cosigner.seed"
# Paste each PEM into the matching field of config.json (a JSON string,
# newlines escaped as \n, ending in \n).

# 5. Run.
./bin/cactus -config config.json
```

On startup the witness follower briefly logs one `connection refused`
while the monitoring listener finishes binding, then catches up; that is
harmless. `curl http://localhost:14090/metrics | grep cactus_mirror`
shows `cactus_mirror_consistency_failures_total 0` once it is healthy.

### Public exposure

`acme.listen`/`monitoring.listen` are the public surfaces; set their
`external_url` to whatever clients reach (cactus speaks plaintext HTTP,
so terminate TLS at a reverse proxy if you need HTTPS, and set
`external_url` to the public `https://…`). Keep `metrics.listen` and
`mirror.sign_subtree_listen` on `127.0.0.1` — they are internal. The
loopback URLs inside the `mirror`/`ca_cosigner_quorum` blocks must stay
`127.0.0.1` regardless of the public `external_url`.

`challenge_mode: auto-pass` makes every authorization instantly valid, so
anyone who can reach the ACME port gets a cert for any name — fine for a
test instance, but switch to `http-01` if that matters.

## Issuing certificates

Use any RFC 8555 client against `<acme external_url>/directory`, e.g.:

```sh
lego --server http://localhost:14000/directory \
     --email you@example.com --domains example.test \
     --accept-tos --pem --path ./certs run
```

The order's `certificate` URL is the **standalone** cert (CA + witness
cosignatures). The `Link: …; rel="alternate"` header on the finalize and
certificate responses points at the **landmark-relative** variant
(`/cert/{id}/alternate`), which is signature-free and verifies against
predistributed landmark subtree hashes. Both cert URLs are POST-as-GET
resources (RFC 8555 §6.3), so an ACME client — not a plain `curl` —
retrieves them; the alternate returns `503 + Retry-After` until a
covering landmark exists. With `time_between_landmarks_ms: 60000` a
covering landmark appears within ~a minute of issuance; lower it for
snappier testing (at the cost of more active landmarks).

## Verifying against the log

`cactus-cli` talks to the monitoring base plus the log number — here
`http://localhost:14080/1`:

```sh
# Current signed checkpoint (origin / size / root).
curl http://localhost:14080/1/checkpoint
./bin/cactus-cli tree show   http://localhost:14080/1

# Walk every tile, recompute the root, compare to the signed checkpoint.
./bin/cactus-cli tree verify http://localhost:14080/1

# Inspect one entry (N = tree size - 1 for the most recent).
./bin/cactus-cli entry       http://localhost:14080/1 N

# Full §7.2 verification of an issued cert against the live log: splits
# the cert, decodes the MTCProof, recomputes the leaf hash, evaluates the
# inclusion proof, and compares to the log's subtree hash. Prints OK.
# Works for both the standalone and the landmark-relative certificate
# (the inclusion-proof check is independent of the cosignatures).
./bin/cactus-cli cert verify ./certs/example.test.crt http://localhost:14080/1

# Machine-readable inclusion proof for scripting.
./bin/cactus-cli prove http://localhost:14080/1 N | jq .
```

The standalone certificate's `MTCProof` carries two cosignatures (the CA
and the witness, sorted by cosigner ID); the landmark-relative one
carries none. `cactus-cli cert verify` confirms either is correctly
logged; trusting the *witness* cosignature specifically is a
relying-party policy decision and requires the witness public key
(`cactus-keygen -pub -o keys/witness-cosigner.seed`).
