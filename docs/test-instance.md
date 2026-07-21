# Running a standalone test instance

This describes a single-process cactus deployment that issues
certificates carrying the CA cosignature, so an ACME client can request
standalone and landmark-relative certificates and you can verify them
against the log.

A single cactus process is always a full CA (issuance log + ACME server
+ CA cosigner). cactus does not act as a mirror or witness itself; to
have issued certs carry additional cosignatures, point
`ca_cosigner_quorum.mirrors[]` at one or more **external** mirrors and
set `min_signatures` accordingly. Everything below works with or without
that block.

**If what you want is a working mirror, use the compose stack instead.**
[`docker/`](../docker/README.md) runs cactus against
[Sunlight](https://github.com/FiloSottile/sunlight) as a real
c2sp.org/tlog-mirror and ML-DSA-44 cosigner, and handles the key
exchange between the two:

```sh
make docker-up      # cactus :14000 ACME, :14080 monitoring
make docker-logs
make docker-down    # deletes volumes, and therefore key material
```

Certificates issued against that stack carry Sunlight's mirror
cosignature alongside the CA's. Standing the same thing up by hand means
replicating the log yourself (`mirror_push`), which the rest of this
document does not cover — read `docker/README.md` for what the wiring
actually has to get right.

> **This is not real transparency.** See
> [threat-model.md](threat-model.md).

The sample config is [`config-example.json`](../config-example.json).

All identifiers use the **relative** trust-anchor-ID form (the arcs
below the `1.3.6.1.4.1` enterprise base). The log ID is the CA ID with
`.0.<log number>` appended, e.g. `44363.47.1.99.0.1`.

## Setup

```sh
# 0. Build (cactus needs Go 1.27 / gotip; see README).
make build                      # ./bin/cactus, cactus-cli, cactus-keygen

# 1. Pick a data dir and create the keys dir.
export DATA_DIR=/tmp/cactus-data
mkdir -p "$DATA_DIR/keys"

# 2. Generate the CA cosigner seed.
./bin/cactus-keygen -o "$DATA_DIR/keys/ca-cosigner.seed"

# 3. Start from the sample config and point it at $DATA_DIR.
cp config-example.json config.json
sed -i "s|/tmp/cactus-data|$DATA_DIR|" config.json

# 4. Export the CA public key. `-pub` prints the PEM block whose body is
#    the raw public key. Peers verifying the log's checkpoints need it.
./bin/cactus-keygen -pub -o "$DATA_DIR/keys/ca-cosigner.seed" > "$DATA_DIR/keys/ca-cosigner.pub.pem"

# 5. Run.
./bin/cactus -config config.json
```

### Public exposure

`acme.listen`/`monitoring.listen` are the public surfaces; set their
`external_url` to whatever clients reach (cactus speaks plaintext HTTP,
so terminate TLS at a reverse proxy if you need HTTPS, and set
`external_url` to the public `https://…`). Keep `metrics.listen` on
`127.0.0.1` — it is internal.

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

The order's `certificate` URL is the **standalone** cert. It is a
POST-as-GET resource (RFC 8555 §6.3), so an ACME
client — not a plain `curl` — retrieves it. Its response carries a
`Link: …; rel="acme-optional-alternate"` header pointing at the signature-free
**landmark-relative** variant (which verifies against predistributed
landmark subtree hashes). That URL is pinned to the landmark the cert is
relative to and returns `HTTP 202 (Accepted)` + `Retry-After` until that
landmark is allocated (within ~`time_between_landmarks_ms`), then the
cert. The optional alternate is exactly that — optional and
non-blocking: per draft §9.1 a client SHOULD NOT fail the transaction if
it is unavailable, and must never let a 202 hold up deploying the
standalone cert. The same landmark-relative
cert is also derivable from the log with `cactus-cli cert
landmark-relative` (see below).

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

The standalone certificate's `MTCProof` carries the CA cosignature, plus
one per external mirror configured in `ca_cosigner_quorum` (sorted by
cosigner ID); the landmark-relative one carries none. `cactus-cli cert
verify` confirms either is correctly logged; trusting any *mirror*
cosignature specifically is a relying-party policy decision and requires
that mirror's public key.
