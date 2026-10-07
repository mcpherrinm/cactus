# Local cactus + Sunlight stack

A `docker compose` stack that runs cactus as a Merkle Tree Certificate CA
and [Sunlight](https://github.com/FiloSottile/sunlight) as a
[c2sp.org/tlog-mirror](https://c2sp.org/tlog-mirror@v0.1.0) and ML-DSA-44
cosigner for it.

```sh
make docker-up      # build binaries + images, then start
make docker-logs    # follow
make docker-down    # stop and delete volumes (destroys key material)
```

| Service | Port | Role |
| --- | --- | --- |
| `cactus` | 14000 | ACME (RFC 8555 + draft §9 extensions) |
| `cactus` | 14080 | monitoring: checkpoint, tiles, landmarks, CA certificate |
| `cactus` | 14090 | Prometheus metrics |
| `sunlight` | 8080 | mirror write path: `add-checkpoint`, `add-entries`, `sign-subtree` |
| `skylight` | 8081 | mirror read path: mirrored checkpoint and tiles |

## Building the images

Both images build from source inside Docker on `golang:1.27`. cactus
needs 1.27 for the standard library's `crypto/mldsa`; Sunlight v0.10.0
declares `go 1.27.0` too, though it gets ML-DSA from `filippo.io/mldsa`.
The Sunlight image clones a pinned release (`SUNLIGHT_REF`, at least
v0.10.0, the first that runs as a mirror without a CT log of its own).
It needs **cgo**, because its checkpoint lock backend uses
`crawshaw.io/sqlite`; with `CGO_ENABLED=0` only `sunlight-keygen` builds.

## Mirroring is push-based

A tlog-mirror never fetches from the log it mirrors. cactus pushes: it
drives `add-checkpoint` to advance the mirror's pending checkpoint,
uploads entries with `add-entries`, and gets back a mirror cosignature on
the checkpoint. That cosigned checkpoint is then what makes `sign-subtree`
work, because the current spec requires the reference checkpoint to carry
the responding mirror's *own* cosignature.

This is why cactus no longer has a mirror mode of its own: it is the
client of this protocol, not the server.

## Key exchange

The two sides need each other's public keys before either can start, so
startup is three init containers:

1. `cactus-init` — generates the CA cosigner seed and exports the
   issuance log's c2sp **vkey** (`cactus-keygen -vkey -cosigner-id ...`).
   Sunlight will not accept a push for an origin it has no key for.
2. `sunlight-init` — derives Sunlight's witness and mirror keys from a
   single seed, writes the `logs/v0` log list naming cactus's log, and
   pre-creates the SQLite checkpoint lock table. Sunlight deliberately
   refuses to create that table itself, as a guard against pointing a log
   at the wrong backend.
3. `cactus-wire` — converts Sunlight's mirror vkey into the PEM form
   cactus's `ca_cosigner_quorum` config consumes
   (`cactus-keygen -from-vkey`), recomputing the key ID from the name and
   key so a mistyped vkey fails loudly here.

All three are idempotent: re-running leaves existing key material alone,
so `docker compose up` twice will not rotate keys out from under a log
that has already been mirrored. `make docker-down` deletes the volumes
and therefore the keys.

## Two configuration quirks worth knowing

**`submissionprefix` must be an `https` URL.** Sunlight validates the
scheme and exits if it is not https, but it mounts its handlers under the
*host* alone and, with no `acme:` section, serves plain HTTP/h2c. So the
config says `https://sunlight:8080` while cactus actually talks plain
HTTP to the same host and port. The host must stay in sync with the
compose service name.

**Sunlight routes by `Host`.** Requests must carry a `Host` header
matching `submissionprefix`, which inside the compose network is the
service name. Reaching Sunlight from the host via the published port
requires setting `Host: sunlight:8080` explicitly.

## Poking at it

```sh
# cactus's own checkpoint
curl -s localhost:14080/1/checkpoint

# the CA certificate a relying party configures from (§7.1)
curl -s localhost:14080/ca-certificate

# the mirrored checkpoint, from skylight. <originhash> is the lowercase
# hex SHA-256 of the log origin line.
origin='oid/1.3.6.1.4.1.44363.47.1.99.0.1'
originhash=$(printf '%s' "$origin" | sha256sum | cut -d' ' -f1)
curl -s -H "Host: skylight:8081" \
    "localhost:8081/mirror/$originhash/checkpoint"
```
