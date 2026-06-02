# Cactus literature review

**Date:** 2026-06-02. **Scope:** every specification cactus depends on,
as catalogued in `specs/README.md` — the Merkle Tree Certificate draft
and its tiled-log profile, the C2SP transparency-log specs, the X.509 /
PKIX stack, the NIST algorithm standards, and the ACME / TLS / HTTP
layer.

This document maps each specification to the cactus code that
implements it and records the conformance state: what cactus honors,
the deliberate choices it makes, and the parts of the draft it does not
implement. Section numbers reference
draft-ietf-plants-merkle-tree-certs-04 unless otherwise noted. Cactus is
ML-DSA-44-only (no ECDSA cosigning), builds on Go 1.27's `crypto/mldsa`,
and targets the draft plus the MTC-with-tlog profile
(`specs/mtc-tlog-draft.md`).

## Per-spec relevance

### Merkle Tree Certificates

| Spec | Relevance | What cactus honors |
|---|---|---|
| **draft-…-merkle-tree-certs-04** | Defines everything | §4 subtree math, §5 log entries/cosigners, §6 cert + landmark assembly, §7.2 verification, §9 ACME extensions, Appendix A ASN.1 |
| **mtc-tlog-draft.md** (profile) | High | CA-prefix-URL serving, `/<log number>/` tlog-tiles layout, checkpoint origin = log ID as `oid/1.3.6.1.4.1.…`, cosigner-name derivation, `/landmarks` URL, ML-DSA-44-only cosigning |
| **RFC 9162** (CT v2) | High | §2.1.1 leaf/interior hash prefixes (`0x00`/`0x01`) and the proof algorithms §4 specialises |

### C2SP transparency-log specs

| Spec | Relevance | What cactus honors |
|---|---|---|
| **signed-note** | High | Signature-line format `base64(keyID ‖ signature)`; key-ID `SHA-256(name ‖ 0x0A ‖ sigType ‖ pubkey)[:4]` |
| **tlog-checkpoint** | High | `/checkpoint` body: origin / size / base64 root |
| **tlog-cosignature** | High | ML-DSA-44 `cosigned_message` (12-byte `subtree/v1\n\0` label); note-line `timestamped_signature` wrapper |
| **tlog-tiles** | High | Tile path layout, `.p/<W>` partials, uint16-length-prefixed entry bundles, checkpoint endpoint |
| **tlog-witness** (PR #245) | High | `POST /sign-subtree` request/response framing + the CA-signature DoS gate |
| **tlog-mirror** | Medium | Follower consistency semantics (cactus uses a polling tile-follower, not the push API) |
| **tlog-proof** | Low | Offline inclusion-proof format; cactus ships the equivalent inside the X.509 MTCProof instead |

### X.509 / PKIX

| Spec | Relevance | What cactus honors |
|---|---|---|
| **RFC 5280** (PKIX) | High | §4.1.2.2 serial positivity/length, §4.1.2.5 UTCTime<2050 cutoff, §4.1.2.7 SPKI, §4.2 extension criticality |
| **RFC 9881** (ML-DSA in PKIX) | High | `id-ml-dsa-44` OID, absent parameters, raw FIPS 204 key in the SPKI BIT STRING, pure-mode signatures |
| **RFC 9925** (Unsigned X.509) | High | `id-alg-unsigned` + zero-length `signatureValue` on the CA certificate |
| **X.690** (DER) | High | Definite/minimal lengths, BIT STRING unused-bits octet, SET-OF ordering |
| **RFC 5912** (PKIX ASN.1) | Low | Reference for `AlgorithmIdentifier` / `Extensions` / `Validity` types; no code maps to it directly |
| **RFC 6960** (OCSP) | Trivial | Cited only for the domain-separation argument (cosignature label ≠ `ResponseData` SEQUENCE); cactus does not implement OCSP |

### Cryptographic algorithms

| Spec | Relevance | What cactus honors |
|---|---|---|
| **FIPS 204** (ML-DSA) | High | Pure-mode ML-DSA-44 with empty context; 32-byte key-gen seed |
| **FIPS 180-4** (SHA-2) | High | SHA-256 for tree hashing, SPKI/key-ID hashing, HKDF PRF |
| **RFC 8032** (Ed25519) | Low | Only as an accepted ACME *account-key* JWS algorithm via go-jose |
| **FIPS 186-5** (DSS) | Background | ECDSA is not used for cactus's own signing; relevant only to ECDSA ACME account keys |

### ACME, TLS, and HTTP

| Spec | Relevance | What cactus honors |
|---|---|---|
| **RFC 8555** (ACME) | High | §6 JWS/nonce/url/Content-Type, §7 resource state machine, §7.4 finalize/badCSR, plus the MTC §9 download extensions |
| **draft-…-tls-trust-anchor-ids-03** | Medium | §3 TrustAnchorID binary rep, §4.1 `opaque<1..2^8-1>` cap, §6 property-list encoding, §6.1 PEM layout |
| **RFC 9110** (HTTP) | Medium | Retry-After, 503, Accept negotiation |
| **RFC 4648** (base64) | High | base64url (no pad) for ACME JWS; standard base64 for C2SP note bodies |
| **RFC 7807** (Problem Details) | Medium | ACME error documents (`application/problem+json`) |
| **RFC 7638** (JWK Thumbprint) | Medium | Account identity + key authorization |
| **RFC 3339** (timestamps) | Low | ACME `expires` / `notBefore` / `notAfter` |
| **RFC 1035** (DNS names) | Low | `dns` identifier validation |
| **RFC 8446** (TLS 1.3) | Low | §3 presentation language MTC wire formats inherit |
| **RFC 3629** (UTF-8) | Trivial | UTF8String DN attribute value |
| **RFC 2119 / RFC 8174** | Trivial | Requirement-keyword boilerplate |

## Conformance state

### Merkle tree, entries, and verification

- **Subtree math (MTC §4)** — `tlogx/subtree.go`, `inclusion.go`, and
  `consistency.go` implement §4.1 validity, §4.3.2 inclusion-proof
  evaluation, §4.4 consistency proofs (generation and verification), and
  §4.5 `FindSubtrees`, over the RFC 9162 §2.1.1 `0x00`/`0x01` hash
  prefixes.
- **Entry hashing and §7.2 verification** — `cert/entry.go` builds the
  TBSCertificateLogEntry and the single-pass leaf hash; `cert/rpverify.go`
  performs §7.2 steps 1–12, including the landmark trusted-subtree fast
  path and the revoked-range check.

### Cosignatures and the transparency-log wire formats

- **`cosigned_message`** (`cert/proof.go`) matches tlog-cosignature: the
  12-byte `subtree/v1\n\0` label, cosigner_name, `timestamp = 0`,
  log_origin, start, end, and hash.
- **Key-ID derivation** (`cert/keyid.go`) is
  `SHA-256(name ‖ 0x0A ‖ 0x06 ‖ pubkey)[:4]` for ML-DSA-44, with the
  signed-note `0xff` escape for the experimental -65/-87 cosigners. The
  public-key length is validated against the FIPS 204 size for the
  algorithm.
- **Note-line signature values** are `keyID ‖ timestamped_signature`,
  where `timestamped_signature` is `u64 timestamp ‖ signature` with a
  zero timestamp for MTC subtree cosignatures (tlog-cosignature). This
  applies to the checkpoint signature line (`log/note.go`), the
  sign-subtree response (`mirror/server.go`), and the CA DoS-gate line in
  a sign-subtree request (`cert/cosigner_request.go`); the matching
  parsers strip the timestamp. The MTCProof signature carried in the
  X.509 certificate is a bare PKIX signature over the `CosignedMessage`
  (§6.1), with no note-line wrapper.
- **Checkpoint body** (`log/note.go`) is origin / size / base64 root, and
  **tile and entry-bundle framing** (`log/tilewriter`, `tile/server.go`)
  uses the tlog-tiles path layout, `.p/<W>` partials, and uint16
  length-prefixed entry bundles.
- **`POST /sign-subtree`** (`mirror/server.go`) implements the
  tlog-witness request/response framing — `subtree <start> <end>`, base64
  hash, 0–8 cosignature lines, 0–63 consistency-proof lines, blank line,
  reference checkpoint — and the DoS gate requiring a valid CA subtree
  cosignature. The mirror follower (`mirror/follower.go`) polls an
  upstream over tlog-tiles and verifies append-only progress.

### MTC-with-tlog profile

- Checkpoint origins and cosigner names are
  `oid/1.3.6.1.4.1.<relative-OID>` (`cert/proof.go`, `cert/trustanchorid.go`);
  the issuance-log ID is `caID.0.logNumber` (`cert/caid.go`); each log is
  served under the CA prefix at `/<log number>/…` with `/landmarks` at
  `/<log number>/landmarks` (`tile/server.go`, `cmd/cactus/main.go`); and
  cosigning is ML-DSA-44 only.

### X.509 / PKIX

- **RFC 5280** — serial number is `(logNumber<<48)|index`, always
  positive, non-zero, and minimally encoded (`cert/caid.go`, `ca/issuer.go`);
  validity uses UTCTime below the year 2050 and GeneralizedTime at or
  above it; basicConstraints, keyUsage, and id-pe-mtcCertificationAuthority
  are marked critical.
- **RFC 9881** — the `id-ml-dsa-44` OID is emitted with absent parameters
  and the raw FIPS 204 key in the SPKI BIT STRING (`cert/rpverify.go`);
  the SPKI parser requires the AlgorithmIdentifier OID to equal the
  configured sig-alg and rejects present parameters.
- **RFC 9925** — the CA certificate uses `id-alg-unsigned` with a
  zero-length `signatureValue` (`cert/cacert.go`).
- **X.690** — hand-rolled DER uses definite, minimal lengths and a
  correct BIT STRING unused-bits octet.

### Cryptography

- ML-DSA-44 signing and verification use pure mode with an empty context
  (FIPS 204 / RFC 9881); keys derive deterministically from a 32-byte
  seed via HKDF-SHA256 with a per-algorithm info string
  (`signer/mldsa.go`). SHA-256 is used consistently for tree hashing and
  for SPKI/key-ID hashing.

### Trust Anchor IDs and TLS-presentation encoding

- The TrustAnchorID binary representation is the RELATIVE-OID content
  octets (`cert/trustanchorid.go`; e.g. `32473.1 → 81 fd 59 01`), used on
  the wire fields that require it, while the relative dotted-decimal ASCII
  form backs the `oid/…` names and the DN attribute value.
- The CertificatePropertyList is sorted by type, rejects duplicates, and
  frames each value as `opaque<0..2^16-1>` (`cert/properties.go`). The
  `application/pem-certificate-chain-with-properties` body places the
  `CERTIFICATE PROPERTIES` block first and the certificate second, per
  trust-anchor-ids §6.1.

### ACME

- **§6 JWS** (`acme/handler.go`, `acme/jose.go`) — the protected `url` is
  checked against the request URL; nonces are single-use with `badNonce`
  on failure; the `alg` allow-list (RS256/ES256/384/512/EdDSA, no `none`
  or MAC algorithms) drives `badSignatureAlgorithm` with the `algorithms`
  field; a non-`application/jose+json` body is rejected with 415; and
  jwk/kid are mutually exclusive.
- **§6.3 POST-as-GET** — certificate download requires a signed JWS with
  an empty payload, checks account ownership (returning 401
  `unauthorized` on mismatch), and issues a fresh `Replay-Nonce`.
- **§6.5.1** — the `Replay-Nonce` is the base64url encoding of random
  octets (`acme/state.go`).
- **§7.1.2 account resource** — `POST /account/{id}` serves the account
  object (POST-as-GET) with the required `orders` member, and
  `POST /account/{id}/orders` serves the orders list.
- **§7.4 finalize** — atomic ready→processing claim with `orderNotReady`
  for the race loser, `badCSR` mapping for CSR errors, and rejection of a
  malformed `notBefore`/`notAfter` (RFC 3339) with `malformed`. The order
  moves to `valid` once its entry is sequenced (MTC §9).
- **§9 download extensions** — the `CertificatePropertyList` carries the
  `trust_anchor_id`, the alternate URL returns 503 + Retry-After until a
  covering landmark exists and the landmark-relative certificate
  thereafter, and the error documents follow RFC 7807. Account-key
  thumbprints and key authorizations use the RFC 7638 SHA-256 thumbprint.

## Deliberate choices and known gaps

- **Experimental placeholder OIDs** — `id-alg-mtcProof`,
  `id-rdna-trustAnchorID`, and `id-pe-mtcCertificationAuthority` use the
  `1.3.6.1.4.1.44363.47.*` private arc pending IANA assignment, matching
  the draft's experimental status (`cert/oid.go`).
- **ASCII TrustAnchorID in the DN UTF8String** — the "for initial
  experimentation" form (`cert/dn.go`, `cert/oid.go`); the binary
  RELATIVE-OID representation is used on the wire fields that require it.
- **Pull-mode mirror** — `mirror/follower.go` polls an upstream over
  tlog-tiles and verifies append-only progress by root recomputation; it
  does not implement the tlog-mirror push API
  (`add-checkpoint`/`add-entries`).
- **Challenge modes** — `auto-pass` is a test-only mode; `http-01` is
  real; DNS-01 is not implemented.
- **FIPS 186-5** — ECDSA is not used for cactus's own signing, so 186-5
  is relevant only to ECDSA ACME account keys handled by go-jose.
- **Log pruning** (MTC §5.2.3 / the profile's pruning rules) is not
  implemented.
- **Revocation by serial range** (§7.5) carries the data model but only a
  stub list.
- **Account update / deactivation** (RFC 8555 §7.3.2/§7.3.6) is not
  implemented; the account resource is read-only beyond creation.
- **DN SET-OF ordering** (`cert/dn.go`) is correct by single-element
  construction; canonical SET ordering would be needed only if a second
  RDN attribute were added.

## Implementation status by MTC section

**Fully implemented:** §4.1–§4.5 subtrees (validity, inclusion +
consistency proof generation/verification, FindSubtrees) · §5.1 CA / log
parameters · §5.2 log IDs + entries (null + tbs_cert_entry, ASN.1 module,
single-pass hash) · §5.3/§5.3.1 cosigner signature format · §5.5 CA
cosigner + CA-certificate extension · §6.1 certificate format / MTCProof
/ serial · §6.2 standalone certs · §6.3.1–§6.3.3 landmark sizes,
allocation, publishing, and landmark-relative cert construction ·
§7.1/§7.2/§7.4/§7.5 relying-party verification (config from CA cert,
verify steps 1–12, trusted subtrees, revoked-range data model) · §9 ACME
extensions · Appendix A ASN.1 module (experimental-OID form). The
MTC-with-tlog profile's serving layout, identity mapping, and
ML-DSA-44-only requirement are honored.

**Partial / not implemented:** §5.2.3 log pruning (none) · §7.3 trusted
cosigner policy (single CA cosigner + N mirrors; no quorum-of-roles
engine) · §7.5 revocation (stub list) · ACME account update /
deactivation (not implemented).

**Out of scope:** §8 use in TLS — the TLS stack lives elsewhere.

## Files reviewed

**Specs:** all of `specs/` (the groups in `specs/README.md`).

**Code (non-test):**

- `acme/{handler,jose,keyauth,persist,readdir,state,types}.go`
- `ca/{issuer,validator}.go`
- `cert/{cacert,caid,cosigner_request,dn,entry,keyid,landmark,oid,proof,properties,rpverify,sigverify,trustanchorid,verify}.go`
- `cmd/cactus/main.go`, `cmd/cactus-cli/{main,treeverify}.go`,
  `cmd/cactus-keygen/main.go`
- `config/config.go`
- `landmark/{handler,sequence}.go`
- `log/{log,note}.go`, `log/tilewriter/tilewriter.go`
- `mirror/{follower,note,note_parse,server}.go`
- `signer/{mldsa,seed,signer}.go`
- `tile/server.go`
- `tlogx/{consistency,inclusion,subtree}.go`

The 22 `integration/*_test.go` end-to-end tests (`TestParallelIssuance`,
`TestRelyingPartyFastPath`, `TestEndToEndCAWithThreeMirrors`,
`TestMirrorRestartResume`, and the binary smoke tests) exercise the
issuance, verification, and mirror-cosignature paths and serve as the
de-facto fixture suite, since the draft itself ships no test vectors.
