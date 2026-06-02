# Cactus literature review

**Date:** 2026-06-02. **Scope:** every spec cactus depends on, as
catalogued in `specs/README.md` — the MTC draft and its tiled-log
profile, the C2SP transparency-log specs, the X.509 / PKIX stack, the
NIST algorithm standards, and the ACME / TLS / HTTP layer.

This is a snapshot review: per-spec relevance, the conformance fixes
that landed in this pass, deliberate choices and known gaps, and the
implementation status of the MTC sections. Cactus is ML-DSA-44-only
(no ECDSA), builds on Go 1.27's `crypto/mldsa`, and targets
draft-ietf-plants-merkle-tree-certs-04 plus the MTC-with-tlog profile
(`specs/mtc-tlog-draft.md`).

Every conformance finding from the review (two interop SHOULD-FIXes,
three smaller ACME/PKIX fixes, and the nits) was fixed in this pass; the
full `-race` suite, the tagged integration tests, and the sign-subtree
fuzzer are green afterwards.

## Method

1. Grouped the vendored specs by the role they play in cactus (the
   same grouping as `specs/README.md`).
2. Spawned six parallel review agents, each owning one group: the MTC
   draft + tlog profile + CT v2; the C2SP transparency-log specs; the
   X.509 / PKIX / DER stack; the cryptographic algorithms; ACME + HTTP;
   and the TLS-presentation / trust-anchor-IDs / encoding layer.
3. Each agent read the relevant spec sections and the cactus packages
   they govern, then returned a punch list with severities
   (BLOCKER / SHOULD-FIX / NIT / OK-NOTE), each citing `file:line`.
4. Consolidated and independently re-verified the two material interop
   findings (the cosignature note-line layout and the property-list PEM
   ordering) against the spec text and code.
5. Fixed every finding, updated the tests that pinned the old wire
   bytes, and re-ran the `-race`, integration, and fuzz suites.

## Per-spec relevance

### Merkle Tree Certificates

| Spec | Relevance | What cactus must honor |
|---|---|---|
| **draft-…-merkle-tree-certs-04** | Defines everything | §4 subtree math, §5 log entries/cosigners, §6 cert + landmark assembly, §7.2 verification, §9 ACME extensions, Appendix A ASN.1 |
| **mtc-tlog-draft.md** (profile) | High | CA-prefix-URL serving, `/<log number>/` tlog-tiles layout, checkpoint origin = log ID as `oid/1.3.6.1.4.1.…`, cosigner-name derivation, `/landmarks` URL, ML-DSA-44-only cosigning |
| **RFC 9162** (CT v2) | High | §2.1.1 leaf/interior hash prefixes (`0x00`/`0x01`) and the proof algorithms §4 specialises |

### C2SP transparency-log specs

| Spec | Relevance | What cactus must honor |
|---|---|---|
| **signed-note** | High | Signature-line format `base64(keyID ‖ signature)`; key-ID `SHA-256(name ‖ 0x0A ‖ sigType ‖ pubkey)[:4]` |
| **tlog-checkpoint** | High | `/checkpoint` body: origin / size / base64 root |
| **tlog-cosignature** | High | ML-DSA-44 `cosigned_message` (12-byte `subtree/v1\n\0` label); note-line `timestamped_signature` wrapper |
| **tlog-tiles** | High | Tile path layout, `.p/<W>` partials, uint16-length-prefixed entry bundles, checkpoint endpoint |
| **tlog-witness** (PR #245) | High | `POST /sign-subtree` request/response framing + the CA-signature DoS gate |
| **tlog-mirror** | Medium | Follower consistency semantics (cactus uses a polling tile-follower, not the push API) |
| **tlog-proof** | Low | Offline inclusion-proof format; cactus ships the equivalent inside the X.509 MTCProof instead |

### X.509 / PKIX

| Spec | Relevance | What cactus must honor |
|---|---|---|
| **RFC 5280** (PKIX) | High | §4.1.2.2 serial positivity/length, §4.1.2.5 UTCTime<2050 cutoff, §4.1.2.7 SPKI, §4.2 extension criticality |
| **RFC 9881** (ML-DSA in PKIX) | High | `id-ml-dsa-44` OID, absent parameters, raw FIPS 204 key in the SPKI BIT STRING, pure-mode signatures |
| **RFC 9925** (Unsigned X.509) | High | `id-alg-unsigned` + zero-length `signatureValue` on the CA certificate |
| **X.690** (DER) | High | Definite/minimal lengths, BIT STRING unused-bits octet, SET-OF ordering |
| **RFC 5912** (PKIX ASN.1) | Low | Reference for `AlgorithmIdentifier` / `Extensions` / `Validity` types; no code maps to it directly |
| **RFC 6960** (OCSP) | Trivial | Cited only for the domain-separation argument (cosignature label ≠ `ResponseData` SEQUENCE); cactus does not implement OCSP |

### Cryptographic algorithms

| Spec | Relevance | What cactus must honor |
|---|---|---|
| **FIPS 204** (ML-DSA) | High | Pure-mode ML-DSA-44 with empty context; 32-byte key-gen seed |
| **FIPS 180-4** (SHA-2) | High | SHA-256 for tree hashing, SPKI/key-ID hashing, HKDF PRF |
| **RFC 8032** (Ed25519) | Low | Only as an accepted ACME *account-key* JWS algorithm via go-jose |
| **FIPS 186-5** (DSS) | Background | ECDSA is gone from cactus's own signing; relevant only to ECDSA ACME account keys |

### ACME, TLS, and HTTP

| Spec | Relevance | What cactus must honor |
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

## Fixes landed in this pass

The overwhelming majority of the surface was already conformant (see
"Verified conformant" below). The review surfaced two interop
SHOULD-FIXes, three smaller ACME/PKIX fixes, and a set of nits — all
fixed here.

### Interop SHOULD-FIX

- **Cosignature note lines now carry the `timestamped_signature`
  timestamp (tlog-cosignature).** The signed-note line value for an
  ML-DSA-44 cosignature must be `base64(keyID ‖ timestamped_signature)`,
  where `timestamped_signature` is `u64 timestamp ‖ ml_dsa_44_signature`.
  The code previously emitted `keyID ‖ sig`, dropping the 8-byte (zero)
  timestamp. Added `cert.MarshalTimestampedSignature` /
  `cert.ParseTimestampedSignature` (`cert/keyid.go`) and routed every
  build/parse site through them: the checkpoint signature line
  (`log/note.go`), the sign-subtree response (`mirror/server.go`), the
  CA DoS-gate cosignature line (`cert/cosigner_request.go`), and all
  three parsers (`log/note.go`, `mirror/note.go`, `mirror/server.go`,
  `cert/cosigner_request.go`). The signed `cosigned_message` was already
  correct (`timestamp = 0`), so existing signatures stay valid — only
  the wire framing changed. The MTCProof signature inside the X.509 cert
  was already a bare PKIX signature (§6.1) and is untouched. Tests that
  pinned the old layout (`log/checkpoint_sig_test.go`,
  `integration/{witness_helpers,mirror_server}_test.go`) were updated to
  assert the timestamp and a zero value.

- **`application/pem-certificate-chain-with-properties` element order
  and label fixed (TAI §6.1).** The property list is now the first PEM
  element and the certificate the second, and the block label is now
  `CERTIFICATE PROPERTIES` (was `MTC PROPERTIES`); see
  `cert/properties.go` (`EncodePEMWithProperties`, `PEMBlockProperties`).
  Tests in `cert/properties_test.go` and
  `integration/landmark_properties_test.go` were updated to the
  spec-mandated order.

### ACME (RFC 8555)

- **Cert-download ownership now returns 401, not 403** (`acme/handler.go`),
  matching the `unauthorized` error type (§7.5 / §6.4).
- **Account resource is now addressable with a required `orders` member**
  (§7.1.2 / §7.1.2.1). Added `POST /account/{id}` (POST-as-GET of the
  account object) and `POST /account/{id}/orders` (the orders list),
  plus `State.GetAccount` / `State.OrderIDsForAccount` and the
  `OrdersList` type. The account object always emits `orders`. Account
  update/deactivation remains intentionally out of scope for this test
  server (documented on the handler).
- **`notBefore` / `notAfter` are now validated** (§7.4): a malformed
  RFC 3339 value returns `malformed` instead of being silently dropped
  (`acme/handler.go`).
- **Replay-Nonce is now base64url of random octets** (§6.5.1), via
  `base64.RawURLEncoding` (`acme/state.go`); opaque resource IDs still
  use hex.

### Hardening / hygiene

- **Public-key length validated** in `cert.CosignatureKeyID` against the
  FIPS 204 size for the algorithm (`cert/keyid.go`).
- **SPKI algorithm checked** in `rawKeyFromSPKI`: the inner
  AlgorithmIdentifier OID must equal the expected sig-alg and parameters
  must be absent (RFC 9881 §3) (`cert/rpverify.go`).
- **Stale docstrings corrected** to describe the relative-OID
  TrustAnchorID form (`cert/caid.go`, `ca/issuer.go`), and the
  `MaxLogNumber` ceiling is documented as enforced by the `uint16` type.

The DN SET-OF ordering (`cert/dn.go`) was reviewed and left as-is: it is
correct by single-element construction, and adding canonical SET
ordering now would be dead code. It is noted under "Deliberate choices"
as a latent item should a second RDN attribute ever be added.

## Verified conformant

These were checked in depth and match their specs; recording them so
the next review needn't re-derive them:

- **Subtree math (MTC §4):** `tlogx/subtree.go`, `inclusion.go`,
  `consistency.go` match the draft's §4.1/§4.3.2/§4.4/§4.5 algorithms
  and the RFC 9162 §2.1.1 hash prefixes.
- **Entry hashing & §7.2 verification:** `cert/entry.go` single-pass
  leaf hash and `cert/rpverify.go` verify steps 1–12, including the
  landmark trusted-subtree fast path.
- **`cosigned_message` byte layout** (`cert/proof.go:56-77`), **key-ID
  derivation** (`cert/keyid.go:39-42`, sigType `0x06`), **checkpoint
  body** (`log/note.go`), **tile/entry-bundle framing**
  (`log/tilewriter`, `tile/server.go`), and **sign-subtree framing +
  DoS gate** (`mirror/server.go`) all match the C2SP specs.
- **MTC-with-tlog profile:** origin/cosigner-name derivation
  (`oid/1.3.6.1.4.1.<relative-OID>`), `caID.0.logNumber` log ID,
  CA-prefix `/<log number>/…` serving, and `/landmarks` URL all match
  `mtc-tlog-draft.md`.
- **X.509:** RFC 5280 serial (`(logNumber<<48)|index`, positive,
  minimal), UTCTime/GeneralizedTime cutoff, critical-extension flags;
  RFC 9881 `id-ml-dsa-44` OID + absent-parameter SPKI; RFC 9925
  `id-alg-unsigned` zero-length signature on the CA cert; minimal DER
  throughout.
- **Crypto:** pure ML-DSA-44 with empty context (FIPS 204 / RFC 9881),
  deterministic HKDF-SHA256 seed derivation, consistent SHA-256 usage.
- **TrustAnchorID binary representation** (RELATIVE-OID content octets,
  spec example `32473.1 → 81 fd 59 01`) and **property-list
  sort/dedup/framing** (`cert/properties.go`, `cert/trustanchorid.go`).
- **ACME §6 JWS validation** (url/nonce/badNonce/alg allow-list +
  `badSignatureAlgorithm`/Content-Type 415/jwk-kid exclusivity), **§6.3
  POST-as-GET**, **§7.4 finalize + badCSR**, **§9 download extensions**
  (property list, alternate URL with 503+Retry-After, order→valid on
  sequencing), **RFC 7807/7638** usage, and the **base64url vs base64
  split** (`acme/jose.go` vs `mirror/note.go`).

## Deliberate choices and known gaps

- **Experimental placeholder OIDs** — `id-alg-mtcProof`,
  `id-rdna-trustAnchorID`, `id-pe-mtcCertificationAuthority` use the
  `1.3.6.1.4.1.44363.47.*` private arc pending IANA assignment, matching
  draft-04's experimental status (`cert/oid.go`).
- **ASCII TrustAnchorID in the DN UTF8String** — deliberate "for initial
  experimentation" form (`cert/dn.go`, `cert/oid.go`); the binary
  RELATIVE-OID rep is used on the wire fields that require it.
- **Pull-mode mirror** — `mirror/follower.go` polls an upstream via
  tlog-tiles and verifies append-only by root recomputation; it does not
  implement the tlog-mirror push API (`add-checkpoint`/`add-entries`).
  Intentional.
- **`auto-pass` challenge mode** is test-only; `http-01` is real;
  DNS-01 is not implemented.
- **FIPS 186-5 demoted** — ECDSA was removed from cactus's own signing,
  so 186-5 is background only (ECDSA ACME account keys via go-jose).
- **Log pruning (MTC §5.2.3 / profile pruning rules)** not implemented.
- **Revocation by serial range (§7.5)** carries the data model but only
  a stub list.
- **Account update / deactivation (RFC 8555 §7.3.2/§7.3.6)** — the
  account resource is now addressable (POST-as-GET) and exposes the
  orders list, but mutating an account is out of scope for an
  issuance-only test server.
- **DN SET-OF ordering (`cert/dn.go`)** — correct by single-element
  construction; would need canonical ordering only if a second RDN
  attribute is ever added.

## Implementation status by MTC section

**Fully implemented:** §4.1–§4.5 subtrees (validity, inclusion +
consistency proof gen/verify, FindSubtrees) · §5.1 CA / log parameters ·
§5.2 log IDs + entries (null + tbs_cert_entry, ASN.1 module, single-pass
hash) · §5.3/§5.3.1 cosigner signature format (the signed message) ·
§5.5 CA cosigner + CA-certificate extension · §6.1 certificate format /
MTCProof / serial · §6.2 standalone certs · §6.3.1–§6.3.3 landmark
sizes, allocation, publishing, and landmark-relative cert construction ·
§7.1/§7.2/§7.4/§7.5 relying-party verification (config from CA cert,
verify steps 1–12, trusted subtrees, revoked-range data model) · §9 ACME
extensions · Appendix A ASN.1 module (experimental-OID form). The
MTC-with-tlog profile's serving layout, identity mapping, and
ML-DSA-44-only requirement are all met.

**Partial / known gaps:** §5.2.3 log pruning (none) · §7.3 trusted
cosigner policy (single CA cosigner + N mirrors; no quorum-of-roles
engine) · §7.5 revocation (stub list) · ACME account update /
deactivation (out of scope). The cosignature note-line wrapper and the
property-list PEM serialization, listed as gaps in the review, were
fixed in this pass.

**Out of scope:** §8 use in TLS — the TLS stack lives elsewhere.

## Files reviewed

**Specs:** all of `specs/` (the four groups in `specs/README.md`).

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

**Tests** consulted for behavior confirmation, including the 22
`integration/*_test.go` end-to-end tests (`TestParallelIssuance`,
`TestRelyingPartyFastPath`, `TestEndToEndCAWithThreeMirrors`,
`TestMirrorRestartResume`, and the binary smoke tests), which serve as
the de-facto fixture suite — the draft itself ships no test vectors.
