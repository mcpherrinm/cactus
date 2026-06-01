# Migration Plan: draft-03 → draft-04 (Merkle Tree Certificates)

Target: implement **draft-ietf-plants-merkle-tree-certs-04** only. Drop draft-03
wire formats, identifiers, and terminology entirely — no back-compat shims, no
dual-format parsers. The spec copy in `specs/` has already been replaced with
draft-04 (`specs/draft-ietf-plants-merkle-tree-certs-04.txt`).

This is a **wire-incompatible** upgrade: certificate bytes, cosignature bytes,
log-entry bytes, the identity model, and the TLS negotiation mechanism all
change. Existing logs, certificates, and persisted state are not forward- or
backward-compatible and should be regenerated from scratch.

---

## 1. Summary of what changed in draft-04

The core Merkle/subtree machinery (§4, Appendix B) is **byte-identical** to
draft-03 — `tlogx/` (subtree, inclusion, consistency) needs no logic change.
Everything else in the issuance/identity/TLS layer changed:

| # | Area | draft-03 | draft-04 |
|---|------|----------|----------|
| A | Identity model | per-log "Log ID" | per-CA **CA ID**; log ID = `CA-ID ‖ 0 ‖ logNumber` |
| B | Serial number | `= entry index` | `= (log_number << 48) \| index` |
| C | Cosignature input | `MTCSubtreeSignatureInput`, 16-byte label `mtc-subtree/v1\n\0` | `CosignedMessage`, 12-byte label `subtree/v1\n\0`, new `timestamp`, ASCII `oid/…` names |
| D | `MTCProof` | `{start u64, end u64, …}` | `{extensions, start u48, end u48, …}`, sorted/dedup signatures |
| E | Log entry | `{type, data}`, index-0 must be null | `{extensions, type, data}`, any index may be null |
| F | TLS negotiation | `additional_trust_anchor_ranges` / `TrustAnchorRange` wire extension | deleted; **landmark groups** built on TAI trust-anchor-groups |
| G | CA representation | none | new critical X.509 ext `id-pe-mtcCertificationAuthority` `{logHash, sigAlg, minSerial}` |
| H | Revocation | revoked ranges of **indices** | revoked ranges of **serial numbers** |
| I | Algorithms | fixed enumerated list w/ TLS code points | any PKIX `AlgorithmIdentifier`; ML-DSA context string MUST be empty |
| J | Landmark TAID | `base_id ‖ L` (e.g. `32473.1.42`) | `CA-ID ‖ 1 ‖ logNum ‖ L` individual; `CA-ID ‖ 2 ‖ logNum ‖ L` group |

Spec section remap (for updating code comments): §5 "Issuance Logs" →
"Certification Authorities" (5.1 CA Identifiers, 5.2 Issuance Logs incl. 5.2.1
Log Entries / 5.2.3 Pruning, 5.3 Cosigners incl. 5.3.1 Signature Format / 5.3.2
Semantics / 5.3.3 Algorithms, 5.4 CA Cosigners, 5.5 Representing CAs); §7.1
"Trust Anchors" → "Relying Party Configuration"; §7.5 "Revocation by Index" →
"Revoked Ranges"; §8 restructured (8.1 Standalone, 8.2 Landmark-Relative).
A new `uint48` type (`uint8 uint48[6]`, big-endian) is defined in §2.

---

## 2. Work items (by area)

### A. Identity model: CA ID replaces per-log Log ID  *(foundational — do first)*

draft-04 §5.1/§5.2: a CA has one **CA ID** (a trust anchor ID). Each log's ID is
*derived*: `logID = CA-ID ‖ 0 ‖ logNumber`, with `1 ≤ logNumber ≤ 65535`. The
TBSCertificateLogEntry `issuer` DN is now the **CA ID** (not the per-log ID).

- `cert/dn.go` — rename `BuildLogIDName` → `BuildCAIDName` (or `BuildCAName`);
  it now encodes the CA ID, not a log ID. The DN/OID machinery
  (`OIDRDNATrustAnchorID`, UTF8String value) is unchanged.
- New helper in `cert/` (e.g. `cert/caid.go`): derive a log ID from
  `(caID, logNumber)` and derive landmark / landmark-group trust anchor IDs
  (see item J). Validate `logNumber ∈ [1, 65535]`.
- `ca/issuer.go` — `Issuer.LogIDDN` becomes the CA-ID DN; the `Issuer` (or its
  config) must also carry the **log number** so it can compute serials (item B).
- `cmd/` wiring + `config/` (item K): replace per-log `id` with a CA-level CA ID
  plus an explicit `log_number` per log.

### B. Serial number composition  *(depends on A)*

draft-04 §6.1: `serialNumber = (log_number << 48) | index`. Reject `log_number == 0`
on verify.

- `ca/issuer.go:97-98` — `serialNumber: idx` becomes
  `(uint64(logNumber) << 48) | idx`. Note `assembleCertificate` already encodes
  it as a big.Int, so width is fine.
- The draft-03 "index 0 reserved as null_entry to avoid zero serial" rationale
  is gone; zero-serial avoidance now comes from `logNumber ≥ 1`.
- Verification (item L) must split `index = serial & (2^48-1)`,
  `log_number = serial >> 48`, reject `serial < 0 || > 2^64-1`, reject
  `log_number == 0`, and derive the log ID from CA ID + log_number.

### C. Cosignature signing input rewrite  *(wire-breaking; high blast radius)*

draft-04 §5.3.1 replaces `MTCSubtreeSignatureInput`/`MTCSubtree` with a single
flat `CosignedMessage`:

```
struct {
    uint8 label[12] = "subtree/v1\n\0";   // was 16-byte "mtc-subtree/v1\n\0"
    opaque cosigner_name<1..2^8-1>;        // ASCII "oid/" + dotted-decimal OID
    uint64 timestamp;                       // NEW — MUST be 0 for MTC proofs
    opaque log_origin<1..2^8-1>;            // ASCII "oid/" + dotted-decimal OID
    uint64 start;
    uint64 end;
    HashValue subtree_hash;
} CosignedMessage;
```

`cosigner_name` / `log_origin` = the 16-byte ASCII string `oid/1.3.6.1.4.1.`
concatenated with the trust anchor ID's dotted-decimal ASCII (i.e. `oid/` + the
full dotted OID, e.g. TAID `32473.1` → `oid/1.3.6.1.4.1.32473.1`). This is the
`[TLOG-COSIGNATURE]` / ML-DSA-44-compatible construction.

- `cert/oid.go:27` — `SubtreeSignatureLabel` → `"subtree/v1\n\x00"` (12 bytes);
  update the length guard in `cert/proof.go:59`.
- `cert/proof.go` — delete `MTCSubtree` + `MarshalSignatureInput`; add
  `CosignedMessage` struct + marshal. Add a helper to render a `TrustAnchorID`
  as the `oid/<dotted-decimal>` ASCII string. **Caution:** the current
  `TrustAnchorID` stores the ASCII OID *without* the `oid/1.3.6.1.4.1.` prefix
  (e.g. `"32473.1"`); the new encoding needs the full `oid/1.3.6.1.4.1.32473.1`,
  so be explicit about which representation each call site holds.
- `log/log.go` (cosigner signing path) and `cert/sigverify.go` /
  `cert/cosigner_request.go` (verify path) must build the identical
  `CosignedMessage` with `timestamp = 0`.
- §5.3.2 "Signature Semantics" and §12.8 "Signature Domain Separation" are
  mostly behavioral: the 12-byte label provides domain separation (does not
  collide with DER `0x30…`). No extra wire work, but the CA-cosigner-key reuse
  rules (item G) reference it.

### D. `MTCProof` wire format  *(wire-breaking)*

draft-04 §6.1:

```
struct {
    MerkleTreeCertEntryExtension extensions<0..2^16-1>;  // NEW first field
    uint48 start;                                         // was uint64
    uint48 end;                                           // was uint64
    HashValue inclusion_proof<0..2^16-1>;
    MTCSignature signatures<0..2^16-1>;                   // now sorted + unique
} MTCProof;
```

- `cert/proof.go` — `MTCProof`: add `Extensions []MerkleTreeCertEntryExtension`
  as the first field; change `Start, End` from `uint64` to a 48-bit encoding
  (add `addUint48`/`readUint48` helpers — `cryptobyte` has no native u48; emit 6
  big-endian bytes, reject values ≥ 2^48 on encode and on decode treat the 6
  bytes as the value).
- `MarshalTLS`/`ParseMTCProof` — write/parse the leading extensions vector;
  enforce on parse that `signatures` are **sorted** (shorter `cosigner_id`
  first, then lexicographic) and **unique**, rejecting duplicates/misorder.
  Encoder must sort signatures before emitting.
- `extensions` MUST equal the log entry's extensions value (item E).
- Signing-time rule: the `timestamp` used in the cosignature MUST be 0 (item C).

### E. Log entry format + extensions  *(wire-breaking)*

draft-04 §5.2.1:

```
enum { (2^16-1) } MerkleTreeCertEntryExtensionType;
struct {
    MerkleTreeCertEntryExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} MerkleTreeCertEntryExtension;

struct {
    MerkleTreeCertEntryExtension extensions<0..2^16-1>;  // NEW, prepended
    MerkleTreeCertEntryType type;
    select (type) { … }
} MerkleTreeCertEntry;
```

- `cert/entry.go`:
  - Add `MerkleTreeCertEntryExtension` type + `MerkleTreeCertEntryExtensionType`.
  - `EncodeNullEntry()` / `EncodeTBSCertEntry()` must prepend the extensions
    vector (`uint16` length-prefixed, ascending `extension_type`, no
    duplicates). For now cactus emits an empty extensions list (`0x00 0x00`)
    until an extension type is defined.
  - **`EntryHash` / `SinglePassEntryHash` change** (§7.2): the single-pass hash
    must now write the entry's `extensions` field *before* the `0x00 0x01` type
    bytes: `HASH(0x00 ‖ extensions ‖ 0x00 0x01 ‖ tbsContents)`. This is the most
    error-prone change — it shifts every leaf hash and therefore every Merkle
    root. Add explicit test vectors.
  - Drop the "index 0 MUST be null_entry" assumption (§5.2.1: "Entries at any
    index … MAY have type null_entry"). Review `log/` bootstrap that seeds a
    null entry at index 0, and any verifier/issuer code asserting it.
  - Honor the SHOULD-NOT-exceed-65535-bytes entry-size guidance.
- The `TBSCertificateLogEntry` ASN.1 SEQUENCE itself is **unchanged**; only its
  `issuer` semantics change (now the CA ID — item A).

### F. TLS negotiation: delete TrustAnchorRange, add landmark groups  *(wire-breaking)*

draft-04 §8 **removes** the draft-03 `additional_trust_anchor_ranges` /
`TrustAnchorRange` certificate-property extension and its OID-range containment
decoder. Negotiation is now built purely on the *existing* trust-anchor-groups
feature of `draft-ietf-tls-trust-anchor-ids` (now cited at **-04**).

- `cert/properties.go` — **delete** `PropertyAdditionalTAnchorRanges`,
  `TrustAnchorRange`, and the range encode/parse arms. Keep only
  `PropertyTrustAnchorID`. (Verify the current code-point `0` for
  `trust_anchor_id` still matches TAI-04 §7; adjust if the registry moved.)
- Standalone cert (§8.1): its trust anchor ID is now the **CA ID** (not log ID),
  and is additionally contained in the landmark groups of §8.2.1.
- Landmark-relative (§8.2): the individual landmark TAID format changes (item J)
  and a new **single-log landmark group** ID `CA-ID ‖ 2 ‖ logNum ‖ L` is the
  primary negotiation primitive. The group contains the CA ID plus landmarks
  `L - max_active_landmarks + 1 … L` of that log. A relying party advertises one
  group ID per (CA, log).
- §8.2.2 "Timestamped Landmark Groups" (multi-CA, TAI §5.1 versioning, time-keyed
  versions) is an optional optimization — defer unless needed.
- `acme/handler.go` config (`LogID`, `LandmarkBaseID`) and any property-list
  building for downloaded certs must follow the new IDs.

### G. CA certificate representation  *(new artifact)*

draft-04 §5.5 + Appendix A + §13.3: a new **critical** X.509 extension carries
the CA's parameters.

```
id-pe-mtcCertificationAuthority OBJECT IDENTIFIER ::=
    { 1 3 6 1 5 5 7 1 TBD }     -- experimental fallback: 1.3.6.1.4.1.44363.47.2

MTCCertificationAuthority ::= SEQUENCE {
    logHash   AlgorithmIdentifier{DIGEST-ALGORITHM, …},   -- e.g. mda-sha256
    sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, …},-- CA cosigner alg
    minSerial INTEGER
}
```

- `cert/oid.go` — add `OIDExtMTCCertificationAuthority`
  (experimental `1.3.6.1.4.1.44363.47.2`, mirroring the existing `.0`/`.1`
  experimental arcs).
- New file (e.g. `cert/cacert.go`): build + parse the `MTCCertificationAuthority`
  extension; build/validate a CA certificate where `subject` = CA ID DN,
  `subjectPublicKeyInfo` = CA cosigner public key, extension is critical, key
  usage asserts ≥ `keyCertSign`, basic constraints `cA=TRUE`. SHOULD NOT be
  self-signed; if used as a trust anchor, an unsigned cert ([RFC9925]) is
  recommended.
- This CA cert is what an RP is configured from (item L): CA ID ← subject,
  log-hash ← `logHash`, cosigner alg ← `sigAlg`, initial revoked range
  `[0, minSerial)` ← `minSerial`. The CA cosigner ID MUST equal the CA ID.

### H. Revocation: index ranges → serial-number ranges

draft-04 §7.5: revoked ranges are now over the 64-bit **serial** space
(`log_number << 48 | index`), so a single range can revoke whole logs as well as
index ranges within a log.

- Wherever revoked ranges are represented (config + any RP verification path),
  switch keys from bare indices to 64-bit serials. Seed with `[0, minSerial)`
  from the CA cert (item G). Today this is largely a stub (`acme/types.go`
  `RevokeCert` is reserved) — implement the range model where verification
  consumes it (item L).

### I. Signature algorithms

draft-04 §5.3.3: no fixed enumerated list / no TLS code points; algorithms are
PKIX `AlgorithmIdentifier`s (the CA cosigner's `sigAlg`, item G). ML-DSA per
[RFC9881] with **empty context string**.

- `cert/sigverify.go` — the `SignatureAlgorithm uint16` enum (TLS code points
  `0x0403`…) is now an internal convenience only; the algorithm is resolved
  out-of-band from the cosigner's PKIX `AlgorithmIdentifier`. Re-key
  algorithm resolution off PKIX OIDs rather than TLS SignatureScheme values, or
  document the enum as a purely internal mapping.
- `signer/` — ensure ML-DSA signing uses an empty context string per RFC9881 §3.
- Update normative references in comments: drop FIPS186-5 as normative; add
  RFC9881, RFC9925, TLOG-COSIGNATURE.

### J. Landmark trust anchor ID format  *(depends on A)*

draft-04 §6.3.1/§8.2: per-landmark TAID = `CA-ID ‖ 1 ‖ logNumber ‖ L`
(e.g. `32473.1.1.8.42`); the `base_id`/`landmark_url` fixed parameters are gone.
Landmark *group* TAID = `CA-ID ‖ 2 ‖ logNumber ‖ L`.

- `landmark/sequence.go:36-42` — `Landmark.TrustAnchorID` must take the CA ID +
  log number and emit the 5-component `CA-ID.1.logNum.L` form (arc `1` =
  individual landmark). Add a parallel `LandmarkGroupID` (arc `2`).
- `landmark/sequence.go` `Config.BaseID` → derive from CA ID + log number; drop
  `BaseID` as an independent config field.
- §6.3.3 "Publishing Landmarks": the landmark text file format is unchanged but
  is now SHOULD-publish at a deployment-defined URL (no spec-mandated
  `landmark_url`). `tile/server.go` `/landmarks` endpoint can stay; treat its
  path as a local deployment choice rather than a spec field.

### K. Configuration surface  *(config/, config-example.json)*

- Replace per-log `log.id` with a CA-level **CA ID** + per-log **log_number**.
- Add the CA's **log hash algorithm** explicitly (e.g. `"sha256"`) at CA level
  (draft-04 §7.1 requires RPs be configured with it; the CA cert carries it).
- Drop `landmarks.base_id` (derived from CA ID + log number now).
- Add CA-cert material (logHash/sigAlg/minSerial) or a path to the CA cert from
  which RP config is derived.
- Revoked ranges expressed as serial-number ranges (item H).
- `config/config.go` structs: `LogConfig`, `CosignerConfig`, `LandmarkConfig`,
  `CACosignerQuorum`, plus `Default()` and `config_test.go`.

### L. Relying-party verification flow  *(depends on A–E, G, H)*

draft-04 §7.1/§7.2/§7.4. `cert/verify.go` + `cert/sigverify.go`:

- Parse RP config from a CA certificate (item G): CA ID, log hash, CA cosigner
  (ID == CA ID), trusted subtrees, revoked ranges (incl. `[0, minSerial)`).
- Serial handling: split into `log_number`/`index`, reject `log_number == 0`,
  derive `log_id` from CA ID + log_number, check `serial` against revoked ranges.
- Build the `MerkleTreeCertEntry` with `extensions = MTCProof.extensions` and
  `type = tbs_cert_entry`; single-pass hash writes `extensions` first (item E).
- Trusted-subtree match key is now `(log_number, start, end)` and the stored
  subtree hash (§7.4), not `[start, end)` alone.
- Signature verify constructs `CosignedMessage` (item C) with `timestamp = 0`,
  `log_origin` from the derived log ID, `subtree_hash` = expected subtree hash.

### M. Docs, comments, version strings  *(mechanical, do last)*

- Update every `draft-ietf-plants-merkle-tree-certs-04` reference to `-04`:
  package doc comments in `cert/oid.go:2`, `signer/signer.go`, `tlogx/subtree.go`,
  `acme/types.go`, `landmark/sequence.go`, and others (`grep -rn "certs-03"`).
- Re-map embedded spec section numbers in comments (see §1 remap table) — e.g.
  `§5.3`→`§5.2.1`, `§5.4.1`→`§5.3.1`, `§5.4.2`→`§5.3.3`, `§5.5`→`§5.4`,
  `§5.6.1`→`§5.2.3`, `§7.1` "Trust Anchors"→"Relying Party Configuration",
  `§7.5` "Revocation by Index"→"Revoked Ranges", `§13.3`→`§13.4`.
- Update `MTC.md`, `README.md`, `PROJECT_PLAN.md`, `TODO.md` narrative and any
  "trust anchor range" / "log ID" terminology to the CA-ID / landmark-group model.
- `config-example.json` to match item K.

---

## 3. Suggested sequencing

1. **A + B + K** — CA-ID identity model, serial composition, config surface.
   Foundational; everything else assumes CA ID + log number exist.
2. **E** — log-entry extensions + the new `EntryHash` ordering. Lands the new
   leaf-hash definition (changes all roots) with dedicated test vectors before
   anything depends on hashed entries.
3. **C** — `CosignedMessage` cosignature rewrite (signing + verifying together).
4. **D** — `MTCProof` (extensions field, `uint48`, sorted signatures).
5. **G** — CA certificate + `MTCCertificationAuthority` extension.
6. **L + H** — RP verification flow and serial-range revocation, consuming G.
7. **F + J** — TLS negotiation: delete TrustAnchorRange, add landmark groups,
   new landmark TAID format.
8. **I** — algorithm resolution off PKIX OIDs; ML-DSA empty context.
9. **M** — docs / comments / version strings.

Each numbered step should leave `go test ./...` green. Because the leaf hash
(step 2), cosignature (step 3), and proof (step 4) are independently
wire-breaking, regenerate any committed test fixtures / golden vectors as you go;
do not attempt to keep draft-03 vectors passing.

---

## 4. Test impact

- `cert/entry_test.go`, `cert/proof_test.go`, `cert/sigverify_test.go`,
  `cert/properties_test.go` (delete range cases), `cert/fuzz_test.go`,
  `cert/derstrict_test.go` — new wire formats + new leaf hash.
- `tlogx/*_test.go` — logic unchanged, but any fixtures embedding entry hashes
  shift.
- `landmark/*_test.go` — new TAID format + group IDs.
- `config/config_test.go` — new config shape.
- `integration/*` — broad: `landmark_*`, `*_rp_test`, `mldsa_test`, `rsa_test`,
  `ca_three_mirrors_test`, `binary_*`. Expect to regenerate end-to-end fixtures.
- Add fresh known-answer vectors for: `EntryHash` (with empty extensions),
  `CosignedMessage` bytes (including the `oid/…` name encoding), and a full
  standalone-cert + landmark-cert round trip.

---

## 5. Open questions to confirm against draft-04 / TAI-04 before coding

- Exact `trust_anchor_id` certificate-property code point in TAI-04 §7 (the
  `additional_trust_anchor_ranges = 1` neighbor is gone; confirm `0` still holds).
- Whether cactus needs §8.2.2 timestamped landmark groups now or can defer.
- The `extension_type` field name in §5.2.1 (`ExtensionType` vs.
  `MerkleTreeCertEntryExtensionType` — likely an editorial typo in the draft;
  treat as the latter).
- Confirm `minSerial` semantics drive the initial revoked range `[0, minSerial)`
  and how out-of-band revocations are layered on top.
