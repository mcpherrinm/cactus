# Merkle Tree Certificates: a tutorial

This document is background for the cactus codebase. It walks through
the parts of [draft-ietf-plants-merkle-tree-certs][draft] that you
need to keep in your head while reading the code.

It's deliberately thinner than the IETF draft. For anything you can't
find here, the draft is the source of truth — `specs/draft-ietf-plants-merkle-tree-certs-03.txt`
is the version cactus targets, and section numbers in this doc match
that file.

## Why MTC exists

In a CT-style PKI, every certificate carries:

1. The CA's signature on the cert itself.
2. Two or more **Signed Certificate Timestamps** (SCTs), each a
   signature from a CT log saying "I have logged this certificate."

With ECDSA-P256 that's tolerable: each SCT is ~70 bytes. With ML-DSA-44,
each SCT signature is **2,420 bytes** and each public key is **1,312 bytes**.
Two SCTs plus the cert signature plus the cert's public key starts to
crowd out the rest of the TLS handshake. Worse, every CT log has to
store the same data over and over.

MTC inverts the design. Instead of "the CA signs the cert, then logs it",
the CA *logs* the cert (a small structure with a hash where the public
key would be) and then *signs the log*. Each issued certificate
becomes a Merkle inclusion proof against a logged tree, plus one or
more cosigner signatures over a *subtree* of that tree — never over
the cert directly.

The win:

- Log entries don't carry public keys or signatures, only
  `(name, validity, hash-of-pubkey)`. Storage scales with issuance
  rate, not key/sig size.
- The CA signs O(checkpoints) per unit time, not O(certs). Fewer
  signature operations.
- An optional second mode — *landmark-relative certificates* —
  ships the inclusion proof without any signatures at all, by
  pre-distributing a small set of trusted subtree hashes to clients.

## The big picture

```
+---------+   1. ACME order        +---------+
| client  | --------------------> |   CA    |
+---------+                       +---------+
                                       |
                                       | 2. add to issuance log
                                       v
+---------+   4. inclusion proof  +---------+
| client  | <-------------------- |   CA    |
+---------+   + cosignatures      +---------+
                                       ^
                                       | 3. sign subtree(s)
                                       |
                                  +---------+
                                  | mirrors |
                                  +---------+
```

The cert the client receives is an X.509 with:

- Standard fields: subject, validity, SubjectPublicKeyInfo,
  extensions (e.g. SAN). Same as a regular leaf cert.
- `signatureAlgorithm = id-alg-mtcProof`. New OID, no parameters.
- `signatureValue` (a BIT STRING) whose body is **not** a signature
  but a TLS-presentation-language struct called `MTCProof` that
  contains:
  - The subtree the cert was logged into: `(start, end)`.
  - An inclusion proof from the cert's leaf to that subtree.
  - One or more cosigner signatures over that subtree.

A relying party verifies the cert by:

1. Re-deriving the leaf hash from the cert's TBS (with the public key
   replaced by its hash).
2. Walking the inclusion proof up to the subtree hash.
3. Checking that some sufficient set of trusted cosigners signed
   that subtree.

No signature on the cert itself. No SCTs.

## §4: Subtrees, the new primitive

RFC 9162 (CT v2) defines a Merkle tree, but only ever talks about the
root. MTC introduces **subtrees**: a subtree is any range `[start, end)`
of leaves where:

- `0 ≤ start < end ≤ tree_size`.
- `start` is a multiple of `bit_ceil(end - start)`.
   (So `[4, 8)` is valid; `[1, 4)` is not.)

A subtree of size `2^k` is *full* and lives at a fixed position in the
larger Merkle tree. A non-power-of-two subtree is *partial*; it's only
directly contained in a tree of size exactly `end`, but it can still
be efficiently shown consistent with bigger trees (§4.4).

§4.5 is the algorithmic core of MTC: given any range `[start, end)`,
return the **one or two** subtrees that efficiently cover it. After a
checkpoint flush, the CA uses §4.5 to find the covering subtree(s)
for "everything I added since the last checkpoint" and signs each
one. That's why a single MTCProof has *one* subtree even though
multiple subtrees may be signed at each checkpoint — the proof picks
the one that contains the cert's index.

In cactus, §4 lives in the `tlogx/` package:

- `tlogx.FindSubtrees(start, end)` — the §4.5 procedure.
- `tlogx.IsValid(start, end)` — the §4.1 validity predicate.
- `tlogx.HashLeaf` / `tlogx.HashChildren` — the RFC 9162 prefixes.
- `tlogx.GenerateInclusionProof` / `EvaluateInclusionProof` — §4.3.
- `tlogx.GenerateConsistencyProof` / `VerifyConsistencyProof` — §4.4.

## §5: The issuance log

The log is an append-only tree of `MerkleTreeCertEntry` structures.
The first entry (index 0) is always a `null_entry`; this guarantees
serial numbers are non-zero, sidestepping a stupid X.509 footgun.

Each non-null entry is a `tbs_cert_entry`: the TBS-style fields of
the cert with the public key replaced by `HASH(SubjectPublicKeyInfo)`.
The cert's "issuer" is a special DN containing the log ID.

The log is published as **tiles** ([c2sp.org/tlog-tiles]). For cactus,
that means the read-path (HTTP) serves files at:

- `/checkpoint` — a c2sp signed-note with the latest size + root.
- `/tile/<H>/<L>/<NNN>[.p/<W>]` — Merkle hash tiles.
- `/tile/<H>/data/<NNN>[.p/<W>]` — entry blobs (level -1).
- `/log/v1/entry/<index>` — fetch one entry by index.
- `/subtree/<start>-<end>` — cached signed subtree blob.

Cactus's `log/` and `tile/` packages own this. The log is a
single-writer affair: one goroutine ticks every `flush_period_ms`,
appends pooled entries to the tilewriter, signs the new checkpoint
+ covering subtrees, and writes everything to disk via temp-file +
rename. The "lock" against multiple writers is documentation, not
fcntl — see `docs/threat-model.md`.

### Cosigners

Anyone who attests to the log's append-only property is a **cosigner**.
There are two kinds:

- **CA cosigner** (§5.5): the CA itself, attesting that "I issued every
  entry in this subtree." The CA's signature is the bedrock — without
  it the cert isn't authentic at all.
- **Mirror cosigner** ([c2sp tlog-mirror]): a third party that follows
  the log, verifies consistency proofs, and signs subtrees too.
  Mirrors prove transparency: a misbehaving CA can't issue a cert
  that mirrors haven't seen.

A cosigner's signature is over a structure called
`MTCSubtreeSignatureInput` (§5.4.1):

```
struct {
    uint8 label[16] = "mtc-subtree/v1\n\0";
    TrustAnchorID cosigner_id;
    MTCSubtree subtree;     // log_id, start, end, hash
} MTCSubtreeSignatureInput;
```

The 16-byte label is domain separation: it ensures that a signature
produced by some other protocol (which would not begin with this
exact label) can never be replayed as an MTC subtree signature.

In cactus, the cosigner abstraction is in `signer/`:

- `signer.Signer` — a one-method interface (`Sign(rand, msg) → sig`).
- `signer.FromSeed(alg, seed)` — derives a key from a 32-byte seed
  via HKDF. ECDSA-P256 in the default build; ML-DSA-44/65 with
  `-tags mldsa`.

## §6: Building the certificate

§6.1 specifies how the X.509 cert is laid out:

- `signatureAlgorithm` and `tbsCertificate.signature` both use
  `id-alg-mtcProof` with absent parameters.
- `signatureValue` is a BIT STRING whose body — **with no further
  ASN.1 wrapping** — is the TLS-presentation encoding of:

```
struct {
    uint64 start;
    uint64 end;
    HashValue inclusion_proof<0..2^16-1>;
    MTCSignature signatures<0..2^16-1>;
} MTCProof;
```

- `serialNumber` is the cert's index in the log. Hence index 0 is
  reserved for the null entry: a serialNumber of 0 is forbidden by
  RFC 5280 §4.1.2.2.

This MTCProof can carry **two flavors of cert**:

- **Standalone certificate** (§6.2): the proof's subtree is one of
  the §4.5 covering subtrees from a recent checkpoint, and the
  `signatures<>` slice has at least one cosigner. Issuable
  immediately after the next checkpoint.
- **Landmark-relative certificate** (§6.3): the proof's subtree is
  a special pre-distributed *landmark subtree*, and the
  `signatures<>` slice is empty. Issuable only after the entry has
  been included in a landmark, but smaller and signature-free.

The cert assembly code is in `cert/` and `ca/`:

- `cert.MTCProof` / `cert.MTCSubtree` / `cert.MTCSignature` —
  TLS-presentation encoders.
- `cert.BuildLogIDName` — the §5.2 issuer DN.
- `ca.Validator` / `ca.Issuer` — turn an ACME order + CSR into a
  TBSCertificateLogEntry, submit to the log, await the inclusion
  proof, assemble the X.509 cert.
- `cert.BuildLandmarkRelativeCert` — clones a standalone cert with
  a different MTCProof (signature-less, points at a landmark
  subtree).

### A worked example

Suppose:

- The log has 100 entries.
- The previous checkpoint was at size 95.
- A flush runs and produces checkpoint 100.

The CA:

1. Calls `tlogx.FindSubtrees(95, 100)` → it returns
   `[(start: 88, end: 96), (start: 96, end: 100)]`.

   Note that `(88, 96)` covers indices 88–95, three of which (88, 89,
   90, 91, 92, 93, 94) are from before the previous checkpoint —
   that's fine; "efficiently cover" doesn't mean "exactly cover".

2. Computes the Merkle hashes of those two subtrees from the tiles.

3. Signs each subtree's `MTCSubtreeSignatureInput` with its CA
   cosigner key.

4. Optionally fans the request out to mirrors (Phase 9). Each mirror
   that has caught up returns its own signature.

5. Persists the signed checkpoint and the per-subtree signatures to
   disk.

When a client wants the cert at index 97:

1. Index 97 is in subtree `(96, 100)`. The CA computes the §4.3
   inclusion proof from leaf 97 up to the subtree's root.
2. The X.509 cert is assembled with serial=97, the inclusion proof,
   and however many cosigner signatures are attached to subtree
   `(96, 100)`.

## §6.3: Landmark-relative certificates

This is the subtle part. The promise: **a cert with no signatures**
that an up-to-date relying party can verify in ~constant time.

A *landmark* is a designated tree size. Landmarks are allocated by
the CA (or some coordinating party) at a regular cadence — say, once
per hour — and they're append-only and strictly increasing.

For each landmark `N` with tree size `T_N`, define its **landmark
subtrees** as the §4.5 covering subtrees of `[T_{N-1}, T_N)`. So if
a CA runs hourly landmarks and issues 4M certs/hour, each landmark
has one or two subtrees, each ~22 levels deep (~2M leaves).

Relying parties periodically download the **active** landmarks (the
most recent `max_active_landmarks` of them) and store *just the
subtree hashes* — about 10 KiB per CA at typical settings. When an
authenticating party presents a landmark-relative cert:

1. The cert's MTCProof has a subtree `[s, e)` and an inclusion proof.
2. The relying party looks up that subtree in its trusted set.
3. If found and the inclusion proof matches the trusted hash, the
   cert is valid. **No cosigner signature is consulted.**

That's the size optimization: the cert ships an inclusion proof
(~32 bytes × log₂(N)) and *zero* signatures.

In cactus:

- `landmark/sequence.go` is the CA-side allocator (§6.3.2). Append-only
  on disk; the in-memory state replays from JSONL on restart.
- `landmark.Sequence.Handler()` serves the §6.3.1 text-format URL
  that relying parties poll.
- `cert.BuildLandmarkRelativeCert` re-uses the existing standalone
  cert's TBS (so subject, validity, SPKI all match) and replaces
  only the signature value with a landmark MTCProof.
- `acme.Server`'s alternate URL `(/cert/<id>/alternate)` returns a
  `503 + Retry-After` until a covering landmark exists, then
  returns the real landmark-relative cert.

The relying-party side is exercised by
`integration/TestRelyingPartyFastPath`: the test simulates an RP
that has only `/landmarks` and the tile-served subtree hashes, then
verifies a landmark-relative cert without consulting any cosigner key.

## §7.2: Verifying a certificate

Step-by-step, the relying party's job:

1. Check the cert's `signatureAlgorithm` is `id-alg-mtcProof`.
2. Decode the BIT STRING body as `MTCProof`.
3. The cert's `serialNumber` is the entry index. (Reject if it's in
   the relying party's revocation-by-index list, §7.5 — cactus
   doesn't fully implement this, but the data model carries it.)
4. Reconstruct `TBSCertificateLogEntry` from the cert's TBS by
   replacing `subjectPublicKeyInfo` with `HASH(SubjectPublicKeyInfo)`.
5. Wrap that in a `MerkleTreeCertEntry{type=tbs_cert_entry,data=...}`
   and compute the leaf hash: `HASH(0x00 || entry)`.
6. Evaluate the inclusion proof from the leaf hash up to the
   `MTCProof.subtree` hash.
7. Either match the subtree against a trusted-subtree set
   (landmark fast path) **or** verify enough cosigner signatures
   over the subtree to satisfy local policy.

Cactus's helpers:

- `cert.SplitCertificate` — split a cert DER into TBS, alg-id, sig
  BIT STRING.
- `cert.RebuildLogEntryFromTBS` — step 4.
- `cert.EntryHash` — step 5 (single-pass per §7.2's inline algorithm).
- `tlogx.EvaluateInclusionProof` — step 6.
- `cert.VerifyMTCSignature` — step 7's cosigner check.

The shape of all these helpers — small, composable, zero hidden
state — is intentional. A relying-party library outside cactus
should be able to import just `cert/` and `tlogx/` and verify
certs with a few function calls.

## §9: Doing it over ACME

ACME is what the authenticating party (the cert holder) uses to
*request* certs. The MTC draft layers two changes onto RFC 8555:

1. **The order moves to `valid` once the entry is sequenced** — i.e.
   when its log index is assigned and the next checkpoint is signed
   — *not* when the cosignatures arrive. This decouples ACME state
   from cosignature collection latency.
2. **Cert download negotiation.** The client may send
   `Accept: application/pem-certificate-chain-with-properties`. The
   server then includes a `CertificatePropertyList` alongside the
   PEM (cactus uses an adjacent `MTC PROPERTIES` PEM block; the
   trust-anchor-ids draft hasn't pinned the wire format yet). The
   property list carries:
   - `trust_anchor_id` — the log ID for standalone certs, or the
     specific landmark's ID for landmark-relative certs.
   - `additional_trust_anchor_ranges` — for landmark-relative
     certs, the range of compatible landmark IDs (so a relying
     party that supports a *newer* landmark can also accept this
     cert).
3. **Alternate URL.** Per RFC 8555 §7.4.2, the `Link: <...>;
   rel="alternate"` header on the `/finalize` response points at
   the landmark-relative variant of the cert. Until a landmark
   covers the entry, that URL returns `503 + Retry-After`.

Cactus implements all of the above in `acme/` plus the
property-list builder in `cert/properties.go`.

## Cactus implementation map

If you're reading the code, this is the order I'd recommend:

1. `cert/entry.go` — TBSCertificateLogEntry encoder + the
   single-pass §7.2 entry hash. Fundamental; everything else
   downstream of "what's in the log".
2. `tlogx/subtree.go` and `tlogx/inclusion.go` — §4 primitives.
3. `log/log.go` — the issuance log: how new entries get into a
   checkpoint, how covering subtrees get signed, how Wait blocks
   for a committed entry.
4. `cert/proof.go` — MTCProof, MTCSubtree, MTCSignature on the
   wire.
5. `ca/issuer.go` — assemble the X.509 cert from a CSR + a `log.Issued`.
6. `acme/handler.go` — the ACME state machine.
7. `landmark/sequence.go` — §6.3.1/2 allocator.
8. `mirror/follower.go` and `mirror/server.go` — Phase 9.

The integration test `integration/TestParallelIssuance` exercises
1–6 end-to-end: 100 certs in parallel, each one re-parsed and
re-verified using the §7.2 procedure on the live log.

## Further reading

- [draft-ietf-plants-merkle-tree-certs-03][draft] — the spec.
- [c2sp tlog-tiles] — the read-path layout cactus uses.
- [c2sp tlog-cosignature] — the cosigner signed-note format.
- [c2sp tlog-mirror] — the mirror role.
- [c2sp signed-note] — the underlying note-signing format.
- [RFC 9162] — Certificate Transparency v2; the Merkle-tree
  conventions MTC builds on.

[draft]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-03.txt
[c2sp.org/tlog-tiles]: https://c2sp.org/tlog-tiles
[c2sp tlog-tiles]: https://c2sp.org/tlog-tiles
[c2sp tlog-cosignature]: https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md
[c2sp tlog-mirror]: https://github.com/C2SP/C2SP/blob/main/tlog-mirror.md
[c2sp signed-note]: https://c2sp.org/signed-note
[RFC 9162]: https://www.rfc-editor.org/rfc/rfc9162
