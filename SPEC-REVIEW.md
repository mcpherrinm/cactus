# MTC spec review — under-specification and ambiguities

**Date:** 2026-06-02. **Purpose:** the inverse of `LITERATURE-REPORT.md`.
Instead of asking "does cactus conform to the specs," this asks "where do
the specs leave conforming implementations free to diverge?" It is
feedback for the spec authors, drawn from a close reading plus the
choices the cactus reference implementation was forced to make where the
text was silent.

**Documents reviewed (as vendored in `specs/`):**
- `draft-ietf-plants-merkle-tree-certs-04.txt` — the MTC core draft.
- `mtc-tlog-draft.md` — the "MTC with Tiled Transparency Logs" profile
  (in progress; has its own TODO list).
- `draft-ietf-tls-trust-anchor-ids-03.txt` (the profile cites `-04`).
- C2SP `tlog-witness.md` (from the unmerged `sign-subtree` PR #245),
  `tlog-cosignature.md`, `tlog-tiles.md`, `tlog-checkpoint.md`,
  `signed-note.md`.

**Severity key:** **[CRIT]** two conforming implementations would be
incompatible (often a silent failure); **[CLARIFY]** an implementer must
guess, or a MUST/SHOULD is missing; **[EDIT]** wording, cross-reference,
or internal-consistency nit.

Section/line references are to the files above. Items marked *(verified)*
were checked against the spec text directly while writing this.

---

## 1. Hashing and wire-format correctness

These are the most dangerous class: a divergence produces a different
`entry_hash` or signature input, so *every* proof and signature fails,
silently.

### 1.1 [CRIT] The single-pass `entry_hash` omits the `0x00` leaf prefix *(verified)*
**Where:** MTC §7.2. The step-by-step path (step 9) defines
`entry_hash = MTH({entry}) = HASH(0x00 || entry)`. The "equivalent"
single-pass procedure (steps 1–10, "entry_hash can equivalently be
computed in a single pass") goes: 1. initialize hash; 2. *write the
extensions field*; … 10. finalize. There is no step that writes the
leading `0x00` RFC 9162 leaf-domain-separation octet. The closing note
("This is possible because the structure in §5.2.1 omits the
TBSCertificateLogEntry's identifier and length octets") explains the
absence of the SEQUENCE header but not the missing `0x00`.
**Why it matters:** As written the two procedures the draft calls
equivalent compute different hashes (differing by one leading byte). An
implementer who follows the single-pass verbatim fails every inclusion
proof. (cactus added the `0x00` in both paths to make them agree — i.e.
the reference implementation had to silently correct the draft.)
**Suggestion:** Insert a step 1.5 "Write the octet `0x00` to the hash
(the RFC 9162 leaf prefix)," or state that the single-pass yields
`HASH(entry)` and the `0x00` is prepended by the caller. Make the leaf
prefix explicit and identical in both paths.

### 1.2 [CRIT] `MTCSignature` ordering rule under-specifies the comparator
**Where:** MTC §6.1: "Elements MUST be ordered by `cosigner_id`. Shorter
byte strings are ordered before longer byte strings … same length are
ordered lexicographically … a parser MUST reject … if they are not
ordered correctly."
**Why it matters:** This is "shortlex," **not** plain lexicographic /
`memcmp`. For `cosigner_id` values `0x02` vs `0x0101`, shortlex orders
`0x02` (len 1) first, but `memcmp` orders `0x0101` first. An
implementer who uses ordinary lexicographic comparison both wrongly
accepts and wrongly rejects proofs — and it is a `MUST reject` rule, so
the divergence is a hard interop break. Separately, it is unstated
whether the comparison is over the `TrustAnchorID` *value* octets or the
*length-prefixed wire encoding* (they coincide here only because the
1-byte length prefix is the dominant shortlex key).
**Suggestion:** State that the comparison is over the value octets,
that the order is length-first then lexicographic (explicitly "not
`memcmp`"), and give a two-value worked example. Note in §6.2 that an
authenticating party adding a cosignature MUST re-sort/re-dedup.

### 1.3 [CLARIFY] `HASH(subjectPublicKeyInfo)` OCTET STRING framing is only implicit in the step-by-step path
**Where:** MTC §7.2 step 7.3 ("Set subjectPublicKeyInfoHash to the hash
of the DER encoding of subjectPublicKeyInfo") vs single-pass steps 6–8
(which explicitly emit `0x04 L H`).
**Why it matters:** The two agree only because the §5.2.1
`subjectPublicKeyInfoHash` field is an `OCTET STRING`, so its DER
encoding includes the `04 L` header — but step 7.3 never says so. An
implementer hashing the raw digest bytes (no `04 20` prefix) diverges.
**Suggestion:** In step 7.3, say the value is the OCTET STRING
containing the hash and that the DER hashed in step 8.3 includes the
`04 L` prefix.

### 1.4 [CLARIFY] Leaf (`0x00`) and interior (`0x01`) prefixes are never stated in §4
**Where:** §4 presents a self-contained subtree primitive ("extends the
Merkle Tree definition in RFC 9162") and uses `HASH(0x01 || …)` inline
for interior nodes, but the leaf prefix `0x00` is defined only later in
§7.2. Domain separation is security-critical and the primitive section
omits half of it.
**Suggestion:** State both prefixes in §4 with a pointer to RFC 9162
§2.1.1.

### 1.5 [CLARIFY] `MerkleTreeCertEntryExtension` field type doesn't match its enum
**Where:** §5.2.1 declares `enum { (2^16-1) } MerkleTreeCertEntryExtensionType;`
then defines `struct { ExtensionType extension_type; … }` — the field is
typed `ExtensionType`, not the just-declared `MerkleTreeCertEntryExtensionType`.
**Why it matters:** This field is the leading hashed bytes of every log
entry; an ambiguity about its width or governing registry touches
`entry_hash`. Almost certainly a typo, but it sits on the hashed
structure.
**Suggestion:** Use `MerkleTreeCertEntryExtensionType` and confirm
`uint16`.

### 1.6 [CLARIFY] Empty-tree / size-0 / single-element boundaries undefined
**Where:** §4.1 requires `0 ≤ start < end ≤ n` (minimum subtree size 1,
`[0,0)` excluded), but §5.2/§5.2.3 permit checkpoints of any tree size
including 0, and §4.4.1's recursion assumes `n > 1` after its base case.
The empty-tree hash `MTH({}) = HASH("")` (RFC 9162) is never restated,
and signing a size-0/size-1 checkpoint has no defined behavior.
**Why it matters:** A CA that publishes an early/empty checkpoint, and a
cosigner observing a fresh log, have no defined root hash. (cactus
initially returned all-zeros for the empty tree and had to be corrected
to `SHA-256("")` — a place the spec's silence produced a real bug.)
**Suggestion:** State `MTH(D_0) = HASH("")` and define (or forbid)
checkpoint signatures below some tree size. The C2SP `tlog-checkpoint`
spec, which explicitly allows size 0, should also state the empty root
is `base64(SHA-256(""))`.

### 1.7 [EDIT] `find_subtrees` prose refers to undefined `left` *(verified in §4.5)*
**Where:** §4.5 step 4 says "Within the least significant split bits of
**left** …" but the reference Python uses `start`
(`left_split = (~start & mask).bit_length()`), and `left` is not defined
until later. **Suggestion:** s/left/start/ in the prose.

---

## 2. The checkpoint / cosignature / timestamp model

This cluster is the subtlest integration hazard: MTC, tlog-cosignature,
and tlog-witness describe overlapping-but-not-identical signature
objects, and the relationships are never stated in one place.

### 2.1 [CRIT] "The CA signs a checkpoint," but the wire format has only subtree signatures
**Where:** MTC §3 step 3b and §6.2 steps 1/4 speak of "checkpoint
signatures"/"checkpoint cosignatures," but §5.3.1 defines only
`CosignedMessage` (a `(start, end, subtree_hash)` signature). A
checkpoint signature is evidently the `[0, tree_size)` subtree case, but
the draft never states the equivalence, and the MTC profile's own TODO
admits "MTC's draft never actually signs checkpoints."
**Why it matters:** An implementer of §6.2 cannot tell whether
"checkpoint signature" is a distinct artifact to produce/collect or just
the whole-tree subtree signature; §6.1's MTCProof carries only
`timestamp=0` subtree signatures, so the §6.2 "checkpoint cosignatures"
never appear in the cert. The terms read as two objects when there is
one.
**Suggestion:** State explicitly that a checkpoint signature is a
subtree signature over `[0, tree_size)`, and define which `timestamp`
applies in each context.

### 2.2 [CRIT] `timestamp` makes checkpoint cosignatures and MTC cert cosignatures non-substitutable, and nobody says so
**Where:** MTC §6.1: the MTCProof `timestamp` "MUST be zero."
tlog-cosignature: for `start=0` the timestamp "MAY be zero"; if `start`
is non-zero it MUST be zero. tlog-witness `add-checkpoint`: the returned
cosignature "MUST NOT omit the timestamp, i.e. the timestamp MUST NOT be
zero." `sign-subtree`: "the timestamp MUST be zero."
**Why it matters:** A witness's *checkpoint* cosignature (obtained via
`add-checkpoint`, timestamp ≠ 0) is a valid signature over the same
`(0, size, root)` tuple but is **byte-incompatible** with what an MTC
standalone cert needs (timestamp = 0), because the timestamp is inside
the signed message. A CA that reuses the checkpoint cosignature it
already collected will ship certs that fail verification; the only
spec-defined source of an MTC-usable signature is `sign-subtree`. This
is the single most likely cross-implementation bug at the boundary, and
no document states the two signatures are different objects.
**Suggestion:** In the MTC profile (or tlog-cosignature), state that MTC
certificate cosignatures are the `timestamp=0` variant obtained via
`sign-subtree`, and are distinct from the timestamp-bearing checkpoint
cosignatures from `add-checkpoint`.

### 2.3 [CLARIFY] `sign-subtree` is effectively mandatory for MTC cosigners but only SHOULD
**Where:** `mtc-tlog-draft.md` §Cosigners: a witness/mirror used in
standalone certs "MUST be an MTC cosigner … It SHOULD implement the
`sign-subtree` endpoint." But per 2.2, `sign-subtree` is the only
spec-defined way to obtain the `timestamp=0` subtree signature a
standalone cert requires.
**Why it matters:** A conforming-but-`sign-subtree`-less cosigner cannot
supply usable cosignatures, making standalone certs naming it
unconstructable — an internal inconsistency (MUST-be-a-cosigner +
SHOULD-implement-the-only-mechanism).
**Suggestion:** Upgrade `sign-subtree` to MUST for any cosigner used in
standalone certificates, or describe the alternative path.

### 2.4 [CLARIFY] The `subtree/v1\n\0` label is shared across roles; cross-protocol replay is only informally excluded
**Where:** The identical 12-byte label and `CosignedMessage` struct cover
both whole-tree checkpoint statements and subtree certifications; the
semantics ride entirely on `start`/`timestamp`. tlog-cosignature notes
"subtrees with non-zero start values currently don't have a checkpoint
representation" but does not forbid a `(cosigner,key)` from producing a
`start=0, timestamp=0` message for a non-MTC purpose, which would be
byte-identical to an MTC whole-tree certification.
**Suggestion:** State that a key used for MTC MUST NOT produce
`start=0, timestamp=0` `CosignedMessage` signatures for any other
meaning, tying the existing "distinct cosigner ID per role" guidance to
the byte level.

---

## 3. The tiled-log profile (`mtc-tlog-draft.md`) vs C2SP `tlog-tiles`

### 3.1 [CRIT] tlog-tiles requires an Ed25519 checkpoint signature; the profile is ML-DSA-44-only and silent *(verified)*
**Where:** The profile: the issuance log "MUST serve issuance logs as
tiled transparency logs" and the checkpoint "MUST [include] a signature
from its CA cosigner," which "MUST use an ML-DSA-44 key." `tlog-tiles`:
"If the log is public, or is interacting in any way with the public
witness network, the checkpoint MUST carry at least one Ed25519
signature by the log."
**Why it matters:** A public MTC log following both specs is contradicted:
ML-DSA-44 CA cosignature vs a mandatory Ed25519 log signature. The
profile's "MAY serve additional cosignatures" does **not** relax a
`tlog-tiles` MUST. An implementer cannot tell whether an MTC log must
also hold an Ed25519 log key.
**Suggestion:** The profile must explicitly either (a) require an
additional Ed25519 log key and define its name, or (b) profile out the
`tlog-tiles` Ed25519 requirement (and get `tlog-tiles` to permit a
PQ-only alternative for this ecosystem).

### 3.2 [CRIT] Pruning rule is unsatisfiable as written and mismatches subtree granularity
**Where:** Profile: "an issuance log MUST set its minimum index such
that only expired entries are pruned." `tlog-tiles` prunes at
whole-tile/bundle granularity and 404s resources with
`end_index ≤ minimum_index`.
**Why it matters:** (a) Expiry order need not match index order (entry K
may outlive K+1 with variable validity), so "only expired entries are
pruned" may be unsatisfiable for any minimum index past the
earliest-unexpired entry. (b) A standalone/landmark cert's subtree
`[start, end)` is fixed at issuance; if the minimum index advances past
`end`, the inclusion-proof tiles become unfetchable even for an
unexpired cert; a subtree that *straddles* the minimum index has
undefined status. (c) `tlog-tiles` requires an ecosystem retention
policy or `minimum_index` MUST be 0 — the profile doesn't establish one.
**Suggestion:** Define "expired" (validity-end vs now, with skew),
require `minimum_index` never exceed the index of the earliest
non-expired entry, prune at landmark-subtree granularity so no valid
cert's proof is lost, and state the retention policy `tlog-tiles`
demands (e.g. CAs SHOULD retain expired entries ≥ 6 months — currently
only a relying-party-side MAY, which the log cannot enforce).

### 3.3 [CRIT] CA-prefix-URL ⊕ log-number join (slashes, canonical decimal) is unspecified
**Where:** Profile: per-log prefix is "`<CA prefix>/<log number>`,"
log number "encoded as an ASCII decimal integer." `tlog-tiles` derives
resource URLs by concatenation and defines origins with "no trailing
slashes."
**Why it matters:** Trailing slash on the CA prefix → `…//42`; leading
zeros → `/042` vs `/42`. Each yields different, non-interoperable tile
URLs and a different `tlog-tiles` prefix. The worked example only shows
the *origin* (derived from the log ID), not the URL.
**Suggestion:** Define the CA prefix URL as having no trailing slash,
the join as `<prefix> "/" <decimal-no-leading-zeros>`, and give a
concrete URL example. Same fix for the `/<log number>/landmarks` URL,
and bind that resource to the MTC §6.3.3 format + `text/plain;
charset=utf-8`.

### 3.4 [CLARIFY] The TrustAnchorID → origin/name mapping isn't pinned (canonicalization, length)
**Where:** Profile §Trust Anchor IDs: name = `oid/1.3.6.1.4.1.` +
"the trust anchor ID's ASCII representation."
**Why it matters:** (a) No canonical-form rule (leading zeros in arcs,
empty ID), yet the name is hashed into the signed-note key ID and must
match byte-for-byte across CA, witness, and RP. (b) A trust anchor ID's
binary form can be up to 255 bytes; the derived ASCII name plus prefix
can exceed the `cosigner_name`/`log_origin` `<1..2^8-1>` (max 255) field,
with no stated bound — a legal ID can produce an unserializable name.
(c) Two "equivalent" constructions are given with neither marked
normative.
**Suggestion:** Require canonical dotted-decimal (minimal arcs, no
leading zeros), assert injectivity, bound IDs so the derived name ≤ 255
bytes, and pick one construction as normative.

### 3.5 [EDIT] Dead link and unpinned references in the profile
**Where:** `[note signature](http://signed-note)` is a placeholder URL
(should be `https://c2sp.org/signed-note@vX`); the `sign-subtree`
reference points at PR #245; the profile cites trust-anchor-ids `-04`
while the repo carries `-03`. See also §6 on the unmerged-PR risk.

---

## 4. Landmarks

### 4.1 [CLARIFY] Who allocates landmarks, and how cadence is "agreed across the ecosystem"
**Where:** §6.3.1 frames a landmark as "an agreed tree size, as a common
point of reference across the ecosystem," but §6.3.1/§6.3.2 make
allocation and `time_between_landmarks` purely unilateral per-CA. There
is no coordination mechanism or second party.
**Why it matters:** "Agreed across the ecosystem" implies a protocol
that does not exist; an implementer may look for alignment between CAs'
landmark sequences. **Suggestion:** Reword to state each CA maintains
its own sequence; the "common reference" is between that CA's
authenticating parties and its relying parties.

### 4.2 [CRIT] The landmark publishing format omits the log number (and is unauthenticated)
**Where:** §6.3.3 publishes `last_landmark`, `num_active_landmarks`, then
decreasing tree sizes — with no field identifying *which* log. §7.4's
trusted-subtree data model requires "the log number of the containing
log."
**Why it matters:** A CA runs multiple logs, each with its own landmark
sequence; the format cannot say which log it describes, and it is
unclear whether there is one file per log. The format is also plain
integers over HTTP with no authentication/freshness, while §7.4 treats
it as untrusted input requiring a consistency check — a tension §6.3.3
never flags.
**Suggestion:** Add a log-number field (or define one file per log with
a deterministic URL), state the file is unauthenticated and the §7.4
consistency procedure is mandatory before trust, and add freshness
guidance.

### 4.3 [CLARIFY] `max_active_landmarks` is needed by relying parties but never delivered to them
**Where:** §8.2.1 defines landmark-group membership in terms of
`max_active_landmarks`; §6.3.1 sizes RP state as "2 ×
max_active_landmarks." But `max_active_landmarks` is not in
`MTCCertificationAuthority` (§5.5 / Appendix A carries only `logHash`,
`sigAlg`, `minSerial`) and is not in the published landmark file.
**Why it matters:** CA and RP must agree on `max_active_landmarks` to
agree on group contents and on how much state to retain, but no channel
conveys it. **Suggestion:** Add it to the CA extension, or state it is
conveyed via trust-anchor-ids group configuration and the RP does not
compute membership itself.

### 4.4 [CLARIFY] "Active" has two definitions (count vs expiry) that only coincide under the RECOMMENDED allocation
**Where:** §6.3.1: active = "the most recent `max_active_landmarks`
landmarks," *and* "only active landmarks contain unexpired certificates."
The recommended §6.3.2 allocation makes these agree, but it is
RECOMMENDED, not MUST.
**Why it matters:** Under a non-recommended cadence the count-based and
expiry-based notions diverge, and the RP — which sees only
`num_active_landmarks` — cannot tell which trusted subtrees are safe to
drop. Cadence/parameter *changes* over time are also undefined.
**Suggestion:** Make the published active set authoritative, state
authenticating parties MUST NOT ship landmark-relative certs against
landmarks outside it, and describe behavior across cadence changes
(grow-only).

### 4.5 [CRIT] Landmark-group OID arcs (`.1.` vs `.2.`) are easy to transpose
**Where:** §8: a standalone cert's trust anchor ID is the bare CA ID; a
landmark-relative cert carries `CA.1.log.landmark`; the RP advertises the
group `CA.2.log.landmark`; and `CA.0.log` is a log ID. The near-identical
examples `32473.1.1.8.42` and `32473.1.2.8.42` differ only in the
`logs(0)/landmarks(1)/landmarkGroups(2)` constant.
**Why it matters:** Implementers will transpose which ID the
*certificate* carries vs. which the *relying party advertises*, causing
silent TLS negotiation failures. **Suggestion:** Add one table mapping
{standalone, landmark-relative cert ID, landmark-group advertisement} to
their arcs with a single consistent example.

### 4.6 [CLARIFY] Version→timestamp mapping for timestamped landmark groups is "predictable" but undefined
**Where:** §8.2.2: groups "SHOULD define versions predictably based on
the time. For example, … increment the version component every hour."
No concrete epoch/period/rounding. **Suggestion:** Define a concrete
convention or state it is part of trust-anchor-ids group configuration
and out of scope, with a pointer.

---

## 5. ACME issuance (§9)

### 5.1 [CRIT] The download body format is entirely punted, and the boundary + media-type registration are unclear
**Where:** §9 references `application/pem-certificate-chain-with-properties`
and says to "include trust anchor ID information as described in
[trust-anchor-ids] §7," but defines no PEM framing or property-list
structure here, never states "the format is wholly defined there," and
§13 (IANA) does not register the media type (nor say who does).
**Why it matters:** An implementer reading only MTC cannot build or parse
the response, cannot tell whether MTC adds properties on top of the TAI
base, and the media type has no registration owner.
**Suggestion:** State the body format is wholly defined by
trust-anchor-ids §7 with no MTC-specific additions (or enumerate them),
and add the media-type registration (or name the registering document).

### 5.2 [CRIT] Order becomes "valid" on sequencing, before the standalone cert can be assembled
**Where:** §9: the order moves to "valid" "once the corresponding entry
is sequenced," and the certificate URL "then serves the standalone
certificate." But §6.2 cannot construct the standalone cert until
cosignatures are collected (which §10.2 notes "may take longer").
**Why it matters:** At the instant the order is "valid," the certificate
URL may be unable to serve a complete cert. RFC 8555 clients expect a
valid order's cert to be downloadable. Implementers will diverge on
whether to delay "valid" or to 503/error the cert URL meanwhile.
**Suggestion:** Define the certificate URL's behavior between "sequenced"
and "fully cosigned" — either delay "valid" until the standalone is
constructible, or specify a 503 + Retry-After on the certificate URL too.

### 5.3 [CLARIFY] Alternate URL has no terminal/failure semantics, and legacy-client behavior is undefined
**Where:** §9: before the landmark-relative cert exists the alternate URL
"SHOULD return 503"; clients "SHOULD retry." No upper bound, no `404`
terminal for "never available" (e.g. the cert expires before a covering
landmark), no `Retry-After` estimation guidance. Separately, the
behavior when a client does *not* send the new `Accept` header is
unspecified (plain chain? trust-anchor-ID info lost?).
**Suggestion:** Specify a terminal condition distinct from "not yet," and
define the default/legacy-client response.

---

## 6. Trust policy, predistribution, and revocation (§7.3–§7.5)

### 6.1 [CLARIFY] No normative floor on the cosigner policy — CA cosigner is SHOULD, "quorum" is undefined
**Where:** §7.3 "does not prescribe a particular policy." RPs "SHOULD
ensure authenticity by requiring a signature from the CA cosigner key";
"quorum" is used without a numeric definition; unrecognized cosigners
"MUST be ignored."
**Why it matters:** With an empty policy and a CA-cosigner-only-SHOULD, a
degenerate RP accepting a cert with no CA signature is not clearly
forbidden. Authenticating parties (who must attach "sufficient"
signatures) and RPs have no common, comparable policy language.
**Suggestion:** Make the CA cosigner signature a MUST (authenticity
floor), and give a parameterized way to express "quorum" (k-of-named-set)
so policies are comparable and communicable.

### 6.2 [CLARIFY] §7.4 mandates a consistency check, then permits delegating it wholesale to an "update service"
**Where:** §7.4: the RP "MUST obtain assurance that each subtree is
consistent with checkpoints observed by a sufficient set of cosigners,"
then "MAY trust the update service to perform these checks" if it
"considers the service sufficiently trusted." No authentication is
defined for the predistribution channel, and no minimum criteria for
"sufficiently trusted."
**Why it matters:** The transparency guarantee of a landmark-relative
cert collapses to "trust whoever ships your trust store," and is not
visible from the cert. The mapping from a §7.3 policy ("signed this
subtree") to the §7.4 form ("observed a consistent checkpoint") is also
left implicit, so the security level of a landmark-relative cert may
silently differ from its standalone twin.
**Suggestion:** Separate the verification obligation from who may perform
it; state minimum integrity requirements on the (possibly delegated)
channel; define how a §7.3 policy translates to the §7.4 consistency
form; add reference-checkpoint freshness guidance.

### 6.3 [CLARIFY] `minSerial` is a single scalar that cannot express per-log floors, and §7.2 never references it
**Where:** §5.5/§7.1: `minSerial` "can be used to set a minimum allowed
log number *or* a minimum allowed index in a particular log," but
serial = `(log_number << 48) | index`, so one threshold cannot
independently floor multiple active logs. §7.2's verification steps never
mention enforcing `serial ≥ minSerial`.
**Suggestion:** Specify the exact comparison and where §7.2 enforces it;
clarify that per-log pruning floors are expressed via the §7.5 revoked
ranges, not `minSerial`; give a two-log example.

### 6.4 [CLARIFY] Revoked-range distribution has no format, channel, authentication, or precedence rules
**Where:** §7.5/§7.1: the RP "maintains a list of revoked ranges" and
"MAY incorporate additional ranges from out-of-band information." No wire
format, distribution mechanism, authentication, ordering/overlap rules,
or relationship to the (signed) `minSerial` floor are defined.
**Why it matters:** Revocation is security-critical; an unauthenticated
channel is a withholding/downgrade vector, and it is unstated whether
out-of-band data can only *add* revocations (safe) or could shrink the
`[0, minSerial)` floor (dangerous).
**Suggestion:** Require the channel be authenticated to the CA trust
root, recommend a concrete format (sorted, non-overlapping half-open
`[lo, hi)` serials), and state the effective set is the union (add-only).

---

## 7. Identifiers, OIDs, ASN.1, and algorithm agility

### 7.1 [CLARIFY] Experimental placeholder OIDs are scattered in prose, with a wire-format divergence and no migration plan
**Where:** The `1.3.6.1.4.1.44363.47.*` placeholders for `id-alg-mtcProof`,
`id-rdna-trustAnchorID`, and `id-pe-mtcCertificationAuthority` appear only
in body prose; §13 (IANA) lists the to-be-assigned values as TBD and
never mentions the experimental arc. Worse, §5.1's experimental mode also
changes the *encoding* (the trust-anchor-ID attribute is a `UTF8String`
"for initial experimentation" instead of the `RELATIVE-OID` the ASN.1
module defines).
**Why it matters:** Experimental deployments are mutually incompatible
during migration, and the encoding change (not just an OID swap) means
two experimenters who switch at different times can't interoperate.
**Suggestion:** Add a consolidated experimental→assigned table (including
the encoding difference) and a transition policy stating verifier
behavior during the switchover.

### 7.2 [CLARIFY] The ASN.1 module omits structures the prose/§8 depend on
**Where:** Appendix A defines `id-alg-mtcProof` with absent params but
cannot capture the `MTCProof` BIT STRING contents (TLS syntax) and gives
no comment pointing to §6.1; `MTCCertificationAuthority` carries only
`logHash`/`sigAlg`/`minSerial` (not `max_active_landmarks` or landmark
cadence — see 4.3); `at-trustAnchorID` is typed `RELATIVE-OID` while §5.1
mandates `UTF8String` in the experimental mode; `minSerial` is an
unbounded INTEGER while serials are 64-bit structured values.
**Suggestion:** Add comments tying the module to the out-of-ASN.1 pieces,
reconcile the experimental encoding, and either carry the landmark
parameters or state they come from trust-anchor-ids config.

### 7.3 [CLARIFY] One certificate carries the same cosigner identity in two encodings
**Where:** A cosigner is named in ASCII (`oid/1.3.6.1.4.1.<TAI>`, the
signed-note key name) but encoded in binary (`MTCSignature.cosigner_id`
= RELATIVE-OID content octets) within the same certificate; the dual
encoding is never called out.
**Suggestion:** Add a note that both derive from one trust anchor ID, in
ASCII on the note line and binary in the MTCProof.

### 7.4 [CLARIFY] Algorithm agility is claimed but only SHA-256 / ML-DSA-44 is fully specifiable end to end
**Where:** §5.3.3 ("any PKIX signature algorithm MAY be used") and the
`HashValue[HASH_SIZE]` fixed-length fields. But `HASH_SIZE` for *parsing*
a certificate's MTCProof is known only from the trusted CA's `logHash`
(Appendix A) — an implicit dependency the parser must resolve before it
can parse — and the only fully specified signature context is ML-DSA's
empty context. For a non-ML-DSA scheme, how a native context string
composes with the `subtree/v1\n\0` label is unspecified. The single-pass
hash also assumes `L ≤ 127` (1.3) which silently caps the digest size.
**Suggestion:** State that `HASH_SIZE` is bound by the trusted CA's
`logHash`; give the rule for composing the label with schemes that have
native context strings (or restrict to empty/absent-context schemes);
either cap registered digests at ≤127 bytes or have the single-pass emit
long-form DER length.

---

## 8. Normative-reference and process risks

### 8.1 [CRIT] Circular, unmerged, version-skewed normative references
**Where:** MTC's profile depends on `sign-subtree`, defined only in the
unmerged C2SP PR #245. That `tlog-witness` text normatively cites
`draft-ietf-plants-merkle-tree-certs-03` §4.4 for the subtree consistency
proof, while the profile and current work are `-04`; `tlog-cosignature`
references `-02`. So MTC → unmerged C2SP PR → older MTC draft.
**Why it matters:** A witness and CA built against different draft
revisions can disagree on the consistency-proof structure (→ `422`s), and
citing a mutable PR as normative is a publication hazard.
**Suggestion:** Merge `tlog-witness` before MTC cites it normatively; pin
the consistency-proof reference to a stable MTC version; confirm `-03`
§4.4 == `-04` §4.4 algorithmically.

### 8.2 [CRIT] `sign-subtree` doesn't enumerate failure status codes, especially for the DoS gate
**Where:** `tlog-witness` `add-checkpoint` exhaustively lists
404/403/400/409/422/200, but `sign-subtree` has no comparable table. The
DoS-gate cosignature is entirely "MAY," "witnesses MUST ignore subtree
cosignatures from unknown keys," and there is no status for "gate
required but missing/failed," no rate-limit status, and no way for a CA
to discover which gate key a witness accepts. The `409` body's
`Content-Type` is also unspecified (unlike `add-checkpoint`'s
`text/x.tlog.size`).
**Why it matters:** The MTC CA is the `sign-subtree` client. Without a
status table it cannot distinguish "retry with a gate cosignature" from
"permanently refused," and witnesses by different authors return
different codes — breaking the public-witness interoperability MTC
envisions. (cactus had to pick `403` for the gate-failure case; another
implementation might pick `400`/`401`/`429`.)
**Suggestion:** Add a `sign-subtree` status-code table mirroring
`add-checkpoint`, a normative code for the DoS-gate case, a `Content-Type`
for the `409` body, and a gate-key discovery mechanism (or state the gate
key is part of witness config distributed to clients).

### 8.3 [CLARIFY] signed-note's `0x06` entry doesn't state the ML-DSA-44 public-key encoding/length
**Where:** signed-note assigns signature type `0x06` to "Timestamped
ML-DSA-44 (sub)tree cosignatures" but, unlike the Ed25519 `0x01` entry
("32 bytes according to RFC 8032"), does not state the public-key
material (the 1312-byte raw FIPS 204 encoding); only tlog-cosignature
does.
**Why it matters:** Key IDs are `SHA-256(name || 0x0A || 0x06 ||
pubkey)[:4]`. If two parties disagree on the key encoding, their key IDs
differ and all signatures are *silently ignored* (verifiers MUST ignore
unknown keys) — a silent failure. **Suggestion:** Reference the
1312-byte raw encoding in signed-note's `0x06` bullet, as the `0x01`
entry does for Ed25519.

---

## What is well-specified (checked, not gaps)

- The `trust_anchor_id` CertificateProperty codepoint **is** pinned
  (`trust_anchor_id(0)`) in trust-anchor-ids §6.
- The `CERTIFICATE PROPERTIES` PEM label and element order (property list
  first, then EE cert) **are** pinned in trust-anchor-ids §6.1 (only the
  worked example is a TODO).
- The TrustAnchorID binary representation (RELATIVE-OID content octets;
  `32473.1 → 81 fd 59 01`) and its non-minimal/truncation rejection rules
  are unambiguous in trust-anchor-ids §3.
- MTCProof signature *dedup/ordering enforcement* is explicitly a
  `MUST reject` (the only gap is the comparator definition, 1.2).

---

## Priorities for the authors

If triaging, the highest-leverage fixes are:

1. **1.1** — the single-pass `entry_hash` is missing the `0x00` leaf
   prefix (a concrete, silent, total interop break).
2. **2.1 / 2.2** — pin down "checkpoint signature" = `[0,size)` subtree
   signature, and that MTC cert cosignatures (`timestamp=0`,
   `sign-subtree`) are distinct from checkpoint cosignatures
   (`timestamp≠0`, `add-checkpoint`).
3. **3.1** — resolve ML-DSA-44-only vs the `tlog-tiles` Ed25519 MUST.
4. **5.1 / 5.2** — define the §9 download body's spec boundary and the
   certificate URL's state between "sequenced" and "cosigned."
5. **8.1 / 8.2** — stabilize the `sign-subtree` normative reference and
   give it a status-code table (it is the load-bearing CA↔witness API).
6. **1.2** — the shortlex comparator for MTCProof signature ordering.
