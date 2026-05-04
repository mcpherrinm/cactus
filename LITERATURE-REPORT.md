# Cactus literature review

**Date:** 2026-05-04. **Scope:** every normative reference in
`draft-ietf-plants-merkle-tree-certs-03` §14.1, plus the draft itself.

This is a snapshot review: per-spec relevance, findings, fixes that
landed in this pass, and findings deferred for later. The 17 fetched
specs live in `specs/`.

## Method

1. Pulled every normative reference cited in `draft-…-03` §14.1
   (`specs/rfc*.txt`, `specs/draft-ietf-tls-trust-anchor-ids-03.txt`,
   `specs/nist.fips.{180-4,186-5,204}.pdf`, `specs/x.690.pdf`).
2. Spawned six parallel review agents, each owning one spec group:
   ACME + HTTP, X.509 + ASN.1, Merkle / CT v2, Cryptography, MTC
   draft proper, and a sweep of small/tangential refs.
3. Each agent read the relevant spec sections and the specific
   cactus packages they govern, then returned a punch list with
   severities (BLOCKER / SHOULD-FIX / NIT / OK-NOTE).
4. Consolidated findings, fixed the BLOCKER and SHOULD-FIX items
   inline, captured the rest as deferred work.

## Per-spec relevance

| Spec | Relevance | What cactus must honor |
|---|---|---|
| **draft-…-merkle-tree-certs-03** | Defines everything | Wire formats, OIDs, cert assembly, log/checkpoint signing inputs, ACME extension semantics, ASN.1 module |
| **RFC 8555** (ACME) | High | §6 request signing/nonces/URL/Content-Type, §7 directory/account/order/finalize/cert resources, §8.1/§8.3 challenges |
| **RFC 9162** (CT v2) | High | §2.1.1 leaf+internal hash domain separators (`0x00`/`0x01`), §2.1.3/§2.1.4 inclusion+consistency proof algorithms (specialised by MTC §4) |
| **RFC 5280** (PKIX) | High | §4.1 TBSCertificate fields, §4.1.2.5 UTCTime/GeneralizedTime cutoff at year 2050, §4.1.2.2 serialNumber positivity+length, §4.2 extension criticality, §4.1.2.7 SPKI |
| **X.690** (DER) | High | §8 BER, §10/§11 DER restrictions (definite-length, minimum-length, BIT STRING padding, SET ordering) |
| **RFC 4648** (base64url) | High | §5 base64url, used by ACME JWS, JWK thumbprint (RFC 7638), CSR field |
| **RFC 9110** (HTTP) | Medium | §10.2.3 Retry-After, §15.6.4 503, §12.5.1 Accept negotiation |
| **FIPS 186-5** (DSS) | High | §6 ECDSA over P-256/P-384, Appendix A.2.1 rejection-sampled `k` |
| **FIPS 180-4** (SHS) | High | §6.2 SHA-256 (used by Go stdlib via `crypto/sha256`) |
| **RFC 8032** (EdDSA) | Medium | §5.1 PureEd25519 (32-byte SPKI raw, 64-byte sig, deterministic) |
| **FIPS 204** (ML-DSA) | Medium (build-tagged) | §3.4 / Algorithm 2 pure-mode prefix, deterministic mode |
| **RFC 5912** (PKIX ASN.1) | Low | Source of `Validity`, `Name`, `Extensions`, `AlgorithmIdentifier` types imported by MTC §A.1 |
| **draft-…-tls-trust-anchor-ids-03** | Medium | §3 binary representation of TrustAnchorID, §4.1 `opaque<1..2^8-1>` size cap, §6 CertificatePropertyList encoding |
| **RFC 8446** (TLS 1.3) | Low | §3 presentation language is the wire-format basis MTC inherits |
| **RFC 6960** (OCSP) | Trivial | Cited only in §10.4 to note that existing PKIX revocation continues to apply unchanged. Cactus does not implement OCSP. |
| **RFC 3629** (UTF-8) | Trivial | Used implicitly when emitting UTF8String in DNs and in ACME JSON. |
| **RFC 2119 / RFC 8174** | Trivial | Keyword-interpretation boilerplate. |

## Fixes landed in this pass

### BLOCKERs (3)

- **`url` header check (RFC 8555 §6.4)** — `acme/handler.go` now
  compares the JWS protected `url` to the absolute request URL
  (`s.urlFor(r.URL.Path)`) and rejects mismatches with `unauthorized`
  (HTTP 401). Previously `ParsedJWS.URL` was captured but never
  validated, allowing a JWS signed for one ACME endpoint to be
  replayed at a different endpoint.
- **POST-as-GET for cert download (RFC 8555 §6.3)** —
  `/cert/{id}` and `/cert/{id}/alternate` switched from `GET` to
  `POST`, and the handlers now require a signed JWS with empty
  payload, validate that the cert belongs to the requesting
  account, and emit a fresh `Replay-Nonce`. All eight test sites
  that previously did `http.Get` on these URLs now use a new
  `postAsGet` / `postAsGetWithAccept` helper.
- **UTCTime / GeneralizedTime cutoff (RFC 5280 §4.1.2.5)** —
  `cert/entry.go` and `ca/issuer.go` previously emitted
  GeneralizedTime unconditionally, in violation of the MUST that
  validity dates < 2050 use UTCTime. Replaced with
  `encodeRFC5280Time` that picks UTCTime (`0x17`,
  `YYMMDDHHMMSSZ`) for years 1950–2049 and GeneralizedTime
  (`0x18`, `YYYYMMDDHHMMSSZ`) for 2050+.

### SHOULD-FIX (10)

- **`badNonce` error type (RFC 8555 §6.5)** — `readJWS` now
  returns a typed `*jwsError` and the nonce-failure path maps to
  `urn:ietf:params:acme:error:badNonce` (instead of the previous
  `malformed`). `Replay-Nonce` is still always issued via
  `s.problem`/`problemFull`.
- **`badSignatureAlgorithm` with `algorithms` field (RFC 8555
  §6.2)** — `peekJOSEHeader` now extracts the protected header's
  `alg`. If it isn't in `AcceptedJWSAlgs`, `readJWS` returns a
  `badSignatureAlgorithm` problem with the `algorithms` array
  populated (added as a new `Algorithms []string` field on
  `Problem`).
- **Content-Type 415 (RFC 8555 §6.2)** — `readJWS` rejects
  anything other than `application/jose+json` with HTTP 415 +
  `malformed`, before reading the body.
- **`badCSR` mapping (RFC 8555 §7.4)** — `ca.Validator.Validate`
  now wraps its identifier-mismatch / signature / no-SAN errors
  with `errors.Is`-detectable `ca.ErrBadCSR`, and
  `handleFinalize` maps that to the `badCSR` problem type with
  HTTP 400 (instead of 500 + serverInternal).
- **ECDSA curve check (MTC §5.4.2)** — `cert/sigverify.go`
  `verifyECDSA` now takes the expected `elliptic.Curve` and
  rejects keys whose curve doesn't match the configured
  algorithm. Previously a P-384 SPKI tagged as
  `AlgECDSAP256SHA256` would silently use the P-384 curve.
- **Checkpoint signature verified on load (MTC §C.1)** —
  `log/log.go` `loadCheckpoint` now reconstructs the §5.4.1
  `MTCSubtreeSignatureInput` for `[0, size, root)` and verifies
  it against the configured CA cosigner's public key before
  trusting the on-disk state. New helper
  `parseSignedNoteFull` in `log/note.go` extracts the signature
  records.
- **`trust_anchor_id` property body fix (TAI §6)** —
  `cert/properties.go` was double-wrapping the value with an
  inner `uint8` length prefix. The body now carries the raw
  binary representation of the trust anchor ID directly. The
  255-byte cap from TAI §4.1 (`opaque<1..2^8-1>`) is still
  enforced as a sanity check.
- **Property list sorting + dedupe (TAI §6)** —
  `BuildPropertyList` now sorts entries by Type before encoding
  and rejects duplicates. `ParsePropertyList` now enforces
  ascending-Type order on read and rejects duplicates.
- **`issuerUniqueID` / `subjectUniqueID` parsing (RFC 5280
  §4.1, MTC §7.2)** — `cert/verify.go`
  `RebuildLogEntryFromTBS` previously parsed only one trailing
  context-specific element (assumed to be `[3] extensions`).
  Now it dispatches on tag number for `[1]`, `[2]`, `[3]`
  individually, preserves them in the rebuilt log entry, and
  rejects duplicates / unknown tags. The cactus issuer never
  emits `[1]`/`[2]` itself, so this is a verifier-side latent
  bug fix.
- **`serialNumber` uint64 encoding (RFC 5280 §4.1.2.2)** — the
  issuer's `AddASN1Int64(int64(serial))` would silently encode a
  log index ≥ 2^63 as a negative INTEGER. Switched to
  `AddASN1BigInt(new(big.Int).SetUint64(...))`. The verifier
  switched from `int64` to `big.Int` and accepts the 9-byte
  high-bit form, with `IsUint64()` as the cap.

### Test infrastructure changes

- `acme.handler_test.go` got a `postAsGet` helper used by all in-package
  tests that download a cert.
- `integration_test.go` got `postAsGetWithAccept` for tests that need
  to specify a custom Accept media type, plus an `acmeIssueOneWithKeys`
  variant that exposes the account key + kid so per-test cert
  re-downloads can authenticate.
- `acme.persist_test.go` `finalizeOneCert` now returns the account
  key + kid alongside the cert URL, so the post-restart cert fetch
  can do POST-as-GET against the rehydrated account.
- 11 test sites (8 in `acme`/`integration`, 3 in `landmark_*` tests)
  were updated from plain `http.Get` to POST-as-GET against
  `/cert/{id}` and `/cert/{id}/alternate`.

All 15 packages green after the rewrite.

## Findings deferred to a later pass

The following are real but were left out of this pass either because
they're cosmetic, latent (not exercised by current callers), or
require ecosystem-side decisions that haven't settled:

- **Trust-anchor-ID binary representation everywhere on the wire**
  (TAI §3) — cactus stores `TrustAnchorID` as ASCII bytes (e.g.
  `"32473.1"`) and feeds those bytes into TLS-presentation
  length-prefixed fields (`MTCSubtreeSignatureInput.cosigner_id`,
  `MTCSubtree.log_id`, the `trust_anchor_id` property body, the
  `MTCSignature.cosigner_id`). The interop-correct form is the
  binary representation = contents-octets of the relative-OID DER
  per TAI §3. This is a future-spec interop blocker, not a security
  bug; everyone in the cactus deployment agrees on ASCII for now.
  Tracking-issue territory.
- **PEM block label `MTC PROPERTIES` vs `CERTIFICATE PROPERTIES`**
  — TAI §6.1 fixes the label to `CERTIFICATE PROPERTIES`. Cactus
  uses `MTC PROPERTIES` deliberately while the spec is unstable
  (already commented in `cert/properties.go`).
- **`PropertyTrustAnchorID = 0` codepoint** — TAI §6 hasn't
  formally pinned the trust_anchor_id property type number; cactus
  uses 0 as a best guess. Confirm and align once trust-anchor-ids
  reaches WGLC.
- **Strict DER reparse of CSR bytes (MTC §12.6)** — cactus passes
  `csr.RawSubject`, `csr.RawSubjectPublicKeyInfo`, and each
  `csr.Extensions[i].Value` through verbatim into the log entry.
  Go's `encoding/asn1` produces DER on output and is reasonably
  strict on input, but a non-DER BER CSR could (in theory)
  produce a non-DER `TBSCertificateLogEntry`. A defensive
  re-encode pass would close this gap.
- **`SubjectPublicKeyInfo` hash hard-coded to SHA-256** —
  `cert/verify.go` line 126 uses `sha256.Sum256` directly. When a
  log uses a non-SHA-256 hash this needs to be parameterised.
- **Account `orders` URL not implemented (RFC 8555 §7.1.2.1)** —
  `AccountResp.Orders` is unset and there is no
  `/account/{id}/orders` POST-as-GET handler. Optional per the
  spec when there are no orders to enumerate; cactus has the
  data already (orders carry `AccountID`).
- **CORS `Access-Control-Allow-Origin: *` (RFC 8555 §6.1)** —
  not emitted; SHOULD per spec.
- **Replay-Nonce uses hex encoding** (RFC 8555 §6.5.1) — value is
  hex-encoded random rather than `base64url(rand)`. The wire
  characters happen to be a subset of the base64url alphabet so
  parsers won't reject, but it isn't a base64url encoding of an
  octet string.
- **Accept header q-value parsing (RFC 9110 §12.5.1)** — cactus
  uses `strings.Contains` on the Accept header rather than a
  parser; a client sending `q=0` would still get the
  with-properties form.
- **MTC.md / TODO.md spec references** — MTC.md mentions
  Appendix C.3 (cosig). The draft Appendix C only has C.1 and
  C.2 today. Update MTC.md if/when the cosig appendix lands.
- **Spec editorial nit upstream** — MTC §7.2 single-pass
  algorithm omits the leading `0x00` RFC-9162 leaf prefix that
  the prose definition requires. Cactus's `EntryHash` and
  `SinglePassEntryHash` correctly include the prefix; worth
  flagging upstream.
- **Test vectors** — the draft contains no test vectors;
  Appendix B is non-normative explanatory text. Cactus's lack of
  upstream test vectors is therefore not a gap, but its own
  integration tests (`TestParallelIssuance`,
  `TestRelyingPartyFastPath`, `TestEndToEndCAWithThreeMirrors`)
  serve as the de-facto fixture suite.

## Sections fully implemented / partially implemented / not implemented

**Fully implemented:** §3 Overview · §4.1 Subtree definition · §4.3
Subtree inclusion proofs (gen + eval) · §4.4 Subtree consistency
proofs (gen + verify) · §4.5 Arbitrary intervals (FindSubtrees) ·
§5.1 Log parameters · §5.2 Log IDs (experimental DN form) · §5.3 Log
entries (null + tbs_cert_entry, ASN.1 module conformance, single-pass
hash) · §5.4 Cosigners · §5.4.1 Signature format · §5.5 CA cosigner ·
§6.1 Certificate format · §6.2 Standalone certs · §6.3.1 Landmark tree
sizes · §6.3.2 Landmark allocation · §6.3.3 Landmark-relative cert
construction · §7.2 Verifying cert signatures · §9 ACME extensions ·
§A ASN.1 module (experimental-OID form) · §C.1 Subtree signed-note
format · §C.2 sign-subtree endpoint (mirror server side) and request
building (CA side).

**Partial / known gaps:** §5.4.2 ML-DSA verification (build-tag-gated)
· §5.6.1 Log pruning (not implemented) · §7.1 Trust anchors (no
formal trust-anchor representation; cactus is the issuer, not a
relying-party library beyond the CLI) · §7.3 Trusted cosigners
policy (single CA cosigner + N mirrors; no quorum-of-different-roles
policy engine) · §7.4 Trusted subtree predistribution (CA serves
`/landmarks`; RP-side ingest is in the integration test only) ·
§7.5 Revocation by index (stub list).

**Out of scope:** §8 Use in TLS (Phase-10+, the TLS stack lives
elsewhere).

## Files reviewed

Specs (under `specs/`): all 17 normative refs.

Code (under repo root):

- `acme/{handler,jose,keyauth,persist,readdir,state,types}.go`
  + tests
- `ca/{issuer,validator}.go` + tests
- `cert/{cosigner_request,dn,entry,landmark,oid,proof,properties,
   sha256_helper,sigverify,verify}.go` + tests
- `cmd/cactus/main.go`, `cmd/cactus-cli/{main,treeverify}.go`,
  `cmd/cactus-keygen/main.go`
- `config/config.go`
- `landmark/{handler,sequence}.go` + tests
- `log/{log,note}.go`, `log/tilewriter/tilewriter.go` + tests
- `mirror/{follower,note,note_parse,server}.go` + tests
- `signer/{mldsa,seed,signer,spki}.go` + tests
- `tile/server.go`
- `tlogx/{consistency,inclusion,subtree}.go` + tests
- `integration/*.go` (15 integration tests)

Docs reviewed and updated: this report. `MTC.md`, `README.md`,
`PROJECT_PLAN.md`, `TODO.md`, `docs/disk-layout.md`,
`docs/threat-model.md` were read; nothing in them is wrong against
the post-fix code, but the deferred items listed above remain
documented in `TODO.md`'s "Notes for future contributors" section.
