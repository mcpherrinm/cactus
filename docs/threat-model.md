# Threat model

Cactus is **not** a production CA. This document explains what we
explicitly do not protect against, so nobody mistakes its convenience
for safety.

## Single-writer assumption

The issuance log uses **no fcntl, no SQLite CAS, no S3 conditional
writes**. The operator must not run two cactus instances against the
same `data_dir`. If they do, both will append concurrently to the
same tile files and corrupt the tree. We do not detect this.

This is the same simplification pebble makes for ACME.

## No fsync ladder

Every tile / state write uses `O_RDWR | O_CREATE` + `rename(2)`, but
we do not fsync the parent directory between rename and the next
operation. A power loss may leave the on-disk state inconsistent with
the most recent reported `Wait()` result. **Don't use cactus on a
host that loses power.**

## Auto-pass challenges

In `auto-pass` challenge mode, every authorization is marked `valid`
the moment the order is created. **Anyone who can reach the ACME
listener can obtain a certificate for any name.** This is fine for
local testing, awful for anything else.

## Tile data trust

Cactus does not validate that the entry blobs in data tiles are
parseable MerkleTreeCertEntry structures. If you tamper with a tile
file out-of-band, the next reload will replay garbage through
`tlog.StoredHashes` and produce a tree the server happily continues
with — but the resulting cosigner signatures will be over a tree
nobody else has ever seen. Don't tamper with the data dir.

## Cosigner key handling

The CA cosigner private key is derived from a 32-byte seed at
`keys/ca-cosigner.seed`. The seed is generated with
`crypto/rand.Read` (and so depends on the OS PRNG); it sits on disk
with mode 0600 but with no HSM, no encryption at rest, nothing
fancier. Anyone who can read the seed can mint certificates that
verify against `cactus_acme_orders_total`.

## What's intentionally OK

- **Restart-resume**: in-flight orders that were `valid` at restart
  continue to serve their cert. Orders in `processing` may be re-
  driven; the log's idempotency key on the TBS entry hash means
  re-`Append` is safe.
- **Concurrent ACME requests** within one process: the log is
  goroutine-safe under `-race`.
