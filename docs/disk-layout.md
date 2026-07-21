# Disk layout

Everything cactus persists lives under the configured `data_dir`:

```
$DATA_DIR/
├── keys/
│   └── ca-cosigner.seed          32 bytes, mode 0600
├── log/
│   ├── checkpoint                latest signed-note checkpoint (mutable)
│   ├── state/
│   │   └── treeSize              uint64 BE; source-of-truth for log size on reload
│   ├── tile/
│   │   ├── 0/...                 level-0 hash tiles (c2sp tlog-tiles)
│   │   ├── 0/000.p/<W>           partial tiles (W < 256)
│   │   ├── 1/...                 level-1 hash tiles
│   │   └── entries/...           entry ("data") tiles
├── mirrorpush/
│   └── <8-byte-hash>.json        per-(log,mirror) resumable push state
└── state/
    ├── accounts/<id>.json        ACME accounts
    ├── orders/<id>.json          ACME orders
    ├── authzs/<id>.json          ACME authorizations
    ├── challs/<id>.json          ACME challenges
    ├── certs/<cert-id>.der       issued cert DERs
    └── landmarks/sequence.jsonl  append-only landmark sequence (§6.4)
```

Note: the per-subtree cosigner signatures are **not** persisted. They are
kept only in memory and travel inside issued certs (the MTCProof); see
`log/log.go` (`persistCheckpoint`). Only the mutable `log/checkpoint`
signed note is written.

## File semantics

- Every write goes via `os.CreateTemp` + `os.Rename` (the non-exclusive
  `storage.Put` path), so readers never see a half-written file.
- `log/checkpoint` is rewritten in place on every flush (mutable); the
  rename invariant covers it.
- Full hash/data tiles are immutable once written; partial data tiles
  (`*.p/<W>`) get a distinct file per width `W`, each written by the same
  temp-file + rename path. cactus does not currently use `storage.Put`'s
  exclusive (`O_EXCL`) mode for tiles.

## Hash-tile bytes

A tile at level L width W contains W concatenated 32-byte hashes at
storage level L*8. The bytes are exactly what `golang.org/x/mod/sumdb/tlog`
emits via `tlog.ReadTileData(t, hr)` — this matches the
[c2sp tlog-tiles] convention.

## Data tile bytes

Each entries ("data") tile holds up to 256 entries, each encoded as:

```
uint16 length (2 bytes, big-endian) || MerkleTreeCertEntry bytes
```

This is the [c2sp tlog-tiles] entry-bundle framing ("entry bundles are
sequences of big-endian uint16 length-prefixed log entries"), matching
the IETF reference tooling.

[c2sp tlog-tiles]: https://c2sp.org/tlog-tiles
