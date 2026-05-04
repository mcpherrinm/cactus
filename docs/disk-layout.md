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
│   │   ├── 8/0/...               level-0 hash tiles (height 8)
│   │   ├── 8/0/000.p/<W>         partial tiles (W < 256)
│   │   ├── 8/1/...               level-1 hash tiles
│   │   └── 8/data/...            level=-1 data tiles (entry blobs)
│   └── subtrees/
│       └── <start>-<end>         per-subtree signature blob
└── state/
    ├── accounts/<id>.json        ACME accounts
    ├── orders/<id>.json          ACME orders
    ├── authzs/<id>.json          ACME authorizations
    ├── challs/<id>.json          ACME challenges
    └── certs/<cert-id>.der       issued cert DERs
```

## File semantics

- All non-exclusive writes go via `os.CreateTemp` + `os.Rename`, so
  readers never see a half-written file.
- `log/checkpoint` is the only file that gets rewritten in place
  (mutable), and the rename invariant covers it.
- `log/tile/8/N/...` files are written exclusive (`O_EXCL`) once they
  reach the full width; partial widths (`*.p/<W>`) are append-only by
  width but each width has its own immutable file.

## Hash-tile bytes

A tile at level L width W contains W concatenated 32-byte hashes at
storage level L*8. The bytes are exactly what `golang.org/x/mod/sumdb/tlog`
emits via `tlog.ReadTileData(t, hr)` — this matches the
[c2sp tlog-tiles] convention.

## Data tile bytes

Each data tile holds up to 256 entries, each encoded as:

```
uint24 length (3 bytes, big-endian) || MerkleTreeCertEntry bytes
```

This is **not** a published spec — it is an internal cactus convention.
A future tlog-tiles extension may pin a standard format; if so, we will
adopt it.

[c2sp tlog-tiles]: https://c2sp.org/tlog-tiles
