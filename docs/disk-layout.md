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
- `log/tile/<L>/...` files are written exclusive (`O_EXCL`) once they
  reach the full width; partial widths (`*.p/<W>`) are append-only by
  width but each width has its own immutable file.

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
