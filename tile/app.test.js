// Tests for the tile-browser UI logic in app.js. Run with: bun test tile/
//
// app.js auto-runs in the browser but stays inert under Bun (it checks
// globalThis.__CACTUS_TEST__, set below before the require), so we can import
// it directly and exercise the real functions. Functions that touch the DOM
// or network read the *global* `document`/`fetch`, which makeUI() swaps out
// per test, keeping tests isolated.
import { test, expect } from "bun:test";
import { readFileSync } from "fs";

globalThis.__CACTUS_TEST__ = true;
const app = require("./app.js");

// --- minimal DOM + fetch stubs -------------------------------------------
class El {
  constructor(tag) {
    this.tag = tag; this._value = ""; this.textContent = "";
    this._innerHTML = ""; this.style = {}; this.children = [];
    this.title = ""; this.className = ""; this.onclick = null;
  }
  get value() { return this._value; }
  set value(v) { this._value = String(v); }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(v) { this._innerHTML = v; if (v === "") this.children = []; }
  appendChild(c) { this.children.push(c); return c; }
  scrollIntoView() {}
  get options() { return this.children.filter((c) => c.tag === "option"); }
}

function makeUI() {
  const els = {};
  globalThis.document = {
    getElementById: (id) => (els[id] ||= new El("#" + id)),
    createElement: (tag) => new El(tag),
  };
  const fetches = [];
  globalThis.fetch = (url) => {
    fetches.push(url);
    return Promise.resolve({
      ok: true, status: 200,
      text: () => Promise.resolve(""),
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    });
  };
  return { els, fetches, document: globalThis.document };
}

// The byte-exact MerkleTreeCertEntry fixture (a v3 tbs_cert_entry), generated
// from the real cert package — see testdata/sample-entry.hex.
function fixtureEntry() {
  const h = readFileSync(new URL("./testdata/sample-entry.hex", import.meta.url), "utf8").trim();
  return new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
}

// =========================================================================
// tile math
// =========================================================================
test("treeHeight: levels (root level) for a tree of n entries", () => {
  for (const [n, want] of [[0, 0], [1, 0], [2, 1], [3, 2], [12, 4], [16, 4], [256, 8], [257, 9]]) {
    expect(app.treeHeight(n)).toBe(want);
  }
});

test("tileLevels: how many tiles tall, matching tlog.NewTiles", () => {
  for (const [n, want] of [[0, 0], [1, 1], [12, 1], [255, 1], [256, 2], [257, 2], [65535, 2], [65536, 3]]) {
    expect(app.tileLevels(n)).toBe(want);
  }
});

test("tileWidth: auto-sized partial/full widths from the tree size", () => {
  app.treeSize = 12;
  expect(app.tileWidth("entries", 0)).toBe(12);
  expect(app.tileWidth("0", 0)).toBe(12);

  app.treeSize = 300;
  expect(app.tileWidth("entries", 0)).toBe(256); // full first data tile
  expect(app.tileWidth("entries", 1)).toBe(44);  // partial remainder
  expect(app.tileWidth("0", 0)).toBe(256);
  expect(app.tileWidth("0", 1)).toBe(44);
  expect(app.tileWidth("1", 0)).toBe(1);         // one level-8 hash
  expect(app.tileWidth("entries", 5)).toBe(0);   // out of range
});

test("tileURL: only the partial frontier tile gets a .p/<width> suffix", () => {
  expect(app.tileURL("0", 0, 256)).toBe("tile/0/000");
  expect(app.tileURL("0", 0, null)).toBe("tile/0/000");
  expect(app.tileURL("entries", 1, 44)).toBe("tile/entries/001.p/44");
});

// =========================================================================
// dropdown / drill-down (DOM-stub driven)
// =========================================================================
test("populateLevels: tile levels high-to-low, entries last", () => {
  const { document } = makeUI();
  app.treeSize = 257; // 2 tiles tall
  app.populateLevels();
  const opts = document.getElementById("mlevel").options.map((o) => o.value);
  expect(opts).toEqual(["1", "0", "entries"]);
  const l0 = document.getElementById("mlevel").options.find((o) => o.value === "0");
  expect(l0.textContent).toBe("0 (leaf hashes)");
});

test("populateLevels: a small tree has only level 0 + entries", () => {
  const { document } = makeUI();
  app.treeSize = 12;
  app.populateLevels();
  expect(document.getElementById("mlevel").options.map((o) => o.value)).toEqual(["0", "entries"]);
});

test("drillDown from a hash level >= 1 descends to the child hash tile", () => {
  const { els, fetches } = makeUI();
  app.treeSize = 393216; // 3 tiles tall; level-1 tile 5 is full
  app.drillDown(2, 0, 5); // row 5 of tile (2,0) -> tile (1, 0*256+5)
  expect(els.mlevel.value).toBe("1");
  expect(els.mindex.value).toBe("5");
  expect(fetches.at(-1)).toBe("tile/1/005");
});

test("drillDown from level 0 descends to the aligned entry (data) tile", () => {
  const { els, fetches } = makeUI();
  app.treeSize = 393216;
  app.drillDown(0, 1, 3); // level-0 tile 1 lines up 1:1 with entries tile 1
  expect(els.mlevel.value).toBe("entries");
  expect(els.mindex.value).toBe("1");
  expect(fetches.at(-1)).toBe("tile/entries/001");
});

test("openEntry opens a tile-loaded entry without any extra fetch", () => {
  const { els, fetches } = makeUI();
  app.treeSize = 600;
  // Render a data tile so its entries are cached, then click one.
  const out = new El("#tileout");
  const buf = new Uint8Array([0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // one 4-byte null_entry blob
  app.renderEntriesTile(out, "tile/entries/000", buf, 0);
  app.openEntry(0);
  expect(els.eindex.value).toBe("0");
  expect(els.inspector.style.display).toBe("grid"); // inspector populated
  expect(fetches.length).toBe(0);                   // no network call
});

test("openEntry falls back to the standard data tile for an uncached entry", () => {
  const { els, fetches } = makeUI();
  app.treeSize = 600;
  app.openEntry(257); // not loaded from a tile yet → fetch its data tile
  expect(els.eindex.value).toBe("257");
  expect(fetches.at(-1)).toBe("tile/entries/001"); // tile 1 (full), standard path
});

// =========================================================================
// tile render output (the per-row drill links)
// =========================================================================
test("renderHashTile emits a drillDown link per node hash", () => {
  makeUI();
  app.treeSize = 393216; // ensure child level-0 tiles are full
  const out = new El("#tileout");
  app.renderHashTile(out, "tile/1/000", new Uint8Array(64), 1, 0); // 2 hashes
  expect(out.innerHTML).toContain('onclick="drillDown(1,0,0);return false"');
  expect(out.innerHTML).toContain('onclick="drillDown(1,0,1);return false"');
  expect(out.innerHTML).toContain('title="tile/0/000"');
  expect(out.innerHTML).toContain('title="tile/0/001"');
  expect(out.innerHTML).toContain("descend to its level 0 tile");
});

test("renderEntriesTile emits an openEntry link per entry, with global index", () => {
  makeUI();
  app.treeSize = 600;
  const out = new El("#tileout");
  const buf = new Uint8Array([0x00, 0x03, 0x61, 0x62, 0x63]); // one 3-byte entry "abc"
  app.renderEntriesTile(out, "tile/entries/001", buf, 1);
  expect(out.innerHTML).toContain('onclick="openEntry(256);return false"'); // 1*256 + 0
  expect(out.innerHTML).toContain("entry 0</a> (#256):");
});

// =========================================================================
// generic DER parser
// =========================================================================
test("DER.tlv: reports absolute header/value offsets", () => {
  // SEQUENCE { INTEGER 1 } = 30 03 02 01 01
  const buf = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);
  const t = new app.DER(buf).tlv();
  expect(t.cls).toBe(0);
  expect(t.constructed).toBe(true);
  expect(t.tag).toBe(16); // SEQUENCE
  expect([t.hdrStart, t.valStart, t.valEnd]).toEqual([0, 2, 5]);
});

test("derNode: recurses into constructed types with correct ranges", () => {
  const buf = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x05]); // SEQUENCE { INTEGER 5 }
  const node = app.derNode(buf, new app.DER(buf).tlv());
  expect(node.label).toBe("SEQUENCE");
  expect(node.range).toEqual([0, 5]);
  expect(node.children).toHaveLength(1);
  expect(node.children[0].label).toBe("INTEGER");
  expect(node.children[0].value).toBe("5 (0x05)");
  expect(node.children[0].range).toEqual([2, 5]);
});

test("derNode: OCTET STRING encapsulating DER is expanded", () => {
  // OCTET STRING { SEQUENCE { [2] "x" } } — like a SAN extnValue.
  const buf = new Uint8Array([0x04, 0x05, 0x30, 0x03, 0x82, 0x01, 0x78]);
  const node = app.derNode(buf, new app.DER(buf).tlv());
  expect(node.label).toBe("OCTET STRING");
  expect(node.note).toBe("encapsulates DER");
  expect(node.children[0].label).toBe("SEQUENCE");
});

test("derNode: an opaque OCTET STRING (a hash) is NOT mis-parsed as DER", () => {
  const body = new Uint8Array(32).fill(0x10);
  const buf = new Uint8Array([0x04, 0x20, ...body]);
  const node = app.derNode(buf, new app.DER(buf).tlv());
  expect(node.children).toHaveLength(0);
  expect(node.value).toContain("(32 bytes)");
});

test("decodeOID + tagName: dotted OIDs and tag names", () => {
  expect(app.decodeOID(new Uint8Array([0x55, 0x04, 0x03]))).toBe("2.5.4.3");
  expect(app.tagName(0, true, 16)).toBe("SEQUENCE");
  expect(app.tagName(2, false, 2)).toBe("[2]");
  expect(app.tagName(2, true, 0)).toBe("[0] constructed");
});

// =========================================================================
// MerkleTreeCertEntry parsing — against the real fixture
// =========================================================================
test("parseEntry: framing nodes for the TLS-presentation header", () => {
  const buf = fixtureEntry();
  const res = app.parseEntry(buf);
  expect(res.type).toBe(1);
  expect(res.typeLabel).toBe("tbs_cert_entry");
  expect(res.error).toBeNull();

  // extensions<0..2^16-1> (empty) ‖ entry_type ‖ tbs_cert_entry_data.
  const [ext, type, tbs] = res.structure;
  expect(ext.label).toBe("extensions<0..2^16-1>");
  expect(ext.range).toEqual([0, 2]);
  expect(ext.value).toBe("empty");
  expect(type.label).toBe("entry_type (uint16)");
  expect(type.range).toEqual([2, 4]);
  expect(type.value).toContain("tbs_cert_entry");
  expect(tbs.label).toBe("tbs_cert_entry_data");
  expect(tbs.range).toEqual([4, buf.length]);
});

test("parseEntry: tbs DER fields are nested under tbs_cert_entry_data", () => {
  const res = app.parseEntry(fixtureEntry());
  const tbs = res.structure[2];
  const semantics = tbs.children.map((c) => c.semantic);
  expect(semantics).toEqual([
    "version [0] EXPLICIT", "issuer Name", "validity", "subject Name",
    "subjectPublicKeyAlgorithm", "subjectPublicKeyInfoHash", "extensions [3] EXPLICIT",
  ]);
});

test("parseEntry: high-level annotations for the fixture", () => {
  const res = app.parseEntry(fixtureEntry());
  const byLabel = Object.fromEntries(res.annotations.map((a) => [a.label, a.value]));
  expect(byLabel["entry type"]).toBe("tbs_cert_entry (1)");
  expect(byLabel["version"]).toBe("v3");
  expect(byLabel["issuer"]).toBe("trustAnchorID=44947.4.1.99");
  expect(byLabel["not before"]).toBe("2026-06-02T04:17:30Z");
  expect(byLabel["not after"]).toBe("2026-06-09T04:17:30Z");
  expect(byLabel["subject"]).toBe("CN=certcat.dev");
  expect(byLabel["spki algorithm"]).toBe("ML-DSA-44 (2.16.840.1.101.3.4.3.17)");
  expect(byLabel["spki hash"]).toContain("(sha-256)");
  expect(byLabel["extension"]).toContain("subjectAltName");
  expect(byLabel["extension"]).toContain("DNS:certcat.dev");
});

test("parseEntry: every annotation range points inside its structure node", () => {
  const buf = fixtureEntry();
  const res = app.parseEntry(buf);
  // The SAN annotation's bytes should decode to the dNSName "certcat.dev".
  const san = res.annotations.find((a) => a.label === "extension");
  const slice = buf.subarray(san.range[0], san.range[1]);
  expect(new TextDecoder().decode(slice)).toContain("certcat.dev");
});

test("parseEntry: null_entry and malformed blobs degrade gracefully", () => {
  const nullEntry = app.parseEntry(new Uint8Array([0x00, 0x00, 0x00, 0x00]));
  expect(nullEntry.type).toBe(0);
  expect(nullEntry.typeLabel).toBe("null_entry");
  expect(nullEntry.structure).toHaveLength(2); // framing only, no tbs

  const tooShort = app.parseEntry(new Uint8Array([0x00]));
  expect(tooShort.error).toBe("entry too short");

  // Valid framing, truncated DER body → error set, framing still present.
  const broken = app.parseEntry(new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x30, 0x7f]));
  expect(broken.type).toBe(1);
  expect(broken.error).toContain("decode error");
  expect(broken.structure[0].label).toBe("extensions<0..2^16-1>");
});

// =========================================================================
// inspector rendering — DOM stub + byte-range linking
// =========================================================================
test("renderHexDump: 16 bytes/row with offset + per-byte data-off", () => {
  const out = new El("#hexbody");
  app.renderHexDump(out, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  expect(out.innerHTML).toContain('<span class="off">0000</span>');
  expect(out.innerHTML).toContain('data-off="0">de</span>');
  expect(out.innerHTML).toContain('data-off="3">ef</span>');
});

test("renderStructure: indented rows carry their byte range", () => {
  const out = new El("#structbody");
  const res = app.parseEntry(fixtureEntry());
  app.renderStructure(out, res.structure);
  expect(out.innerHTML).toContain('data-start="0" data-end="2"');   // extensions vector
  expect(out.innerHTML).toContain("SEQUENCE");
  expect(out.innerHTML).toContain("ML-DSA-44");
});

test("renderAnnotations: each row carries its structure's byte range", () => {
  const out = new El("#annotbody");
  const res = app.parseEntry(fixtureEntry());
  app.renderAnnotations(out, res.annotations);
  const san = res.annotations.find((a) => a.label === "extension");
  expect(out.innerHTML).toContain('data-start="' + san.range[0] + '" data-end="' + san.range[1] + '"');
  expect(out.innerHTML).toContain("<dt>subject</dt><dd>CN=certcat.dev</dd>");
});

test("renderEntry: fills all three columns and reports byte count", () => {
  const { els } = makeUI();
  const buf = fixtureEntry();
  const res = app.renderEntry(buf, "tile/entries/000 · entry 0 (#0)");
  expect(res.type).toBe(1);
  expect(els.entrymeta.innerHTML).toContain(buf.length + " bytes");
  expect(els.entrymeta.innerHTML).toContain("tbs_cert_entry");
  expect(els.inspector.style.display).toBe("grid");
  expect(els.hexbody.innerHTML).toContain("data-off=");
  expect(els.structbody.innerHTML).toContain("tbs_cert_entry_data");
  expect(els.annotbody.innerHTML).toContain("CN=certcat.dev");
});

test("within: range containment used by the highlight linker", () => {
  expect(app.within(2, 4, 0, 10)).toBe(true);
  expect(app.within(0, 10, 2, 4)).toBe(false);
  expect(app.within(2, 4, 2, 4)).toBe(true);
});
