// Tests for the tile-browser UI logic embedded in index.html.
//
// Rather than duplicate the code, we extract the <script> body from
// index.html (everything up to the bottom event-wiring block, i.e. the
// definitions) and evaluate it against a tiny DOM/fetch stub, then exercise
// the real functions. Run with: bun test tile/index.test.js
import { test, expect } from "bun:test";
import { readFileSync } from "fs";

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
  const document = {
    getElementById: (id) => (els[id] ||= new El("#" + id)),
    createElement: (tag) => new El(tag),
  };
  const fetches = [];
  const fetch = (url) => {
    fetches.push(url);
    return Promise.resolve({
      ok: true, status: 200,
      text: () => Promise.resolve(""),
      arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    });
  };

  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const m = html.match(/<script>\s*"use strict";([\s\S]*?)\n\/\/ Hide the landmarks link/);
  if (!m) throw new Error("could not extract script definitions from index.html");
  const body = m[1] +
    "\n;return {treeHeight,tileLevels,tileWidth,tileURL,formatTileIndex," +
    "populateLevels,selectAndFetch,drillDown,openEntry,fetchTile," +
    "renderHashTile,renderEntriesTile," +
    "get treeSize(){return treeSize}, set treeSize(v){treeSize=v}, _els: arguments[0]};";
  const factory = new Function("document", "fetch", body);
  const ui = factory(document, fetch);
  return { ui, els, fetches, document };
}

// --- pure math -----------------------------------------------------------
test("treeHeight: levels (root level) for a tree of n entries", () => {
  const { ui } = makeUI();
  for (const [n, want] of [[0, 0], [1, 0], [2, 1], [3, 2], [12, 4], [16, 4], [256, 8], [257, 9]]) {
    expect(ui.treeHeight(n)).toBe(want);
  }
});

test("tileLevels: how many tiles tall, matching tlog.NewTiles", () => {
  const { ui } = makeUI();
  for (const [n, want] of [[0, 0], [1, 1], [12, 1], [255, 1], [256, 2], [257, 2], [65535, 2], [65536, 3]]) {
    expect(ui.tileLevels(n)).toBe(want);
  }
});

test("tileWidth: auto-sized partial/full widths from the tree size", () => {
  const { ui } = makeUI();
  ui.treeSize = 12;
  expect(ui.tileWidth("entries", 0)).toBe(12);
  expect(ui.tileWidth("0", 0)).toBe(12);

  ui.treeSize = 300;
  expect(ui.tileWidth("entries", 0)).toBe(256); // full first data tile
  expect(ui.tileWidth("entries", 1)).toBe(44);  // partial remainder
  expect(ui.tileWidth("0", 0)).toBe(256);
  expect(ui.tileWidth("0", 1)).toBe(44);
  expect(ui.tileWidth("1", 0)).toBe(1);         // one level-8 hash
  expect(ui.tileWidth("entries", 5)).toBe(0);   // out of range
});

test("tileURL: only the partial frontier tile gets a .p/<width> suffix", () => {
  const { ui } = makeUI();
  expect(ui.tileURL("0", 0, 256)).toBe("tile/0/000");
  expect(ui.tileURL("0", 0, null)).toBe("tile/0/000");
  expect(ui.tileURL("entries", 1, 44)).toBe("tile/entries/001.p/44");
});

// --- dropdown ------------------------------------------------------------
test("populateLevels: tile levels high-to-low, entries last", () => {
  const { ui, document } = makeUI();
  ui.treeSize = 257; // 2 tiles tall
  ui.populateLevels();
  const opts = document.getElementById("mlevel").options.map((o) => o.value);
  expect(opts).toEqual(["1", "0", "entries"]);
  // level 0 is labelled as the leaf-hash level.
  const l0 = document.getElementById("mlevel").options.find((o) => o.value === "0");
  expect(l0.textContent).toBe("0 (leaf hashes)");
});

test("populateLevels: a small tree has only level 0 + entries", () => {
  const { ui, document } = makeUI();
  ui.treeSize = 12;
  ui.populateLevels();
  expect(document.getElementById("mlevel").options.map((o) => o.value)).toEqual(["0", "entries"]);
});

test("populateLevels: keeps the current selection if still present", () => {
  const { ui, document } = makeUI();
  ui.treeSize = 65536; // levels 0,1,2
  ui.populateLevels();
  const sel = document.getElementById("mlevel");
  sel.value = "1";
  ui.populateLevels();
  expect(sel.value).toBe("1");
});

// --- drill-down ----------------------------------------------------------
test("drillDown from a hash level >= 1 descends to the child hash tile", () => {
  const { ui, els, fetches } = makeUI();
  ui.treeSize = 393216; // 3 tiles tall; level-1 tile 5 is full
  ui.drillDown(2, 0, 5); // row 5 of tile (2,0) -> tile (1, 0*256+5)
  expect(els.mlevel.value).toBe("1");
  expect(els.mindex.value).toBe("5");
  expect(fetches.at(-1)).toBe("tile/1/005");
});

test("drillDown from level 0 descends to the aligned entry (data) tile", () => {
  const { ui, els, fetches } = makeUI();
  ui.treeSize = 393216;
  ui.drillDown(0, 1, 3); // level-0 tile 1 lines up 1:1 with entries tile 1
  expect(els.mlevel.value).toBe("entries");
  expect(els.mindex.value).toBe("1");
  expect(fetches.at(-1)).toBe("tile/entries/001");
});

test("openEntry fetches the single entry by global index", () => {
  const { ui, els, fetches } = makeUI();
  ui.openEntry(1283);
  expect(els.eindex.value).toBe("1283");
  expect(fetches.at(-1)).toBe("log/v1/entry/1283");
});

// --- render output (the per-row drill links) -----------------------------
test("renderHashTile emits a drillDown link per node hash", () => {
  const { ui } = makeUI();
  ui.treeSize = 393216; // ensure child level-0 tiles are full
  const out = new El("#tileout");
  ui.renderHashTile(out, "tile/1/000", new Uint8Array(64), 1, 0); // 2 hashes
  expect(out.innerHTML).toContain('onclick="drillDown(1,0,0);return false"');
  expect(out.innerHTML).toContain('onclick="drillDown(1,0,1);return false"');
  // descends to level-0 child tiles, named in the link title.
  expect(out.innerHTML).toContain('title="tile/0/000"');
  expect(out.innerHTML).toContain('title="tile/0/001"');
  expect(out.innerHTML).toContain("descend to its level 0 tile");
});

test("renderEntriesTile emits an openEntry link per entry, with global index", () => {
  const { ui } = makeUI();
  ui.treeSize = 600;
  const out = new El("#tileout");
  // one entry of 3 bytes: uint16 len=3 then "abc".
  const buf = new Uint8Array([0x00, 0x03, 0x61, 0x62, 0x63]);
  ui.renderEntriesTile(out, "tile/entries/001", buf, 1); // data tile index 1
  expect(out.innerHTML).toContain('onclick="openEntry(256);return false"'); // 1*256 + 0
  expect(out.innerHTML).toContain("entry 0</a> (#256):");
});
