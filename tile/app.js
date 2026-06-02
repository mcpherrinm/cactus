// cactus issuance-log browser logic. Loaded by index.html as a classic
// <script src="app.js"> (no build step, no dependencies) and embedded into
// the binary via go:embed alongside index.html.
//
// The file is written so the pure logic (tile math, the DER/TLS-presentation
// parser, the renderers) can also be exercised under Bun: it auto-runs in the
// browser but exports its functions under CommonJS for tile/app.test.js.
// All fetches use relative URLs, so it works under any log-number prefix.
"use strict";

const TILE_W = 256; // 1 << TileHeight(8)

const $ = (id) => document.getElementById(id);
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

let treeSize = 0;

// ---- tile addressing / geometry -----------------------------------------

// Mirrors tilewriter.formatTileIndex: last 3 digits, then "x"-prefixed
// 3-digit groups for higher-order digits.
function formatTileIndex(n) {
  let s = String(n % 1000).padStart(3, "0");
  n = Math.floor(n / 1000);
  while (n > 0) {
    s = "x" + String(n % 1000).padStart(3, "0") + "/" + s;
    n = Math.floor(n / 1000);
  }
  return s;
}

// Build a tile URL relative to the log root. level is a number or "entries".
function tileURL(level, index, width) {
  let p = "tile/" + level + "/" + formatTileIndex(index);
  if (width && width !== TILE_W) p += ".p/" + width;
  return p;
}

// Number of tree levels (the level of the root); 0 for an empty or
// single-leaf tree. E.g. a size-12 tree is 4 levels tall.
function treeHeight(n) {
  let h = 0, p = 1;
  while (p < n) { p *= 2; h++; }
  return h;
}

// Number of tile levels the tree spans (how many tiles tall it is): the
// count of levels L >= 0 with floor(n / 256^L) > 0. Mirrors the level loop
// in tlog.NewTiles, so it matches exactly which tile/<L>/… paths exist.
function tileLevels(n) {
  let levels = 0;
  while (n > 0) { levels++; n = Math.floor(n / TILE_W); }
  return levels;
}

// Width (node/entry count) of the tile at tile level (a number or
// "entries") and tile index, derived from the current tree size. Returns 0
// when the tile is empty / out of range, TILE_W (256) for a full tile, or
// the partial width otherwise. Mirrors the per-tile width in tlog.NewTiles.
function tileWidth(level, index) {
  let units = treeSize; // entries, or count of stored hashes at this level
  if (level !== "entries") {
    for (let k = 0; k < Number(level); k++) units = Math.floor(units / TILE_W);
  }
  const w = units - index * TILE_W;
  if (w <= 0) return 0;
  return Math.min(TILE_W, w);
}

// ---- checkpoint ---------------------------------------------------------

async function loadCheckpoint() {
  $("cpstatus").textContent = "fetching…";
  $("cpstatus").className = "hint";
  try {
    const r = await fetch("checkpoint", { cache: "no-store" });
    if (r.status === 503) {
      $("origin").textContent = "(no checkpoint yet — the log is empty)";
      $("cpstatus").textContent = "no checkpoint yet";
      return;
    }
    if (!r.ok) throw new Error("HTTP " + r.status);
    const text = await r.text();
    // signed-note body: origin \n size \n base64(root) \n  (then blank + sig lines)
    const lines = text.split("\n");
    const origin = lines[0] || "";
    treeSize = parseInt(lines[1] || "0", 10);
    const root = lines[2] || "";
    $("origin").textContent = origin;
    $("size").textContent = treeSize.toLocaleString();
    const th = tileLevels(treeSize);
    $("height").textContent = treeSize === 0 ? "0" :
      treeHeight(treeSize) + " levels · " + th + " tile" + (th === 1 ? "" : "s") + " high";
    $("root").textContent = root;
    $("cpstatus").innerHTML = '<span class="ok">updated ' + new Date().toLocaleTimeString() + "</span>";
    populateLevels();
    renderTileLists();
  } catch (e) {
    $("cpstatus").innerHTML = '<span class="err">checkpoint error: ' + esc(String(e.message)) + "</span>";
  }
}

// ---- tile browser -------------------------------------------------------

function tileChip(level, index, width) {
  const partial = width !== TILE_W;
  const el = document.createElement("span");
  el.className = "tile" + (partial ? " partial" : "");
  el.textContent = (level === "entries" ? "e" : level) + "/" + index + (partial ? " (" + width + ")" : "");
  el.title = tileURL(level, index, width);
  el.onclick = () => fetchTile(level, index, partial ? width : null);
  return el;
}

// Render the level-0 hash tiles and entry tiles implied by the tree size.
function renderTileLists() {
  for (const [containerId, level, label] of [
    ["level0", "0", "Level-0 hash tiles"],
    ["entries0", "entries", "Entry (data) tiles"],
  ]) {
    const box = $(containerId);
    box.innerHTML = "";
    if (treeSize === 0) continue;
    const h = document.createElement("div");
    h.className = "hint";
    h.style.marginTop = ".5rem";
    h.textContent = label + ":";
    box.appendChild(h);
    const tiles = document.createElement("div");
    tiles.className = "tiles";
    const full = Math.floor(treeSize / TILE_W);
    const rem = treeSize % TILE_W;
    const MAX = 64;
    const total = full + (rem ? 1 : 0);
    for (let i = 0; i < Math.min(full, MAX); i++) tiles.appendChild(tileChip(level, i, TILE_W));
    if (rem && full < MAX) tiles.appendChild(tileChip(level, full, rem));
    if (total > MAX) {
      const more = document.createElement("span");
      more.className = "hint";
      more.textContent = "+" + (total - MAX) + " more (use manual fetch)";
      tiles.appendChild(more);
    }
    box.appendChild(tiles);
  }
}

// Rebuild the manual-fetch level dropdown from the current checkpoint so it
// lists exactly the tile levels that exist (using the tree's tile height,
// not its level height), ordered to match the tree: the highest hash level
// on top, level 0 just above the entries, entries at the bottom.
function populateLevels() {
  const sel = $("mlevel");
  const prev = sel.value;
  const top = Math.max(tileLevels(treeSize) - 1, 0);
  sel.innerHTML = "";
  for (let L = top; L >= 0; L--) {
    const o = document.createElement("option");
    o.value = String(L);
    o.textContent = L === 0 ? "0 (leaf hashes)" : String(L);
    sel.appendChild(o);
  }
  const oe = document.createElement("option");
  oe.value = "entries";
  oe.textContent = "entries (data)";
  sel.appendChild(oe);
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
}

// Point the manual-fetch controls at (level, index) and fetch that tile,
// auto-sizing the width from the current checkpoint.
function selectAndFetch(level, index) {
  $("mlevel").value = level;
  $("mindex").value = index;
  const w = tileWidth(level, index);
  $("mwidth").value = (w && w !== TILE_W) ? w : "";
  fetchTile(level, index, w || null);
}

// Descend one layer from row i of the hash tile at (level, index): to the
// child hash tile for level >= 1, or to the corresponding entry (data) tile
// for level 0 (whose tiles line up 1:1 with the level-0 hash tiles).
function drillDown(level, index, i) {
  if (level >= 1) selectAndFetch(String(level - 1), index * TILE_W + i);
  else selectAndFetch("entries", index);
}

// Open one entry (global index) in the entry viewer below.
function openEntry(globalIndex) {
  $("eindex").value = globalIndex;
  fetchEntry();
  $("inspector").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function fetchTile(level, index, width) {
  const out = $("tileout");
  out.style.display = "block";
  const url = tileURL(level, index, width);
  out.textContent = "GET " + url + " …";
  try {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) { out.innerHTML = '<span class="err">GET ' + esc(url) + " → HTTP " + r.status + "</span>"; return; }
    const buf = new Uint8Array(await r.arrayBuffer());
    if (level === "entries") renderEntriesTile(out, url, buf, index);
    else renderHashTile(out, url, buf, Number(level), index);
  } catch (e) {
    out.innerHTML = '<span class="err">' + esc(String(e.message)) + "</span>";
  }
}

function renderHashTile(out, url, buf, level, index) {
  const n = Math.floor(buf.length / 32);
  const down = level >= 1 ? "level " + (level - 1) + " tile" : "entry (data) tile";
  let html = '<span class="ok">GET ' + esc(url) + "</span>\n" +
    buf.length + " bytes · " + n + " node hash" + (n === 1 ? "" : "es") + "\n" +
    '<span class="hint">click an index to descend to its ' + down + "</span>\n\n";
  html += '<div class="hash">';
  for (let i = 0; i < n; i++) {
    // Drill target: the child hash tile (level >= 1) or the aligned entry
    // (data) tile (level 0). Shown in the link's title; the click is wired
    // to drillDown which also resyncs the manual-fetch controls.
    const tgt = level >= 1
      ? tileURL(String(level - 1), index * TILE_W + i, tileWidth(String(level - 1), index * TILE_W + i))
      : tileURL("entries", index, tileWidth("entries", index));
    html += '<span class="i"><a href="#" title="' + esc(tgt) +
      '" onclick="drillDown(' + level + ',' + index + ',' + i + ');return false">' + i + "</a></span>" +
      "<span>" + hex(buf.subarray(i * 32, i * 32 + 32)) + "</span>";
  }
  html += "</div>";
  if (buf.length % 32 !== 0) html += '\n<span class="err">note: length not a multiple of 32</span>';
  out.innerHTML = html;
}

// Entry (data) tiles are uint16-big-endian length-prefixed entries.
function renderEntriesTile(out, url, buf, tileIndex) {
  let html = '<span class="ok">GET ' + esc(url) + "</span>\n" + buf.length + " bytes\n" +
    '<span class="hint">click an entry to open it in the entry viewer</span>\n\n';
  let pos = 0, i = 0;
  try {
    while (pos + 2 <= buf.length) {
      const len = (buf[pos] << 8) | buf[pos + 1];
      pos += 2;
      const body = buf.subarray(pos, pos + len);
      pos += len;
      const preview = hex(body.subarray(0, 32));
      const gidx = tileIndex * TILE_W + i;
      html += '<a href="#" onclick="openEntry(' + gidx + ');return false">entry ' + i + "</a>" +
        " (#" + gidx + "): " + len + " bytes  " + preview + (len > 32 ? "…" : "") + "\n";
      i++;
    }
    html = html.replace("\n\n", "\n" + i + " entr" + (i === 1 ? "y" : "ies") + "\n\n");
  } catch (e) {
    html += '<span class="err">decode error: ' + esc(String(e.message)) + "</span>";
  }
  out.innerHTML = html;
}

// ======================================================================
// MerkleTreeCertEntry inspector
// ======================================================================
//
// A MerkleTreeCertEntry (cert/entry.go, §5.2.1) is TLS-presentation framing
//
//     extensions<0..2^16-1> ‖ uint16 entry_type ‖ data
//
// wrapping, for tbs_cert_entry (type 1), the *contents octets* of a
// TBSCertificateLogEntry DER (the SEQUENCE value, with no outer header).
// parseEntry() walks that wire format into a structure tree (each node
// carrying its absolute [start,end) byte range) plus a flat list of
// high-level annotations, also range-tagged. The three columns of the
// inspector (hex dump / raw structure / annotations) are then linked purely
// by those byte ranges.

const td = new TextDecoder();

// Minimal DER reader over a Uint8Array. Each read advances .pos.
class DER {
  constructor(buf, pos = 0, end = buf.length) { this.b = buf; this.pos = pos; this.end = end; }
  eof() { return this.pos >= this.end; }
  // Read one TLV. Returns the tag class/number plus byte offsets and views:
  //   hdrStart/valStart/valEnd: absolute offsets of the identifier+length,
  //                             the contents, and one past the contents.
  //   bytes:   the content octets (the V), as a Uint8Array
  //   content: a DER positioned over those content octets, for nesting
  //   full:    the whole TLV (T+L+V), as a Uint8Array
  tlv() {
    const start = this.pos;
    if (this.pos + 2 > this.end) throw new Error("short TLV");
    const t = this.b[this.pos++];
    const cls = t >> 6, constructed = (t & 0x20) !== 0, tag = t & 0x1f;
    let len = this.b[this.pos++];
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error("bad length");
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | this.b[this.pos++];
    }
    if (this.pos + len > this.end) throw new Error("truncated value");
    const cStart = this.pos;
    this.pos += len;
    return { cls, constructed, tag,
             hdrStart: start, valStart: cStart, valEnd: this.pos,
             bytes: this.b.subarray(cStart, cStart + len),
             content: new DER(this.b, cStart, cStart + len),
             full: this.b.subarray(start, this.pos) };
  }
}

const OID_TRUST_ANCHOR_ID = "1.3.6.1.4.1.44363.47.1";
const ATTR_NAMES = { [OID_TRUST_ANCHOR_ID]: "trustAnchorID", "2.5.4.3": "CN",
  "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU" };
const ALG_NAMES = { "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
  "1.2.840.10045.2.1": "ecPublicKey", "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.10045.3.1.7": "prime256v1" };
const EXT_NAMES = { "2.5.29.15": "keyUsage", "2.5.29.17": "subjectAltName",
  "2.5.29.19": "basicConstraints", "2.5.29.37": "extKeyUsage" };
// Merged lookup used for the structure column's OID previews.
const OID_NAMES = Object.assign({}, ATTR_NAMES, ALG_NAMES, EXT_NAMES);

const DER_UNIVERSAL = { 1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING",
  4: "OCTET STRING", 5: "NULL", 6: "OBJECT IDENTIFIER", 10: "ENUMERATED",
  12: "UTF8String", 16: "SEQUENCE", 17: "SET", 19: "PrintableString",
  20: "T61String", 22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime",
  26: "VisibleString", 27: "GeneralString" };

// Human label for a DER tag. Universal tags get their type name; everything
// else gets its class + number (e.g. "[0]", "[APPLICATION 1]").
function tagName(cls, constructed, tagNum) {
  if (cls === 0) return DER_UNIVERSAL[tagNum] || ("[UNIVERSAL " + tagNum + "]");
  const base = cls === 2 ? "[" + tagNum + "]"
    : cls === 1 ? "[APPLICATION " + tagNum + "]" : "[PRIVATE " + tagNum + "]";
  return base + (constructed ? " constructed" : "");
}

// Decode a DER OBJECT IDENTIFIER's content bytes to dotted-decimal.
function decodeOID(bytes) {
  if (bytes.length === 0) return "";
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = (v << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

function oidName(oid, table) { return table[oid] ? table[oid] + " (" + oid + ")" : oid; }

// Hex preview of a byte string, truncated past 16 bytes with a count.
function hexPreview(bytes) {
  const head = hex(bytes.subarray(0, 16));
  if (bytes.length === 0) return "(empty)";
  return bytes.length > 16 ? head + "… (" + bytes.length + " bytes)" : head;
}

// Decimal (plus hex) for small INTEGERs, hex for big ones.
function previewInteger(bytes) {
  if (bytes.length === 0) return "0";
  if (bytes.length <= 8) {
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v.toString() + " (0x" + hex(bytes) + ")";
  }
  return "0x" + hexPreview(bytes);
}

// Format a Time TLV (UTCTime tag 23 or GeneralizedTime tag 24) as
// YYYY-MM-DDTHH:MM:SSZ. Falls back to the raw string on anything else.
function formatTime(t) {
  const s = td.decode(t.bytes);
  let y, rest;
  if (t.tag === 23 && s.length >= 12) {            // UTCTime: YYMMDDHHMMSSZ
    const yy = parseInt(s.slice(0, 2), 10);
    y = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = s.slice(2);
  } else if (t.tag === 24 && s.length >= 14) {     // GeneralizedTime: YYYYMMDD…
    y = s.slice(0, 4);
    rest = s.slice(4);
  } else {
    return s;
  }
  return y + "-" + rest.slice(0, 2) + "-" + rest.slice(2, 4) + "T" +
    rest.slice(4, 6) + ":" + rest.slice(6, 8) + ":" + rest.slice(8, 10) + "Z";
}

// A short, human value preview for a primitive DER TLV.
function previewPrimitive(cls, tagNum, bytes) {
  if (cls === 0) {
    switch (tagNum) {
      case 1: return bytes.length && bytes[0] ? "TRUE" : "FALSE";
      case 2: case 10: return previewInteger(bytes);
      case 5: return "NULL";
      case 6: return oidName(decodeOID(bytes), OID_NAMES);
      case 12: case 19: case 20: case 22: case 26: case 27: return JSON.stringify(td.decode(bytes));
      case 3: return hexPreview(bytes);
      case 23: case 24: return formatTime({ tag: tagNum, bytes });
    }
  }
  return hexPreview(bytes);
}

// If an OCTET STRING's content is itself one-or-more complete DER TLVs
// (e.g. an extnValue wrapping GeneralNames), return that nested forest so
// the structure view can descend into it; otherwise null. Gated on a
// SEQUENCE/SET first byte to avoid mis-parsing opaque octets like a hash.
function tryEncapsulated(buf, start, end) {
  if (start >= end) return null;
  const t = buf[start];
  if (t !== 0x30 && t !== 0x31) return null;
  try {
    return derForest(buf, start, end);
  } catch (e) {
    return null;
  }
}

// Build a generic structural node for one DER TLV, recursing into
// constructed types and into encapsulating OCTET STRINGs.
function derNode(buf, tlv) {
  const node = {
    kind: "der", cls: tlv.cls, constructed: tlv.constructed, tagNum: tlv.tag,
    label: tagName(tlv.cls, tlv.constructed, tlv.tag),
    range: [tlv.hdrStart, tlv.valEnd],
    headerRange: [tlv.hdrStart, tlv.valStart],
    children: [], value: null, note: null, semantic: null,
  };
  if (tlv.constructed) {
    node.children = derForest(buf, tlv.valStart, tlv.valEnd);
  } else if (tlv.cls === 0 && tlv.tag === 4) {
    const enc = tryEncapsulated(buf, tlv.valStart, tlv.valEnd);
    if (enc) { node.children = enc; node.note = "encapsulates DER"; }
    else node.value = previewPrimitive(tlv.cls, tlv.tag, tlv.bytes);
  } else {
    node.value = previewPrimitive(tlv.cls, tlv.tag, tlv.bytes);
  }
  return node;
}

// Parse a DER range into a flat list of sibling nodes; throws unless the
// range is consumed exactly by whole TLVs.
function derForest(buf, start, end) {
  const der = new DER(buf, start, end);
  const out = [];
  while (!der.eof()) out.push(derNode(buf, der.tlv()));
  return out;
}

// Render a Name (RDNSequence) DER as "type=value, …". der is positioned
// at the outer Name SEQUENCE.
function decodeDN(der) {
  try {
    const rdns = der.tlv().content; // SEQUENCE OF RDN
    const parts = [];
    while (!rdns.eof()) {
      const set = rdns.tlv().content; // SET OF AttributeTypeAndValue
      while (!set.eof()) {
        const atv = set.tlv().content; // SEQUENCE { type, value }
        const oid = decodeOID(atv.tlv().bytes);
        const val = td.decode(atv.tlv().bytes);
        parts.push((ATTR_NAMES[oid] || oid) + "=" + val);
      }
    }
    return parts.length ? parts.join(", ") : "(empty)";
  } catch (e) { return "(unparseable)"; }
}

// dNSName entries from a SubjectAltName extension value (a GeneralNames
// SEQUENCE). der is positioned at that SEQUENCE.
function decodeSAN(der) {
  try {
    const names = der.tlv().content;
    const out = [];
    while (!names.eof()) {
      const gn = names.tlv();
      if (gn.cls === 2 && gn.tag === 2) out.push("DNS:" + td.decode(gn.bytes)); // [2] dNSName
    }
    return out.join(", ");
  } catch (e) { return ""; }
}

// Walk an extensions [3] EXPLICIT field, appending one annotation per
// extension (range-tagged to that Extension SEQUENCE).
function decodeExtensions(buf, f, ann) {
  const exts = f.content.tlv().content; // [3] → Extensions SEQUENCE → its contents
  while (!exts.eof()) {
    const extTlv = exts.tlv();
    const ext = new DER(buf, extTlv.valStart, extTlv.valEnd);
    const oid = decodeOID(ext.tlv().bytes);
    let next = ext.tlv();
    let critical = false;
    if (next.cls === 0 && next.tag === 1) { critical = next.bytes[0] !== 0; next = ext.tlv(); }
    let value = EXT_NAMES[oid] ? EXT_NAMES[oid] + " (" + oid + ")" : oid;
    if (critical) value += " — critical";
    if (EXT_NAMES[oid] === "subjectAltName") {
      const sans = decodeSAN(new DER(next.bytes)); // next is the extnValue OCTET STRING
      if (sans) value += " — " + sans;
    }
    ann.push({ label: "extension", value, range: [extTlv.hdrStart, extTlv.valEnd] });
  }
}

// Walk the TBSCertificateLogEntry contents octets starting at `base`,
// appending DER structure nodes under tbsNode.children and high-level
// fields to ann. Mirrors cert.ParseTBSCertificateLogEntry's field order.
function decodeTBS(buf, base, tbsNode, ann) {
  const data = new DER(buf, base);

  // version [0] EXPLICIT INTEGER (optional, omitted for v1), then issuer Name.
  let rv = data.tlv();
  if (rv.cls === 2 && rv.tag === 0) {
    const node = derNode(buf, rv); node.semantic = "version [0] EXPLICIT";
    tbsNode.children.push(node);
    const vb = rv.content.tlv().bytes;        // INTEGER content (stored 0=v1, 2=v3)
    ann.push({ label: "version", value: "v" + (vb[vb.length - 1] + 1), range: node.range });
    rv = data.tlv();
  } else {
    ann.push({ label: "version", value: "v1 (default; field omitted)", range: [base, base] });
  }

  // issuer Name (rv currently holds it).
  const issuer = derNode(buf, rv); issuer.semantic = "issuer Name";
  tbsNode.children.push(issuer);
  ann.push({ label: "issuer", value: decodeDN(new DER(rv.full)), range: issuer.range });

  // validity SEQUENCE { notBefore Time, notAfter Time }.
  const valTlv = data.tlv();
  const validity = derNode(buf, valTlv); validity.semantic = "validity";
  tbsNode.children.push(validity);
  const vDer = new DER(buf, valTlv.valStart, valTlv.valEnd);
  const nb = vDer.tlv(), na = vDer.tlv();
  ann.push({ label: "not before", value: formatTime(nb), range: [nb.hdrStart, nb.valEnd] });
  ann.push({ label: "not after", value: formatTime(na), range: [na.hdrStart, na.valEnd] });

  // subject Name.
  const subjTlv = data.tlv();
  const subject = derNode(buf, subjTlv); subject.semantic = "subject Name";
  tbsNode.children.push(subject);
  ann.push({ label: "subject", value: decodeDN(new DER(subjTlv.full)), range: subject.range });

  // subjectPublicKeyAlgorithm AlgorithmIdentifier.
  const algTlv = data.tlv();
  const alg = derNode(buf, algTlv); alg.semantic = "subjectPublicKeyAlgorithm";
  tbsNode.children.push(alg);
  const algOid = decodeOID(new DER(buf, algTlv.valStart, algTlv.valEnd).tlv().bytes);
  ann.push({ label: "spki algorithm", value: oidName(algOid, ALG_NAMES), range: alg.range });

  // subjectPublicKeyInfoHash OCTET STRING.
  const hashTlv = data.tlv();
  const hashNode = derNode(buf, hashTlv); hashNode.semantic = "subjectPublicKeyInfoHash";
  tbsNode.children.push(hashNode);
  ann.push({ label: "spki hash", value: hex(hashTlv.bytes) + " (sha-256)", range: hashNode.range });

  // Optional tail: issuerUID [1], subjectUID [2], extensions [3] EXPLICIT.
  while (!data.eof()) {
    const f = data.tlv();
    const node = derNode(buf, f);
    if (f.cls === 2 && f.tag === 3) {
      node.semantic = "extensions [3] EXPLICIT";
      tbsNode.children.push(node);
      decodeExtensions(buf, f, ann);
    } else if (f.cls === 2 && f.tag === 1) {
      node.semantic = "issuerUniqueID [1]";
      tbsNode.children.push(node);
      ann.push({ label: "issuerUID", value: hex(f.bytes), range: node.range });
    } else if (f.cls === 2 && f.tag === 2) {
      node.semantic = "subjectUniqueID [2]";
      tbsNode.children.push(node);
      ann.push({ label: "subjectUID", value: hex(f.bytes), range: node.range });
    } else {
      node.semantic = "(unexpected field)";
      tbsNode.children.push(node);
    }
  }
}

// A simple length-prefixed framing node for the TLS-presentation header.
function framingNode(label, range, value, note) {
  return { kind: "tls", label, range, value, note: note || null,
           headerRange: null, semantic: null, children: [] };
}

// Parse a whole MerkleTreeCertEntry blob into { structure, annotations,
// type, typeLabel, dataLen, error }. Never throws: a malformed body leaves
// a partial tree plus an `error` string, so the hex dump still renders.
function parseEntry(buf) {
  const res = { structure: [], annotations: [], type: null, typeLabel: null, dataLen: 0, error: null };
  if (buf.length < 4) { res.error = "entry too short"; return res; }

  const extLen = (buf[0] << 8) | buf[1];
  if (4 + extLen > buf.length) { res.error = "bad extensions length"; return res; }

  // extensions<0..2^16-1>: uint16 length prefix + body (cactus emits empty).
  const extNode = framingNode("extensions<0..2^16-1>", [0, 2 + extLen],
    extLen === 0 ? "empty" : extLen + " bytes", "MerkleTreeCertEntry framing");
  extNode.children.push(framingNode("length (uint16)", [0, 2], String(extLen)));
  if (extLen > 0) extNode.children.push(framingNode("body", [2, 2 + extLen], hexPreview(buf.subarray(2, 2 + extLen))));
  res.structure.push(extNode);

  const type = (buf[2 + extLen] << 8) | buf[3 + extLen];
  res.type = type;
  res.typeLabel = type === 0 ? "null_entry" : type === 1 ? "tbs_cert_entry" : "unknown(" + type + ")";
  res.structure.push(framingNode("entry_type (uint16)", [2 + extLen, 4 + extLen], type + " — " + res.typeLabel));
  res.annotations.push({ label: "entry type", value: res.typeLabel + " (" + type + ")", range: [2 + extLen, 4 + extLen] });

  if (type !== 1) return res; // null_entry / unknown: nothing more to decode

  const base = 4 + extLen;
  res.dataLen = buf.length - base;
  const tbsNode = { kind: "der-contents", label: "tbs_cert_entry_data", value: null, semantic: null,
    note: "TBSCertificateLogEntry contents octets (no outer SEQUENCE)",
    range: [base, buf.length], headerRange: null, children: [] };
  res.structure.push(tbsNode);
  try {
    decodeTBS(buf, base, tbsNode, res.annotations);
  } catch (e) {
    res.error = "decode error: " + e.message;
  }
  return res;
}

// ---- inspector rendering ------------------------------------------------

// Column 1: an offset/hex/ASCII dump. Every byte cell carries data-off so a
// hover anywhere in the inspector can light up the matching bytes.
function renderHexDump(container, buf) {
  let html = "";
  for (let off = 0; off < buf.length; off += 16) {
    const row = buf.subarray(off, off + 16);
    let bytes = "", ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i < row.length) {
        const b = row[i];
        bytes += '<span class="b" data-off="' + (off + i) + '">' + b.toString(16).padStart(2, "0") + "</span>";
        ascii += '<span class="a" data-off="' + (off + i) + '">' +
          (b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : "·") + "</span>";
      } else {
        bytes += '<span class="b pad">··</span>';
      }
      if (i === 7) bytes += '<span class="gap"> </span>';
    }
    html += '<div class="hexrow"><span class="off">' + off.toString(16).padStart(4, "0") + "</span>" +
      '<span class="hbytes">' + bytes + "</span>" +
      '<span class="hascii">' + ascii + "</span></div>";
  }
  if (buf.length === 0) html = '<div class="hexrow hint">(empty)</div>';
  container.innerHTML = html;
}

// Column 2: the structure tree, indented by depth. Each row carries its
// [data-start,data-end) byte range for cross-column highlighting.
function renderStructure(container, nodes) {
  let html = "";
  const walk = (node, depth) => {
    const len = node.range[1] - node.range[0];
    const sem = node.semantic ? '<span class="sem">' + esc(node.semantic) + "</span> " : "";
    const val = (node.value != null && node.value !== "") ? ' <span class="sval">' + esc(node.value) + "</span>" : "";
    const note = node.note ? ' <span class="snote">' + esc(node.note) + "</span>" : "";
    html += '<div class="node" data-start="' + node.range[0] + '" data-end="' + node.range[1] +
      '" style="padding-left:' + (depth * 1.1 + 0.1) + 'rem">' +
      sem + '<span class="stag">' + esc(node.label) + "</span> " +
      '<span class="slen">' + len + "B</span>" + val + note + "</div>";
    for (const c of node.children || []) walk(c, depth + 1);
  };
  for (const n of nodes) walk(n, 0);
  container.innerHTML = html || '<div class="hint">(no structure)</div>';
}

// Column 3: the high-level annotations. Each row carries the byte range of
// the structure it summarizes.
function renderAnnotations(container, ann) {
  let html = '<dl class="agrid">';
  for (const a of ann) {
    html += '<div class="arow" data-start="' + a.range[0] + '" data-end="' + a.range[1] + '">' +
      "<dt>" + esc(a.label) + "</dt><dd>" + esc(a.value) + "</dd></div>";
  }
  html += "</dl>";
  container.innerHTML = ann.length ? html : '<div class="hint">(no annotations)</div>';
}

// Render the full three-column inspector for one entry blob.
function renderEntry(buf, url) {
  const res = parseEntry(buf);
  const meta = $("entrymeta");
  meta.style.display = "block";
  let m = '<span class="ok">GET ' + esc(url) + "</span> · " + buf.length + " bytes (MerkleTreeCertEntry)";
  if (res.typeLabel) m += " · type " + esc(res.typeLabel);
  if (res.error) m += ' · <span class="err">' + esc(res.error) + "</span>";
  meta.innerHTML = m;

  $("inspector").style.display = "grid";
  renderHexDump($("hexbody"), buf);
  renderStructure($("structbody"), res.structure);
  renderAnnotations($("annotbody"), res.annotations);
  return res;
}

async function fetchEntry() {
  const idx = parseInt($("eindex").value, 10) || 0;
  const url = "log/v1/entry/" + idx;
  const meta = $("entrymeta");
  meta.style.display = "block";
  meta.textContent = "GET " + url + " …";
  $("inspector").style.display = "none";
  try {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) { meta.innerHTML = '<span class="err">GET ' + esc(url) + " → HTTP " + r.status + "</span>"; return; }
    const buf = new Uint8Array(await r.arrayBuffer());
    renderEntry(buf, url);
  } catch (e) {
    meta.innerHTML = '<span class="err">' + esc(String(e.message)) + "</span>";
  }
}

// ---- cross-column highlighting (browser only) ---------------------------

// True when [s,e) is contained within [S,E).
function within(s, e, S, E) { return s >= S && e <= E; }

// Light up every byte cell, structure row and annotation row whose range
// falls inside [start,end). Passing a null start just clears.
function setHighlight(start, end) {
  const insp = $("inspector");
  if (!insp) return;
  for (const el of insp.querySelectorAll(".hl")) el.classList.remove("hl");
  if (start == null) return;
  for (const el of insp.querySelectorAll("[data-off]")) {
    const o = +el.getAttribute("data-off");
    if (o >= start && o < end) el.classList.add("hl");
  }
  for (const el of insp.querySelectorAll(".node, .arow")) {
    if (within(+el.getAttribute("data-start"), +el.getAttribute("data-end"), start, end)) {
      el.classList.add("hl");
    }
  }
}

// Hovering a single byte highlights the smallest structure node covering it.
function highlightOffset(off) {
  const insp = $("inspector");
  let best = null, bestLen = Infinity;
  for (const el of insp.querySelectorAll(".node")) {
    const s = +el.getAttribute("data-start"), e = +el.getAttribute("data-end");
    if (off >= s && off < e && e - s < bestLen) { best = [s, e]; bestLen = e - s; }
  }
  if (best) setHighlight(best[0], best[1]);
  else setHighlight(off, off + 1);
}

// ---- bootstrap ----------------------------------------------------------

function init() {
  // Hide the landmarks link if the endpoint isn't enabled.
  fetch("landmarks", { method: "HEAD" }).then((r) => {
    if (!r.ok) $("lmlink").style.display = "none";
  }).catch(() => { $("lmlink").style.display = "none"; });

  $("refresh").onclick = loadCheckpoint;
  $("mfetch").onclick = () => {
    const level = $("mlevel").value;
    const index = parseInt($("mindex").value, 10) || 0;
    const wraw = parseInt($("mwidth").value, 10);
    // If no width is given, size it from the current checkpoint (so the
    // rightmost partial tile resolves to its .p/<width> path automatically).
    const width = Number.isFinite(wraw) ? wraw : (tileWidth(level, index) || null);
    fetchTile(level, index, width);
  };
  $("efetch").onclick = fetchEntry;

  // Link the three inspector columns by byte range on hover.
  const insp = $("inspector");
  insp.addEventListener("mouseover", (ev) => {
    const t = ev.target;
    const off = t.getAttribute && t.getAttribute("data-off");
    if (off != null) { highlightOffset(+off); return; }
    const row = t.closest && t.closest(".node, .arow");
    if (row) setHighlight(+row.getAttribute("data-start"), +row.getAttribute("data-end"));
  });
  insp.addEventListener("mouseleave", () => setHighlight(null));

  populateLevels(); // seed the dropdown before the first checkpoint loads
  loadCheckpoint();
}

// Auto-run in the browser; stay inert under Bun (which sets the test flag
// before requiring this file) so the module can be imported for testing.
if (typeof document !== "undefined" && !globalThis.__CACTUS_TEST__) init();

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    TILE_W, formatTileIndex, tileURL, treeHeight, tileLevels, tileWidth,
    loadCheckpoint, renderTileLists, populateLevels, selectAndFetch, drillDown,
    openEntry, fetchTile, renderHashTile, renderEntriesTile, fetchEntry,
    DER, tagName, decodeOID, oidName, decodeDN, decodeSAN, hexPreview,
    previewInteger, formatTime, previewPrimitive, derNode, derForest,
    parseEntry, renderHexDump, renderStructure, renderAnnotations, renderEntry,
    within, setHighlight, highlightOffset, init,
    get treeSize() { return treeSize; },
    set treeSize(v) { treeSize = v; },
  };
}
