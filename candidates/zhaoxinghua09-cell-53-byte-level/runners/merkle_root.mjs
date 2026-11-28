#!/usr/bin/env node
/* merkle_root.mjs —— 默克尔根与包含证明，Node 侧
 *
 * 规则必须与 Python 侧一致但代码独立：
 *   leaf(m)   = sha256(0x00 || JCS(m))
 *   node(l,r) = sha256(0x01 || l || r)
 *   奇数末位：原样上提
 *   空树根    = 32×0x00
 *
 * 用法：node merkle_root.mjs <vectors.json> [--json]
 */
import fs from "node:fs";
import crypto from "node:crypto";

const ZERO = "00".repeat(32);

function esc(s) {
  let o = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') o += '\\"';
    else if (ch === "\\") o += "\\\\";
    else if (ch === "\n") o += "\\n";
    else if (ch === "\r") o += "\\r";
    else if (ch === "\t") o += "\\t";
    else if (ch === "\b") o += "\\b";
    else if (ch === "\f") o += "\\f";
    else if (c < 0x20) o += "\\u" + c.toString(16).padStart(4, "0");
    else o += ch;
  }
  return o;
}

function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return '"' + esc(v) + '"';
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const ks = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + ks.map(k => '"' + esc(k) + '":' + canon(v[k])).join(",") + "}";
}

const sha = b => crypto.createHash("sha256").update(b).digest();
const leaf = m => sha(Buffer.concat([Buffer.from([0]), Buffer.from(canon(m), "utf8")]));
const node = (l, r) => sha(Buffer.concat([Buffer.from([1]), l, r]));

function levels(ms) {
  let cur = ms.map(leaf);
  const lv = [cur];
  while (cur.length > 1) {
    const nxt = [];
    let i = 0;
    for (; i + 1 < cur.length; i += 2) nxt.push(node(cur[i], cur[i + 1]));
    if (i < cur.length) nxt.push(cur[i]);   // 上提
    cur = nxt;
    lv.push(cur);
  }
  return lv;
}

const rootOf = ms => (ms.length ? levels(ms).at(-1)[0].toString("hex") : ZERO);

function proof(ms, idx0) {
  const lv = levels(ms);
  let idx = idx0;
  const p = [];
  for (const h of lv.slice(0, -1)) {
    const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (sib < h.length) p.push([sib < idx ? "L" : "R", h[sib].toString("hex")]);
    idx = Math.floor(idx / 2);
  }
  return p;
}

function verify(m, p, root) {
  let h = leaf(m);
  for (const [side, sib] of p) {
    const s = Buffer.from(sib, "hex");
    h = side === "L" ? node(s, h) : node(h, s);
  }
  return h.toString("hex") === root;
}

const file = process.argv[2];
const asJson = process.argv.includes("--json");
const cases = JSON.parse(fs.readFileSync(file, "utf8")).cases;
const rows = [];
for (const c of cases) {
  const ms = c.leaves;
  const root = rootOf(ms);
  let code = null;
  if (c.index !== undefined && c.index !== null) {
    if (c.tamper) {
      const bad = Object.assign({}, ms[c.index], { __tampered__: true });
      code = verify(bad, proof(ms, c.index), root) ? "PROOF_ACCEPT" : "PROOF_REJECT";
    } else {
      code = verify(ms[c.index], proof(ms, c.index), root) ? "PROOF_ACCEPT" : "PROOF_REJECT";
    }
  }
  const ok = root === c.expect.root && code === (c.expect.code || null);
  const _r = "root=" + root + " " + (code || "");
  rows.push({ id: c.id, got: _r, reasons: [_r], reason: _r, ok, root, code });
}
const passed = rows.filter(r => r.ok).length;
if (asJson) {
  console.log(JSON.stringify({ rows, verdict: passed === rows.length ? "PASS" : "FAIL", passed, total: rows.length }));
  process.exit(passed === rows.length ? 0 : 1);
}
for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(20) + r.reason.slice(0, 90));
console.log(`TOTAL ${rows.length}  pass=${passed} fail=${rows.length - passed}`);
process.exit(passed === rows.length ? 0 : 1);


