// actionref_historical.mjs —— draft-01 历史 4.1 action_ref 形态（Node 侧）
// camelCase 四成员；scope 每串 NFC，列表按 Unicode 码点排序（不是 UTF-16 码元，故用 [...s] 逐码点比）；
// JCS；sha256；无域前缀。与 Python 侧不共享代码。
// 用法：node actionref_historical.mjs <vectors.json> [--json]

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { createHash } from "node:crypto";

const ALIAS = "actionref-historical.json";

function numstr(x) {
  if (Object.is(x, -0) || x === 0) return "0";
  const neg = x < 0;
  const ax = Math.abs(x);
  if (ax >= 1e-6 && ax < 1e21) return String(neg ? -ax : ax);
  let s = String(ax);
  if (!s.includes("e")) throw new Error("unexpected " + ax);
  let [mant, exp] = s.split("e");
  exp = Number(exp);
  if (mant.endsWith(".0")) mant = mant.slice(0, -2);
  return (neg ? "-" : "") + mant + "e" + (exp > 0 ? "+" : "-") + Math.abs(exp);
}

function esc(s) {
  let out = "";
  for (const ch of s) {
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch.codePointAt(0) < 0x20) out += "\\u" + ch.codePointAt(0).toString(16).padStart(4, "0");
    else out += ch;
  }
  return out;
}

function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return numstr(v);
  if (typeof v === "string") return '"' + esc(v) + '"';
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") {
    const ks = Object.keys(v).sort(); // 单层 ASCII 成员名：UTF-16 序与码点序一致
    return "{" + ks.map((k) => '"' + esc(k) + '":' + canon(v[k])).join(",") + "}";
  }
  throw new TypeError(typeof v);
}

// 码点序比较：先比首个不同的码点，短串在前
function cmpCodepoint(a, b) {
  const A = Array.from(a), B = Array.from(b);
  const n = Math.min(A.length, B.length);
  for (let i = 0; i < n; i++) {
    const x = A[i].codePointAt(0), y = B[i].codePointAt(0);
    if (x !== y) return x - y;
  }
  return A.length - B.length;
}

const sha = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

function decide(c) {
  const inp = c.input;
  const scopes = inp.scopeRequired.map((s) => s.normalize("NFC"));
  const uniq = [];
  let dup = false;
  for (const s of scopes) {
    if (uniq.includes(s)) dup = true;
    else uniq.push(s);
  }
  if (dup)
    return { id: c.id, got: "REJECT", reasons: ["DUPLICATE_SCOPE_REQUIRED"], ok: c.expect === "REJECT" };
  const order = uniq.slice().sort(cmpCodepoint);
  const obj = { agentId: inp.agentId, actionType: inp.actionType, scopeRequired: order, timestamp: inp.timestamp };
  const ref = sha(canon(obj));
  const scopeOrderOk = c.canonical_scope_order ? JSON.stringify(order) === JSON.stringify(c.canonical_scope_order) : true;
  return { id: c.id, got: ref, reasons: ["SCOPE_CANONICALIZED"], ok: ref === c.expect, scope_order: scopeOrderOk };
}

const argv = process.argv.slice(2);
const jsonFlag = argv.includes("--json");
const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const given = argv.filter((x) => !x.startsWith("--"))[0];
const cands = [];
if (given) cands.push(given);
cands.push(path.join(path.dirname(here), "out", "actionref_hist_vectors.json"));
cands.push(path.join(path.dirname(here), "vectors", ALIAS));
const vecPath = cands.find((p) => p && fs.existsSync(p));
if (!vecPath) { console.error("vectors not found"); process.exit(2); }

const rows = JSON.parse(fs.readFileSync(vecPath, "utf8")).cases.map(decide);
const ok = rows.every((r) => r.ok);
if (jsonFlag) {
  console.log(JSON.stringify({ rows, verdict: ok ? "PASS" : "FAIL", passed: rows.filter((r) => r.ok).length, total: rows.length }));
} else {
  for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(34) + String(r.got).slice(0, 24) + " " + r.reasons.join(","));
  console.log(`TOTAL ${rows.length}  pass=${rows.filter((r) => r.ok).length} fail=${rows.filter((r) => !r.ok).length}`);
}
process.exit(ok ? 0 : 1);
