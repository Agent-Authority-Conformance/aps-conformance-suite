#!/usr/bin/env node
/* action_ref_dual.mjs —— action_ref 两形态，Node 侧
 *
 * 与 Python 侧规则相同、代码独立：
 *   v1 = sha256(JCS({agent_id, action_type, scope, timestamp}))，无域名前缀
 *   v2 = sha256("APS-ACTION-REF-V2\0" + JCS(8 成员对象))
 *
 * 输出串格式必须与 Python 侧逐字相同（parity 会逐字比）：
 *   MATCH ref=<hex> / RECOMPUTE_MISMATCH ref=<hex> / OK ref=<hex> / <CODE>
 *
 * 用法：node action_ref_dual.mjs <vectors.json> [--json]
 */
import fs from "node:fs";
import crypto from "node:crypto";

const V1_KEYS = ["agent_id", "action_type", "scope", "timestamp"];
const V2_KEYS = ["agent_id", "action_type", "issued_at", "nonce", "payload_ref", "profile", "scope_required", "target"];
const TS = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:60)?\.\d{3}Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX64ANY = /^[0-9a-fA-F]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const HEX32ANY = /^[0-9a-fA-F]{32}$/;
const DOMAIN = Buffer.from("APS-ACTION-REF-V2\0", "utf8");

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

const shaStr = s => crypto.createHash("sha256").update(s, "utf8").digest("hex");
const v1Ref = pre => shaStr(canon(pre));
const v2Ref = o => crypto.createHash("sha256").update(Buffer.concat([DOMAIN, Buffer.from(canon(o), "utf8")])).digest("hex");
const keysOf = o => Object.keys(o).sort();
const sameKeys = (o, ks) => keysOf(o).join(",") === [...ks].sort().join(",");

function v1Gate(pre) {
  if (!sameKeys(pre, V1_KEYS)) return "V1_KEYS";
  for (const k of V1_KEYS) if (typeof pre[k] !== "string") return "GRAMMAR_REJECT";
  if (!TS.test(pre.timestamp)) return "GRAMMAR_REJECT";
  return null;
}

const isStr = x => typeof x === "string";

function v2Gate(o) {
  if (!sameKeys(o, V2_KEYS)) return "V2_KEYS";
  if (o.profile !== "aps-action-ref-v2") return "PROFILE";
  for (const k of ["agent_id", "action_type", "target", "issued_at"]) {
    if (!isStr(o[k]) || o[k] === "") return "EMPTY_STRING";
  }
  if (!isStr(o.payload_ref) || !HEX64.test(o.payload_ref)) {
    return isStr(o.payload_ref) && HEX64ANY.test(o.payload_ref) ? "HEX_CASE" : "HEX_SHAPE";
  }
  if (!isStr(o.nonce) || !HEX32.test(o.nonce)) {
    return isStr(o.nonce) && HEX32ANY.test(o.nonce) ? "HEX_CASE" : "HEX_SHAPE";
  }
  if (!TS.test(o.issued_at)) return "ISSUED_AT_SHAPE";
  const sc = o.scope_required;
  if (!Array.isArray(sc) || sc.length === 0 || !sc.every(s => isStr(s) && s)) return "SCOPE_SHAPE";
  if (new Set(sc).size !== sc.length) return "SCOPE_DUP";
  for (const s of sc) if (s !== s.normalize("NFC")) return "SCOPE_NOT_NFC";
  // UTF-8 字节升序：用 Buffer 比较，不用 localeCompare
  for (let i = 1; i < sc.length; i++) {
    const a = Buffer.from(sc[i - 1], "utf8"), b = Buffer.from(sc[i], "utf8");
    if (Buffer.compare(a, b) >= 0) return "SCOPE_NOT_SORTED";
  }
  return null;
}

function run(c) {
  if (c.form === "v1") {
    const pre = c.preimage || c.payload;
    const g = v1Gate(pre);
    if (g) return g;
    const ref = v1Ref(pre);
    if (c.claim === undefined || c.claim === null) return "OK ref=" + ref;
    return ref === c.claim ? "MATCH ref=" + ref : "RECOMPUTE_MISMATCH ref=" + ref;
  }
  if (c.form === "v2") {
    const o = c.input;
    const g = v2Gate(o);
    if (g) return g;
    const ref = v2Ref(o);
    if (c.claim_plain) {
      const plain = shaStr(canon(o));
      return ref === plain ? "OK ref=" + ref : "REF_DOMAIN_MISSING";
    }
    return "OK ref=" + ref;
  }
  if (c.form === "v2slot") {
    const o = c.input;
    const g = v2Gate(o);
    if (g) return g;
    const ref = v2Ref(o);
    if (c.claimed === ref) return "OK ref=" + ref;
    const proj = {
      agent_id: o.agent_id, action_type: o.action_type,
      scope: o.scope_required.join(","), timestamp: o.issued_at,
    };
    if (c.claimed === v1Ref(proj)) return "V1_DIGEST_IN_V2_SLOT ref=" + ref;
    return "SLOT_NOT_V2_REF ref=" + ref;
  }
  if (c.form === "v2pair") {
    const refs = [];
    for (const o of c.inputs) {
      const g = v2Gate(o);
      if (g) return g;
      refs.push(v2Ref(o));
    }
    return refs[0] !== refs[1] ? "REFS_DIFFER ref0=" + refs[0] : "REFS_SAME";
  }
  return "UNKNOWN_FORM";
}

const file = process.argv[2];
const asJson = process.argv.includes("--json");
const cases = JSON.parse(fs.readFileSync(file, "utf8")).cases;
const rows = [];
for (const c of cases) {
  const got = run(c);
  const exp = c.expect || {};
  const code = got.split(" ")[0];
  let ok;
  if (exp.refs_differ) ok = got.split(" ")[0] === "REFS_DIFFER";
  else if (exp.ref) ok = got.endsWith("ref=" + exp.ref) && (exp.code === undefined || code === exp.code);
  else if (exp.code) ok = code === exp.code;
  else ok = false;
  rows.push({ id: c.id, got, reasons: [got], ok });
}
const passed = rows.filter(r => r.ok).length;
if (asJson) {
  console.log(JSON.stringify({ rows, verdict: passed === rows.length ? "PASS" : "FAIL", passed, total: rows.length }));
  process.exit(passed === rows.length ? 0 : 1);
}
for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(26) + r.got.slice(0, 100));
console.log(`TOTAL ${rows.length}  pass=${passed} fail=${rows.length - passed}`);
process.exit(passed === rows.length ? 0 : 1);
