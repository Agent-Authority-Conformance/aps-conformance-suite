// recompute41.mjs —— 4.1 对象侧的重算与失败闭合（Node 侧）
// 对应草案 REQ-4.1-7 / REQ-4.1-8。与 Python 侧不共享代码：JCS 规范化、域前缀、
// 判定次序都在这一侧重写一遍，只用 node:crypto 的 sha256。
// 判定次序 = 被测语义：载荷缺失 → payload_ref → action_ref → 之后才进策略。
// 用法：node recompute41.mjs <vectors.json> [--json]

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { createHash } from "node:crypto";

const PR_DOMAIN = "APS-ACTION-PAYLOAD-V1\u0000";
const AR_DOMAIN = "APS-ACTION-REF-V2\u0000";
const MEMBERS = ["profile", "agent_id", "action_type", "target", "payload_ref", "scope_required", "issued_at", "nonce"];
const ALIAS = "recompute-41.json";

function numstr(x) {
  if (Object.is(x, -0) || x === 0) return "0";
  const neg = x < 0;
  const ax = Math.abs(x);
  if (ax >= 1e-6 && ax < 1e21) {
    // ECMAScript Number::toString 在这些范围内就是最短十进制表示
    return String(neg ? -ax : ax);
  }
  let s = String(ax); // 形如 1e+21 / 1.5e+300 / 1e-7
  let mant, exp;
  if (s.includes("e")) {
    [mant, exp] = s.split("e");
    exp = Number(exp);
  } else {
    throw new Error("unexpected non-exponential for " + ax);
  }
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

// UTF-16 码元排序：JS 默认 string 比较就是按 UTF-16 码元，正好与 JCS 一致
function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return numstr(v);
  if (typeof v === "string") return '"' + esc(v) + '"';
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") {
    const ks = Object.keys(v).sort();
    return "{" + ks.map((k) => '"' + esc(k) + '":' + canon(v[k])).join(",") + "}";
  }
  throw new TypeError("unsupported " + typeof v);
}

const sha = (s) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
const payloadRef = (p) => sha(PR_DOMAIN + canon(p));
const actionRef = (o) => {
  const m = {};
  for (const k of MEMBERS) m[k] = o[k];
  return sha(AR_DOMAIN + canon(m));
};

function decide(c) {
  const rec = c.received;
  if (!("payload" in c) || c.payload === null || c.payload === undefined)
    return { id: c.id, got: "PAYLOAD_ABSENT", stage: "ref-check", reasons: ["PAYLOAD_ABSENT"], ok: c.expect === "PAYLOAD_ABSENT" };
  const reasons = [];
  if (payloadRef(c.payload) !== rec.payload_ref) reasons.push("PAYLOAD_REF_MISMATCH");
  if (actionRef(rec) !== rec.action_ref) reasons.push("ACTION_REF_MISMATCH");
  if (reasons.length) {
    const got = reasons.length === 1 ? reasons[0] : "BOTH_MISMATCH";
    return { id: c.id, got, stage: "ref-check", reasons, ok: got === c.expect };
  }
  if (c.policy === "DENY")
    return { id: c.id, got: "POLICY_DENIED", stage: "policy", reasons: ["POLICY_DENIED"], ok: c.expect === "POLICY_DENIED" };
  return { id: c.id, got: "DISPATCH", stage: "policy", reasons: ["DISPATCH"], ok: c.expect === "DISPATCH" };
}

const argv = process.argv.slice(2);
const jsonFlag = argv.includes("--json");
const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const given = argv.filter((x) => !x.startsWith("--"))[0];
const cands = [];
if (given) cands.push(given);
cands.push(path.join(path.dirname(here), "out", "recompute_vectors.json"));
cands.push(path.join(path.dirname(here), "vectors", ALIAS));
const vecPath = cands.find((p) => p && fs.existsSync(p));
if (!vecPath) { console.error("vectors not found"); process.exit(2); }

const rows = JSON.parse(fs.readFileSync(vecPath, "utf8")).cases.map(decide);
const ok = rows.every((r) => r.ok);

if (jsonFlag) {
  console.log(JSON.stringify({ rows, verdict: ok ? "PASS" : "FAIL",
                               passed: rows.filter((r) => r.ok).length, total: rows.length }));
} else {
  for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(28) + r.got.padEnd(20) + r.stage + " " + r.reasons.join(","));
  console.log(`TOTAL ${rows.length}  pass=${rows.filter((r) => r.ok).length} fail=${rows.filter((r) => !r.ok).length}`);
}
process.exit(ok ? 0 : 1);
