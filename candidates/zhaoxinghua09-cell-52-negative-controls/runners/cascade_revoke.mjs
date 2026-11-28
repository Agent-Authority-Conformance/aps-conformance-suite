// cascade_revoke.mjs —— 级联撤销判定（v2 候选，Node 侧；与 Python 侧不共享代码）
//
// 输入：cascade_revoke.py --vectors 导出的向量（每条记录带签名与裸公钥）。
// 本侧自己做两件 Python 侧做过的事，且用不同的库：窄序列化 + Ed25519 验签（node:crypto）。
// 判定顺序写死：签名 → 撤销成立性 → 级联失效 → 过期。
// 用法：node cascade_revoke.mjs <vectors.json> [--json]

import fs from "node:fs";
import crypto from "node:crypto";

const ROOT_TYPE = "zc/cascade-v0";
const DECL = "aps:authority-delegation:v1";
const REV = "aps:authority-revocation:v1";
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// 与 Python 侧 json.dumps(sort_keys=True, separators=(",",":")) 同形的窄序列化
function canon(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  }
  if (typeof v === "string") return JSON.stringify(v);
  return String(v);
}

function verify(rec, pubkeyHex) {
  const body = {};
  for (const k of Object.keys(rec)) if (k !== "signature") body[k] = rec[k];
  const key = crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubkeyHex, "hex")]),
    format: "der", type: "spki",
  });
  const sig = Buffer.from(rec.signature || "", "hex");
  if (sig.length !== 64) return false;
  return crypto.verify(null, Buffer.from(canon(body), "utf8"), key, sig);
}

function checkCase(c) {
  const chain = c.chain.map((w) => w.rec);
  const pubs = c.chain.map((w) => w.pubkey);

  for (let i = 0; i < chain.length; i++)
    if (!verify(chain[i], pubs[i])) return { verdict: "indeterminate", reasons: ["DECL_SIG_INVALID: " + (chain[i].delegation_id ?? "?")] };

  const issuers = new Map(chain.map((d) => [d.delegation_id, d.issuer]));
  const established = [];
  const notes = [];

  for (const w of c.revocations) {
    const r = w.rec;
    if (r.record_type !== REV) { notes.push("EVIDENCE_IS_NOT_CAUSE: 忽略非撤销记录 " + String(r.record_type)); continue; }
    if (!verify(r, w.pubkey)) return { verdict: "indeterminate", reasons: ["REVOCATION_UNESTABLISHED: 签名验不过"] };
    if (!issuers.has(r.delegation_id)) return { verdict: "indeterminate", reasons: ["REVOCATION_UNKNOWN_TARGET: " + String(r.delegation_id)] };
    if (r.issuer !== issuers.get(r.delegation_id)) return { verdict: "indeterminate", reasons: ["REVOCATION_UNESTABLISHED: 签署方不是该委派的 issuer"] };
    established.push(r.delegation_id);
  }

  for (let i = 0; i < chain.length; i++)
    if (established.includes(chain[i].delegation_id))
      return { verdict: "invalid", reasons: [`REVOKED_CASCADE: ${chain[i].delegation_id} 位于第 ${i} 跳，其后代一并失效`] };

  for (const d of chain)
    if (d.expires_at != null && c.now >= d.expires_at)
      return { verdict: "invalid", reasons: ["DELEGATION_EXPIRED: " + d.delegation_id] };

  return { verdict: "valid", reasons: [], notes };
}

export { checkCase, canon, verify };

function main() {
const file = process.argv[2];
if (!file) { console.error("用法: node cascade_revoke.mjs <vectors.json> [--json]"); process.exit(2); }
const v = JSON.parse(fs.readFileSync(file, "utf8"));

const rows = v.cases.map((c) => {
  const r = checkCase({ ...c, chain: c.chain, revocations: c.revocations });
  const codeOk = !c.want_code ? r.reasons.length === 0 : (c.want_code === "EVIDENCE_IS_NOT_CAUSE" ? r.verdict === "valid" : r.reasons.some((x) => x.startsWith(c.want_code)));
  return { id: c.id, expect: c.expect, got: r.verdict, reasons: r.reasons, ok: r.verdict === c.expect && codeOk };
});
const passed = rows.filter((x) => x.ok).length;

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ profile: ROOT_TYPE, total: rows.length, passed, rows,
    verdict: passed === rows.length ? "PASS" : "FAIL" }));
} else {
  for (const x of rows) console.log((x.ok ? "PASS " : "FAIL ") + x.id.padEnd(24) + x.got.padEnd(14) + x.reasons.join(" "));
  console.log(`RESULT: ${passed}/${rows.length}  ${passed === rows.length ? "PASS" : "FAIL"}`);
}
process.exit(passed === rows.length ? 0 : 1);
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
