#!/usr/bin/env node
// actionref_v2_members.mjs —— aps-action-ref-v2 的 profile 与成员非空（Node 侧）
//
// 与 Python 侧不共享代码：本文件自己走一遍同样两条要求的判定，逐例输出
// verdict / reasons / layer，供 parity_check 逐字比对。
//
//   node actionref_v2_members.mjs <vectors.json> [--json]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STRING_FIELDS = ["agent_id", "action_type", "target", "payload_ref", "issued_at", "nonce"];

function decide(c) {
  const inp = c.input ?? {};
  if (inp.profile !== "aps-action-ref-v2")
    return { id: c.id, got: "REJECT", reasons: ["PROFILE_NOT_V2"], layer: "profile", ok: c.expect === "REJECT" };
  for (const f of STRING_FIELDS) {
    const v = inp[f];
    if (typeof v !== "string" || v.length === 0)
      return { id: c.id, got: "REJECT", reasons: ["EMPTY_MEMBER " + f], layer: "members", ok: c.expect === "REJECT" };
  }
  const sc = inp.scope_required;
  if (!Array.isArray(sc))
    return { id: c.id, got: "REJECT", reasons: ["SCOPE_REQUIRED_NOT_ARRAY"], layer: "members", ok: c.expect === "REJECT" };
  if (sc.length === 0)
    return { id: c.id, got: "REJECT", reasons: ["EMPTY_SCOPE_ARRAY"], layer: "members", ok: c.expect === "REJECT" };
  for (const s of sc) {
    if (typeof s !== "string" || s.length === 0)
      return { id: c.id, got: "REJECT", reasons: ["EMPTY_MEMBER scope_required"], layer: "members", ok: c.expect === "REJECT" };
  }
  return { id: c.id, got: "ACCEPT", reasons: ["PROFILE_AND_MEMBERS_OK"], layer: "members", ok: c.expect === "ACCEPT" };
}

function resolveVectors(arg) {
  if (arg) return arg;
  const cand = [
    path.join(path.dirname(HERE), "out", "actionref_v2_member_vectors.json"),
    path.join(path.dirname(HERE), "vectors", "actionref-v2-members.json"),
  ];
  for (const p of cand) if (fs.existsSync(p)) return p;
  throw new Error("vectors not found");
}

const args = process.argv.slice(2);
const json = args.includes("--json");
const vpath = resolveVectors(args.find((a) => !a.startsWith("--")));
const cases = JSON.parse(fs.readFileSync(vpath, "utf8")).cases;
const rows = cases.map(decide);
const ok = rows.every((r) => r.ok);
if (json) {
  process.stdout.write(JSON.stringify({ rows, verdict: ok ? "PASS" : "FAIL",
    passed: rows.filter((r) => r.ok).length, total: rows.length }));
} else {
  for (const r of rows)
    console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(30) + r.got.padEnd(24) + r.reasons.join(","));
  console.log(`TOTAL ${rows.length}  pass=${rows.filter((r) => r.ok).length} fail=${rows.filter((r) => !r.ok).length}`);
}
process.exit(ok ? 0 : 1);
