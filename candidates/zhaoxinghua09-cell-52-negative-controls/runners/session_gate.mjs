// session_gate.mjs —— 串起来的会话门（v2 候选，Node 侧）
//
// 把三段串成一条：链有效性（cascade） → 策略是否 ≤ 根授权（narrowing） → 这次调用是否 ≤ 策略（predispatch）。
// 本侧不新写判法，而是**复用本侧已有的三件 Node 实现**，只补「层序编排」这一层——
// 与 Python 侧的做法不同（Python 是 import 同目录模块，Node 是 ESM import），这样两侧的拼接方式各自独立。
//
// 层序写死 L1→L5：L1 结构 → L2 链签名 → L3 撤销/过期 → L4 收窄 → L5 派发。
// 用法：node session_gate.mjs <vectors.json> [--json]

import fs from "node:fs";
import { checkCase, verify } from "./cascade_revoke.mjs";
import { decide as narrow } from "./narrowing_check.mjs";
import { decide as predispatch } from "./mcp_predispatch.mjs";

const FACETS = ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"];
const PROFILE = "zc/session-gate-v0";

// 绑定：策略必须由链尾 issuer 签、且指向链尾那一跳。验不了 → INDETERMINATE，不降格成 DENY。
function bind(chain, c) {
  const leaf = chain[chain.length - 1].rec;
  const env = c.envelope;
  if (!env || typeof env !== "object" || !("policy" in env))
    return "POLICY_UNBOUND: 出示的策略没有信封（无 delegation_id / 无签名）";
  if (!env.signature) return "POLICY_SIG_MISSING: 信封没有签名";
  if ((env.signed_by || "") !== leaf.issuer)
    return `POLICY_ISSUER_MISMATCH: 签名方 ${env.signed_by} 不是链尾 issuer ${leaf.issuer}`;
  if (env.delegation_id !== leaf.delegation_id)
    return `POLICY_NOT_LEAF: 信封指向 ${env.delegation_id}，链尾是 ${leaf.delegation_id}`;
  if (!c.policy_pubkey || !verify(env, c.policy_pubkey))
    return "POLICY_SIG_INVALID: 信封签名验不过（策略被改过或签名方不对）";
  return null;
}

function gate(c) {
  // L1 结构
  const unknown = Object.keys(c.policy).filter((k) => !FACETS.includes(k));
  if (unknown.length) return { verdict: "UNSUPPORTED", layer: "L1", code: "FACET_UNKNOWN: " + unknown.sort().join(","), also: [] };
  const missing = FACETS.filter((f) => !(f in c.policy));
  if (missing.length) return { verdict: "INVALID", layer: "L1", code: "FACET_MISSING: " + missing.join(","), also: [] };

  // L2 链真实性（不带撤销）
  const r2 = checkCase({ chain: c.chain, revocations: [], now: c.now });
  if (r2.reasons.length && r2.reasons[0].startsWith("DECL_SIG_INVALID"))
    return { verdict: "INDETERMINATE", layer: "L2", code: r2.reasons[0], also: [] };

  // L2' 绑定
  const b = bind(c.chain, c);
  if (b) return { verdict: "INDETERMINATE", layer: "L2", code: b, also: [] };

  // L3 有效性（撤销 + 过期）
  const r3 = checkCase({ chain: c.chain, revocations: c.revocations, now: c.now });
  if (r3.verdict === "invalid") return { verdict: "DENY", layer: "L3", code: r3.reasons[0], also: [] };
  if (r3.verdict === "indeterminate") return { verdict: "INDETERMINATE", layer: "L3", code: r3.reasons[0], also: [] };

  // L4 收窄：两道闸——策略 ≤ 根授权，且策略 ≤ 该跳被授予的 authority
  const r4 = narrow(c.root_authority, c.policy);
  if (r4.verdict === "REJECT") return { verdict: "DENY", layer: "L4", code: r4.reasons[0], also: r4.reasons.slice(1) };
  const leafAuth = c.chain[c.chain.length - 1].rec.authority || {};
  const r4b = narrow(leafAuth, c.policy);
  if (r4b.verdict === "REJECT")
    return { verdict: "DENY", layer: "L4", code: "POLICY_WIDENS_DELEGATED: 策略比该跳被授予的更宽 —— " + r4b.reasons[0], also: r4b.reasons.slice(1) };

  // L5 派发
  const r5 = predispatch(c.policy, c.call, c.state);
  if (r5.verdict === "ALLOW") return { verdict: "ALLOW", layer: null, code: null, also: [] };
  if (r5.verdict === "DENY") return { verdict: "DENY", layer: "L5", code: r5.code, also: r5.also };
  return { verdict: r5.verdict, layer: "L1", code: r5.code, also: [] };
}

function main() {
  const file = process.argv[2];
  if (!file) { console.error("用法: node session_gate.mjs <vectors.json> [--json]"); process.exit(2); }
  const v = JSON.parse(fs.readFileSync(file, "utf8"));
  const rows = v.cases.map((c) => {
    const r = gate(c);
    const codeOk = !c.want_code || String(r.code || "").startsWith(c.want_code);
    return { id: c.id, expect: c.expect, got: r.verdict, layer: r.layer, code: r.code,
             also: r.also, ok: r.verdict === c.expect && r.layer === c.want_layer && codeOk };
  });
  const passed = rows.filter((x) => x.ok).length;
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ profile: PROFILE, total: rows.length, passed, rows,
      verdict: passed === rows.length ? "PASS" : "FAIL" }));
  } else {
    for (const x of rows) {
      const extra = x.also.length ? "  also=" + x.also.join(" | ") : "";
      console.log((x.ok ? "PASS " : "FAIL ") + x.id.padEnd(24) + x.got.padEnd(14) + String(x.layer ?? "-").padEnd(4) + (x.code || "") + extra);
    }
    console.log(`RESULT: ${passed}/${rows.length}  ${passed === rows.length ? "PASS" : "FAIL"}`);
  }
  process.exit(passed === rows.length ? 0 : 1);
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
