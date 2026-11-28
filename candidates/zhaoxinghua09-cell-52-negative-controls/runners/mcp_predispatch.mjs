// mcp_predispatch.mjs —— 预派发授权判定（v2 候选，Node 侧；与 Python 侧不共享代码）
//
// 输入：mcp_predispatch.py --vectors 导出的向量（policy / call / state / expect）。
// 判法与 Python 侧独立实现：先结构（未知维→UNSUPPORTED，缺维→INVALID），
// 再按 scope→spend→depth→time→reputation→values→reversibility 逐维查，
// 首个失败码作主码，其余失败一律进 also（不吞、也不靠顺序掩盖）。
// 用法：node mcp_predispatch.mjs <vectors.json> [--json]

import fs from "node:fs";

const FACETS = ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"];
const PROFILE = "zc/predispatch-v0";
const SENSITIVE = ["pii", "exfil", "minors", "weapons"];

function vScope(pol, call) {
  const allowed = new Set(pol || []);
  if (allowed.has("*")) return null;
  const tag = String(call.scope_tag);
  if (allowed.has(call.scope_tag)) return null;
  return `PREDISPATCH_SCOPE: 调用标记 '${tag}' 不在授权域 ${[...allowed].sort().join(",")}`;
}

function vSpend(pol, call, state) {
  pol = pol || {};
  const amt = call.amount ?? 0;
  const tx = pol.max_per_tx ?? 0;
  const cap = pol.daily_cap ?? 0;
  if (amt > tx) return `PREDISPATCH_SPEND_TX: 单笔 ${amt} > 上限 ${tx}`;
  const spent = state.spent_today ?? 0;
  if (spent + amt > cap) return `PREDISPATCH_SPEND_DAY: 当日已用 ${spent} + 本笔 ${amt} > 日限 ${cap}`;
  return null;
}

const checks = {
  scope: (p, c) => vScope(p, c),
  spend: (p, c, s) => vSpend(p, c, s),
  depth: (p, c) => ((c.depth ?? 0) > p ? `PREDISPATCH_DEPTH: 调用深度 ${c.depth ?? 0} > 授权 ${p}` : null),
  time: (p, c) => (c.at == null ? null : (c.at >= p ? `PREDISPATCH_EXPIRED: 调用时刻 ${c.at} 已过授权到期 ${p}` : null)),
  reputation: (p, c) => (c.reputation == null ? null : (c.reputation < p ? `PREDISPATCH_REPUTATION: 调用方声誉 ${c.reputation} < 门槛 ${p}` : null)),
  values: (p, c) => {
    const tags = new Set(c.tags || []);
    const require = new Set(p || []);
    const hit = SENSITIVE.filter((t) => tags.has(t) && !require.has(t));
    return hit.length ? "PREDISPATCH_VALUES: 触碰未授权标签 " + hit.join(",") : null;
  },
  reversibility: (p, c) => (c.reversible === false && p !== true ? "PREDISPATCH_IRREVERSIBLE: 不可逆动作未被授权" : null),
};

function decide(policy, call, state) {
  state = state || {};
  if (typeof policy !== "object" || policy === null || typeof call !== "object" || call === null)
    return { verdict: "INVALID", code: "PARSE_ERROR", also: [] };
  const unknown = Object.keys(policy).filter((k) => !FACETS.includes(k));
  if (unknown.length) return { verdict: "UNSUPPORTED", code: "FACET_UNKNOWN: " + unknown.sort().join(","), also: [] };
  const missing = FACETS.filter((f) => !(f in policy));
  if (missing.length) return { verdict: "INVALID", code: "FACET_MISSING: " + missing.join(","), also: [] };

  const fails = FACETS.map((f) => checks[f](policy[f], call, state)).filter(Boolean);
  if (fails.length === 0) return { verdict: "ALLOW", code: null, also: [] };
  return { verdict: "DENY", code: fails[0], also: fails.slice(1) };
}

export { decide };

function main() {
const file = process.argv[2];
if (!file) { console.error("用法: node mcp_predispatch.mjs <vectors.json> [--json]"); process.exit(2); }
const v = JSON.parse(fs.readFileSync(file, "utf8"));

const rows = v.cases.map((c) => {
  const r = decide(c.policy, c.call, c.state);
  const codeOk = !c.want_code || String(r.code || "").startsWith(c.want_code);
  return { id: c.id, expect: c.expect, got: r.verdict, code: r.code, also: r.also,
           ok: r.verdict === c.expect && codeOk };
});
const passed = rows.filter((x) => x.ok).length;

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ profile: PROFILE, total: rows.length, passed, rows,
    verdict: passed === rows.length ? "PASS" : "FAIL" }));
} else {
  for (const x of rows) {
    const extra = x.also.length ? "  also=" + x.also.join(" | ") : "";
    console.log((x.ok ? "PASS " : "FAIL ") + x.id.padEnd(18) + x.got.padEnd(12) + (x.code || "") + extra);
  }
  console.log(`RESULT: ${passed}/${rows.length}  ${passed === rows.length ? "PASS" : "FAIL"}`);
}
process.exit(passed === rows.length ? 0 : 1);
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
