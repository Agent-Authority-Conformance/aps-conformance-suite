// narrowing_check.mjs —— 七维收窄判定（v2 候选，Node 侧；与 Python 侧不共享代码）
//
// 输入：narrowing_check.py --vectors 导出的向量文件（parent/child 两张授权表）。
// 判法与 Python 侧独立实现，语义同 draft-pidlisnyi-aps-04 §4.1/§4.2：
//   七 facet 缺一即 INVALID；未知 facet → UNSUPPORTED；任一维放宽 → REJECT 并带 NARROW_<FACET>。
// 用法：node narrowing_check.mjs <vectors.json> [--json]

import fs from "node:fs";

const FACETS = ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"];
const PROFILE = "zc/narrowing-v0";

const subsetOk = (parent, child) => {
  const p = new Set(parent);
  if (p.has("*")) return null;
  const extra = [...new Set(child)].filter((x) => !p.has(x));
  return extra.length ? "NARROW_SCOPE: 子授权多出 " + extra.sort().join(",") : null;
};

const cmps = {
  scope: (p, c) => subsetOk(p, c),
  spend: (p, c) => {
    for (const k of ["max_per_tx", "daily_cap"]) {
      const pv = p[k] ?? 0, cv = c[k] ?? 0;
      if (cv > pv) return `NARROW_SPEND: ${k} 上调 ${pv} -> ${cv}`;
    }
    if (p.currency && c.currency && p.currency !== c.currency) return "NARROW_SPEND: 币种被换";
    return null;
  },
  depth: (p, c) => (c > p ? `NARROW_DEPTH: 深度上调 ${p} -> ${c}` : null),
  time: (p, c) => (c > p ? `NARROW_TIME: 到期被推后 ${p} -> ${c}` : null),
  reputation: (p, c) => (c < p ? `NARROW_REPUTATION: 门槛被压低 ${p} -> ${c}` : null),
  values: (p, c) => {
    const missing = [...new Set(p)].filter((x) => !new Set(c).has(x));
    return missing.length ? "NARROW_VALUES: 要求被删 " + missing.sort().join(",") : null;
  },
  reversibility: (p, c) => (c === true && p !== true ? "NARROW_REVERSIBILITY: 放开不可逆" : null),
};

function decide(parent, child) {
  if (typeof parent !== "object" || parent === null || typeof child !== "object" || child === null)
    return { verdict: "INVALID", reasons: ["PARSE_ERROR"] };
  const unknown = Object.keys(child).filter((k) => !FACETS.includes(k));
  if (unknown.length)
    return { verdict: "UNSUPPORTED", reasons: ["FACET_UNKNOWN: " + unknown.sort().join(",")] };
  const missing = FACETS.filter((f) => !(f in child));
  if (missing.length)
    return { verdict: "INVALID", reasons: ["FACET_MISSING: " + missing.join(",")] };
  const reasons = FACETS.map((f) => cmps[f](parent[f], child[f])).filter(Boolean);
  return { verdict: reasons.length ? "REJECT" : "ACCEPT", reasons };
}

export { decide };

function main() {
const file = process.argv[2];
if (!file) {
  console.error("用法: node narrowing_check.mjs <vectors.json> [--json]");
  process.exit(2);
}
const v = JSON.parse(fs.readFileSync(file, "utf8"));
const rows = v.cases.map((c) => {
  const r = decide(c.parent, c.child);
  return { id: c.id, expect: c.expect, got: r.verdict, reasons: r.reasons, ok: r.verdict === c.expect };
});
const passed = rows.filter((x) => x.ok).length;

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ profile: PROFILE, total: rows.length, passed, rows,
    verdict: passed === rows.length ? "PASS" : "FAIL" }, null, 0));
} else {
  for (const x of rows) console.log((x.ok ? "PASS " : "FAIL ") + x.id.padEnd(20) + x.got.padEnd(12) + x.reasons.join(" "));
  console.log(`RESULT: ${passed}/${rows.length}  ${passed === rows.length ? "PASS" : "FAIL"}`);
}
process.exit(passed === rows.length ? 0 : 1);
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
