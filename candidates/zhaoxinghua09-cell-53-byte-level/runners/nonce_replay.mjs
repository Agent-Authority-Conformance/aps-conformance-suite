// nonce_replay.mjs —— 同 agent 窗口内 nonce 复用必须拒（Node 侧）
// 对应草案 REQ-4.1-9。与 Python 侧不共享代码。
// 判：ACCEPT / NONCE_REUSE / NONCE_MISSING / WINDOW_UNSPECIFIED / LEDGER_MALFORMED
// 用法：node nonce_replay.mjs <vectors.json> [--json]

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const ALIAS = "nonce-replay.json";

const isInt = (x) => typeof x === "number" && Number.isInteger(x);

function decide(c) {
  const ledger = c.ledger;
  const window = c.window_seconds;
  const pres = c.presented || {};
  const agent = pres.agent_id;
  const nonce = pres.nonce;
  const ts = pres.issued_at;

  if (!isInt(window) || window < 0)
    return { id: c.id, got: "WINDOW_UNSPECIFIED", reasons: ["WINDOW_UNSPECIFIED"], ok: c.expect === "WINDOW_UNSPECIFIED" };
  if (typeof nonce !== "string" || nonce === "")
    return { id: c.id, got: "NONCE_MISSING", reasons: ["NONCE_MISSING"], ok: c.expect === "NONCE_MISSING" };
  if (!Array.isArray(ledger))
    return { id: c.id, got: "LEDGER_MALFORMED", reasons: ["LEDGER_MALFORMED"], ok: c.expect === "LEDGER_MALFORMED" };
  for (const e of ledger) {
    if (!e || typeof e !== "object" || !("agent_id" in e) || !("nonce" in e) || !isInt(e.issued_at))
      return { id: c.id, got: "LEDGER_MALFORMED", reasons: ["LEDGER_MALFORMED"], ok: c.expect === "LEDGER_MALFORMED" };
  }
  if (!isInt(ts))
    return { id: c.id, got: "LEDGER_MALFORMED", reasons: ["MISSING_ISSUED_AT"], ok: c.expect === "LEDGER_MALFORMED" };

  const same = ledger.filter((e) => e.agent_id === agent && e.nonce === nonce);
  if (same.length === 0) {
    const other = ledger.some((e) => e.nonce === nonce);
    const why = other ? "OTHER_AGENT_ONLY" : "NO_PRIOR_PRESENTATION";
    return { id: c.id, got: "ACCEPT", reasons: [why], ok: c.expect === "ACCEPT" };
  }
  const inside = same.filter((e) => Math.abs(ts - e.issued_at) <= window);
  if (inside.length > 0)
    return { id: c.id, got: "NONCE_REUSE", reasons: ["NONCE_REUSE"], ok: c.expect === "NONCE_REUSE" };
  return { id: c.id, got: "ACCEPT", reasons: ["OUTSIDE_WINDOW"], ok: c.expect === "ACCEPT" };
}

const argv = process.argv.slice(2);
const jsonFlag = argv.includes("--json");
const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const given = argv.filter((x) => !x.startsWith("--"))[0];
const cands = [];
if (given) cands.push(given);
cands.push(path.join(path.dirname(here), "out", "nonce_vectors.json"));
cands.push(path.join(path.dirname(here), "vectors", ALIAS));
const vecPath = cands.find((p) => p && fs.existsSync(p));
if (!vecPath) { console.error("vectors not found"); process.exit(2); }

const cases = JSON.parse(fs.readFileSync(vecPath, "utf8")).cases;
const rows = cases.map(decide);
const ok = rows.every((r) => r.ok);

if (jsonFlag) {
  console.log(JSON.stringify({ rows, verdict: ok ? "PASS" : "FAIL",
                               passed: rows.filter((r) => r.ok).length, total: rows.length }));
} else {
  for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(30) + r.got + " " + r.reasons.join(","));
  console.log(`TOTAL ${rows.length}  pass=${rows.filter((r) => r.ok).length} fail=${rows.filter((r) => !r.ok).length}`);
}
process.exit(ok ? 0 : 1);
