// dupmember_check.mjs —— 序列化 JSON 重复成员名检测（字节级，转换前），Node 侧
// 对应草案 REQ-4.1-4。与 Python 侧不共享任何代码：这一侧用「逐字符游标 + 成员名集合」
// 自己走一遍，不调用 JSON.parse（JSON.parse 本身就会静默取后者，用它等于把要测的东西抹掉）。
// 判三个结果：ACCEPT / DUPLICATE_MEMBER / NOT_JSON
// 用法：node dupmember_check.mjs <vectors.json> [--json]

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const WS = " \t\r\n";

class Bad extends Error {}

function hex4(s, i) {
  if (i + 4 > s.length) throw new Bad("NOT_JSON:truncated-escape");
  const h = s.slice(i, i + 4);
  if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new Bad("NOT_JSON:bad-hex");
  return [parseInt(h, 16), i + 4];
}

function str(s, i) {
  if (s[i] !== '"') throw new Bad("NOT_JSON:expected-string");
  i += 1;
  let out = "";
  while (true) {
    if (i >= s.length) throw new Bad("NOT_JSON:unterminated-string");
    const ch = s[i];
    if (ch === '"') return [out, i + 1];
    if (ch === "\\") {
      const e = s[i + 1];
      if (e === undefined) throw new Bad("NOT_JSON:unterminated-escape");
      if (e === "u") {
        let [cp, j] = hex4(s, i + 2);
        if (cp >= 0xd800 && cp <= 0xdbff) {
          if (!(s[j] === "\\" && s[j + 1] === "u")) throw new Bad("NOT_JSON:lone-surrogate");
          const [lo, k] = hex4(s, j + 2);
          if (!(lo >= 0xdc00 && lo <= 0xdfff)) throw new Bad("NOT_JSON:lone-surrogate");
          cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
          j = k;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) {
          throw new Bad("NOT_JSON:lone-surrogate");
        }
        out += String.fromCodePoint(cp);
        i = j;
        continue;
      }
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (!(e in simple)) throw new Bad("NOT_JSON:bad-escape");
      out += simple[e];
      i += 2;
      continue;
    }
    if (ch.charCodeAt(0) < 0x20) throw new Bad("NOT_JSON:raw-control-in-string");
    out += ch;
    i += 1;
  }
}

function num(s, i) {
  const start = i;
  if (s[i] === "-") i += 1;
  if (!(s[i] >= "0" && s[i] <= "9")) throw new Bad("NOT_JSON:bad-number");
  if (s[i] === "0") {
    i += 1;
    if (s[i] >= "0" && s[i] <= "9") throw new Bad("NOT_JSON:leading-zero");
  } else {
    while (s[i] >= "0" && s[i] <= "9") i += 1;
  }
  if (s[i] === ".") {
    i += 1;
    if (!(s[i] >= "0" && s[i] <= "9")) throw new Bad("NOT_JSON:bad-fraction");
    while (s[i] >= "0" && s[i] <= "9") i += 1;
  }
  if (s[i] === "e" || s[i] === "E") {
    i += 1;
    if (s[i] === "+" || s[i] === "-") i += 1;
    if (!(s[i] >= "0" && s[i] <= "9")) throw new Bad("NOT_JSON:bad-exponent");
    while (s[i] >= "0" && s[i] <= "9") i += 1;
  }
  return [s.slice(start, i), i];
}

function skipWs(s, i) {
  while (i < s.length && WS.includes(s[i])) i += 1;
  return i;
}

function value(s, i, depth, found) {
  if (depth > 200) throw new Bad("NOT_JSON:too-deep");
  i = skipWs(s, i);
  if (i >= s.length) throw new Bad("NOT_JSON:eof");
  const ch = s[i];
  if (ch === "{") return obj(s, i, depth, found);
  if (ch === "[") return arr(s, i, depth, found);
  if (ch === '"') return str(s, i);
  if (ch === "-" || (ch >= "0" && ch <= "9")) return num(s, i);
  for (const [lit, rep] of [["true", true], ["false", false], ["null", null]]) {
    if (s.startsWith(lit, i)) return [rep, i + lit.length];
  }
  throw new Bad("NOT_JSON:unexpected-char");
}

function arr(s, i, depth, found) {
  i = skipWs(s, i + 1);
  if (s[i] === "]") return [[], i + 1];
  const out = [];
  while (true) {
    const [v, j] = value(s, i, depth + 1, found);
    out.push(v);
    i = skipWs(s, j);
    if (i >= s.length) throw new Bad("NOT_JSON:eof-in-array");
    if (s[i] === ",") { i += 1; continue; }
    if (s[i] === "]") return [out, i + 1];
    throw new Bad("NOT_JSON:expected-comma-or-close");
  }
}

function obj(s, i, depth, found) {
  i += 1;
  const seen = new Set();
  let first = true;
  while (true) {
    i = skipWs(s, i);
    if (i >= s.length) throw new Bad("NOT_JSON:eof-in-object");
    if (s[i] === "}") {
      if (!first) throw new Bad("NOT_JSON:trailing-comma");
      return [{}, i + 1];
    }
    if (!first) {
      if (s[i] !== ",") throw new Bad("NOT_JSON:expected-comma");
      i = skipWs(s, i + 1);
      if (s[i] === "}") throw new Bad("NOT_JSON:trailing-comma");
    }
    const [key, j] = str(s, i);
    if (seen.has(key)) found.add("DUPLICATE_MEMBER");
    seen.add(key);
    i = skipWs(s, j);
    if (s[i] !== ":") throw new Bad("NOT_JSON:expected-colon");
    const [v, k] = value(s, i + 1, depth + 1, found);
    i = skipWs(s, k);
    if (i >= s.length) throw new Bad("NOT_JSON:eof-in-object");
    if (s[i] === "}") return [{}, i + 1];
    if (s[i] !== ",") throw new Bad("NOT_JSON:expected-comma-or-close");
    first = false;
  }
}

function decide(c) {
  const found = new Set();
  try {
    const [, i] = value(c.input, 0, 0, found);
    const rest = skipWs(c.input, i);
    if (rest !== c.input.length) throw new Bad("NOT_JSON:trailing-content");
  } catch (e) {
    if (!(e instanceof Bad)) throw e;
    return { id: c.id, got: "NOT_JSON", reasons: [e.message.slice(0, 60)], ok: c.expect === "NOT_JSON" };
  }
  if (found.size) {
    return { id: c.id, got: "DUPLICATE_MEMBER", reasons: ["DUPLICATE_MEMBER"],
             ok: c.expect === "DUPLICATE_MEMBER", duplicate_anywhere: true };
  }
  return { id: c.id, got: "ACCEPT", reasons: ["ACCEPT"], ok: c.expect === "ACCEPT" };
}

const ALIAS = "dup-member.json";
const argv = process.argv.slice(2);
const jsonFlag = argv.includes("--json");
const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const given = argv.filter((x) => !x.startsWith("--"))[0];
const cands = [];
if (given) cands.push(given);
cands.push(path.join(path.dirname(here), "out", "dup_vectors.json"));
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
  for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(30) + r.got);
  console.log(`TOTAL ${rows.length}  pass=${rows.filter((r) => r.ok).length} fail=${rows.filter((r) => !r.ok).length}`);
}
process.exit(ok ? 0 : 1);
