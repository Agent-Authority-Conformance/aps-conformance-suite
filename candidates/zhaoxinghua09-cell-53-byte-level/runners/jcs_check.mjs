#!/usr/bin/env node
/* jcs_check.mjs —— RFC 8785 (JCS) 字节级一致性，Node 侧
 *
 * 独立于 Python 侧：不共用代码、不共用向量构造逻辑，只读同一份向量文件。
 * 排序用 JS 字符串比较（按 UTF-16 码元，这正是 JCS 要求的口径）。
 * 数字交给 JSON.stringify —— 它产出的就是 ECMAScript Number::toString。
 *
 * 已知边界：
 * - 重复键只在**顶层对象**检测（文本扫描）；嵌套层重复键本实现取后者。
 * - 安全整数：正则扫文本里 >=16 位的整数字面量，命中即 INT_UNSAFE；字符串内的
 *   数字不会误判，因为扫描前先把字符串内容抹成空格。
 *
 * 用法：
 *   node jcs_check.mjs <vectors.json> [--json]
 */
import fs from "node:fs";

const SAFE = Number.MAX_SAFE_INTEGER;

function blankStrings(text) {
  let out = "", i = 0, inStr = false, esc = false;
  while (i < text.length) {
    const ch = text[i];
    if (inStr) {
      if (esc) { out += " "; esc = false; i++; continue; }
      if (ch === "\\") { out += " "; esc = true; i++; continue; }
      if (ch === '"') { out += '"'; inStr = false; i++; continue; }
      out += " "; i++; continue;
    }
    if (ch === '"') { out += '"'; inStr = true; i++; continue; }
    out += ch; i++;
  }
  return out;
}

function topLevelDuplicateKeys(text) {
  // 只处理顶层对象：{ "k": ... , "k": ... }
  const t = text.trim();
  if (t[0] !== "{") return null;
  const keys = [];
  let i = 1, depth = 0, inStr = false, esc = false, buf = "", readingKey = true;
  while (i < t.length) {
    const ch = t[i];
    if (inStr) {
      if (esc) { buf += ch; esc = false; i++; continue; }
      if (ch === "\\") { buf += ch; esc = true; i++; continue; }
      if (ch === '"') { inStr = false; keys.push(JSON.parse('"' + buf + '"')); buf = ""; readingKey = false; i++; continue; }
      buf += ch; i++; continue;
    }
    if (ch === '"') {
      if (depth === 0 && readingKey) { inStr = true; i++; continue; }
      inStr = true; i++; continue;
    }
    if (ch === ":" && depth === 0) { readingKey = false; i++; continue; }
    if (ch === "," && depth === 0) { readingKey = true; i++; continue; }
    if (ch === "{" || ch === "[") depth++;
    if (ch === "}" || ch === "]") { if (depth === 0) break; depth--; }
    i++;
  }
  const seen = new Set();
  for (const k of keys) {
    if (seen.has(k)) return k;
    seen.add(k);
  }
  return null;
}

function unsafeInt(text) {
  const flat = blankStrings(text);
  const m = flat.match(/(^|[^0-9.eE+\-])-?([0-9]{16,})(?![0-9.eE])/);
  if (!m) return null;
  const v = Number(m[2]);
  if (Math.abs(v) > SAFE) return m[2];
  return null;
}

function esc(s) {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out;
}

function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") return '"' + esc(v) + '"';
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map(k => '"' + esc(k) + '":' + canon(v[k])).join(",") + "}";
}

function loneSurrogate(v) {
  // 未配对代理必须拒；U+FFFD 替换会改掉签名字节而不报错
  if (typeof v === "string") {
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        const n = i + 1 < v.length ? v.charCodeAt(i + 1) : 0;
        if (n >= 0xdc00 && n <= 0xdfff) { i++; continue; }
        return true;
      }
      if (c >= 0xdc00 && c <= 0xdfff) return true;
    }
    return false;
  }
  if (Array.isArray(v)) return v.some(loneSurrogate);
  if (v && typeof v === "object") return Object.keys(v).some((k) => loneSurrogate(k) || loneSurrogate(v[k]));
  return false;
}

const file = process.argv[2];
const asJson = process.argv.includes("--json");
const vec = JSON.parse(fs.readFileSync(file, "utf8"));
const rows = [];
for (const c of vec.cases) {
  const want = c.expect;
  let got, code = null;
  if (c.raw_invalid) { got = "INVALID"; code = c.raw_invalid; }
  else {
    const dup = topLevelDuplicateKeys(c.input);
    const big = dup ? null : unsafeInt(c.input);
    if (dup) { got = "INVALID"; code = "DUPLICATE_KEY"; }
    else if (big) { got = "INVALID"; code = "INT_UNSAFE"; }
    else {
      const obj = JSON.parse(c.input);
      if (loneSurrogate(obj)) { got = "INVALID"; code = "LONE_SURROGATE"; }
      else got = canon(obj);
    }
  }
  rows.push({ id: c.id, got, code, ok: got === (want === undefined ? null : want) });
}
const passed = rows.filter(r => r.ok).length;
if (asJson) {
  console.log(JSON.stringify({ rows, verdict: passed === rows.length ? "PASS" : "FAIL", passed, total: rows.length }));
  process.exit(passed === rows.length ? 0 : 1);
}
for (const r of rows) console.log((r.ok ? "ok   " : "FAIL ") + r.id.padEnd(22) + String(r.code || r.got).slice(0, 80));
console.log(`TOTAL ${rows.length}  pass=${passed} fail=${rows.length - passed}`);
process.exit(passed === rows.length ? 0 : 1);
