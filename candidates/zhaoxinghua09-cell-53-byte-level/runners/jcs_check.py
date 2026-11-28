#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jcs_check.py —— RFC 8785 (JCS) 字节级一致性，Python 侧

判什么：把一段 JSON 文本规范成 JCS 字节串，与向量里写死的期望串逐字节比。
为什么要有：双实现对跑只证明"两边语义一致"，证明不了"两边序列化出的字节一样"。
字节不一致，签名就对不上，而签名对不上的收据在两个实现之间根本没法互验。

已知边界（写在代码里而不是事后补）：
- 数字格式按 ECMAScript Number::toString 的规则实现，只覆盖本向量集出现的形态，
  不做 MSVC/printf 那种 17 位有效数字的兜底。
- 重复键只在**顶层对象**检测；嵌套层的重复键本实现会静默取后者。
- 安全整数上限按 IEEE 754 双精度：|n| > 2**53-1 判 INT_UNSAFE。

用法：
  python jcs_check.py --vectors <path>     # 导出向量并逐例判定
  python jcs_check.py --json               # 机读结果（给 parity_check 用）
"""
from __future__ import annotations
import json, sys, os, argparse, decimal

SAFE = 2 ** 53 - 1


class Dup(Exception):
    pass


def _pairs(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Dup("DUPLICATE_KEY:" + k)
        seen[k] = v
    return seen


def _num(s):
    # 浮点字面量（含 e 指数）没有整数精度问题，不在这里判 INT_UNSAFE
    return float(s)


def _int(s):
    v = int(s)
    if abs(v) > SAFE:
        raise ValueError("INT_UNSAFE:" + s)
    return v


def numstr(x: float) -> str:
    """ECMAScript Number::toString 的常用分支"""
    if x == 0:
        return "0"
    neg = x < 0
    ax = abs(x)
    r = repr(ax)
    if 1e-6 <= ax < 1e21:
        if "e" in r or "E" in r:
            d = decimal.Decimal(r)
            s = format(d, "f")
            if "." in s:
                s = s.rstrip("0").rstrip(".")
            return ("-" if neg else "") + s
        if r.endswith(".0"):
            r = r[:-2]
        return ("-" if neg else "") + r
    # exponential form: d[.ddd]e±x, no zero padding
    if "e" not in r and "E" not in r:
        d = decimal.Decimal(r)
        r = format(d.normalize(), "e")
    mant, exp = r.split("e")
    if mant.endswith(".0"):
        mant = mant[:-2]
    exp = int(exp)
    return ("-" if neg else "") + mant + "e" + ("+" if exp > 0 else "-") + str(abs(exp))


ESC = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t",
       "\b": "\\b", "\f": "\\f"}


def esc(s: str) -> str:
    out = []
    for ch in s:
        if ch in ESC:
            out.append(ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def canon(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return numstr(float(v))
    if isinstance(v, str):
        return '"' + esc(v) + '"'
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join('"' + esc(k) + '":' + canon(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


def _no_lone_surr(v, where=""):
    """JSON 文本里未配对的代理必须拒：替换成 U+FFFD 会改变签名字节而不报错"""
    if isinstance(v, str):
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise ValueError("LONE_SURROGATE:" + where)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _no_lone_surr(x, where + "[%d]" % i)
    elif isinstance(v, dict):
        for k, x in v.items():
            _no_lone_surr(k, where + ".key")
            _no_lone_surr(x, where + "." + k)


def decide(case):
    cid = case["id"]
    want = case.get("expect")
    try:
        if case.get("raw_invalid"):
            return {"id": cid, "got": "INVALID", "code": case["raw_invalid"], "ok": want == "INVALID"}
        obj = json.loads(case["input"], object_pairs_hook=_pairs, parse_int=_int, parse_float=_num)
        _no_lone_surr(obj, "$")
        got = canon(obj)
        return {"id": cid, "got": got, "code": None, "ok": got == want}
    except Dup as e:
        return {"id": cid, "got": "INVALID", "code": "DUPLICATE_KEY", "ok": want == "INVALID"}
    except (ValueError, TypeError) as e:
        code = str(e).split(":")[0] or "PARSE_ERROR"
        return {"id": cid, "got": "INVALID", "code": code, "ok": want == "INVALID"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.vectors and not a.json:
        v = json.load(open(a.vectors, encoding="utf-8"))
        json.dump({"profile": "rfc8785-jcs-bytes", "note": v.get("note"),
                   "cases": v["cases"]}, open(a.vectors, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("vectors written: " + a.vectors + " (%d cases)" % len(v["cases"]))
        return 0
    here = os.path.dirname(os.path.abspath(__file__))
    # 两处布局都认：开发布局 out/<name>，候选目录布局 vectors/<alias>
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "jcs_vectors.json"),
             os.path.join(os.path.dirname(here), "vectors", "jcs.json")]
    vec = next(p for p in cand if p and os.path.isfile(p))
    cases = json.load(open(vec, encoding="utf-8"))["cases"]
    rows = [decide(c) for c in cases]
    if a.json:
        print(json.dumps({"rows": rows, "verdict": "PASS" if all(r["ok"] for r in rows) else "FAIL",
                          "passed": sum(1 for r in rows if r["ok"]), "total": len(rows)}, ensure_ascii=False))
        return 0
    for r in rows:
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(22) + str(r["code"] or r["got"])[:80])
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), sum(1 for r in rows if r["ok"]),
                                         sum(1 for r in rows if not r["ok"])))
    return 0 if all(r["ok"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
