#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actionref_historical.py —— draft-01 历史 4.1 action_ref 形态（Python 侧）

这一形态与当前的 v1/v2 都不同：成员名是 camelCase（agentId / actionType /
scopeRequired / timestamp），scope 每串先 NFC，scope 列表按 **Unicode 码点** 排序
（不是 UTF-16 码元），再 JCS，再 sha256，**无域前缀**。

四个正例的期望值直接取对方语料库
`fixtures/actionref-canonical/actionref-canonical-fixture-v1.json`（提交 `79e9a7d4`），
我们做第三方复算；两个负例也取自同文件，含义是"重复 scopeRequired 必须拒，
NFC 之后再判"——他们在 note 里写明这是实现自定行为，不是草案 4.1 的要求。

用法：
  python actionref_historical.py --vectors <path>
  python actionref_historical.py --json [--vectors <path>]
"""
from __future__ import annotations
import hashlib, json, os, sys, argparse, decimal, unicodedata

ALIAS = "actionref-historical.json"


def numstr(x: float) -> str:
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
    if "e" not in r and "E" not in r:
        r = format(decimal.Decimal(r).normalize(), "e")
    mant, exp = r.split("e")
    if mant.endswith(".0"):
        mant = mant[:-2]
    e = int(exp)
    return ("-" if neg else "") + mant + "e" + ("+" if e > 0 else "-") + str(abs(e))


ESC = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}


def esc(s):
    out = []
    for ch in s:
        if ch in ESC:
            out.append(ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def canon(v):
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
        ks = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join('"' + esc(k) + '":' + canon(v[k]) for k in ks) + "}"
    raise TypeError(type(v))


def codepoints(s):
    return [ord(ch) for ch in s]


def decide(case):
    inp = case["input"]
    scopes = [unicodedata.normalize("NFC", s) for s in inp["scopeRequired"]]
    uniq = []
    dup = False
    for s in scopes:
        if s in uniq:
            dup = True
        else:
            uniq.append(s)
    if dup:
        return {"id": case["id"], "got": "REJECT", "reasons": ["DUPLICATE_SCOPE_REQUIRED"],
                "ok": case["expect"] == "REJECT"}
    order = sorted(uniq, key=codepoints)
    obj = {"agentId": inp["agentId"], "actionType": inp["actionType"],
           "scopeRequired": order, "timestamp": inp["timestamp"]}
    ref = hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()
    return {"id": case["id"], "got": ref, "reasons": ["SCOPE_CANONICALIZED"],
            "ok": ref == case["expect"], "scope_order": order == case.get("canonical_scope_order", order)}


def resolve(a):
    here = os.path.dirname(os.path.abspath(__file__))
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "actionref_hist_vectors.json"),
             os.path.join(os.path.dirname(here), "vectors", ALIAS)]
    return next(p for p in cand if p and os.path.isfile(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    cases = json.load(open(resolve(a), encoding="utf-8"))["cases"]
    rows = [decide(c) for c in cases]
    ok = all(r["ok"] for r in rows)
    if a.json:
        print(json.dumps({"rows": rows, "verdict": "PASS" if ok else "FAIL",
                          "passed": sum(1 for r in rows if r["ok"]), "total": len(rows)}, ensure_ascii=False))
        return 0 if ok else 1
    for r in rows:
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(34) + str(r["got"])[:24] + " " + ",".join(r["reasons"]))
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), sum(1 for r in rows if r["ok"]),
                                         sum(1 for r in rows if not r["ok"])))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
