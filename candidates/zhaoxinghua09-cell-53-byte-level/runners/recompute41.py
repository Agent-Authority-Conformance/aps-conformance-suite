#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recompute41.py —— 4.1 对象侧的重算与失败闭合（Python 侧）

对应草案 REQ-4.1-7 / REQ-4.1-8：实现必须从"将要派发的载荷"重算 payload_ref、
从"收到的 4.1 对象"重算 action_ref，并且在策略评估之前就失败闭合。

与对方语料库的差别在于落点：他们自记这两条只对 4.2 外部形态成立
（docs/ID-COVERAGE.md，"no reachable test recomputes payload_ref or action_ref
for a Section 4.1 object"）。这里做的正是 4.1 对象侧。

判定次序即被测语义：
  1) 载荷缺失            → PAYLOAD_ABSENT      （stage=ref-check）
  2) payload_ref 重算不等 → PAYLOAD_REF_MISMATCH（stage=ref-check）
  3) action_ref  重算不等 → ACTION_REF_MISMATCH （stage=ref-check）
  4) 两项都过才进入策略   → DISPATCH / POLICY_DENIED（stage=policy）
因此"重算不过 + 策略本来会放行"的用例必须停在 ref-check，不得走到 DISPATCH。

用法：
  python recompute41.py --vectors <path>
  python recompute41.py --json [--vectors <path>]
"""
from __future__ import annotations
import hashlib, json, os, sys, argparse, decimal

PR_DOMAIN = "APS-ACTION-PAYLOAD-V1\x00"
AR_DOMAIN = "APS-ACTION-REF-V2\x00"
MEMBERS = ("profile", "agent_id", "action_type", "target", "payload_ref", "scope_required", "issued_at", "nonce")


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
        d = decimal.Decimal(r)
        r = format(d.normalize(), "e")
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


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def payload_ref(payload) -> str:
    return sha(PR_DOMAIN + canon(payload))


def action_ref(obj) -> str:
    return sha(AR_DOMAIN + canon({k: obj[k] for k in MEMBERS}))


def decide(c):
    rec = c["received"]
    if "payload" not in c or c["payload"] is None:
        return {"id": c["id"], "got": "PAYLOAD_ABSENT", "stage": "ref-check",
                "reasons": ["PAYLOAD_ABSENT"], "ok": c["expect"] == "PAYLOAD_ABSENT"}
    reasons = []
    pr = payload_ref(c["payload"])
    if pr != rec.get("payload_ref"):
        reasons.append("PAYLOAD_REF_MISMATCH")
    ar = action_ref(rec)
    if ar != rec.get("action_ref"):
        reasons.append("ACTION_REF_MISMATCH")
    if reasons:
        got = reasons[0] if len(reasons) == 1 else "BOTH_MISMATCH"
        return {"id": c["id"], "got": got, "stage": "ref-check",
                "reasons": reasons, "ok": got == c["expect"]}
    if c.get("policy") == "DENY":
        return {"id": c["id"], "got": "POLICY_DENIED", "stage": "policy", "reasons": ["POLICY_DENIED"],
                "ok": c["expect"] == "POLICY_DENIED"}
    return {"id": c["id"], "got": "DISPATCH", "stage": "policy", "reasons": ["DISPATCH"],
            "ok": c["expect"] == "DISPATCH"}


ALIAS = "recompute-41.json"


def resolve(a):
    here = os.path.dirname(os.path.abspath(__file__))
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "recompute_vectors.json"),
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
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(28) + r["got"].ljust(20) + r["stage"] + " " + ",".join(r["reasons"]))
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), sum(1 for r in rows if r["ok"]),
                                         sum(1 for r in rows if not r["ok"])))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
