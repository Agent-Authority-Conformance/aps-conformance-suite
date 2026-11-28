#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""narrowing_check.py —— 七维收窄判定（v2 候选，Python 侧；Node 侧未做，别当双实现）

来源：`draft-pidlisnyi-aps-04` §4.1/§4.2 把授权写成恰好七个 facet：
  scope / spend / depth / time / reputation / values / reversibility，
  「缺一个 facet 是 invalid，不是隐式不受限」；子授权在每个分量上必须 ≤ 父授权。
本件照这个形状做，**并多做一件对方 §19.2.17 自己承认没做的事**：
  遇到不认识的 facet 名，给 `Unsupported` 而不是猜。对方原文：「no family exercises a
  facet set other than the seven, so no vector shows what a verifier should return for a
  facet it does not know.」——我们给这条向量。

判定口径：
  ACCEPT       七维都在，且每维都 ≤ 父
  INVALID      缺 facet（缺即无效，不补默认值）
  UNSUPPORTED  出现未知 facet 名（不认识就不判，不许当成更宽或更窄）
  REJECT       某维放宽，带 `NARROW_<FACET>` 码

用法：
  python narrowing_check.py --selftest     # 跑内置 10 例
  python narrowing_check.py --json         # 机读
"""
from __future__ import annotations
import argparse, json, sys

FACETS = ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"]
PROFILE = "zc/narrowing-v0"


def _cmp_scope(parent, child):
    # scope 用集合包含：child ⊆ parent；'*' 视作全集
    ps, cs = set(parent), set(child)
    if "*" in ps:
        return True, None
    extra = cs - ps
    if extra:
        return False, "NARROW_SCOPE: 子授权多出 " + ",".join(sorted(extra))
    return True, None


def _cmp_spend(parent, child):
    for k in ("max_per_tx", "daily_cap"):
        if child.get(k, 0) > parent.get(k, 0):
            return False, f"NARROW_SPEND: {k} 上调 {parent.get(k,0)} -> {child.get(k,0)}"
    if parent.get("currency") and child.get("currency") and parent["currency"] != child["currency"]:
        return False, "NARROW_SPEND: 币种被换"
    return True, None


def _cmp_depth(parent, child):
    if child > parent:
        return False, f"NARROW_DEPTH: 深度上调 {parent} -> {child}"
    return True, None


def _cmp_time(parent, child):
    if child > parent:
        return False, f"NARROW_TIME: 到期被推后 {parent} -> {child}"
    return True, None


def _cmp_reputation(parent, child):
    if child < parent:
        return False, f"NARROW_REPUTATION: 门槛被压低 {parent} -> {child}"
    return True, None


def _cmp_values(parent, child):
    ps, cs = set(parent), set(child)
    if not ps.issubset(cs):
        return False, "NARROW_VALUES: 要求被删 " + ",".join(sorted(ps - cs))
    return True, None


def _cmp_reversibility(parent, child):
    if child is True and parent is not True:
        return False, "NARROW_REVERSIBILITY: 放开不可逆"
    return True, None


CMP = {"scope": _cmp_scope, "spend": _cmp_spend, "depth": _cmp_depth, "time": _cmp_time,
       "reputation": _cmp_reputation, "values": _cmp_values, "reversibility": _cmp_reversibility}


def check(parent, child):
    if not isinstance(parent, dict) or not isinstance(child, dict):
        return {"profile": PROFILE, "verdict": "INVALID", "reasons": ["PARSE_ERROR"]}
    unknown = [k for k in child if k not in FACETS]
    if unknown:
        return {"profile": PROFILE, "verdict": "UNSUPPORTED",
                "reasons": ["FACET_UNKNOWN: " + ",".join(sorted(unknown))]}
    missing = [k for k in FACETS if k not in child]
    if missing:
        return {"profile": PROFILE, "verdict": "INVALID",
                "reasons": ["FACET_MISSING: " + ",".join(missing)]}
    reasons = []
    for f in FACETS:
        ok, why = CMP[f](parent[f], child[f])
        if not ok:
            reasons.append(why)
    return {"profile": PROFILE, "verdict": "ACCEPT" if not reasons else "REJECT",
            "reasons": reasons}


BASE = {"scope": ["tools:read", "tools:write"], "spend": {"currency": "USD", "max_per_tx": 500, "daily_cap": 2000},
        "depth": 3, "time": 1767225600, "reputation": 2, "values": ["no-pii"], "reversibility": False}

CASES = [
    ("ok-same", BASE, dict(BASE), "ACCEPT", []),
    ("ok-tighter", BASE,
     {**BASE, "scope": ["tools:read"], "spend": {"currency": "USD", "max_per_tx": 100, "daily_cap": 500},
      "depth": 1, "time": 1767225600 - 3600, "reputation": 3, "values": ["no-pii", "no-exfil"]}, "ACCEPT", []),
    ("scope-widen", BASE, {**BASE, "scope": ["tools:read", "tools:write", "payments:wire"]}, "REJECT", ["NARROW_SCOPE"]),
    ("spend-widen", BASE, {**BASE, "spend": {"currency": "USD", "max_per_tx": 800, "daily_cap": 2000}}, "REJECT", ["NARROW_SPEND"]),
    ("depth-widen", BASE, {**BASE, "depth": 5}, "REJECT", ["NARROW_DEPTH"]),
    ("time-later", BASE, {**BASE, "time": 1767225600 + 86400}, "REJECT", ["NARROW_TIME"]),
    ("reputation-lower", BASE, {**BASE, "reputation": 1}, "REJECT", ["NARROW_REPUTATION"]),
    ("values-drop", BASE, {**BASE, "values": []}, "REJECT", ["NARROW_VALUES"]),
    ("irreversible-open", BASE, {**BASE, "reversibility": True}, "REJECT", ["NARROW_REVERSIBILITY"]),
    ("facet-missing", BASE, {k: v for k, v in BASE.items() if k != "spend"}, "INVALID", ["FACET_MISSING"]),
    ("facet-unknown", BASE, {**BASE, "geo_fence": ["EU"]}, "UNSUPPORTED", ["FACET_UNKNOWN"]),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--vectors", help="把 11 例导出成互通向量，供 Node 侧独立判定")
    a = ap.parse_args()

    if a.vectors:
        v = [{"id": c[0], "parent": c[1], "child": c[2], "expect": c[3]} for c in CASES]
        with open(a.vectors, "w", encoding="utf-8") as f:
            json.dump({"profile": PROFILE, "cases": v}, f, ensure_ascii=False, indent=1)
        print("VECTORS: %d -> %s" % (len(v), a.vectors))
        return 0

    rows, ok = [], True
    for cid, parent, child, want_v, want_reason in CASES:
        r = check(parent, child)
        got_v = r["verdict"]
        hit = any(reason.startswith(want_reason[0].split(":")[0]) for reason in r["reasons"]) if want_reason else not r["reasons"]
        good = got_v == want_v and hit
        ok &= good
        rows.append({"id": cid, "expect": want_v, "got": got_v, "reasons": r["reasons"], "ok": good})

    if a.json:
        print(json.dumps({"profile": PROFILE, "total": len(rows), "passed": sum(1 for x in rows if x["ok"]),
                          "rows": rows, "verdict": "PASS" if ok else "FAIL"}, ensure_ascii=False))
        return 0 if ok else 1

    for x in rows:
        print(("PASS " if x["ok"] else "FAIL ") + x["id"].ljust(20) + x["got"].ljust(12) + " ".join(x["reasons"]))
    print(f"RESULT: {sum(1 for x in rows if x['ok'])}/{len(rows)}  {'PASS' if ok else 'FAIL'}")
    print("NOTE: 本件为 Python 侧；Node 侧见 narrowing_check.mjs，逐例比对由 parity_check.py 出。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
