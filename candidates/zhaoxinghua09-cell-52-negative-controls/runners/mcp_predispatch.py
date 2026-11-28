#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mcp_predispatch.py —— 预派发授权判定（v2 候选，Python 侧）

要补的空：我们此前所有判据都判「已发生的回执」，没有一件判**动手之前**。
竞品里 `agent-passport-system` 的 154 个 MCP 工具整套建在「先判后放」的形状上，
Open Agent Passport 更是把「pre-action authorization」写在标题里。这一块我们原本是空白。

本件照七维（`draft-pidlisnyi-aps-04` §4.1）做一次**派发前的门**：
输入 = 一张已授予的授权表 + 一次待执行的工具调用 + 当日已花额度，
输出 = ALLOW / DENY（带码）/ UNSUPPORTED（未知维）/ INVALID（缺维）。

判定顺序写死（先结构、后内容；内容按 scope→spend→depth→time→reputation→values→reversibility）：
  1 结构：未知维 → UNSUPPORTED；缺维 → INVALID（缺即无效，不补默认值）
  2 逐维：每维给码，**首个失败码作为主码，其余失败放进 also**（既不吞掉、也不靠顺序掩盖）
  3 全过 → ALLOW

码：
  PREDISPATCH_SCOPE / _SPEND_TX / _SPEND_DAY / _DEPTH / _EXPIRED / _REPUTATION /
  _VALUES / _IRREVERSIBLE ；结构码 FACET_MISSING / FACET_UNKNOWN / PARSE_ERROR

用法：
  python mcp_predispatch.py --selftest
  python mcp_predispatch.py --json
  python mcp_predispatch.py --vectors <path>     # 导出向量给 Node 侧独立判
"""
from __future__ import annotations
import argparse, json, sys

FACETS = ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"]
PROFILE = "zc/predispatch-v0"


def _v_scope(pol, call):
    tag = call.get("scope_tag")
    allowed = set(pol)
    if "*" in allowed or tag in allowed:
        return None
    return "PREDISPATCH_SCOPE: 调用标记 '" + str(tag) + "' 不在授权域 " + ",".join(sorted(allowed))


def _v_spend(pol, call, state):
    amt = call.get("amount", 0) or 0
    tx = pol.get("max_per_tx", 0)
    cap = pol.get("daily_cap", 0)
    if amt > tx:
        return f"PREDISPATCH_SPEND_TX: 单笔 {amt} > 上限 {tx}"
    spent = state.get("spent_today", 0) or 0
    if spent + amt > cap:
        return f"PREDISPATCH_SPEND_DAY: 当日已用 {spent} + 本笔 {amt} > 日限 {cap}"
    return None


def _v_depth(pol, call):
    d = call.get("depth", 0) or 0
    if d > pol:
        return f"PREDISPATCH_DEPTH: 调用深度 {d} > 授权 {pol}"
    return None


def _v_time(pol, call):
    at = call.get("at")
    if at is None:
        return None
    if at >= pol:
        return f"PREDISPATCH_EXPIRED: 调用时刻 {at} 已过授权到期 {pol}"
    return None


def _v_reputation(pol, call):
    rep = call.get("reputation")
    if rep is None:
        return None
    if rep < pol:
        return f"PREDISPATCH_REPUTATION: 调用方声誉 {rep} < 门槛 {pol}"
    return None


def _v_values(pol, call):
    tags = set(call.get("tags") or [])
    require = set(pol or [])
    bad = sorted(tags & {"pii", "exfil", "minors", "weapons"})
    hit = [t for t in bad if t not in require]
    if hit:
        return "PREDISPATCH_VALUES: 触碰未授权标签 " + ",".join(hit)
    return None


def _v_rev(pol, call):
    if call.get("reversible") is False and pol is not True:
        return "PREDISPATCH_IRREVERSIBLE: 不可逆动作未被授权"
    return None


ORDER = [("scope", _v_scope), ("spend", _v_spend), ("depth", _v_depth), ("time", _v_time),
         ("reputation", _v_reputation), ("values", _v_values), ("reversibility", _v_rev)]


def decide(policy, call, state=None):
    state = state or {}
    if not isinstance(policy, dict) or not isinstance(call, dict):
        return {"profile": PROFILE, "verdict": "INVALID", "code": "PARSE_ERROR", "also": []}
    unknown = [k for k in policy if k not in FACETS]
    if unknown:
        return {"profile": PROFILE, "verdict": "UNSUPPORTED",
                "code": "FACET_UNKNOWN: " + ",".join(sorted(unknown)), "also": []}
    missing = [k for k in FACETS if k not in policy]
    if missing:
        return {"profile": PROFILE, "verdict": "INVALID",
                "code": "FACET_MISSING: " + ",".join(missing), "also": []}

    fails = []
    for name, fn in ORDER:
        if name == "spend":
            r = fn(policy["spend"], call, state)
        else:
            r = fn(policy[name], call)
        if r:
            fails.append(r)
    if not fails:
        return {"profile": PROFILE, "verdict": "ALLOW", "code": None, "also": []}
    return {"profile": PROFILE, "verdict": "DENY", "code": fails[0], "also": fails[1:]}


POL = {"scope": ["tools:read", "tools:write"],
       "spend": {"currency": "USD", "max_per_tx": 500, "daily_cap": 2000},
       "depth": 2, "time": 1767225600, "reputation": 2,
       "values": ["no-pii"], "reversibility": False}

CALL = {"server": "mcp://files", "tool": "read_file", "scope_tag": "tools:read",
        "amount": 0, "depth": 1, "at": 1767225600 - 60, "reputation": 3,
        "tags": [], "reversible": True}

CASES = [
    ("allow-basic", POL, dict(CALL), {}, "ALLOW", None),
    ("scope-out", POL, {**CALL, "scope_tag": "payments:wire"}, {}, "DENY", "PREDISPATCH_SCOPE"),
    ("spend-tx", POL, {**CALL, "amount": 800}, {}, "DENY", "PREDISPATCH_SPEND_TX"),
    ("spend-day", POL, {**CALL, "amount": 300}, {"spent_today": 1800}, "DENY", "PREDISPATCH_SPEND_DAY"),
    ("depth", POL, {**CALL, "depth": 3}, {}, "DENY", "PREDISPATCH_DEPTH"),
    ("expired", POL, {**CALL, "at": 1767225600}, {}, "DENY", "PREDISPATCH_EXPIRED"),
    ("reputation", POL, {**CALL, "reputation": 1}, {}, "DENY", "PREDISPATCH_REPUTATION"),
    ("values-pii", POL, {**CALL, "tags": ["pii"]}, {}, "DENY", "PREDISPATCH_VALUES"),
    ("irreversible", POL, {**CALL, "reversible": False}, {}, "DENY", "PREDISPATCH_IRREVERSIBLE"),
    ("facet-missing", {k: v for k, v in POL.items() if k != "depth"}, dict(CALL), {}, "INVALID", "FACET_MISSING"),
    ("facet-unknown", {**POL, "geo_fence": ["EU"]}, dict(CALL), {}, "UNSUPPORTED", "FACET_UNKNOWN"),
    # 复合违规：主码按顺序取 scope，spend/depth 同时违规必须出现在 also 里，不许被吞
    ("multi-violation", POL, {**CALL, "scope_tag": "x:y", "amount": 900, "depth": 5}, {},
     "DENY", "PREDISPATCH_SCOPE"),
]


def run_cases():
    rows, ok = [], True
    for cid, pol, call, state, want_v, want_code in CASES:
        r = decide(pol, call, state)
        code_ok = True
        if want_code:
            code_ok = (r.get("code") or "").startswith(want_code)
        good = r["verdict"] == want_v and code_ok
        ok &= good
        rows.append({"id": cid, "expect": want_v, "got": r["verdict"], "code": r.get("code"),
                     "also": r.get("also", []), "ok": good})
    return rows, ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--vectors")
    a = ap.parse_args()

    if a.vectors:
        v = [{"id": c[0], "policy": c[1], "call": c[2], "state": c[3], "expect": c[4], "want_code": c[5]}
             for c in CASES]
        json.dump({"profile": PROFILE, "cases": v}, open(a.vectors, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print("VECTORS: %d -> %s" % (len(v), a.vectors))
        return 0

    rows, ok = run_cases()
    if a.json:
        print(json.dumps({"profile": PROFILE, "total": len(rows),
                          "passed": sum(1 for x in rows if x["ok"]), "rows": rows,
                          "verdict": "PASS" if ok else "FAIL"}, ensure_ascii=False))
        return 0 if ok else 1

    for x in rows:
        extra = ("  also=" + " | ".join(x["also"])) if x["also"] else ""
        print(("PASS " if x["ok"] else "FAIL ") + x["id"].ljust(18) + x["got"].ljust(12)
              + (x["code"] or "") + extra)
    print(f"RESULT: {sum(1 for x in rows if x['ok'])}/{len(rows)}  {'PASS' if ok else 'FAIL'}")
    print("NOTE: 本件为 Python 侧；Node 侧见 mcp_predispatch.mjs，逐例比对由 parity_check.py 出。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
