#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""actionref_v2_members.py —— aps-action-ref-v2 的 profile 与成员非空（Python 侧）

对应的两条要求（对方 `docs/ID-COVERAGE.md` 在 `b0bf645c` 都记 **NOT EXERCISED**）：

  REQ-4.1-1  profile MUST equal "aps-action-ref-v2"
  REQ-4.1-2  All string fields MUST be non-empty except that a profile MAY permit
             an empty scope_required array.

本件只判这两条，不算 action_ref，不涉及 JCS 或域前缀（那在别的族里）。
本文档的读法：本 profile 未声明允许空 scope_required 数组，故空数组按拒处理；
期望值来自草案句面，不来自任何实现（他们 SDK 的 computeActionRefV2 不做这类校验）。

用法：
  python actionref_v2_members.py --vectors <path>
  python actionref_v2_members.py --json [--vectors <path>]
"""
from __future__ import annotations
import json, os, sys, argparse

ALIAS = "actionref-v2-members.json"

STRING_FIELDS = ["agent_id", "action_type", "target", "payload_ref", "issued_at", "nonce"]


def decide(case):
    inp = case["input"]
    if inp.get("profile") != "aps-action-ref-v2":
        return {"id": case["id"], "got": "REJECT", "reasons": ["PROFILE_NOT_V2"],
                "layer": "profile", "ok": case["expect"] == "REJECT"}
    for f in STRING_FIELDS:
        v = inp.get(f)
        if not isinstance(v, str) or v == "":
            return {"id": case["id"], "got": "REJECT", "reasons": ["EMPTY_MEMBER " + f],
                    "layer": "members", "ok": case["expect"] == "REJECT"}
    sc = inp.get("scope_required")
    if not isinstance(sc, list):
        return {"id": case["id"], "got": "REJECT", "reasons": ["SCOPE_REQUIRED_NOT_ARRAY"],
                "layer": "members", "ok": case["expect"] == "REJECT"}
    if len(sc) == 0:
        return {"id": case["id"], "got": "REJECT", "reasons": ["EMPTY_SCOPE_ARRAY"],
                "layer": "members", "ok": case["expect"] == "REJECT"}
    for s in sc:
        if not isinstance(s, str) or s == "":
            return {"id": case["id"], "got": "REJECT", "reasons": ["EMPTY_MEMBER scope_required"],
                    "layer": "members", "ok": case["expect"] == "REJECT"}
    return {"id": case["id"], "got": "ACCEPT", "reasons": ["PROFILE_AND_MEMBERS_OK"],
            "layer": "members", "ok": case["expect"] == "ACCEPT"}


def resolve(a):
    here = os.path.dirname(os.path.abspath(__file__))
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "actionref_v2_member_vectors.json"),
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
                          "passed": sum(1 for r in rows if r["ok"]), "total": len(rows)},
                         ensure_ascii=False))
        return 0 if ok else 1
    for r in rows:
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(30) + r["got"][:22].ljust(24)
              + r["layer"].ljust(8) + ",".join(r["reasons"]))
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), sum(1 for r in rows if r["ok"]),
                                         sum(1 for r in rows if not r["ok"])))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
