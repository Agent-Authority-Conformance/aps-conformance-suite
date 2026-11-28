#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nonce_replay.py —— 同 agent 在重放窗口内复用 nonce 必须拒（Python 侧）

对应草案 REQ-4.1-9。草案原文要求"reject reuse of nonce by the same agent within
the deployment's replay window"。这里把它落成一个可判的门：
  - 部署给一个窗口 W（秒，整数）；取不到窗口即 WINDOW_UNSPECIFIED，不许默认放行
  - 判的是 (agent_id, nonce) 这一对，不是 nonce 单值：不同 agent 撞 nonce 不算复用
  - 窗口是两端闭区间：|presented.issued_at - prior.issued_at| <= W 才算"窗口内"
  - 同 agent 同 nonce 但 issued_at 差超过 W，视为窗口外，放行（理由写明 OUTSIDE_WINDOW）
  - nonce 缺失/空串 → NONCE_MISSING；台账条目字段不全 → LEDGER_MALFORMED

判四个结果：ACCEPT / NONCE_REUSE / NONCE_MISSING / WINDOW_UNSPECIFIED / LEDGER_MALFORMED

用法：
  python nonce_replay.py --vectors <path>
  python nonce_replay.py --json [--vectors <path>]
"""
from __future__ import annotations
import json, os, sys, argparse

ALIAS = "nonce-replay.json"


def _int(x):
    if isinstance(x, bool) or not isinstance(x, int):
        return None
    return x


def decide(case):
    ledger = case.get("ledger")
    window = _int(case.get("window_seconds"))
    pres = case.get("presented") or {}
    agent = pres.get("agent_id")
    nonce = pres.get("nonce")
    ts = _int(pres.get("issued_at"))

    if window is None or window < 0:
        return {"id": case["id"], "got": "WINDOW_UNSPECIFIED", "reasons": ["WINDOW_UNSPECIFIED"], "ok": case["expect"] == "WINDOW_UNSPECIFIED"}
    if not isinstance(nonce, str) or nonce == "":
        return {"id": case["id"], "got": "NONCE_MISSING", "reasons": ["NONCE_MISSING"], "ok": case["expect"] == "NONCE_MISSING"}
    if not isinstance(ledger, list):
        return {"id": case["id"], "got": "LEDGER_MALFORMED", "reasons": ["LEDGER_MALFORMED"], "ok": case["expect"] == "LEDGER_MALFORMED"}
    for e in ledger:
        if not isinstance(e, dict) or "agent_id" not in e or "nonce" not in e or _int(e.get("issued_at")) is None:
            return {"id": case["id"], "got": "LEDGER_MALFORMED", "reasons": ["LEDGER_MALFORMED"], "ok": case["expect"] == "LEDGER_MALFORMED"}
    if ts is None:
        return {"id": case["id"], "got": "LEDGER_MALFORMED", "reasons": ["MISSING_ISSUED_AT"], "ok": case["expect"] == "LEDGER_MALFORMED"}

    same_agent_nonce = [e for e in ledger if e["agent_id"] == agent and e["nonce"] == nonce]
    if not same_agent_nonce:
        other = [e for e in ledger if e["nonce"] == nonce]
        why = "OTHER_AGENT_ONLY" if other else "NO_PRIOR_PRESENTATION"
        return {"id": case["id"], "got": "ACCEPT", "reasons": [why], "ok": case["expect"] == "ACCEPT"}
    inside = [e for e in same_agent_nonce if abs(ts - e["issued_at"]) <= window]
    if inside:
        return {"id": case["id"], "got": "NONCE_REUSE", "reasons": ["NONCE_REUSE"], "ok": case["expect"] == "NONCE_REUSE"}
    return {"id": case["id"], "got": "ACCEPT", "reasons": ["OUTSIDE_WINDOW"], "ok": case["expect"] == "ACCEPT"}


def resolve(a):
    here = os.path.dirname(os.path.abspath(__file__))
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "nonce_vectors.json"),
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
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(30) + r["got"] + " " + ",".join(r["reasons"]))
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), sum(1 for r in rows if r["ok"]),
                                         sum(1 for r in rows if not r["ok"])))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
