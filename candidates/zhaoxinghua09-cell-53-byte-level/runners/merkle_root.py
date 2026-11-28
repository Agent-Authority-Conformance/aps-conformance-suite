#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""merkle_root.py —— 默克尔根与包含证明，Python 侧

构造规则（写死在这里，Node 侧必须独立实现出同一套）：
  leaf(m)  = sha256(0x00 || JCS(m))
  node(l,r)= sha256(0x01 || l || r)
  奇数末位：直接上提（carry up），不与自身配对
  空树根   = 32 字节全零

为什么奇数末位要写死：比特币式"末位复制自身"会让含重复叶的树与另一棵不同叶数的树根相同
（CVE-2012-2459 那类问题）。上提则不会，代价是证明路径长度随树形而变。

用法：
  python merkle_root.py --vectors <path>
  python merkle_root.py --json
"""
from __future__ import annotations
import json, sys, os, argparse, hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jcs_check import canon  # 同一侧复用 JCS，不跨侧

ZERO = "00" * 32


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf(m) -> bytes:
    return H(b"\x00" + canon(m).encode("utf-8"))


def node(l: bytes, r: bytes) -> bytes:
    return H(b"\x01" + l + r)


def levels(ms):
    cur = [leaf(m) for m in ms]
    lv = [cur]
    while len(cur) > 1:
        nxt = []
        i = 0
        while i + 1 < len(cur):
            nxt.append(node(cur[i], cur[i + 1]))
            i += 2
        if i < len(cur):
            nxt.append(cur[i])          # 奇数末位原样上提
        cur = nxt
        lv.append(cur)
    return lv


def root_of(ms) -> str:
    if not ms:
        return ZERO
    return levels(ms)[-1][0].hex()


def proof(ms, idx):
    lv = levels(ms)
    p = []
    for h in lv[:-1]:
        sib = idx - 1 if idx % 2 else idx + 1
        if sib < len(h):
            p.append(("L" if sib < idx else "R", h[sib].hex()))
        idx //= 2
    return p


def verify(m, p, root: str) -> bool:
    h = leaf(m)
    for side, sib in p:
        s = bytes.fromhex(sib)
        h = node(s, h) if side == "L" else node(h, s)
    return h.hex() == root


def run(c):
    ms = c["leaves"]
    r = root_of(ms)
    code = None
    if c.get("index") is not None:
        if c.get("tamper"):
            # 证明是对原叶的，验的时候换成改过的叶
            bad = dict(ms[c["index"]])
            bad["__tampered__"] = True
            ok = verify(bad, proof(ms, c["index"]), r)
        else:
            ok = verify(ms[c["index"]], proof(ms, c["index"]), r)
        code = "PROOF_ACCEPT" if ok else "PROOF_REJECT"
    return {"id": c["id"], "root": r, "code": code}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    if a.vectors and not a.json:
        v = json.load(open(a.vectors, encoding="utf-8"))
        json.dump(v, open(a.vectors, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("vectors touched: %s (%d cases)" % (a.vectors, len(v["cases"])))
        return 0
    cand = [a.vectors] if a.vectors else []
    cand += [os.path.join(os.path.dirname(here), "out", "merkle_vectors.json"),
             os.path.join(os.path.dirname(here), "vectors", "merkle.json")]
    vec = next(p for p in cand if p and os.path.isfile(p))
    cases = json.load(open(vec, encoding="utf-8"))["cases"]
    rows = []
    for c in cases:
        got = run(c)
        exp = c["expect"]
        ok = got["root"] == exp["root"] and got["code"] == exp.get("code")
        _r = "root=" + got["root"] + " " + (got["code"] or "")
        rows.append({"id": c["id"], "got": _r, "reasons": [_r], "reason": _r, "ok": ok})
    if a.json:
        print(json.dumps({"rows": rows, "verdict": "PASS" if all(r["ok"] for r in rows) else "FAIL",
                          "passed": sum(1 for r in rows if r["ok"]), "total": len(rows)}, ensure_ascii=False))
        return 0
    for r in rows:
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(20) + r["reason"][:90])
    n = sum(1 for r in rows if r["ok"])
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), n, len(rows) - n))
    return 0 if n == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())


