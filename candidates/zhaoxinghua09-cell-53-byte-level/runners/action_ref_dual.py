#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""action_ref_dual.py —— action_ref 两形态（v1 外部 / v2 指派），Python 侧

两种形态（都按对方草案的字面定义实现，不做自己的发挥）：
  v1 = sha256(JCS({agent_id, action_type, scope, timestamp}))          无域名前缀
       标签 "action-ref-v1-jcs-sha256"，只用于外部引用，不得标识一次指派
  v2 = sha256("APS-ACTION-REF-V2\\0" + JCS(8 成员对象))                profile 固定 aps-action-ref-v2

判什么：
  - v1 正例：按对方写死的 four-field preimage 复算，必须与其 action_ref 逐字节相等
  - v1 负例：grammar 不合先拒（不得先哈希再补救），哈希不等则 fail-closed
  - v2：先做成员/hex/时间/scope 规范化闸，再算 ref；与对方 SDK 算的期望值比
  - 槽位：4.1 的 action_ref 槽里放 v1 摘要必须拒；能证明是"同事实的四字段投影"时单独报
            V1_DIGEST_IN_V2_SLOT，否则报 SLOT_NOT_V2_REF —— 只在可证时才归属

用法：
  python action_ref_dual.py --vectors <path>
  python action_ref_dual.py --json
"""
from __future__ import annotations
import json, sys, os, re, hashlib, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jcs_check import canon

V1_KEYS = {"agent_id", "action_type", "scope", "timestamp"}
V2_KEYS = {"profile", "agent_id", "action_type", "target", "payload_ref",
           "scope_required", "issued_at", "nonce"}
TS = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:60)?\.\d{3}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
V2_DOMAIN = "APS-ACTION-REF-V2\0".encode("utf-8")


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def v1_ref(pre: dict) -> str:
    return sha(canon(pre))


def v2_ref(obj: dict) -> str:
    return hashlib.sha256(V2_DOMAIN + canon(obj).encode("utf-8")).hexdigest()


def v1_gate(pre) -> str | None:
    if set(pre) != V1_KEYS:
        return "V1_KEYS"
    for k in V1_KEYS:
        if not isinstance(pre[k], str):
            return "GRAMMAR_REJECT"
    if not TS.match(pre["timestamp"]):
        return "GRAMMAR_REJECT"
    return None


def v2_gate(o) -> str | None:
    if set(o) != V2_KEYS:
        return "V2_KEYS"
    if o["profile"] != "aps-action-ref-v2":
        return "PROFILE"
    for k in ("agent_id", "action_type", "target", "issued_at"):
        if not isinstance(o[k], str) or o[k] == "":
            return "EMPTY_STRING"
    if not isinstance(o["payload_ref"], str) or not HEX64.match(o["payload_ref"]):
        return "HEX_CASE" if isinstance(o["payload_ref"], str) and re.match(r"^[0-9a-fA-F]{64}$", o["payload_ref"]) else "HEX_SHAPE"
    if not isinstance(o["nonce"], str) or not HEX32.match(o["nonce"]):
        return "HEX_CASE" if isinstance(o["nonce"], str) and re.match(r"^[0-9a-fA-F]{32}$", o["nonce"]) else "HEX_SHAPE"
    if not TS.match(o["issued_at"]):
        return "ISSUED_AT_SHAPE"
    sc = o["scope_required"]
    if not isinstance(sc, list) or not sc or not all(isinstance(s, str) and s for s in sc):
        return "SCOPE_SHAPE"
    if len(set(sc)) != len(sc):
        return "SCOPE_DUP"
    if any(s != __import__("unicodedata").normalize("NFC", s) for s in sc):
        return "SCOPE_NOT_NFC"
    if [s.encode("utf-8") for s in sc] != sorted(s.encode("utf-8") for s in sc):
        return "SCOPE_NOT_SORTED"
    return None


def run(c):
    form = c["form"]
    if form == "v1":
        pre = c.get("preimage") or c["payload"]
        gate = v1_gate(pre)
        if gate:
            return gate
        ref = v1_ref(pre)
        if "claim" not in c or c["claim"] is None:
            return "OK ref=" + ref
        if ref == c["claim"]:
            return "MATCH ref=" + ref
        return "RECOMPUTE_MISMATCH ref=" + ref
    if form == "v2":
        o = c["input"]
        gate = v2_gate(o)
        if gate:
            return gate
        ref = v2_ref(o)
        if c.get("claim_plain"):
            # 槽里放的是"少了域名前缀的 JCS 哈希"。若本实现漏了域名前缀，ref 会等于它 → 本判器立刻红
            plain = sha(canon(o))
            return "OK ref=" + ref if ref == plain else "REF_DOMAIN_MISSING"
        return "OK ref=" + ref
    if form == "v2slot":
        o = c["input"]
        gate = v2_gate(o)
        if gate:
            return gate
        ref = v2_ref(o)
        claimed = c["claimed"]
        if claimed == ref:
            return "OK ref=" + ref
        proj = {"agent_id": o["agent_id"], "action_type": o["action_type"],
                "scope": ",".join(o["scope_required"]), "timestamp": o["issued_at"]}
        if claimed == v1_ref(proj):
            return "V1_DIGEST_IN_V2_SLOT ref=" + ref
        return "SLOT_NOT_V2_REF ref=" + ref
    if form == "v2pair":
        refs = []
        for o in c["inputs"]:
            g = v2_gate(o)
            if g:
                return g
            refs.append(v2_ref(o))
        return "REFS_DIFFER ref0=" + refs[0] if refs[0] != refs[1] else "REFS_SAME"
    return "UNKNOWN_FORM"


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
    cand += [os.path.join(os.path.dirname(here), "out", "actionref_vectors.json"),
             os.path.join(os.path.dirname(here), "vectors", "action-ref.json")]
    vec = next(p for p in cand if p and os.path.isfile(p))
    cases = json.load(open(vec, encoding="utf-8"))["cases"]
    rows = []
    for c in cases:
        got = run(c)
        exp = c["expect"]
        code = got.split(" ")[0]
        want = exp.get("code")
        if exp.get("refs_differ"):
            ok = got.split(" ")[0] == "REFS_DIFFER"
        elif exp.get("ref"):
            ok = got.endswith("ref=" + exp["ref"]) and (want is None or code == want)
        elif want:
            ok = code == want
        else:
            ok = False
        rows.append({"id": c["id"], "got": got, "reasons": [got], "ok": ok})
    if a.json:
        print(json.dumps({"rows": [{"id": r["id"], "got": r["got"], "reasons": r["reasons"], "ok": r["ok"]}
                                   for r in rows],
                          "verdict": "PASS" if all(r["ok"] for r in rows) else "FAIL",
                          "passed": sum(1 for r in rows if r["ok"]), "total": len(rows)}, ensure_ascii=False))
        return 0
    for r in rows:
        print(("ok   " if r["ok"] else "FAIL ") + r["id"].ljust(26) + r["got"][:100])
    n = sum(1 for r in rows if r["ok"])
    print("TOTAL %d  pass=%d fail=%d" % (len(rows), n, len(rows) - n))
    return 0 if n == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
