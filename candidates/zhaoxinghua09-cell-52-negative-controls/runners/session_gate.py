#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""session_gate.py —— 串起来的会话门（v2 候选，Python 侧）

此前三件是散的：`narrowing_check` 判「子授权是否比父授权窄」，`cascade_revoke` 判「链是否还有效」，
`mcp_predispatch` 判「这一次调用是否越权」。但真实场景里它们是**同一次决策的四段**，任何一段单独跑都对，
拼起来就可能对不上：链有效但策略被放宽、策略合规但调用越域、调用合规但链已被撤。

本件把四段串成一条，并给每次拒绝**钉层**（层序即 L1→L5，与 `spec/10_claim_scope_v1.md` 一致）：

  L1 结构    policy 的七维是否齐、是否有不认识的维      （FACET_MISSING / FACET_UNKNOWN）
  L2 真实性  链上每条委派的签名是否验得过               （DECL_SIG_INVALID）
  L3 有效性  撤销是否成立、链是否过期                    （REVOKED_CASCADE / REVOCATION_* / DELEGATION_EXPIRED）
  L4 收窄    这张 policy 是否 ≤ 根授权                   （NARROW_<FACET>）
  L5 派发    这次调用是否 ≤ 这张 policy                  （PREDISPATCH_*）

判定词：ALLOW / DENY / INDETERMINATE / INVALID / UNSUPPORTED。
**层序不可跳**：L1 不过就不看 L2；L2 不确定（签名验不过）就报 INDETERMINATE，不许降格成 DENY。

用法：
  python session_gate.py --selftest
  python session_gate.py --json
  python session_gate.py --vectors <path>
"""
from __future__ import annotations
import argparse, json, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cascade_revoke as CR
import narrowing_check as NC
import mcp_predispatch as PD
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FACETS = NC.FACETS
PROFILE = "zc/session-gate-v0"


def _struct(policy):
    unknown = [k for k in policy if k not in FACETS]
    if unknown:
        return "UNSUPPORTED", "L1", "FACET_UNKNOWN: " + ",".join(sorted(unknown))
    missing = [k for k in FACETS if k not in policy]
    if missing:
        return "INVALID", "L1", "FACET_MISSING: " + ",".join(missing)
    return None


def _bind(chain, envelope):
    """把出示的策略钉到链尾委派：谁签的、签的是哪一跳。
    返回 (layer, code) 或 None。全部是 INDETERMINATE —— 验不了不等于越权。"""
    leaf = chain[-1]
    if not isinstance(envelope, dict) or "policy" not in envelope:
        return "POLICY_UNBOUND: 出示的策略没有信封（无 delegation_id / 无签名）"
    if not envelope.get("signature"):
        return "POLICY_SIG_MISSING: 信封没有签名"
    signer = envelope.get("signed_by", "")
    if signer != leaf.get("issuer"):
        return f"POLICY_ISSUER_MISMATCH: 签名方 {signer} 不是链尾 issuer {leaf.get('issuer')}"
    if envelope.get("delegation_id") != leaf.get("delegation_id"):
        return f"POLICY_NOT_LEAF: 信封指向 {envelope.get('delegation_id')}，链尾是 {leaf.get('delegation_id')}"
    if not CR.sig_ok({k: v for k, v in envelope.items()}, signer):
        return "POLICY_SIG_INVALID: 信封签名验不过（策略被改过或签名方不对）"
    return None


def gate(chain, revocations, envelope, call, now, state=None):
    # 裸表（没有信封）也要能跑到 L1，然后在 L2' 判 POLICY_UNBOUND
    if isinstance(envelope, dict) and "policy" in envelope:
        policy = envelope["policy"]
    else:
        policy = envelope if isinstance(envelope, dict) else {}

    # L1 结构
    s = _struct(policy)
    if s:
        return {"profile": PROFILE, "verdict": s[0], "layer": s[1], "code": s[2], "also": []}

    # L2 真实性（不带撤销，只看签名；过期留给 L3 判）
    r2 = CR.check(chain, [], now)
    if r2["reasons"] and r2["reasons"][0].startswith("DECL_SIG_INVALID"):
        return {"profile": PROFILE, "verdict": "INDETERMINATE", "layer": "L2",
                "code": r2["reasons"][0], "also": []}

    # L2' 绑定：策略必须由链尾 issuer 签、且指向链尾那一跳
    b = _bind(chain, envelope)
    if b:
        return {"profile": PROFILE, "verdict": "INDETERMINATE", "layer": "L2", "code": b, "also": []}

    # L3 有效性（撤销 + 过期）
    r3 = CR.check(chain, revocations, now)
    if r3["verdict"] == "invalid":
        return {"profile": PROFILE, "verdict": "DENY", "layer": "L3", "code": r3["reasons"][0], "also": []}
    if r3["verdict"] == "indeterminate":
        return {"profile": PROFILE, "verdict": "INDETERMINATE", "layer": "L3",
                "code": r3["reasons"][0], "also": []}

    # L4 收窄：两道闸——策略 ≤ 根授权，且策略 ≤ 该跳被授予的 authority
    # （只查第一道会放过「签发方签过头」：签名真、却没权签这么宽）
    root_auth = chain[0].get("authority", {})
    r4 = NC.check(root_auth, policy)
    if r4["verdict"] == "REJECT":
        return {"profile": PROFILE, "verdict": "DENY", "layer": "L4",
                "code": r4["reasons"][0], "also": r4["reasons"][1:]}
    r4b = NC.check(chain[-1].get("authority", {}), policy)
    if r4b["verdict"] == "REJECT":
        return {"profile": PROFILE, "verdict": "DENY", "layer": "L4",
                "code": "POLICY_WIDENS_DELEGATED: 策略比该跳被授予的更宽 —— " + r4b["reasons"][0],
                "also": r4b["reasons"][1:]}

    # L5 派发
    r5 = PD.decide(policy, call, state or {})
    if r5["verdict"] == "ALLOW":
        return {"profile": PROFILE, "verdict": "ALLOW", "layer": None, "code": None, "also": []}
    if r5["verdict"] == "DENY":
        return {"profile": PROFILE, "verdict": "DENY", "layer": "L5", "code": r5["code"], "also": r5["also"]}
    return {"profile": PROFILE, "verdict": r5["verdict"], "layer": "L1", "code": r5["code"], "also": []}


# ---------- 用例 ----------
AUTH_ROOT = {"scope": ["tools:read", "tools:write"],
             "spend": {"currency": "USD", "max_per_tx": 500, "daily_cap": 2000},
             "depth": 2, "time": 1767225600, "reputation": 2,
             "values": ["no-pii"], "reversibility": False}

POLICY_OK = {**AUTH_ROOT, "scope": ["tools:read"], "depth": 1,
             "spend": {"currency": "USD", "max_per_tx": 100, "daily_cap": 500}}

CALL_OK = {"server": "mcp://files", "tool": "read_file", "scope_tag": "tools:read",
           "amount": 0, "depth": 0, "at": 1767225260, "reputation": 3,
           "tags": [], "reversible": True}

NOW = 1767225000


def decl_with(ident, parent, issuer, subject, exp, authority, signer=None):
    """带真实 authority 的委派记录（cascade_revoke.decl 的 authority 只是占位）。"""
    return CR.sign({"record_type": "aps:authority-delegation:v1", "delegation_id": ident,
                    "parent_delegation_id": parent, "issuer": issuer, "subject": subject,
                    "issued_at": 0, "expires_at": exp, "authority": authority}, signer or issuer)


def envelope_of(policy, delegation_id="d:leaf", signer="agent:b", sign=True, keep_sig=False):
    e = {"policy": policy, "delegation_id": delegation_id, "signed_by": signer}
    if sign:
        e = CR.sign(e, signer)
    elif not keep_sig:
        e.pop("signature", None)
    return e


def build_case(policy=POLICY_OK, call=None, revs=None, chain_mut=None,
               env=None, env_kw=None, leaf_auth=None):
    T = 1767225600
    leaf_auth = POLICY_OK if leaf_auth is None else leaf_auth
    root = decl_with("d:root", None, "principal:acme", "agent:a", T + 3600, AUTH_ROOT)
    mid = decl_with("d:mid", "d:root", "agent:a", "agent:b", T + 1800, leaf_auth, signer="agent:a")
    leaf = decl_with("d:leaf", "d:mid", "agent:b", "agent:c", T + 600, leaf_auth, signer="agent:b")
    chain = [root, mid, leaf]
    if chain_mut:
        chain = chain_mut(chain)
    env = env if env is not None else envelope_of(policy, **(env_kw or {}))
    return chain, list(revs or []), env, dict(call or CALL_OK)


CASES = [
    ("allow-all", lambda: build_case(), "ALLOW", None, None),
    # ---- L2' 绑定：策略必须由链尾 issuer 签、且指向链尾那一跳 ----
    ("L2-policy-unbound", lambda: build_case(env=POLICY_OK),
     "INDETERMINATE", "L2", "POLICY_UNBOUND"),
    ("L2-policy-sig-missing", lambda: build_case(env_kw={"sign": False}),
     "INDETERMINATE", "L2", "POLICY_SIG_MISSING"),
    ("L2-policy-not-leaf", lambda: build_case(env=envelope_of(POLICY_OK, "d:mid", "agent:b")),
     "INDETERMINATE", "L2", "POLICY_NOT_LEAF"),
    ("L2-policy-issuer-mismatch", lambda: build_case(env=envelope_of(POLICY_OK, "d:leaf", "agent:a")),
     "INDETERMINATE", "L2", "POLICY_ISSUER_MISMATCH"),
    ("L2-policy-sig-invalid", lambda: build_case(env=dict(envelope_of(POLICY_OK), policy={**POLICY_OK, "depth": 9})),
     "INDETERMINATE", "L2", "POLICY_SIG_INVALID"),
    # 签发方签出比该跳授权更宽的策略（签名是真的，但签过了头）→ 由 L4 第二道闸判
    ("L4-policy-widens-delegated",
     lambda: build_case({**POLICY_OK, "spend": {"currency": "USD", "max_per_tx": 300, "daily_cap": 500}}),
     "DENY", "L4", "POLICY_WIDENS_DELEGATED"),
    ("L1-policy-missing", lambda: build_case({k: v for k, v in POLICY_OK.items() if k != "spend"}),
     "INVALID", "L1", "FACET_MISSING"),
    ("L1-policy-unknown", lambda: build_case({**POLICY_OK, "geo_fence": ["EU"]}),
     "UNSUPPORTED", "L1", "FACET_UNKNOWN"),
    ("L2-chain-sig-bad", lambda: build_case(chain_mut=lambda ch: [ch[0], {**ch[1], "issued_at": 99}, ch[2]]),
     "INDETERMINATE", "L2", "DECL_SIG_INVALID"),
    ("L3-chain-expired", lambda: build_case(chain_mut=lambda ch: [CR.decl("d:root", None, "principal:acme", "agent:a", 0, NOW - 1), ch[1], ch[2]]),
     "DENY", "L3", "DELEGATION_EXPIRED"),
    ("L3-revoke-root", lambda: build_case(revs=[CR.rev("d:root", "principal:acme", NOW - 10)]),
     "DENY", "L3", "REVOKED_CASCADE"),
    ("L3-revoke-forged", lambda: build_case(revs=[CR.rev("d:mid", "agent:a", NOW - 10, signer="agent:b")]),
     "INDETERMINATE", "L3", "REVOCATION_UNESTABLISHED"),
    ("L4-policy-widen-scope", lambda: build_case({**POLICY_OK, "scope": ["tools:read", "payments:wire"]}, leaf_auth=AUTH_ROOT),
     "DENY", "L4", "NARROW_SCOPE"),
    ("L4-policy-widen-spend", lambda: build_case({**POLICY_OK, "spend": {"currency": "USD", "max_per_tx": 800, "daily_cap": 2000}}, leaf_auth=AUTH_ROOT),
     "DENY", "L4", "NARROW_SPEND"),
    ("L5-call-scope-out", lambda: build_case(call={**CALL_OK, "scope_tag": "payments:wire"}),
     "DENY", "L5", "PREDISPATCH_SCOPE"),
    ("L5-call-spend-day", lambda: build_case(call={**CALL_OK, "amount": 100},
                                             ), "DENY", "L5", "PREDISPATCH_SPEND_DAY"),
    ("L5-call-irreversible", lambda: build_case(call={**CALL_OK, "reversible": False}),
     "DENY", "L5", "PREDISPATCH_IRREVERSIBLE"),
    ("evidence-not-cause-allow", lambda: build_case(revs=[CR.sign({"record_type": "aps:cascade-evidence:v0",
                                                                  "delegation_id": "d:root", "claims": "revoked"}, "witness:third")]),
     "ALLOW", None, None),
]


def run_cases():
    rows, ok = [], True
    for cid, mk, want_v, want_layer, want_code in CASES:
        chain, revs, policy, call = mk()
        state = {"spent_today": 1600} if cid == "L5-call-spend-day" else {}
        r = gate(chain, revs, policy, call, NOW, state)
        good = r["verdict"] == want_v and r["layer"] == want_layer and \
            (want_code is None or str(r["code"]).startswith(want_code))
        ok &= good
        rows.append({"id": cid, "expect": want_v, "got": r["verdict"], "layer": r["layer"],
                     "code": r["code"], "also": r["also"], "ok": good})
    return rows, ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--vectors")
    a = ap.parse_args()

    if a.vectors:
        v = []
        for cid, mk, want_v, want_layer, want_code in CASES:
            chain, revs, envelope, call = mk()
            state = {"spent_today": 1600} if cid == "L5-call-spend-day" else {}
            def wrap(rec):
                name = rec.get("issuer") or "witness:third"
                pk = CR.pub_of(name).public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
                return {"rec": rec, "signer": name, "pubkey": pk}
            pol = envelope["policy"] if isinstance(envelope, dict) and "policy" in envelope else envelope
            sb = envelope.get("signed_by") if isinstance(envelope, dict) else None
            pol_pub = CR.pub_of(sb).public_bytes(Encoding.Raw, PublicFormat.Raw).hex() if sb else None
            v.append({"id": cid, "now": NOW, "state": state,
                      "envelope": envelope, "policy": pol, "policy_pubkey": pol_pub, "call": call,
                      "root_authority": chain[0].get("authority", {}),
                      "chain": [wrap(d) for d in chain],
                      "revocations": [wrap(r) for r in revs],
                      "expect": want_v, "want_layer": want_layer, "want_code": want_code})
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
        print(("PASS " if x["ok"] else "FAIL ") + x["id"].ljust(24) + str(x["got"]).ljust(14)
              + str(x["layer"]).ljust(4) + str(x["code"] or "") + extra)
    print(f"RESULT: {sum(1 for x in rows if x['ok'])}/{len(rows)}  {'PASS' if ok else 'FAIL'}")
    print("NOTE: 本件为 Python 侧；Node 侧见 session_gate.mjs，逐例比对由 parity_check.py 出。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
