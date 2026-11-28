#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cascade_revoke.py —— 级联撤销判定（v2 候选，Python 侧；Node 侧未做）

来源：`draft-pidlisnyi-aps-04` §1.4(3) 与 §4.5：
  - 撤销的是「依赖该委派的每条链」，父被撤，所有后代一并失效；
  - 撤销记录由对该委派有 issuer 身份的方签署；
  - 「级联证据只作为处理过的证据，不是无效的原因」；
  - 撤销一经确立即不可逆；未知不等于有效，链上不确定就报 indeterminate。

本件只做这一层：签名的委派链 + 撤销记录 + 四种判定
  valid / invalid(带码) / indeterminate(带码) / unsupported。

判定口径（写死，别猜）：
  1) 任何一条委派记录签名验不过 → INDETERMINATE（DECL_SIG_INVALID）
  2) 撤销记录签名验不过或签署方不是该委派的 issuer → INDETERMINATE（REVOCATION_UNESTABLISHED）
  3) 撤销记录指向链上不存在的委派 → INDETERMINATE（REVOCATION_UNKNOWN_TARGET）
  4) 仅有「级联证据」而无撤销记录 → **不据此判无效**（EVIDENCE_IS_NOT_CAUSE，仍 valid）
  5) 链上任一祖先被确立撤销 → invalid（REVOKED_CASCADE，并指出是哪一条）
  6) 委派自身过期 → invalid（DELEGATION_EXPIRED）
  6) 优先顺序：先签名（1/2），再撤销（5），再过期（6）——与 L1→L5 层序一致。

用法：
  python cascade_revoke.py --selftest
  python cascade_revoke.py --json
"""
from __future__ import annotations
import argparse, hashlib, json, sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT_TYPE = "zc/cascade-v0"
FACETS = ("scope", "spend", "depth", "time", "reputation", "values", "reversibility")


def key_of(name):
    seed = hashlib.sha256(("zc-demo-key:" + name).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def pub_of(name):
    return key_of(name).public_key()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(obj, signer):
    body = {k: v for k, v in obj.items() if k != "signature"}
    return {**body, "signature": key_of(signer).sign(canon(body)).hex()}


def sig_ok(obj, signer):
    body = {k: v for k, v in obj.items() if k != "signature"}
    try:
        pub_of(signer).verify(bytes.fromhex(obj.get("signature", "")), canon(body))
        return True
    except Exception:
        return False


def decl(ident, parent, issuer, subject, issued_at, expires_at, signer=None):
    return sign({"record_type": "aps:authority-delegation:v1", "delegation_id": ident,
                 "parent_delegation_id": parent, "issuer": issuer, "subject": subject,
                 "issued_at": issued_at, "expires_at": expires_at,
                 "authority": {f: "x" for f in FACETS}}, signer or issuer)


def rev(target, issuer, issued_at, signer=None):
    return sign({"record_type": "aps:authority-revocation:v1", "delegation_id": target,
                 "issuer": issuer, "issued_at": issued_at}, signer or issuer)


def check(chain, revocations, now):
    """chain: 从根到叶的委派记录列表；revocations: 撤销记录列表。"""
    # 1) 委派签名
    for d in chain:
        if not sig_ok(d, d.get("issuer", "")):
            return {"verdict": "indeterminate", "reasons": ["DECL_SIG_INVALID: " + d.get("delegation_id", "?")]}
    ids = [d["delegation_id"] for d in chain]
    issuers = {d["delegation_id"]: d["issuer"] for d in chain}

    # 2) 撤销记录：签名与签署资格
    established, notes = [], []
    for r in revocations:
        if r.get("record_type") != "aps:authority-revocation:v1":
            # 别的记录（如级联证据）不进判定，只记一笔
            notes.append("EVIDENCE_IS_NOT_CAUSE: 忽略非撤销记录 " + str(r.get("record_type")))
            continue
        if not sig_ok(r, r.get("issuer", "")):
            return {"verdict": "indeterminate", "reasons": ["REVOCATION_UNESTABLISHED: 签名验不过"]}
        target = r.get("delegation_id")
        if target not in issuers:
            return {"verdict": "indeterminate", "reasons": ["REVOCATION_UNKNOWN_TARGET: " + str(target)]}
        if r.get("issuer") != issuers[target]:
            return {"verdict": "indeterminate", "reasons": ["REVOCATION_UNESTABLISHED: 签署方不是该委派的 issuer"]}
        established.append(target)

    # 3) 撤销（级联）：任一祖先被撤，整链无效
    for i, ident in enumerate(ids):
        if ident in established:
            return {"verdict": "invalid", "reasons": [f"REVOKED_CASCADE: {ident} 位于第 {i} 跳，其后代一并失效"]}

    # 4) 过期（撤销先于过期判）
    for d in chain:
        if d.get("expires_at") is not None and now >= d["expires_at"]:
            return {"verdict": "invalid", "reasons": ["DELEGATION_EXPIRED: " + d["delegation_id"]]}

    return {"verdict": "valid", "reasons": [], "notes": notes}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--vectors", help="导出全部用例（每条记录附裸公钥），供 Node 侧独立验签与判定")
    a = ap.parse_args()

    T = 1_800_000_000            # now
    root = decl("d:root", None, "principal:acme", "agent:a", 0, T + 3600)
    mid = decl("d:mid", "d:root", "agent:a", "agent:b", 0, T + 1800, signer="agent:a")
    leaf = decl("d:leaf", "d:mid", "agent:b", "agent:c", 0, T + 600, signer="agent:b")
    chain = [root, mid, leaf]

    cases = []
    cases.append(("chain-valid", chain, [], T, "valid", None))
    cases.append(("revoke-root", chain, [rev("d:root", "principal:acme", T - 10)], T, "invalid", "REVOKED_CASCADE"))
    cases.append(("revoke-leaf", chain, [rev("d:leaf", "agent:b", T - 10)], T, "invalid", "REVOKED_CASCADE"))
    cases.append(("revoke-mid", chain, [rev("d:mid", "agent:a", T - 10)], T, "invalid", "REVOKED_CASCADE"))

    bad_signer = rev("d:mid", "agent:a", T - 10, signer="agent:b")   # 冒充
    cases.append(("revoke-forged-signer", chain, [bad_signer], T, "indeterminate", "REVOCATION_UNESTABLISHED"))

    tampered = rev("d:mid", "agent:a", T - 10)
    tampered["issued_at"] = T - 20
    cases.append(("revoke-tampered", chain, [tampered], T, "indeterminate", "REVOCATION_UNESTABLISHED"))

    cases.append(("revoke-unknown-target", chain, [rev("d:ghost", "agent:a", T - 10)], T,
                  "indeterminate", "REVOCATION_UNKNOWN_TARGET"))

    witness = sign({"record_type": "aps:cascade-evidence:v0", "delegation_id": "d:root",
                    "claims": "revoked"}, "witness:third")
    cases.append(("evidence-not-cause", chain, [witness], T, "valid", "EVIDENCE_IS_NOT_CAUSE"))

    expired_root = decl("d:root", None, "principal:acme", "agent:a", 0, T - 1)
    exp_chain = [expired_root, mid, leaf]
    cases.append(("chain-expired", exp_chain, [], T, "invalid", "DELEGATION_EXPIRED"))

    dup = rev("d:root", "principal:acme", T - 10)
    cases.append(("revoke-twice-idempotent", chain, [dup, dup], T, "invalid", "REVOKED_CASCADE"))

    if a.vectors:
        def wrap(rec, signer=None):
            name = signer or rec.get("issuer") or "witness:third"
            pk = pub_of(name).public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            return {"rec": rec, "pubkey": pk, "signer": name}
        out = {"profile": ROOT_TYPE, "now": T, "cases": [
            {"id": cid, "now": now, "expect": want_v, "want_code": want_code,
             "chain": [wrap(d) for d in ch], "revocations": [wrap(r) for r in rv]}
            for cid, ch, rv, now, want_v, want_code in cases]}
        with open(a.vectors, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        print("VECTORS: %d -> %s" % (len(cases), a.vectors))
        return 0

    rows, ok = [], True
    for cid, ch, rv, now, want_v, want_code in cases:
        r = check(ch, rv, now)
        got = r["verdict"]
        code_hit = True
        if want_code:
            if want_code == "EVIDENCE_IS_NOT_CAUSE":
                # 该码是「不判无效」的说明，出现在 reasons 之外，这里检查判定本身
                code_hit = (got == "valid")
            else:
                code_hit = any(x.startswith(want_code) for x in r["reasons"])
        good = got == want_v and code_hit
        ok &= good
        rows.append({"id": cid, "expect": want_v, "got": got, "reasons": r["reasons"], "ok": good})

    if a.json:
        print(json.dumps({"profile": ROOT_TYPE, "total": len(rows),
                          "passed": sum(1 for x in rows if x["ok"]), "rows": rows,
                          "verdict": "PASS" if ok else "FAIL"}, ensure_ascii=False))
        return 0 if ok else 1

    for x in rows:
        print(("PASS " if x["ok"] else "FAIL ") + x["id"].ljust(24) + x["got"].ljust(14) + " ".join(x["reasons"]))
    print(f"RESULT: {sum(1 for x in rows if x['ok'])}/{len(rows)}  {'PASS' if ok else 'FAIL'}")
    print("NOTE: 本件为 Python 侧；Node 侧见 cascade_revoke.mjs（自带验签），逐例比对由 parity_check.py 出。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
