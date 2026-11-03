#!/usr/bin/env python3
"""Weaken each check in a plausible way and show that some case catches it. A mutant is killed
when at least one case's verdict changes away from its expectation. Exit 0 when every mutant is
killed. Usage: mutate.py [vectors.json]"""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

def sig_skip_verify(i):
    p = check.parse(i["dpop"])
    return p is not None and p[0].get("typ") == "dpop+jwt" and p[0].get("alg") in i["policy"]["accepted_algs"] and "d" not in (p[0].get("jwk") or {})

def sig_allow_private(i):
    p = check.parse(i["dpop"])
    if p and isinstance(p[0].get("jwk"), dict) and "d" in p[0]["jwk"]:
        return True
    return check.proof_signature(i)

def sig_allow_none(i):
    p = check.parse(i["dpop"])
    return True if (p and p[0].get("alg") == "none") else check.proof_signature(i)

def sig_ignore_typ(i):
    p = check.parse(i["dpop"])
    return True if (p and p[0].get("typ") != "dpop+jwt" and p[0].get("alg") == "EdDSA") else check.proof_signature(i)

def bind_skip_jkt(i):
    p = check.parse(i["dpop"])
    return p is not None and p[1].get("ath") == check.b64u(hashlib.sha256(i["access_token"].encode("ascii")).digest())

def bind_skip_ath(i):
    p = check.parse(i["dpop"])
    jkt = ((i["token_claims"] or {}).get("cnf") or {}).get("jkt")
    return p is not None and jkt is not None and check.thumbprint(p[0]["jwk"]) == jkt

def bind_bearer_ok(i):
    if ((i["token_claims"] or {}).get("cnf") or {}).get("jkt") is None:
        return True
    return check.key_binding(i)

def req_no_htm(i):
    p = check.parse(i["dpop"])
    return check.request_binding(dict(i, request=dict(i["request"], method=p[1].get("htm")))) if p else False

def req_query_strict(i):
    p = check.parse(i["dpop"])
    return False if (p and p[1].get("htu") != i["request"]["uri"]) else check.request_binding(i)

def req_path_lax(i):
    p = check.parse(i["dpop"])
    return check.request_binding(dict(i, request=dict(i["request"], uri=p[1].get("htu")))) if p else False

def req_no_nonce(i):
    return check.request_binding(dict(i, request=dict(i["request"], server_nonce=None)))

def req_no_window(i):
    return check.request_binding(dict(i, policy=dict(i["policy"], iat_window_s=10**9)))

def req_future_ok(i):
    return check.request_binding(dict(i, policy=dict(i["policy"], future_skew_s=i["policy"].get("future_skew_s") or 60)))

def req_no_jti(i):
    return check.request_binding(dict(i, policy=dict(i["policy"], tracks_jti=False)))

def auth_always(i):
    return True

MUTANTS = {
    "R-SIG: signature not verified": ("proof_signature", sig_skip_verify),
    "R-SIG: private key in jwk allowed": ("proof_signature", sig_allow_private),
    "R-SIG: alg none allowed": ("proof_signature", sig_allow_none),
    "R-SIG: typ not checked": ("proof_signature", sig_ignore_typ),
    "R-BIND: cnf.jkt not compared": ("key_binding", bind_skip_jkt),
    "R-BIND: ath not compared": ("key_binding", bind_skip_ath),
    "R-BIND: bearer token treated as bound": ("key_binding", bind_bearer_ok),
    "R-REQ: htm not compared": ("request_binding", req_no_htm),
    "R-REQ: query not ignored": ("request_binding", req_query_strict),
    "R-REQ: htu path not compared": ("request_binding", req_path_lax),
    "R-REQ: nonce not compared": ("request_binding", req_no_nonce),
    "R-REQ: no iat window": ("request_binding", req_no_window),
    "R-REQ: future iat accepted without a declared allowance": ("request_binding", req_future_ok),
    "R-REQ: jti replay not tracked": ("request_binding", req_no_jti),
    "R-AUTH: scope not checked": ("authority", auth_always),
}

def decision_any_axis(i, o):
    t = check.truth(i)
    if any(v is False for v in t.values()):
        return "conformant" if o.get("decision") == "reject" else "nonconformant"
    return check.r_decision(i, o)

def main(path):
    doc = json.load(open(path))
    killed = 0
    total = len(MUTANTS) + 1
    for name, (axis, fn) in MUTANTS.items():
        orig = check.DERIVE[axis]
        check.DERIVE[axis] = fn
        try:
            by = [c["id"] for c in doc["cases"] if check.verdict(c) != c["expect"]]
        finally:
            check.DERIVE[axis] = orig
        killed += bool(by)
        print(f"{'killed' if by else 'SURVIVED'} {name:<58} by {','.join(by) or '-'}")
    rules = dict(check.RULES, **{"R-DECISION": decision_any_axis})
    by = [c["id"] for c in doc["cases"] if check.verdict(c, rules) != c["expect"]]
    killed += bool(by)
    print(f"{'killed' if by else 'SURVIVED'} {'R-DECISION: any reject axis accepted':<58} by {','.join(by) or '-'}")
    print(f"{killed}/{total} mutants killed")
    return 0 if killed == total else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "vectors.json")))
