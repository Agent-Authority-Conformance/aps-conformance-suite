#!/usr/bin/env python3
"""Recompute each axis from the case input, compare it with the verifier's answer in the
outcome, and compare the case verdict with the declared expectation. Needs the
`cryptography` package for Ed25519. Exit 0 when every case agrees, 1 otherwise.
Usage: check.py vectors.json"""
import base64, hashlib, json, sys
from urllib.parse import urlsplit
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

AXES = ("proof_signature", "key_binding", "request_binding", "authority")

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def parse(dpop):
    """RFC 9449 4.3 item 2: a single well-formed JWT. Returns (header, claims, signing input, signature) or None."""
    parts = dpop.split(".") if isinstance(dpop, str) else []
    if len(parts) != 3:
        return None
    try:
        return json.loads(b64d(parts[0])), json.loads(b64d(parts[1])), f"{parts[0]}.{parts[1]}".encode(), b64d(parts[2])
    except (ValueError, json.JSONDecodeError):
        return None

def thumbprint(jwk):
    m = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(m.encode()).digest())

def required_claims(i):
    """RFC 9449 4.2: jti, htm, htu, iat always, ath with an access token, nonce when the server provided one."""
    req = ["jti", "htm", "htu", "iat"]
    if i.get("access_token") is not None:
        req.append("ath")
    if i["request"].get("server_nonce") is not None:
        req.append("nonce")
    return req

def proof_signature(i):
    """RFC 9449 4.3 items 2 to 7."""
    p = parse(i["dpop"])
    if p is None:
        return False
    header, claims, signing_input, sig = p
    if any(c not in claims for c in required_claims(i)):
        return False                                    # item 3
    if header.get("typ") != "dpop+jwt":
        return False                                    # item 4
    alg = header.get("alg")
    if alg in (None, "none") or alg not in i["policy"]["accepted_algs"]:
        return False                                    # item 5
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        return False                                    # item 7
    if alg != "EdDSA" or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False                                    # this candidate's checker supports EdDSA over Ed25519 only
    try:
        Ed25519PublicKey.from_public_bytes(b64d(jwk["x"])).verify(sig, signing_input)
    except (InvalidSignature, ValueError, KeyError):
        return False                                    # item 6
    return True

def key_binding(i):
    """RFC 9449 4.3 item 12 and 7.1: ath equals the hash of the presented token, and the proof key is the key the token is bound to (6.1 cnf.jkt)."""
    p = parse(i["dpop"])
    if p is None:
        return False
    header, claims, _, _ = p
    jkt = ((i["token_claims"] or {}).get("cnf") or {}).get("jkt")
    jwk = header.get("jwk")
    if jkt is None or not isinstance(jwk, dict) or any(k not in jwk for k in ("crv", "kty", "x")):
        return False
    want_ath = b64u(hashlib.sha256(i["access_token"].encode("ascii")).digest())
    return claims.get("ath") == want_ath and thumbprint(jwk) == jkt

def strip(uri):
    s = urlsplit(uri)
    return (s.scheme, s.netloc, s.path)

def request_binding(i):
    """RFC 9449 4.3 items 8 to 11 and 11.1. Returns True, False or 'ambiguous'."""
    p = parse(i["dpop"])
    if p is None:
        return False
    _, claims, _, _ = p
    r, pol = i["request"], i["policy"]
    if claims.get("htm") != r["method"]:
        return False                                    # item 8
    if not isinstance(claims.get("htu"), str) or strip(claims["htu"]) != strip(r["uri"]):
        return False                                    # item 9, query and fragment ignored
    if r.get("server_nonce") is not None and claims.get("nonce") != r["server_nonce"]:
        return False                                    # item 10
    iat = claims.get("iat")
    if not isinstance(iat, int) or iat < r["now"] - pol["iat_window_s"]:
        return False                                    # item 11
    if iat > r["now"]:
        if pol.get("future_skew_s") is None:
            return "ambiguous"                          # 11.1: a server MAY accept a near-future iat, no allowance declared
        if iat > r["now"] + pol["future_skew_s"]:
            return False
    if pol.get("tracks_jti") and [strip_uri(r["uri"]), claims.get("jti")] in [[strip_uri(u), j] for u, j in r.get("seen_jti", [])]:
        return False                                    # 11.1: jti seen before for the same URI
    return True

def strip_uri(u):
    s = urlsplit(u)
    return f"{s.scheme}://{s.netloc}{s.path}"

def authority(i):
    """The operation's required scope is in the token's scope. RFC 9449 leaves authorization to the resource server, so this axis is the candidate's representation."""
    return i["request"]["required_scope"] in ((i["token_claims"] or {}).get("scope") or "").split()

DERIVE = {"proof_signature": proof_signature, "key_binding": key_binding, "request_binding": request_binding, "authority": authority}

def truth(i):
    return {a: DERIVE[a](i) for a in AXES}

def axis_rule(axis):
    def rule(i, o):
        t = truth(i)[axis]
        if t == "ambiguous":
            return "ambiguous"
        return "conformant" if o.get(axis) is t else "nonconformant"
    return rule

def r_decision(i, o):
    t = truth(i)
    if any(v is False for v in t.values()):
        failing = [a for a in AXES if t[a] is False]
        return "conformant" if (o.get("decision") == "reject" and o.get("reject_axis") in failing) else "nonconformant"
    if any(v == "ambiguous" for v in t.values()):
        return "ambiguous"
    return "conformant" if (o.get("decision") == "accept" and o.get("reject_axis") is None) else "nonconformant"

RULES = {"R-SIG": axis_rule("proof_signature"), "R-BIND": axis_rule("key_binding"),
         "R-REQ": axis_rule("request_binding"), "R-AUTH": axis_rule("authority"), "R-DECISION": r_decision}

def combine(values):
    if "nonconformant" in values:
        return "nonconformant"
    if "ambiguous" in values:
        return "ambiguous"
    return "conformant"

def verdict(c, rules=RULES):
    return combine([rules[r](c["input"], c["outcome"]) for r in c["rules"]])

def main(path):
    doc = json.load(open(path))
    bad = 0
    for c in doc["cases"]:
        got = verdict(c)
        ok = got == c["expect"]
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {c['id']}  expect={c['expect']:<14} got={got}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
