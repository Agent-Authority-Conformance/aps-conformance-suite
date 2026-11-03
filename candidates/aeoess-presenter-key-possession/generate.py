#!/usr/bin/env python3
"""Build vectors.json for aeoess-presenter-key-possession. Deterministic: Ed25519 keys come
from public seed labels and Ed25519 signatures are deterministic, so two runs give the same
bytes. Needs the `cryptography` package. Usage: generate.py > vectors.json"""
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("aeoess-presenter-key-possession/" + label).encode()).digest())

def pub_jwk(k):
    x = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"crv": "Ed25519", "kty": "OKP", "x": b64u(x)}

def thumbprint(jwk):
    # RFC 7638 with the RFC 8037 required members for OKP, in lexicographic order.
    m = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(m.encode()).digest())

def jws(header, payload, signer):
    h = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = b"" if signer is None else signer.sign(f"{h}.{p}".encode())
    return f"{h}.{p}.{b64u(sig)}"

def ath(token):
    return b64u(hashlib.sha256(token.encode("ascii")).digest())

AGENT, ATTACKER = key("agent"), key("attacker")
AGENT_JWK, ATTACKER_JWK = pub_jwk(AGENT), pub_jwk(ATTACKER)
NOW = 1793750400  # 2026-11-03T16:00:00Z
TOKEN = "at-7f3c1e2a-agent-orders"
OTHER_TOKEN = "at-90bd44c1-agent-reports"
URI = "https://api.example.test/orders"
CLAIMS = {"sub": "agent-1", "scope": "orders:write orders:read", "cnf": {"jkt": thumbprint(AGENT_JWK)}}
POLICY = {"accepted_algs": ["EdDSA"], "iat_window_s": 300, "future_skew_s": None, "tracks_jti": True}

def proof(signer=AGENT, jwk=None, typ="dpop+jwt", alg="EdDSA", **over):
    claims = {"jti": over.pop("jti", "p-0001"), "htm": "POST", "htu": URI, "iat": NOW - 5, "ath": ath(TOKEN)}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jws({"typ": typ, "alg": alg, "jwk": jwk or pub_jwk(signer if signer else AGENT)}, claims, signer)

def request(**over):
    r = {"method": "POST", "uri": URI, "now": NOW, "server_nonce": None, "seen_jti": [], "required_scope": "orders:write"}
    r.update(over)
    return r

def case(cid, title, basis, dpop, outcome, expect, rules, req=None, token=TOKEN, claims=CLAIMS, policy=POLICY):
    return {"id": cid, "title": title, "basis": basis, "rules": rules, "expect": expect,
            "input": {"request": req or request(), "access_token": token, "token_claims": claims, "dpop": dpop, "policy": policy},
            "outcome": outcome}

def out(sig, bind, reqb, auth, decision, axis=None):
    return {"proof_signature": sig, "key_binding": bind, "request_binding": reqb, "authority": auth, "decision": decision, "reject_axis": axis}

ALL = ["R-SIG", "R-BIND", "R-REQ", "R-AUTH", "R-DECISION"]
good = proof()
attacker = proof(signer=ATTACKER)
h, p, s = good.split(".")
tampered = h + "." + b64u(json.dumps({"ath": ath(TOKEN), "htm": "POST", "htu": URI, "iat": NOW - 5, "jti": "p-0001x"}, separators=(",", ":"), sort_keys=True).encode()) + "." + s
priv_jwk = dict(AGENT_JWK, d=b64u(AGENT.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())))
no_cnf = {"sub": "agent-1", "scope": "orders:write orders:read"}

cases = [
    case("PK-01", "Valid proof, bound key, fresh, in scope: accept", ["4.3", "6.1", "7.1"], good, out(True, True, True, True, "accept"), "conformant", ALL),
    case("PK-02", "Attacker's own key, validly signed, accepted as bound", ["4.3 item 6", "4.3 item 12", "6.1"], attacker, out(True, True, True, True, "accept"), "nonconformant", ALL),
    case("PK-03", "Attacker's own key, refused at key binding", ["4.3 item 6", "4.3 item 12", "6.1"], attacker, out(True, False, True, True, "reject", "key_binding"), "conformant", ALL),
    case("PK-04", "Attacker's own key, refused but reported as a bad signature", ["4.3 item 6", "4.3 item 12"], attacker, out(False, False, True, True, "reject", "proof_signature"), "nonconformant", ALL),
    case("PK-05", "Payload changed after signing, accepted", ["4.3 item 6"], tampered, out(True, True, True, True, "accept"), "nonconformant", ["R-SIG", "R-DECISION"]),
    case("PK-06", "Payload changed after signing, refused at the signature", ["4.3 item 6"], tampered, out(False, True, True, True, "reject", "proof_signature"), "conformant", ["R-SIG", "R-DECISION"]),
    case("PK-07", "Private key inside the jwk header, accepted", ["4.3 item 7"], proof(jwk=priv_jwk), out(True, True, True, True, "accept"), "nonconformant", ["R-SIG", "R-DECISION"]),
    case("PK-08", "alg none with an empty signature, accepted", ["4.3 item 5"], proof(signer=None, alg="none"), out(True, True, True, True, "accept"), "nonconformant", ["R-SIG", "R-DECISION"]),
    case("PK-09", "Wrong typ, accepted", ["4.3 item 4"], proof(typ="JWT"), out(True, True, True, True, "accept"), "nonconformant", ["R-SIG", "R-DECISION"]),
    case("PK-10", "Same key, proof made for another access token, accepted", ["4.3 item 12", "4.2 ath"], proof(ath=ath(OTHER_TOKEN)), out(True, True, True, True, "accept"), "nonconformant", ALL),
    case("PK-11", "Bearer token without cnf presented with a valid proof, accepted as bound", ["7.1", "6.1"], good, out(True, True, True, True, "accept"), "nonconformant", ALL, claims=no_cnf),
    case("PK-12", "Proof for GET presented on POST, accepted", ["4.3 item 8"], proof(htm="GET"), out(True, True, True, True, "accept"), "nonconformant", ALL),
    case("PK-13", "htu differs only in its query, accepted", ["4.3 item 9"], good, out(True, True, True, True, "accept"), "conformant", ALL, req=request(uri=URI + "?page=2")),
    case("PK-14", "htu names another path, accepted", ["4.3 item 9"], proof(htu="https://api.example.test/refunds"), out(True, True, True, True, "accept"), "nonconformant", ALL),
    case("PK-15", "Server issued a nonce, proof carries another, accepted", ["4.3 item 10"], proof(nonce="n-old"), out(True, True, True, True, "accept"), "nonconformant", ALL, req=request(server_nonce="n-2026-11-03")),
    case("PK-16", "Proof created ten minutes ago with a 300 s window, accepted", ["4.3 item 11", "11.1"], proof(iat=NOW - 600), out(True, True, True, True, "accept"), "nonconformant", ALL),
    case("PK-17", "Proof dated 20 s ahead, no future skew declared, accepted", ["4.3 item 11", "11.1"], proof(iat=NOW + 20), out(True, True, True, True, "accept"), "ambiguous", ALL),
    case("PK-18", "Server tracks jti, proof jti already seen at this URI, accepted", ["11.1"], good, out(True, True, True, True, "accept"), "nonconformant", ALL, req=request(seen_jti=[[URI, "p-0001"]])),
    case("PK-19", "Possession established, operation outside the token scope, accepted", ["7.1"], good, out(True, True, True, True, "accept"), "nonconformant", ALL, req=request(required_scope="refunds:write")),
    case("PK-20", "Possession established, operation outside the token scope, refused for authority", ["7.1"], good, out(True, True, True, False, "reject", "authority"), "conformant", ALL, req=request(required_scope="refunds:write")),
    case("PK-21", "Operation outside the token scope, refused but blamed on key binding", ["7.1", "6.1"], good, out(True, False, True, False, "reject", "key_binding"), "nonconformant", ALL, req=request(required_scope="refunds:write")),
    case("PK-22", "Attacker's own key, axes reported correctly, refusal names the signature", ["4.3 item 6", "4.3 item 12"], attacker, out(True, False, True, True, "reject", "proof_signature"), "nonconformant", ALL),
]

doc = {
    "label": "aeoess-presenter-key-possession",
    "revision": 1,
    "text_status": "RFC 9449 is a published Proposed Standard. The scope check and the axis names are this candidate's representation, not RFC 9449 text",
    "readings": "an outcome is the verifier's answer for one request. Each axis is read on its own, whatever the other axes say",
    "now": NOW,
    "keys": {"agent": AGENT_JWK, "attacker": ATTACKER_JWK, "seed_rule": "Ed25519 private key = sha256('aeoess-presenter-key-possession/' + label), test keys only"},
    "cases": cases,
}
json.dump(doc, sys.stdout, indent=1, sort_keys=False)
sys.stdout.write("\n")
