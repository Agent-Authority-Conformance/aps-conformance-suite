"""Clean-room offline verifier for draft-asor-wimse-agent-delegation-chain-00.

Implemented from the Internet-Draft text (Section 6 algorithm, Section 4.2
subsumption) and the published vector files ONLY. The reference
implementation's verifier source was not read. Vector-profile notes:
- Vectors sign with HS256 over a fixed shared secret (interop profile),
  so step 1 is HMAC-SHA256 verification of the JWS signing input.
- Vectors carry no cnf/DPoP (step 6) and no status list (step 7); those
  steps are out of vector scope, as is step 8's attempted-action check.
- authorization_details in the vectors: {"type", "scopes": [...],
  "constraints": [{"key", <one of max|rank|one_of|not_one_of|prefix>}]}.
  Subsumption per draft 4.2: scopes subset; every parent constraint must
  be present in the child with an admissible subset; a parent constraint
  absent in the child means unbounded, deny. rank ordering per the
  draft's example: none < internal < any.
Reason vocabulary is taken from the vectors' expect_reject_reason values:
signature_invalid, par_hash_mismatch, depth_invalid, not_narrower, expired.
"""
import base64, hashlib, hmac, json, sys

RANK = {"none": 0, "internal": 1, "any": 2}

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def parts(tok: str):
    h, p, s = tok.split(".")
    return h, p, s, json.loads(b64d(h)), json.loads(b64d(p)), b64d(s)

def sig_ok(h: str, p: str, sig: bytes, secret: bytes) -> bool:
    mac = hmac.new(secret, f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    return hmac.compare_digest(mac, sig)

def constraint_subsumed(c: dict, p: dict) -> bool:
    if "max" in p:
        return "max" in c and isinstance(c["max"], (int, float)) and c["max"] <= p["max"]
    if "rank" in p:
        return "rank" in c and c["rank"] in RANK and p["rank"] in RANK and RANK[c["rank"]] <= RANK[p["rank"]]
    if "one_of" in p:
        return "one_of" in c and set(c["one_of"]) <= set(p["one_of"])
    if "not_one_of" in p:
        return "not_one_of" in c and set(c["not_one_of"]) >= set(p["not_one_of"])
    if "prefix" in p:
        return "prefix" in c and isinstance(c["prefix"], str) and c["prefix"].startswith(p["prefix"])
    return False  # unknown constraint type: fail closed (draft 4.1)

def authority_subsumed(child: list, parent: list) -> bool:
    for cd in child:
        homes = [pd for pd in parent if pd.get("type") == cd.get("type")]
        ok = False
        for pd in homes:
            pscopes = pd.get("scopes", [])
            def covered(sc: str) -> bool:
                for ps in pscopes:
                    if sc == ps:
                        return True
                    if ps == "*" or (ps.endswith(".*") and sc.startswith(ps[:-1])):
                        return True
                return False
            if not all(covered(sc) for sc in cd.get("scopes", [])):
                continue
            pcons = {c["key"]: c for c in pd.get("constraints", [])}
            ccons = {c["key"]: c for c in cd.get("constraints", [])}
            if all(k in ccons and constraint_subsumed(ccons[k], pc) for k, pc in pcons.items()):
                ok = True
                break
        if not ok:
            return False
    return True

def verify(tokens, signer, now):
    secret = bytes.fromhex(signer["secret_hex"])
    parsed = []
    for t in tokens:
        h, p, s64, hd, pl, sig = parts(t)
        if hd.get("alg") != signer["alg"] or not sig_ok(h, p, sig, secret):
            return "signature_invalid"                              # step 1
        parsed.append((h, p, pl))
    for i in range(1, len(parsed)):
        ph, pp, _ = parsed[i - 1]
        want = base64.urlsafe_b64encode(
            hashlib.sha256(f"{ph}.{pp}".encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(want, parsed[i][2].get("par_hash", "")):
            return "par_hash_mismatch"                              # step 2
    root = parsed[0][2]
    if root.get("del_depth") != 0 or "del_max_depth" not in root:
        return "depth_invalid"                                      # step 3
    for i, (_, _, pl) in enumerate(parsed):
        if pl.get("del_depth") != i:
            return "depth_invalid"
    if len(parsed) - 1 >= root["del_max_depth"]:
        return "depth_invalid"
    for i in range(1, len(parsed)):
        if not authority_subsumed(
            parsed[i][2].get("authorization_details", []),
            parsed[i - 1][2].get("authorization_details", []),
        ):
            return "not_narrower"                                   # step 4
    prev_exp = None
    for _, _, pl in parsed:                                         # step 5
        if "nbf" in pl and now < pl["nbf"]:
            return "expired"
        if now > pl["exp"]:
            return "expired"
        if prev_exp is not None and pl["exp"] > prev_exp:
            return "expired"
        prev_exp = pl["exp"]
    return "accept"

if __name__ == "__main__":
    from attenu_guard import vectors
    fails = 0
    for name, data in vectors.load_vectors().items():
        want = data.get("expect") or data.get("expect_reject_reason")
        got = verify(data["tokens"], data["signer"], data["now"])
        mark = "ok " if got == want else "FAIL"
        if got != want:
            fails += 1
        print(f"{mark} {name:32s} want={want:20s} got={got}")
    print(f"\n{'ALL 7 MATCH' if fails == 0 else str(fails) + ' MISMATCH'}")
    sys.exit(1 if fails else 0)
