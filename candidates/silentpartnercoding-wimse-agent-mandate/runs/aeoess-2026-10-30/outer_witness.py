"""Outer-primitive witness for Silentpartnercoding/wimse-agent-mandate-vectors.

Dry run only, runner-authored thin harness. Uses hashlib and the `cryptography`
Ed25519 primitive. Imports nothing from the vector repository. Checks:
  1. every compact JWS signature against the key the draft says signs it
     (anchor key by kid from trust-anchors.json, sub-mandate by its header jwk)
  2. RFC 7638 thumbprint of the sub-mandate header jwk equals root cnf.jkt
  3. reference digests: root.authority[].dig, sub.parent.dig (b64url SHA-256 of
     the compact JWS ASCII bytes, the reading this harness tests)
  4. profile digest over the exact bytes of profile/profil.json
  5. each case's .jws file is byte-identical to a token in presentation.json
It decides no semantic verdict (authority_*, expired). Usage:
  python outer_witness.py <path to vector repo checkout>
"""
import base64, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha(b):
    return b64e(hashlib.sha256(b).digest())


def jkt(jwk):
    m = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                   separators=(",", ":"), sort_keys=True).encode()
    return sha(m)


def parse(jws):
    h, p, s = jws.split(".")
    return json.loads(b64d(h)), json.loads(b64d(p)), (h + "." + p).encode(), b64d(s)


def verify(jwk, signing_input, sig):
    try:
        Ed25519PublicKey.from_public_bytes(b64d(jwk["x"])).verify(sig, signing_input)
        return True
    except InvalidSignature:
        return False


def main(root):
    root = Path(root)
    anchors = {}
    for role, entries in json.loads((root / "trust-anchors.json").read_text()).items():
        for e in entries:
            for k in e["keys"]:
                anchors[k["kid"]] = (role, k)
    prof = (root / "profile/profil.json").read_bytes()
    pd = (root / "profile/profil.digest").read_text().strip()
    fails = 0
    print(f"profile digest recomputed={sha(prof)} published={pd} match={sha(prof) == pd}")
    fails += sha(prof) != pd
    for case in sorted((root / "cases").iterdir()):
        out = []
        files = {f.stem: f.read_text().strip() for f in case.glob("*.jws")}
        parsed = {n: parse(t) for n, t in files.items()}
        for n, (h, p, si, sig) in sorted(parsed.items()):
            if "kid" in h and h["kid"] in anchors:
                ok = verify(anchors[h["kid"]][1], si, sig)
                out.append(f"{n}: sig by {h['kid']} {'ok' if ok else 'FAIL'}")
            elif "jwk" in h:
                ok = verify(h["jwk"], si, sig)
                out.append(f"{n}: sig by header jwk {'ok' if ok else 'FAIL'}")
            else:
                ok = False
                out.append(f"{n}: no key resolved FAIL")
            fails += not ok
        pres = json.loads((case / "presentation.json").read_text())
        pool = [pres["subject_token"], pres["actor_token"]] + list(pres["mandate_evidence"])
        for n, t in sorted(files.items()):
            b = t in pool
            out.append(f"{n}.jws is the token in presentation.json: {b}")
            fails += not b
        rp = parsed["root-mandate"][1]
        sp = parsed["sub-mandate"]
        b = rp["cnf"]["jkt"] == jkt(sp[0]["jwk"])
        out.append(f"root cnf.jkt == jkt(sub header jwk): {b}")
        fails += not b
        b = sp[1]["parent"]["dig"] == sha(files["root-mandate"].encode())
        out.append(f"sub parent.dig == sha256(root-mandate.jws): {b}")
        fails += not b
        for ref in rp.get("authority", []):
            if "authority-assertion" in files:
                b = ref["dig"] == sha(files["authority-assertion"].encode())
                out.append(f"root authority dig == sha256(authority-assertion.jws): {b}")
                fails += not b
            else:
                out.append("root authority dig: assertion not presented (no comparison)")
        print(f"== {case.name}")
        for line in out:
            print("   " + line)
    print("RESULT", "all outer checks hold" if fails == 0 else f"{fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
