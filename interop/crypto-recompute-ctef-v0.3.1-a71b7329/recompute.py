#!/usr/bin/env python3
"""Lab recompute of the crypto-layer claims of the ctef-v0.3.1 family at PR #43 head a71b7329.

Thin harness. For canonicalization, digests and signatures it invokes implementations authored by
neither the contributor nor the lab (`rfc8785` and `cryptography`). Separately, it runs the
contributor's Ed25519 verifier against the pinned C2SP/Wycheproof corpus and compares its outputs
with the corpus's published expected results.

It does not implement or evaluate the family's CTEF admissibility semantics.

Usage: python3 recompute.py <family dir at a71b7329> <ed25519_test.json at 5722833c> [--json]
Exit 0 iff every input matches its pinned digest and every check passes; exit 2 on a digest
mismatch.
"""
import base64, hashlib, json, sys, importlib.util
from pathlib import Path

PINS = {
    "fixtures/positive-authority.json": "b7ee419793a4839515fc2c4a2fd8b471d59f85d055f85950665e74b4f530a5bb",
    "fixtures/negative-scope-violation.json": "1dff00c8b9237486011e878ca88afb85a3bb17200f890071928bce44bf82c9da",
    "fixtures/negative-composition-failure.json": "adc129a291b9f447083bdcc325404402f5e6f210467586fdd045532bbf038d19",
    "fixtures/negative-missing-claim-type.json": "1b49ad3913ef70178f626634c06fec26a23fe7f5c9c8b01e08df117999d4c193",
    "fixtures/negative-expired.json": "d433b10fb5b42412bb27149555cd0131dd13f4fdb7c4e459159dde92735d5e25",
    "jwks.json": "51c05b4a10d12568f2d233eac43866b0797918e5585e1d8a7ac945541c9b5426",
    "fixtures/wycheproof-kat.json": "c582b89a7b0a4054fe07169248b5a8377c99084d23f6544515c80ebba96333dc",
    "plugins/ed25519_pure.py": "25bd6238fd5eba2cba4e1e290bcf04043dbf472cf90368b66c14ff57d59a8fcf",
}
CORPUS_PIN = "752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536"
FIXTURES = ["positive-authority", "negative-scope-violation", "negative-composition-failure",
            "negative-missing-claim-type", "negative-expired"]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main() -> int:
    fam, corpus_path = Path(sys.argv[1]), Path(sys.argv[2])
    out = []

    def rec(name, ok, detail=""):
        out.append({"check": name, "pass": bool(ok), "detail": detail})

    # 0. Input identity, fail closed.
    for rel, want in PINS.items():
        got = sha(fam / rel)
        print(f"  input {rel}: sha256 {got} {'MATCH' if got == want else 'MISMATCH'}")
        if got != want:
            print("digest mismatch: this record does not speak about these bytes"); return 2
    got = sha(corpus_path)
    print(f"  input corpus: sha256 {got} {'MATCH' if got == CORPUS_PIN else 'MISMATCH'}")
    if got != CORPUS_PIN:
        print("digest mismatch: corpus is not the pinned file"); return 2

    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    jwks = json.loads((fam / "jwks.json").read_text())
    keys = {k["kid"]: k for k in jwks["keys"]}

    # 1. Canonical bytes and digest under rfc8785; signature under cryptography.
    for name in FIXTURES:
        fx = json.loads((fam / "fixtures" / f"{name}.json").read_text())
        h, p, s = fx["jws"].split(".")
        payload = b64u(p)
        canon = rfc8785.dumps(fx["input_object"])
        jcs_ok = canon == payload and canon.decode("utf-8") == fx["canonical_bytes_utf8"]
        rec(f"jcs-bytes:{name}", jcs_ok,
            "" if jcs_ok else "rfc8785 output differs from the signed payload or canonical_bytes_utf8")
        rec(f"sha256:{name}", hashlib.sha256(canon).hexdigest() == fx["canonical_sha256"])
        header = json.loads(b64u(h))
        key = keys.get(header.get("kid"))
        try:
            Ed25519PublicKey.from_public_bytes(b64u(key["x"])).verify(b64u(s), (h + "." + p).encode("ascii"))
            ok = True
        except (InvalidSignature, TypeError, KeyError):
            ok = False
        rec(f"ed25519-jws:{name}", ok, f"alg={header.get('alg')} kid={header.get('kid')}")

    # 2. The contributor's verifier (implementation under test) against the full pinned corpus.
    spec = importlib.util.spec_from_file_location("ed25519_pure", fam / "plugins" / "ed25519_pure.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    corpus = json.loads(corpus_path.read_text())
    tally = {"valid": [0, 0], "invalid": [0, 0], "acceptable": [0, 0]}; mism = []; by_id = {}
    for g in corpus["testGroups"]:
        pk = bytes.fromhex(g["publicKey"]["pk"])
        for t in g["tests"]:
            by_id[t["tcId"]] = (g["publicKey"]["pk"], t["msg"], t["sig"], t["result"])
            got = mod.verify(pk, bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]))
            tally[t["result"]][0 if got else 1] += 1
            if (t["result"] == "valid") != got and t["result"] != "acceptable":
                mism.append(t["tcId"])
    rec("wycheproof-full:valid-accepted", tally["valid"][1] == 0, f"{tally['valid'][0]}/{sum(tally['valid'])}")
    rec("wycheproof-full:invalid-rejected", tally["invalid"][0] == 0, f"{tally['invalid'][1]}/{sum(tally['invalid'])}")
    rec("wycheproof-full:mismatches", not mism, str(mism))

    # 3. The vendored KAT subset is byte-identical to the corpus entries it names.
    kat = json.loads((fam / "fixtures" / "wycheproof-kat.json").read_text())
    bad = [t["tcId"] for t in kat["tests"] if by_id.get(t["tcId"]) != (t["pk"], t["msg"], t["sig"], t["result"])]
    rec("kat-subset:byte-match", not bad, f"{len(kat['tests'])} entries; mismatched {bad}")

    passed = sum(1 for r in out if r["pass"])
    summary = {"record": "crypto-recompute-ctef-v0.3.1-a71b7329", "total": len(out), "passed": passed,
               "failed": len(out) - passed, "all_pass": passed == len(out), "checks": out}
    if "--json" in sys.argv:
        print(json.dumps(summary, indent=2))
    else:
        for r in out:
            print(f"  [{'PASS' if r['pass'] else 'FAIL'}] {r['check']}" + (f"  {r['detail']}" if r["detail"] else ""))
        print(f"\n{passed}/{len(out)} checks pass.")
    return 0 if summary["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
