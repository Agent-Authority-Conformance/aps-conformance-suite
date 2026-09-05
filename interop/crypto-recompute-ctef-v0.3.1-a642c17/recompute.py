#!/usr/bin/env python3
"""Lab recompute of the crypto-layer claims of the ctef-v0.3.1 family at PR #43 head a642c17f.

Thin harness. For canonicalization, digests and signatures it invokes implementations authored by
neither the contributor nor the lab (`rfc8785` and `cryptography`). Separately, it runs the
contributor's Ed25519 verifier against the pinned C2SP/Wycheproof corpus and compares its outputs
with the corpus's published expected results.

It does not implement or evaluate the family's CTEF admissibility semantics.

Usage: python3 recompute.py <family dir at a642c17f> <ed25519_test.json at 5722833c> [--json]
Exit 0 iff every input matches its pinned digest and every check passes; exit 2 on a digest
mismatch.
"""
import base64, hashlib, json, sys, importlib.util
from pathlib import Path

PINS = {
    "fixtures/positive-authority.json": "d01c38aecf3c46e168c744277c00c361406fb8f116ced7d13d3c91e5069b8a2e",
    "fixtures/negative-scope-violation.json": "c583bdfdedf4dcaa620581e54c1df270659595499b6dfaf65e9abd64699c6fcf",
    "fixtures/negative-composition-failure.json": "d414707b7346ddbdf0ba9adc7cf5fde11a268a12eb688fe3a14ecc6475e4cadd",
    "fixtures/negative-missing-claim-type.json": "c7770bc1846b6a392238f186c148636a6b80e1e189334a6ec036a8944f74a787",
    "fixtures/negative-expired.json": "581a54c1ce2cf8f6b7c27199ce54547de2a2d34f5be7475dc8f6769d9072352f",
    "jwks.json": "adedee5926d5eb4388fc482798563dd907f8c38086a92952740d717bea36753d",
    "fixtures/wycheproof-kat.json": "57cd4759d62cc0f212b920681913df8bf16cc3642914c47b3fd6d1956ea46a11",
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
    summary = {"record": "crypto-recompute-ctef-v0.3.1-a642c17", "total": len(out), "passed": passed,
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
