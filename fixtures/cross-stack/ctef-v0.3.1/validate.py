#!/usr/bin/env python3
"""CTEF v0.3.1 recompute adapter — stdlib-only, no network.

End-to-end, on signed self-owned CTEF fixtures: for each fixture the signed JWS
payload IS the object being canonicalized and admitted. The adapter

  1. runs a Wycheproof known-answer set against the vendored verifier
     (accept every `valid`, reject every `invalid`);
  2. for each fixture: decodes+verifies the JWS under the header policy
     (alg=EdDSA, kty=OKP, crv=Ed25519, unique kid) against the vendored JWKS,
     re-canonicalizes the decoded payload under RFC 8785 JCS and asserts it
     reproduces the signed bytes / `canonical_bytes_utf8` / `canonical_sha256`,
     then applies the claim model + expiry and compares the outcome to
     `expected_result` / `expected_error_code`;
  3. confirms a tampered signing input is rejected.

Run:  python3 validate.py [--json]   (exit 0 iff every check passes)
No third-party packages, no network.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from plugins import ed25519_pure  # noqa: E402
from plugins.admissibility import admit  # noqa: E402
from plugins.jcs import canonicalize_jcs_strict  # noqa: E402
from plugins.jws import JwsError, decode_and_verify  # noqa: E402

HERE = Path(__file__).parent
FIX = HERE / "fixtures"
FIXTURES = [
    "positive-authority",
    "negative-scope-violation",
    "negative-composition-failure",
    "negative-missing-claim-type",
    "negative-expired",
]


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def run() -> dict:
    results: list[dict] = []

    def rec(name: str, ok: bool, detail: str = "") -> None:
        results.append({"check": name, "pass": bool(ok), "detail": detail})

    # 1. Verifier known-answer set (Wycheproof subset).
    kat = json.loads((FIX / "wycheproof-kat.json").read_text())
    for t in kat["tests"]:
        got = ed25519_pure.verify(bytes.fromhex(t["pk"]), bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"]))
        want = t["result"] == "valid"
        rec(f"wycheproof:tc{t['tcId']}", got == want,
            "" if got == want else f"{'accepted' if got else 'rejected'} a {t['result']} sig")

    jwks = json.loads((HERE / "jwks.json").read_text())

    # 2. End-to-end on each signed fixture.
    for name in FIXTURES:
        fx = json.loads((FIX / f"{name}.json").read_text())
        try:
            payload = decode_and_verify(fx["jws"], jwks)
        except JwsError as e:
            rec(f"jws-verify:{name}", False, str(e))
            continue
        rec(f"jws-verify:{name}", True)

        obj = json.loads(payload)
        canon = canonicalize_jcs_strict(obj)
        recompute_ok = (
            canon == payload
            and canon.decode("utf-8") == fx["canonical_bytes_utf8"]
            and hashlib.sha256(canon).hexdigest() == fx["canonical_sha256"]
        )
        rec(f"recompute:{name}", recompute_ok,
            "" if recompute_ok else "JCS of the decoded payload does not reproduce the signed bytes")

        result, code = admit(obj, fx["verification_time"])
        if fx["expected_result"] == "pass":
            adm_ok = result == "pass"
        else:
            adm_ok = result == "fail-closed" and code == fx.get("expected_error_code")
        rec(f"admissibility:{name}", adm_ok,
            "" if adm_ok else f"expected {fx['expected_result']}/{fx.get('expected_error_code')}, got {result}/{code}")

    # 3. Tamper control: a flipped signing input must fail.
    fx = json.loads((FIX / "positive-authority.json").read_text())
    h, p, s = fx["jws"].split(".")
    tampered = f"{h}.{p}x.{s}"
    try:
        decode_and_verify(tampered, jwks)
        rec("tamper-rejected", False, "tampered JWS verified (must not)")
    except JwsError as e:
        # Isolate signature detection: a header-policy rejection must NOT satisfy
        # this control (only the signature check should catch a payload tamper).
        is_sig = "signature does not verify" in str(e)
        rec("tamper-rejected", is_sig,
            "" if is_sig else f"rejected for the wrong reason ({e}); does not isolate signature tampering")

    passed = sum(1 for r in results if r["pass"])
    return {
        "family": "ctef-v0.3.1",
        "mode": "cold recompute, stdlib-only, no network; signed CTEF fixtures",
        "total": len(results), "passed": passed, "failed": len(results) - passed,
        "all_pass": passed == len(results), "checks": results,
    }


def main() -> int:
    summary = run()
    if "--json" in sys.argv:
        print(json.dumps(summary, indent=2))
    else:
        for r in summary["checks"]:
            line = f"  [{'PASS' if r['pass'] else 'FAIL'}] {r['check']}"
            if r["detail"]:
                line += f"  — {r['detail']}"
            print(line)
        print(f"\n{summary['passed']}/{summary['total']} checks pass ({summary['mode']}).")
    return 0 if summary["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
