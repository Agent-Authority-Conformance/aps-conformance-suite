#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Prints, per vector, what the PyPI reference SDK decided and what it has no
API for. The Python counterpart of sdk-support.ts. Records, does not judge.

Run: python3 fixtures/suspension-cause-composition/sdk_support.py
"""
from __future__ import annotations

import json
import sys
from importlib import metadata
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

UNSUPPORTED_CONCEPTS = [
    "a suspended or restricted state of any arity (the revocation resolver answers active, revoked or unknown)",
    "a lifecycle cause attached to a grant",
    "a release record, or a rule for when one takes effect",
    "lifecycle standing over a cause, or a registry that supplies it",
    "a verdict that names which causes remain",
]


def main():
    fixture = json.loads((HERE / "chain.json").read_text(encoding="utf-8"))
    vectors = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))

    print(f"PyPI agent-passport-system {metadata.version('agent-passport-system')}")
    print("JCS canonicalizer in use: canonicalize_jcs")
    print()

    for case in vectors["cases"]:
        evaluated_at = fixture["clock"][case["evaluated_at"]]
        result = verify_authority_delegation_chain(
            fixture["chains"][case["grant"]],
            now=evaluated_at,
            resolve_verification_key=lambda _issuer, method, _issued_at: fixture["verification_keys"].get(method),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _delegation, answer=case["revocation"]: answer,
        )
        code = result.failures[0].code if result.failures else "none"
        signature_results = []
        for label in case["presented_releases"]:
            release = fixture["releases"][label]
            body = {k: v for k, v in release.items() if k not in ("record_id", "signature")}
            key = fixture["verification_keys"].get(release["verification_method"])
            try:
                ok = verify_ed25519(canonicalize_jcs(body), release["signature"], key)
            except Exception:
                ok = False
            signature_results.append(f"{label}={ok}")
        print(case["id"])
        print(f"  verify_authority_delegation_chain: supported, state={result.state} code={code}")
        joined = " ".join(signature_results) if signature_results else "no release presented"
        print(f"  verify + canonicalize_jcs over release-record bytes: supported, {joined}")
        print(f"  cause verdict: not_supported, no SDK API for: {'; '.join(UNSUPPORTED_CONCEPTS)}")

    print()
    print(f"suspension-cause-composition PyPI SDK observations: {len(vectors['cases'])} vectors recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
