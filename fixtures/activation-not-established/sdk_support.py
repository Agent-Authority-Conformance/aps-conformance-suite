#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Prints, per vector, what the PyPI reference SDK decided and what it has no
API for. The Python counterpart of sdk-support.ts. Records, does not judge.

Run: python3 fixtures/activation-not-established/sdk_support.py
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
    "activation condition attached to a grant, by date or by recorded event",
    "attestor-role registry or role lookup",
    "attestation acceptance against an activation condition",
    "a not_yet_effective verdict, for a condition established as not yet met",
    "a not_established verdict distinct from invalid and indeterminate",
]


def main():
    fixture = json.loads((HERE / "chain.json").read_text(encoding="utf-8"))
    vectors = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))

    print(f"PyPI agent-passport-system {metadata.version('agent-passport-system')}")
    print("JCS canonicalizer in use: canonicalize_jcs (this SDK exposes no ForWrite variant,")
    print("  so both runners rebuild preimages with the plain canonicalizer)")
    print()

    for case in vectors["cases"]:
        action_at = fixture["clock"][case["action_at"]]
        result = verify_authority_delegation_chain(
            fixture["chains"][case["grant"]],
            now=action_at,
            resolve_verification_key=lambda _issuer, method, _issued_at: fixture["verification_keys"].get(method),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _delegation, answer=case["revocation"]: answer,
        )
        code = result.failures[0].code if result.failures else "none"
        signature_results = []
        for label in case["presented_attestations"]:
            attestation = fixture["attestations"][label]
            body = {k: v for k, v in attestation.items() if k not in ("attestation_id", "signature")}
            key = fixture["verification_keys"].get(attestation["verification_method"])
            try:
                ok = verify_ed25519(canonicalize_jcs(body), attestation["signature"], key)
            except Exception:
                ok = False
            signature_results.append(f"{label}={ok}")
        print(case["id"])
        print(f"  verify_authority_delegation_chain: supported, state={result.state} code={code}")
        joined = " ".join(signature_results) if signature_results else "no attestation presented"
        print(f"  verify + canonicalize_jcs over attestation bytes: supported, {joined}")
        print(f"  activation verdict: not_supported, no SDK API for: {'; '.join(UNSUPPORTED_CONCEPTS)}")

    print()
    print(f"activation-not-established PyPI SDK observations: {len(vectors['cases'])} vectors recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
