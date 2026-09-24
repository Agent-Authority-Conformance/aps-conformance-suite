#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Runs this family's vectors against the PyPI reference SDK, agent-passport-system.

Same six claims as sdk-bridge.ts. The two SDKs do not have the same surface
here, so the claim table differs, and nothing is simulated to make them match.

Run against the SDK under test, for example:

    /path/to/venv/bin/python fixtures/conflicting-status-sources/sdk_bridge.py

Exit 0 when every supported claim matched, 1 otherwise, 2 when the SDK is not
importable.
"""
from __future__ import annotations

import importlib
import importlib.metadata as md
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

try:
    from agent_passport.v2.authority_delegation import verify_authority_delegation_chain
except Exception as err:  # pragma: no cover - environment problem, not a result
    print(f"agent-passport-system is not importable: {err}", file=sys.stderr)
    sys.exit(2)

VERSION = md.version("agent-passport-system")

vectors = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
chain_fixture = json.loads((HERE / "chain.json").read_text(encoding="utf-8"))

print(f"implementation: agent-passport-system {VERSION} (PyPI)")
print(f"python: {sys.version.split()[0]}")
print("")

failures: list[str] = []


def project(decision: str, reason: str):
    if decision == "admit":
        return "active", "valid", None
    if decision == "deny" and reason == "status_revoked":
        return "revoked", "invalid", "REVOKED"
    return "unknown", "indeterminate", "REVOCATION_UNKNOWN"


print("claim 1  chain verdict under the projected single revocation answer: SUPPORTED")
print("         api: verify_authority_delegation_chain(resolve_revocation=...)")
matched = 0
total = 0
for case in vectors["cases"]:
    for boundary in case["boundaries"]:
        total += 1
        answer, want_state, want_code = project(
            boundary["expected"]["decision"], boundary["expected"]["reason"]
        )
        result = verify_authority_delegation_chain(
            chain_fixture["chain"],
            now=chain_fixture["now"],
            resolve_verification_key=lambda _issuer, method, _issued_at:
                chain_fixture["verification_keys"].get(method),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _delegation, _answer=answer: _answer,
        )
        code = result.failures[0].code if result.failures else None
        ok = result.state == want_state and code == want_code
        never_valid = boundary["expected"]["decision"] == "admit" or result.state != "valid"
        if ok and never_valid:
            matched += 1
        else:
            failures.append(
                f"claim 1 {boundary['boundary_id']}: projected {answer}, wanted "
                f"{want_state}/{want_code}, got {result.state}/{code}"
            )
        suffix = f"/{code}" if code else ""
        print(
            f"         {boundary['boundary_id']:<12} "
            f"{boundary['expected']['decision']:<16}-> resolve_revocation '{answer}' "
            f"-> {result.state}{suffix}"
        )
print(f"         {matched}/{total} boundaries matched")
print("")

# The remaining five claims. Absence is asserted against the installed package
# rather than asserted from memory, so a later release that adds the surface
# turns this run into a failure instead of a stale note.
ABSENT = [
    (
        "claim 2",
        "per-source freshness bound, answer inside or past it",
        ["decide_freshness", "enforce_freshness_policy", "create_snapshot_freshness",
         "compute_evidence_age", "is_evidence_fresh"],
        "this SDK exposes no freshness-policy or evidence-age surface, so a per-source\n"
        "         bound cannot be expressed. The TypeScript SDK at 7.1.0 does have one,\n"
        "         so the two reference implementations do not cover the same ground here.",
    ),
    (
        "claim 3",
        "two status sources compared for conflict about one delegation",
        ["RevocationObservation", "build_revocation_observation"],
        "resolve_revocation returns one answer for one delegation and no API takes two\n"
        "         answers about one delegation. Nothing was simulated in its place.",
    ),
    (
        "claim 4",
        "coverage over a declared required-source set",
        ["required_sources", "coverage"],
        "no API takes a list of sources a verifier requires.",
    ),
    (
        "claim 5",
        "not_established as an observation-layer outcome",
        ["FreshnessDecision", "RevocationObservationDecision"],
        "there is no observation layer in this SDK. The chain layer does return\n"
        "         indeterminate, which claim 1 exercises.",
    ),
    (
        "claim 6",
        "an offline admission records the snapshot and the age it used",
        ["build_revocation_observation", "verify_revocation_observation"],
        "no observation record exists to carry a snapshot identity, its as_of or its\n"
        "         age, so there is nothing to record into.",
    ),
]

root = importlib.import_module("agent_passport")
for label, title, symbols, reason in ABSENT:
    present = [s for s in symbols if hasattr(root, s)]
    if present:
        failures.append(
            f"{label}: recorded not_supported, but agent_passport now exports {present}. "
            f"Re-run the survey and rewrite the claim."
        )
    print(f"{label}  {title}: NOT_SUPPORTED")
    print(f"         checked absent: {', '.join(symbols)}")
    print(f"         reason: {reason}")
    print("")

if failures:
    for item in failures:
        print(f"FAIL {item}", file=sys.stderr)
    print(
        f"\nconflicting-status-sources SDK bridge (Python): {len(failures)} failure(s)",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"PASSED: conflicting-status-sources SDK bridge (Python), agent-passport-system "
    f"{VERSION}. 1 claim supported and matched, 5 recorded not_supported."
)
