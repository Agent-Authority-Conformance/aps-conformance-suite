#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-conferral-without-authority family.
#
# Same vectors, same chain.json, same expected verdicts as verify.ts, recomputed by the
# other reference SDK. No network. Nothing is minted here: this runner reads the bytes
# verify.ts reads and calls only the published agent-passport-system package.
#
# Run, from the suite root:
#
#     python3 -m venv /tmp/aac-cwa-work/pyenv
#     /tmp/aac-cwa-work/pyenv/bin/pip install agent-passport-system==4.1.0
#     /tmp/aac-cwa-work/pyenv/bin/python \
#         fixtures/lifecycle-conferral-without-authority/verify_python_sdk.py
#
# Exit 0 when the reference verifier matches every vector AND both defective verifiers
# diverge on exactly their declared sets. Exit 1 otherwise.

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import pathlib
import sys

from agent_passport.v2.authority_delegation import (
    compare_authority,
    scope_grant_covers,
    verify_authority_delegation_chain,
    verify_authority_delegation_signature,
)

HERE = pathlib.Path(__file__).resolve().parent

CHAIN_BYTES = (HERE / "chain.json").read_bytes()
VECTOR_BYTES = (HERE / "vectors.json").read_bytes()
CHAIN = json.loads(CHAIN_BYTES)
SUITE = json.loads(VECTOR_BYTES)

NOW = CHAIN["now"]
KEYS = CHAIN["verification_keys"]
TRUSTED_ROOT_ISSUER = CHAIN["trusted_root_issuer"]

failed = 0


def fail(message: str) -> None:
    global failed
    print(f"  FAIL {message}", file=sys.stderr)
    failed += 1


def resolve_verification_key(issuer: str, verification_method: str, issued_at: str):
    return KEYS.get(verification_method)


def trust_root(root: dict) -> bool:
    return root.get("issuer") == TRUSTED_ROOT_ISSUER


def resolve_revocation(delegation: dict) -> str:
    return "active"


def verdict_of(result) -> dict:
    return {
        "state": result.state,
        "failures": [
            {"code": f.code, "index": f.index, "facet": f.facet, "message": f.message}
            for f in result.failures
        ],
    }


def reference_verifier(chain: list) -> dict:
    """The SDK decides. This function only hands it the chain."""
    return verdict_of(
        verify_authority_delegation_chain(
            chain,
            now=NOW,
            resolve_verification_key=resolve_verification_key,
            trust_root=trust_root,
            resolve_revocation=resolve_revocation,
        )
    )


def narrowing_without_depth_verifier(chain: list) -> dict:
    """Monotonic narrowing enforced, conferral authority never asked about.

    The reference verdict with every depth failure removed, which is what an
    implementation that compares six of the seven facets produces.
    """
    reference = reference_verifier(chain)
    failures = [f for f in reference["failures"] if not f["code"].startswith("DEPTH_")]
    if len(failures) == len(reference["failures"]):
        return {"state": reference["state"], "failures": failures}
    return {"state": "invalid" if failures else "valid", "failures": failures}


def scope_coverage_only_verifier(chain: list) -> dict:
    """Signatures plus scope coverage, and nothing else."""
    failures = []
    for i, record in enumerate(chain):
        public_key = KEYS.get(record.get("verification_method", ""))
        if not public_key or not verify_authority_delegation_signature(record, public_key):
            failures.append({"code": "SIGNATURE_INVALID", "index": i, "facet": None, "message": None})
            continue
        if i == 0:
            continue
        parent_grants = chain[i - 1].get("authority", {}).get("scope", {}).get("grants", [])
        child_grants = record.get("authority", {}).get("scope", {}).get("grants", [])
        for needed in child_grants:
            if not any(scope_grant_covers(granted, needed) for granted in parent_grants):
                failures.append({"code": "SCOPE_WIDENING", "index": i, "facet": "scope", "message": None})
                break
    return {"state": "invalid" if failures else "valid", "failures": failures}


VERIFIERS = {
    "reference-verifier": reference_verifier,
    "defective-verifier-narrowing-without-depth": narrowing_without_depth_verifier,
    "defective-verifier-scope-coverage-only": scope_coverage_only_verifier,
}


def first_failure(verdict: dict):
    return verdict["failures"][0] if verdict["failures"] else None


SDK_VERSION = importlib.metadata.version("agent-passport-system")

print("lifecycle-conferral-without-authority Python")
print(f"  sdk            agent-passport-system {SDK_VERSION} (PyPI)")
print(f"  now            {NOW}")
print(f"  status label   {SUITE['status_label']}")
print(
    "  proposed text  "
    f"{SUITE['proposed_text']['repository']} {SUITE['proposed_text']['document']} "
    f"@ {SUITE['proposed_text']['commit']}"
)
print(f"  sha256 chain.json    {hashlib.sha256(CHAIN_BYTES).hexdigest()}")
print(f"  sha256 vectors.json  {hashlib.sha256(VECTOR_BYTES).hexdigest()}")
print("")

print(f"Python SDK support, recorded by this run against {SDK_VERSION}:")
for status, concept, api in [
    ("supported", "chain state, including time and revocation", "verify_authority_delegation_chain"),
    ("supported", "declared conferral right (depth facet)", "compare_authority"),
    ("supported", "conferral refused when the right is exhausted", "DEPTH_EXHAUSTED"),
    ("supported", "conferral right narrows like any other facet", "DEPTH_WIDENING"),
    ("supported", "scope coverage", "scope_grant_covers"),
    ("supported", "issuer-side refusal to mint an unauthorized conferral", "issue_sub_authority_delegation"),
    (
        "not_supported",
        "undeclared conferral right as its own verdict",
        "no API: a missing facet is SCHEMA_INVALID, never not_established",
    ),
]:
    print(f"  {status:<14} {concept}  ({api})")
print("")

# The mint-time claim verify.ts records for CWA-03, recomputed here by the other SDK:
# the strictly narrower child fails on exactly one facet, and that facet is depth.
cwa03 = CHAIN["presented"]["CWA-03"]
cwa03_failures = compare_authority(cwa03[0]["authority"], cwa03[1]["authority"])
if len(cwa03_failures) != 1 or cwa03_failures[0].code != "DEPTH_EXHAUSTED":
    fail(
        "compare_authority on the CWA-03 pair returned "
        f"{[f.code for f in cwa03_failures]}, expected exactly ['DEPTH_EXHAUSTED']"
    )
else:
    print("compare_authority on the CWA-03 pair: ['DEPTH_EXHAUSTED'], one failure, facet depth")
print("")

reference_verdicts: dict[str, dict] = {}

print("reference-verifier")
for vector in SUITE["vectors"]:
    presented = CHAIN["presented"].get(vector["presented_chain"])
    if not isinstance(presented, list):
        fail(f"{vector['id']}: chain.json has no presented chain named {vector['presented_chain']}")
        continue
    if len(presented) != vector["chain_length"]:
        fail(
            f"{vector['id']}: presented chain has {len(presented)} records, "
            f"vectors.json declares {vector['chain_length']}"
        )
    verdict = reference_verifier(presented)
    reference_verdicts[vector["id"]] = verdict

    observed = first_failure(verdict)
    expected = vector["expected"]
    ok_state = verdict["state"] == expected["state"]
    ok_code = (observed["code"] if observed else None) == expected["failure_code"]
    ok_index = (observed["index"] if observed else None) == expected["failure_index"]
    ok_count = len(verdict["failures"]) == (0 if expected["state"] == "valid" else 1)

    if ok_state and ok_code and ok_index and ok_count:
        detail = (
            f"{verdict['state']}, {observed['code']} at index {observed['index']}"
            if expected["failure_code"]
            else verdict["state"]
        )
        print(f"  ok   {vector['id']:<7} {detail}")
    else:
        fail(
            f"{vector['id']}: expected {expected['state']}/{expected['failure_code']}"
            f"@{expected['failure_index']} with {0 if expected['state'] == 'valid' else 1} failure, got "
            f"{verdict['state']}/{observed['code'] if observed else None}"
            f"@{observed['index'] if observed else None} with {len(verdict['failures'])} "
            f"({json.dumps(verdict['failures'])})"
        )
print("")


def verdicts_agree(a: dict, b: dict) -> bool:
    if a["state"] != b["state"]:
        return False
    fa, fb = first_failure(a), first_failure(b)
    return (fa["code"] if fa else None) == (fb["code"] if fb else None) and (
        fa["index"] if fa else None
    ) == (fb["index"] if fb else None)


for name, declared in SUITE["declared_fail_sets"].items():
    declared_set = set(declared)
    print(name)
    print(f"  declared divergences: {', '.join(declared)}")
    for vector in SUITE["vectors"]:
        presented = CHAIN["presented"].get(vector["presented_chain"])
        reference = reference_verdicts.get(vector["id"])
        if not isinstance(presented, list) or reference is None:
            continue
        verdict = VERIFIERS[name](presented)
        agrees = verdicts_agree(reference, verdict)
        should_diverge = vector["id"] in declared_set

        if should_diverge and agrees:
            fail(f"{name} {vector['id']}: declared to diverge, but it agreed with the reference ({verdict['state']})")
        elif not should_diverge and not agrees:
            ref_first, this_first = first_failure(reference), first_failure(verdict)
            fail(
                f"{name} {vector['id']}: undeclared divergence, reference "
                f"{reference['state']}/{ref_first['code'] if ref_first else None}, this verifier "
                f"{verdict['state']}/{this_first['code'] if this_first else None}"
            )
        elif should_diverge:
            wrongly = (
                "wrongly admits" if verdict["state"] == "valid" and reference["state"] == "invalid" else "differs"
            )
            print(f"  ok   {vector['id']:<7} diverges as declared: {wrongly} ({verdict['state']})")
    print("")

if failed:
    print(f"FAILED: {failed} check(s)", file=sys.stderr)
    sys.exit(1)

n = len(SUITE["vectors"])
print(
    f"PASSED: reference-verifier matched all {n}/{n} vectors, "
    "both defective verifiers diverged on exactly their declared sets (python SDK)"
)
