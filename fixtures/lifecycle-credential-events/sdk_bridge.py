#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Runs this family's vectors against the PyPI reference SDK, agent-passport-system.

Records per claim whether the SDK has an API for the behaviour the claim needs.
Where it does not, the claim is recorded not_supported with the reason and the
nearest surface named, and nothing is simulated in its place.

The claim numbering is the same as in sdk-bridge.ts so the two runs line up row
for row in SDK-RUNS.md.

Run from the suite root with agent-passport-system 4.1.0 or later installed:

    python3 fixtures/lifecycle-credential-events/sdk_bridge.py
"""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import platform
import sys
from pathlib import Path

import agent_passport as ap
from agent_passport import scope_covers
from agent_passport.crypto import public_key_from_private, sign
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain
from agent_passport.v2.composition_check import (
    ATTESTOR_INDEPENDENCE_CLASSES,
    COMPOSITION_CHECK_PROFILE,
    COMPOSITION_CHECK_RESULTS,
    composition_check_signing_payload,
    verify_composition_check,
)

HERE = Path(__file__).resolve().parent
VERSION = metadata.version("agent-passport-system")


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


vectors = read_json("vectors.json")
chain_fixture = read_json("chain.json")

print(f"implementation: agent-passport-system {VERSION} (PyPI)")
print(f"python: {platform.python_version()}")
print("")

failures: list[str] = []
boundaries = [
    dict(b, vector_id=c["id"], case_id=c["case_id"])
    for c in vectors["cases"]
    for b in c["boundaries"]
]

# ── claim 1 ───────────────────────────────────────────────────────────────

print("claim 1  chain verdict under the projected single revocation answer: SUPPORTED")
print("         api: verify_authority_delegation_chain(resolve_revocation=...)")


def project(verdict: str) -> tuple[str, str, str | None]:
    if verdict == "valid":
        return "active", "valid", None
    if verdict == "invalid":
        return "revoked", "invalid", "REVOKED"
    return "unknown", "indeterminate", "REVOCATION_UNKNOWN"


keys = chain_fixture["verification_keys"]
claim1 = 0
for b in boundaries:
    answer, want_state, want_code = project(b["expected"]["verdict"])
    result = verify_authority_delegation_chain(
        chain_fixture["chain"],
        now=chain_fixture["now"],
        resolve_verification_key=lambda _issuer, method, _issued_at: keys.get(method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation, _answer=answer: _answer,
    )
    code = result.failures[0].code if result.failures else None
    never_valid = b["expected"]["verdict"] == "valid" or result.state != "valid"
    if result.state == want_state and code == want_code and never_valid:
        claim1 += 1
    else:
        failures.append(
            f"claim 1 {b['boundary_id']}: projected {answer}, wanted {want_state}/{want_code}, "
            f"got {result.state}/{code}"
        )
print(f"         {claim1}/{len(boundaries)} boundaries matched the projection")
print("")

# ── claim 2 ───────────────────────────────────────────────────────────────

print("claim 2  a declared recipient scope checked as its own facet: NOT_SUPPORTED")
print(
    "         reason: the audience-binding module of the npm SDK (checkAudience, bindAudience,\n"
    "         AudienceCheckResult) has no counterpart in this package. Nothing here takes a\n"
    "         proof and a relying-party policy and returns a four-valued audience status, so\n"
    "         LC-G-004's three key-scope outcomes cannot be projected. Nothing was simulated."
)
print("")

# ── claim 3 ───────────────────────────────────────────────────────────────

print("claim 3  scope containment arithmetic for the enforced-scope check: SUPPORTED")
print("         api: scope_covers(granted, required)")
claim3 = 0
claim3_total = 0
for case in [c for c in vectors["cases"] if c["case_id"] == "LC-D-009"]:
    b = case["boundaries"][0]
    attested = next(
        (e for e in b["events"] if e["type"] == "reachable_scope_attestation"), None
    )
    if attested is None:
        continue
    claim3_total += 1
    declared = b["credential"]["declared_scope"]
    contained = all(
        any(scope_covers(d, g) for d in declared) for g in attested["grants"]
    )
    family = next(
        c for c in b["expected"]["record"]["checks"] if c["check_id"] == "enforced_scope_containment"
    )
    want = family["result"] == "established_valid"
    print(
        f"         {case['id']:<58} SDK contained={str(contained):<5} family {family['result']}"
    )
    if contained == want:
        claim3 += 1
    else:
        failures.append(
            f"claim 3 {case['id']}: scope_covers says contained={contained}, "
            f"family says {family['result']}"
        )
print(f"         {claim3}/{claim3_total} attested-scope vectors matched")
print("")

# ── claim 4 ───────────────────────────────────────────────────────────────

print(
    "claim 4  per-check results in a fixed enum with a separate indeterminate, and attestor\n"
    "         independence corroborated from trust context rather than self-declaration: SUPPORTED"
)
print("         api: verify_composition_check, composition_check_signing_payload")
print(f"         COMPOSITION_CHECK_RESULTS = {list(COMPOSITION_CHECK_RESULTS)}")
print(f"         ATTESTOR_INDEPENDENCE_CLASSES = {list(ATTESTOR_INDEPENDENCE_CLASSES)}")

ATTESTOR_KEY_ID = "did:aps:example:lce-sdk-bridge-attestor#key-1"
attestor_priv = hashlib.sha256(
    f"{vectors['determinism']['seed_input']}:sdk-bridge-attestor:v1".encode()
).hexdigest()
attestor_pub = public_key_from_private(attestor_priv)


def project_check(result: str) -> str:
    if result == "established_valid":
        return "pass"
    if result == "established_invalid":
        return "fail"
    return "indeterminate"


def receipt_for(b: dict, independence_class: str) -> dict:
    checks = b["expected"]["record"]["checks"]
    receipt = {
        "profile": COMPOSITION_CHECK_PROFILE,
        "attestor_key_id": ATTESTOR_KEY_ID,
        "attestor_independence_class": independence_class,
        "chain_hash": vectors["credential_ref"],
        "action_ref": b["boundary_id"],
        "context_hash": b["expected"]["canonical_sha256"],
        "policy_profile_ids": ["aac-lifecycle-credential-events-v0"],
        "checks_run": [c["check_id"] for c in checks],
        "result_per_check": [project_check(c["result"]) for c in checks],
        "issued_at": b["gateway_now"],
        "expires_at": "2026-09-30T00:00:00Z",
    }
    receipt["signature"] = sign(composition_check_signing_payload(receipt), attestor_priv)
    return receipt


def ms(value: str) -> float:
    from datetime import datetime

    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(text).timestamp() * 1000.0


def ctx_for(b: dict, registered_by_operator: bool) -> dict:
    return {
        "trusted_attestors": {
            ATTESTOR_KEY_ID: {
                "publicKey": attestor_pub,
                "profiles": ["aac-lifecycle-credential-events-v0"],
                "registered_by_operator": registered_by_operator,
            }
        },
        "expected_chain_hash": vectors["credential_ref"],
        "expected_action_ref": b["boundary_id"],
        "expected_context_hash": b["expected"]["canonical_sha256"],
        "now_ms": ms(b["gateway_now"]),
    }


claim4 = 0
for b in boundaries:
    verified = verify_composition_check(receipt_for(b, "independent_registered"), ctx_for(b, False))
    echoed = verified["result_per_check"]
    projected = [project_check(c["result"]) for c in b["expected"]["record"]["checks"]]
    no_aggregate = "safe" not in verified and "verdict" not in verified
    if verified["anchor_verified"] and echoed == projected and no_aggregate:
        claim4 += 1
    else:
        failures.append(
            f"claim 4 {b['boundary_id']}: anchor_verified={verified['anchor_verified']}, "
            f"violations={verified['violations']}, echo matched={echoed == projected}"
        )
print(
    f"         {claim4}/{len(boundaries)} boundaries: the SDK verified the anchor, echoed the\n"
    f"         per-check results in order, and returned no aggregate verdict of its own"
)

sample = boundaries[0]
self_declared = verify_composition_check(
    receipt_for(sample, "independent_registered"), ctx_for(sample, True)
)
corroborated = verify_composition_check(
    receipt_for(sample, "independent_registered"), ctx_for(sample, False)
)
print(
    "         self-declared independent, context says registered_by_operator=True  -> "
    f"independence_is_second_anchor={self_declared['independence_is_second_anchor']}"
)
print(
    "         self-declared independent, context says registered_by_operator=False -> "
    f"independence_is_second_anchor={corroborated['independence_is_second_anchor']}"
)
if self_declared["independence_is_second_anchor"] is not False:
    failures.append("claim 4: the SDK accepted a self-declared independence the context did not back")
if corroborated["independence_is_second_anchor"] is not True:
    failures.append("claim 4: the SDK did not corroborate an independence the context backs")
# One pinned cross-language constant, the same one sdk-bridge.ts checks. Both
# bridges build the same receipt from vectors.json and sign it with the same
# derived key. The signature is over the composition-check tag plus RFC 8785 JCS
# of the receipt without its signature, so if the two packages' canonicalizers or
# tags ever diverge, both runs fail here rather than silently disagreeing.
CROSS_LANG_SIGNATURE = (
    "fc2acb57697994cc1edbf39f90270f6022b25717fcecb8c5818ed069613ad9a58f71fc41796aa"
    "e686374397b4ec47f20ad9d873ea701beb28c60924ecf5aa50f"
)
pinned = receipt_for(boundaries[0], "independent_registered")
print(
    f"         cross-language signature over {boundaries[0]['boundary_id']}: "
    f"{pinned['signature'][:24]}..."
)
if pinned["signature"] != CROSS_LANG_SIGNATURE:
    failures.append(
        f"claim 4: the signature over the pinned receipt is {pinned['signature']}, "
        f"not the pinned {CROSS_LANG_SIGNATURE}"
    )
else:
    print(
        "         matches the constant the TypeScript bridge checks, so the tag and the RFC 8785\n"
        "         canonicalization agree byte for byte across the two packages."
    )
print("")

# ── claim 5 ───────────────────────────────────────────────────────────────

print("claim 5  a signing key checked for the purpose it was authorized for: NOT_SUPPORTED")
print(
    "         reason: assertKeyPurpose and IdentityCompositionError, which the npm SDK exports,\n"
    "         have no counterpart in this package. is_purpose_permitted is a data-purpose\n"
    "         matcher, not a key-purpose check on a resolved DID document. Nothing was simulated."
)
print("")

# ── claim 6 ───────────────────────────────────────────────────────────────

print("claim 6  clock disagreement as an outcome distinct from expiry: NOT_SUPPORTED")
print(
    "         reason: this package's time surface is RFC 3339 parsing and formatting\n"
    "         (parse_rfc3339, format_rfc3339, now_ms). There is no HybridTimestamp carrying a\n"
    "         wall-clock uncertainty band and no compare_timestamps, so the partial support the\n"
    "         npm bridge records for this claim is absent here. Nothing was simulated."
)
print("")

# ── claims 7 to 10 ────────────────────────────────────────────────────────

ABSENT = [
    (
        7,
        "compromise reach computed over a declared authority graph",
        "No function takes authority edges and a compromised subject and returns the\n"
        "         reachable set. cascade_revoke walks recorded delegation descendants and has no\n"
        "         notion of a \"could mint credentials for\" edge.",
    ),
    (
        8,
        "revocation effectiveness as a property of the credential class",
        "AuthorityRevocation records name one delegation. Nothing takes a credential class\n"
        "         and returns when a recorded revocation becomes effective for it.",
    ),
    (
        9,
        "an issuance-window integrity finding, or trust in an issuer population",
        "Nothing takes a finding about an issuer's own issuance records over a window, and\n"
        "         nothing expresses trust in an issuer's whole population as distinct from\n"
        "         revoking named artifacts.",
    ),
    (
        10,
        "a coverage basis for what was exercised under a credential",
        "Nothing states or checks a completeness claim over an interval, which is the\n"
        "         separate second claim LC-D-025 turns on.",
    ),
]
for number, title, reason in ABSENT:
    print(f"claim {number}  {title}: NOT_SUPPORTED")
    print(f"         reason: {reason}")
    print("")

# Assert the absences against the installed package, so a later release that adds
# the surface turns this run into a failure rather than a stale note.
MUST_BE_ABSENT = [
    "check_audience",
    "assert_key_purpose",
    "compare_timestamps",
    "reachable_authority_subjects",
    "compute_compromise_reach",
    "revocation_effective_from",
    "verify_issuance_window_integrity",
    "issuer_population_trust",
    "exercised_authority_coverage",
    "verify_coverage_basis",
]
for name in MUST_BE_ABSENT:
    if hasattr(ap, name):
        failures.append(
            f"claims 2, 5, 6 to 10: agent-passport-system {VERSION} now exports {name}. "
            "Re-run this bridge and move the claim out of the recorded absences."
        )

if failures:
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    print(
        f"\nlifecycle-credential-events SDK bridge (Python): {len(failures)} failure(s)",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"PASSED: lifecycle-credential-events SDK bridge (Python), agent-passport-system {VERSION}. "
    "3 claims supported and matched, 6 recorded not_supported."
)
