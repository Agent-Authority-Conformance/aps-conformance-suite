#!/usr/bin/env python3
"""Second implementation of the capability-binding-drift boundary rules, in Python.

Runs the same eight presentations in vectors.json over the same chain.json records,
through a from-scratch implementation of the boundary steps and the same declared
defective negative control. No network access.

What this file gets from the Python SDK, agent-passport-system 4.x:

  * verify_authority_delegation_chain, for the grant's structural, temporal and
    revocation state
  * agent_passport.crypto.verify, for the tool registry entry's Ed25519 signature
  * agent_passport.canonicalize and agent_passport.canonicalize_jcs, for the exact
    byte sequences the TypeScript side signs and digests, which is what makes the
    registry-entry signature check and the metadata digest cross-language claims

What it does NOT get from the Python SDK. The Python SDK ships no tool-integrity
module: there is no create_tool_registry_entry, no verify_tool_integrity and no
ToolRegistryEntry type anywhere in the installed package. The registry-entry
signature check and the implementation-hash comparison are therefore written out
here from the SDK's crypto and canonicalization primitives. That is a recorded
gap in the Python SDK, not a claim that the Python SDK decided any of this. See
README "SDK findings".

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/capability-binding-drift/verify.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agent_passport import canonicalize, canonicalize_jcs, crypto
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")

if fixture.get("_placeholder") or not fixture.get("delegations") or not fixture.get("registry_entries"):
    print(
        "capability-binding-drift chain.json is not minted. Run "
        "`npx tsx fixtures/capability-binding-drift/mint.ts` first.",
        file=sys.stderr,
    )
    sys.exit(2)

TOOL = fixture["tool"]
METADATA_DIGEST_DOMAIN = fixture["metadata_digest_domain"]
TRUSTED_ATTESTOR = TOOL["trusted_attestor"]


def implementation_digest(implementation: str) -> str:
    return "sha256:" + hashlib.sha256(implementation.encode("utf-8")).hexdigest()


def metadata_digest(metadata) -> str:
    preimage = (
        METADATA_DIGEST_DOMAIN.encode("utf-8")
        + b"\x00"
        + canonicalize_jcs(metadata).encode("utf-8")
    )
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def registry_entry_signature_valid(entry: dict, public_key_hex: str) -> bool:
    body = {key: value for key, value in entry.items() if key != "signature"}
    return crypto.verify(canonicalize(body), entry["signature"], public_key_hex)


def pins_under(grant: dict, prefix: str):
    return [
        item[len(prefix):]
        for item in grant["authority"]["scope"]["grants"]
        if item.startswith(prefix)
    ]


def admit(presentation: dict, defects: dict) -> dict:
    grant = fixture["delegations"][presentation["grant"]]
    entry = fixture["registry_entries"][presentation["registry_entry"]]
    current_implementation = TOOL["implementations"][presentation["current_implementation"]]
    current_metadata = TOOL["metadata"][presentation["current_metadata"]]
    requested_tool = presentation["requested_tool"]

    # Step 0. The grant itself.
    chain_result = verify_authority_delegation_chain(
        [grant],
        now=presentation["now"],
        resolve_verification_key=lambda _issuer, method, _issued_at:
            fixture["verification_keys"].get(method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: presentation["revocation"],
    )
    if chain_result.state != "valid":
        first = chain_result.failures[0] if chain_result.failures else None
        return {
            "verdict": "invalid",
            "reason": "authority_chain_not_valid",
            "detail": f"{chain_result.state}/{first.code if first else 'none'}",
        }

    # Step 1. Does the grant name this tool, and carry the scopes the action needs.
    grants = grant["authority"]["scope"]["grants"]
    tool_grant = f"tool:{requested_tool}"
    if tool_grant not in grants:
        return {"verdict": "not_established", "reason": "tool_not_in_grant_scope", "detail": tool_grant}
    missing = [scope for scope in fixture["action"]["input"]["scope_required"] if scope not in grants]
    if missing:
        return {"verdict": "not_established", "reason": "scope_not_granted", "detail": ",".join(missing)}

    # Step 2. The tool attestation. The key comes from the tool, never from the
    # attestorId the presented entry asserts about itself.
    attestor_key = (
        fixture["attestor_keys"].get(TRUSTED_ATTESTOR) if requested_tool == TOOL["name"] else None
    )
    if attestor_key is None:
        return {"verdict": "not_established", "reason": "tool_attestor_key_unresolved", "detail": requested_tool}
    if not registry_entry_signature_valid(entry, attestor_key):
        return {"verdict": "not_established", "reason": "tool_attestation_signature_invalid"}
    if entry["toolName"] != requested_tool:
        return {
            "verdict": "not_established",
            "reason": "registry_entry_tool_name_mismatch",
            "detail": f"{entry['toolName']}!={requested_tool}",
        }
    if not defects["skip_running_implementation_check"]:
        if implementation_digest(current_implementation) != entry["implementationHash"]:
            return {"verdict": "not_established", "reason": "registry_entry_implementation_mismatch"}

    # Step 3. The implementation pin carried by the grant.
    implementation_pins = pins_under(grant, f"{tool_grant}:impl:")
    if not implementation_pins:
        if not defects["absent_pin_admits"]:
            return {"verdict": "not_established", "reason": "no_capability_pin_in_grant", "detail": tool_grant}
    elif entry["implementationHash"] not in implementation_pins:
        return {
            "verdict": "not_established",
            "reason": "pinned_implementation_digest_mismatch",
            "detail": f"pinned={'|'.join(implementation_pins)} attested={entry['implementationHash']}",
        }

    # Step 4. The metadata pin carried by the grant.
    if not defects["skip_metadata_pin"]:
        metadata_pins = pins_under(grant, f"{tool_grant}:meta:")
        current_metadata_digest = metadata_digest(current_metadata)
        if not metadata_pins:
            return {"verdict": "not_established", "reason": "metadata_not_pinned_in_grant", "detail": tool_grant}
        if current_metadata_digest not in metadata_pins:
            return {
                "verdict": "not_established",
                "reason": "pinned_metadata_digest_mismatch",
                "detail": f"pinned={'|'.join(metadata_pins)} current={current_metadata_digest}",
            }

    return {"verdict": "admitted", "reason": "capability_continuity_established"}


REFERENCE = {
    "name": "reference-boundary",
    "defects": {
        "skip_metadata_pin": False,
        "absent_pin_admits": False,
        "skip_running_implementation_check": False,
    },
}

DEFECTIVE = {
    "name": "defective-boundary-trusts-registry-entry-digest",
    "defects": {
        "skip_metadata_pin": True,
        "absent_pin_admits": True,
        "skip_running_implementation_check": True,
    },
}


def matches(actual: dict, expected: dict) -> bool:
    if actual["verdict"] != expected["verdict"]:
        return False
    if actual["reason"] != expected["reason"]:
        return False
    if "detail" in expected and actual.get("detail") != expected["detail"]:
        return False
    return True


for presentation in vectors["presentations"]:
    if presentation.get("status") != "candidate_against_proposed":
        print(f"capability-binding-drift: {presentation['id']} is not labelled candidate_against_proposed", file=sys.stderr)
        sys.exit(2)
    named = presentation.get("tests_proposed_text") or []
    if not named:
        print(f"capability-binding-drift: {presentation['id']} names no proposed text", file=sys.stderr)
        sys.exit(2)
    for key in named:
        if key not in vectors["proposed_text"]:
            print(f"capability-binding-drift: {presentation['id']} names unknown proposed text \"{key}\"", file=sys.stderr)
            sys.exit(2)

reference_results = {p["id"]: admit(p, REFERENCE["defects"]) for p in vectors["presentations"]}
defective_results = {p["id"]: admit(p, DEFECTIVE["defects"]) for p in vectors["presentations"]}

print(f"capability-binding-drift: {len(vectors['presentations'])} presentations, status {vectors['status']} (python)")
print("")
print("boundary: reference-boundary")
reference_matched = 0
for presentation in vectors["presentations"]:
    actual = reference_results[presentation["id"]]
    ok = matches(actual, presentation["expected"])
    if ok:
        reference_matched += 1
    print(f"  {'MATCH' if ok else 'MISMATCH'} {presentation['id']}  verdict={actual['verdict']} reason={actual['reason']}")
    if not ok:
        print(f"    expected: {json.dumps(presentation['expected'], sort_keys=True)}")
        print(f"    actual:   {json.dumps(actual, sort_keys=True)}")

declared_fail_set = set(vectors["declared_defective_fail_set"])
defective_ok = True
print("")
print(f"boundary: {DEFECTIVE['name']}")
for presentation in vectors["presentations"]:
    actual = defective_results[presentation["id"]]
    should_match_expected = presentation["id"] not in declared_fail_set
    actually_matches = matches(actual, presentation["expected"])
    ok = actually_matches if should_match_expected else not actually_matches
    if not ok:
        defective_ok = False
    if should_match_expected:
        label = "MATCH" if ok else "UNDECLARED MISMATCH"
    else:
        label = "DECLARED FAIL" if ok else "DEFECT DID NOT REPRODUCE"
    print(f"  {label} {presentation['id']}  verdict={actual['verdict']} reason={actual['reason']}")

reference_ok = reference_matched == len(vectors["presentations"])

print("")
print(f"reference-boundary matched: {reference_matched}/{len(vectors['presentations'])}")
print(f"{DEFECTIVE['name']} failed exactly the declared set: {defective_ok}")

if reference_ok and defective_ok:
    print("PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)")
    sys.exit(0)

print("FAILED", file=sys.stderr)
sys.exit(1)
