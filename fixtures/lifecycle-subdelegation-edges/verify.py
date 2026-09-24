#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-subdelegation-edges candidate family.
#
# It is a mirror of verify.ts, not a port of its output: the three policies are
# implemented again here against the Python SDK, and the record digests are
# recomputed from RFC 8785 canonical bytes rather than read from the
# TypeScript run. A divergence between the two runners is therefore a real
# divergence between two implementations.
#
# Exit 0 when every vector matches under every declared policy, 1 on a
# mismatch, 2 when the fixture is not minted.

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agent_passport.v2.authority_delegation import (
    verify_authority_delegation_chain,
    verify_authority_delegation_signature,
)

HERE = Path(__file__).resolve().parent

POLICIES = ("reference", "per-artifact-only", "issuer-attestation-trusting")


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def canonicalize_jcs(value) -> str:
    """RFC 8785 JSON Canonicalization Scheme, for the value shapes this family
    writes: objects, strings, integers, booleans and null. Object members are
    serialized in code-point order of their keys."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: [ord(ch) for ch in kv[0]])
        return "{" + ",".join(
            f"{canonicalize_jcs(key)}:{canonicalize_jcs(item)}" for key, item in members
        ) + "}"
    raise TypeError(f"canonicalize_jcs does not handle {type(value).__name__}")


fixture = read_json("chains.json")
vectors = read_json("vectors.json")

if (
    fixture.get("_placeholder")
    or not isinstance(fixture.get("mint_now"), str)
    or len(fixture.get("chains") or {}) != 6
    or not fixture.get("verification_keys")
    or not fixture.get("roles")
    or not fixture.get("refusals")
):
    print(
        "lifecycle-subdelegation-edges chains.json is not minted. Run "
        "python3 fixtures/lifecycle-subdelegation-edges/mint.py first.",
        file=sys.stderr,
    )
    sys.exit(2)

ROLE_BY_ID = {delegation_id: role for role, delegation_id in fixture["roles"].items()}
OBSERVATION = fixture["issuer_observation_p9"]


def answer_function(revocation):
    def answer(delegation):
        role = ROLE_BY_ID.get(delegation.get("delegation_id"))
        if role is None:
            raise RuntimeError(
                "subdelegation-edges resolver received a delegation with no registered role"
            )
        return revocation.get(role, "active")

    return answer


def reference_policy(chain_name, now, answer):
    result = verify_authority_delegation_chain(
        fixture["chains"][chain_name],
        now=now,
        resolve_verification_key=lambda _issuer, method, _issued_at:
            fixture["verification_keys"].get(method),
        trust_root=lambda _root: True,
        resolve_revocation=answer,
    )
    first = result.failures[0] if result.failures else None
    verdict = {
        "valid": "valid",
        "indeterminate": "not established",
    }.get(result.state, "invalid")
    return {
        "authority_verdict": verdict,
        "failure_code": first.code if first is not None else None,
        "failure_index": first.index if first is not None else None,
    }


def per_artifact_only_policy(chain_name, now, answer):
    """Each presented record checked on its own, no two records compared.

    The three checks are the per-certificate checks a widely used base path
    algorithm specifies (see README, Sources): the signature verifies under the
    resolved key, the record's own validity period includes the verification
    instant, and the record is not revoked at that instant. No parent linkage
    check, no facet comparison, no depth accounting.
    """
    chain = fixture["chains"][chain_name]
    for index, record in enumerate(chain):
        key = fixture["verification_keys"].get(record["verification_method"])
        if not isinstance(key, str) or not verify_authority_delegation_signature(record, key):
            return {"authority_verdict": "invalid", "failure_code": "SIGNATURE_INVALID", "failure_index": index}
        time_facet = record["authority"]["time"]
        if now < time_facet["not_before"]:
            return {"authority_verdict": "invalid", "failure_code": "NOT_YET_VALID", "failure_index": index}
        if now > time_facet["not_after"]:
            return {"authority_verdict": "invalid", "failure_code": "EXPIRED", "failure_index": index}
        state = answer(record)
        if state == "revoked":
            return {"authority_verdict": "invalid", "failure_code": "REVOKED", "failure_index": index}
        if state != "active":
            return {"authority_verdict": "not established", "failure_code": "REVOCATION_UNKNOWN", "failure_index": index}
    return {"authority_verdict": "valid", "failure_code": None, "failure_index": None}


def run_policy(policy, chain_name, now, revocation):
    declared = answer_function(revocation)
    if policy == "reference":
        return reference_policy(chain_name, now, declared)
    if policy == "per-artifact-only":
        return per_artifact_only_policy(chain_name, now, declared)

    def trusting(delegation):
        if delegation.get("delegation_id") == OBSERVATION["about_delegation_id"]:
            return OBSERVATION["answer"]
        return declared(delegation)

    return reference_policy(chain_name, now, trusting)


def write_record(vector_id, boundary_at, chain_name, outcome, prior_sha256):
    return {
        "record_type": "aac:subdelegation-edge-observation:v0",
        "vector_id": vector_id,
        "boundary_at": boundary_at,
        "chain": chain_name,
        "authority_verdict": outcome["authority_verdict"],
        "failure_code": outcome["failure_code"],
        "failure_index": outcome["failure_index"],
        "prior_record_sha256": prior_sha256,
    }


def record_digest(record) -> str:
    return hashlib.sha256(canonicalize_jcs(record).encode("utf-8")).hexdigest()


records = {}
digests = {}
passed = 0
failed = 0

for vector in vectors["cases"]:
    details = []
    ok = True

    if vector["kind"] == "issuance":
        refusal = fixture["refusals"].get(vector["refusal"])
        ok = (
            refusal is not None
            and refusal["raised"] == vector["expected"]["raised"]
            and refusal["code"] == vector["expected"]["code"]
        )
        details.append(f"raised={refusal and refusal['raised']} code={refusal and refusal['code']}")

    elif vector["kind"] == "record-continuity":
        earlier = records.get(vector["earlier"])
        later = records.get(vector["later"])
        if earlier is None or later is None:
            ok = False
            details.append("a referenced record was never emitted")
        else:
            earlier_now = record_digest(earlier)
            earlier_then = digests[vector["earlier"]]
            later_digest = record_digest(later)
            expected = vector["expected"]
            ok = (
                earlier_now == earlier_then
                and later["prior_record_sha256"] == earlier_then
                and expected["earlier_record_rewritten"] is False
                and expected["earlier_record_sha256"] == earlier_then
                and expected["later_record_prior_sha256"] == earlier_then
                and expected["later_record_sha256"] == later_digest
            )
            details.append(
                f"earlier={earlier_then[:16]} later.prior={str(later['prior_record_sha256'])[:16]}"
            )

    else:
        for policy in POLICIES:
            outcome = run_policy(policy, vector["chain"], vector["now"], vector.get("revocation") or {})
            suffix = (
                f"/{outcome['failure_code']}@{outcome['failure_index']}"
                if outcome["failure_code"]
                else ""
            )
            if policy == "reference":
                expected = vector["expected"]
                matches = (
                    outcome["authority_verdict"] == expected["authority_verdict"]
                    and outcome["failure_code"] == expected["failure_code"]
                    and outcome["failure_index"] == expected["failure_index"]
                )
                ok = ok and matches
                details.append(f"reference={outcome['authority_verdict']}{suffix}")
                if vector.get("emits_record"):
                    prior = digests.get(vector["prior_record_of"]) if vector.get("prior_record_of") else None
                    record = write_record(vector["id"], vector["now"], vector["chain"], outcome, prior)
                    records[vector["id"]] = record
                    digests[vector["id"]] = record_digest(record)
            else:
                declared = (vector.get("policy_expected") or {}).get(policy)
                if declared is None:
                    ok = False
                    details.append(f"{policy}=undeclared")
                    continue
                expected = vector["expected"]
                reached_reference = (
                    outcome["authority_verdict"] == expected["authority_verdict"]
                    and outcome["failure_code"] == expected["failure_code"]
                    and outcome["failure_index"] == expected["failure_index"]
                )
                matches = (
                    outcome["authority_verdict"] == declared["authority_verdict"]
                    and outcome["failure_code"] == declared["failure_code"]
                    and outcome["failure_index"] == declared["failure_index"]
                    and declared["agrees"] == reached_reference
                )
                ok = ok and matches
                details.append(f"{policy}={outcome['authority_verdict']}{suffix}(agrees={declared['agrees']})")

        if vector.get("negative_control"):
            in_a_fail_set = any(
                vector["id"] in ids for ids in vectors["declared_fail_sets"].values()
            )
            someone_disagrees = any(
                entry["agrees"] is False for entry in (vector.get("policy_expected") or {}).values()
            )
            ok = ok and in_a_fail_set and someone_disagrees
            details.append(f"negative_control={in_a_fail_set and someone_disagrees}")

    if ok:
        passed += 1
        print(f"PASS {vector['id']} {' '.join(details)}")
    else:
        failed += 1
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print(f"  expected: {json.dumps(vector['expected'], sort_keys=True)}", file=sys.stderr)
        print(f"  actual:   {' '.join(details)}", file=sys.stderr)

all_ids = {case["id"] for case in vectors["cases"]}
for policy, ids in vectors["declared_fail_sets"].items():
    for vector_id in ids:
        if vector_id not in all_ids:
            print(f"FAIL declared_fail_sets.{policy} names an unknown vector {vector_id}", file=sys.stderr)
            failed += 1

print(f"lifecycle-subdelegation-edges Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if failed == 0 else 1)
