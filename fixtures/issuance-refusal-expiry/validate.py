#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from agent_passport.v2.authority_delegation import (
    AuthorityDelegationError,
    issue_sub_authority_delegation,
    verify_authority_delegation_chain,
)

HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("fixture.json")
vectors = read_json("vectors.json")

if fixture.get("_placeholder") or not isinstance(fixture.get("chain"), list) or len(fixture["chain"]) != 2:
    print(
        "issuance-refusal-expiry fixture.json is still a placeholder. Run mint.py first.",
        file=sys.stderr,
    )
    sys.exit(2)


def resolve_verification_key(_issuer, verification_method, _issued_at):
    return fixture["verification_keys"].get(verification_method)


passed = 0
total = 0

print("issuance-refusal-expiry Part A: issuance refusal")
for vector in vectors["part_a_issuance"]["cases"]:
    total += 1
    parent = fixture["parent"] if vector["parent"] == "parent" else fixture["parent_signature_tampered"]
    now = fixture["now"][vector["now"]]
    resolver_answer = vector["resolver"]

    try:
        child = issue_sub_authority_delegation(
            parent,
            fixture["child_body"],
            fixture["agent_a_priv"],
            now=now,
            resolve_verification_key=resolve_verification_key,
            resolve_revocation=lambda _delegation: resolver_answer,
        )
        outcome = {"outcome": "issued", "delegation_id": child["delegation_id"]}
    except AuthorityDelegationError as err:
        outcome = {"outcome": "refused", "code": err.code, "message": str(err)}

    expected = vector["expected"]
    ok = outcome["outcome"] == expected["outcome"] and (
        expected["outcome"] == "issued" or outcome.get("code") == expected.get("code")
    )

    if ok:
        passed += 1
        suffix = f" code={outcome['code']}" if outcome["outcome"] == "refused" else ""
        print(f"PASS {vector['id']} outcome={outcome['outcome']}{suffix}")
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print("  expected: " + json.dumps(expected, sort_keys=True), file=sys.stderr)
        print("  actual:   " + json.dumps(outcome, sort_keys=True), file=sys.stderr)


def resolver_for(spec, index_by_id):
    mode = spec["mode"]
    if mode == "constant":
        value = spec.get("value")

        def constant(_delegation):
            return value
        return constant

    if mode == "by_index":
        values = spec["values"]

        def by_index(delegation):
            delegation_id = delegation.get("delegation_id")
            if delegation_id not in index_by_id:
                raise RuntimeError("issuance-refusal-expiry resolver received an unknown delegation")
            return values[index_by_id[delegation_id]]
        return by_index

    raise ValueError(f"unknown issuance-refusal-expiry resolver mode: {mode}")


index_by_id = {delegation["delegation_id"]: index for index, delegation in enumerate(fixture["chain"])}

print()
print("issuance-refusal-expiry Part B: verification codes")
for vector in vectors["part_b_verification"]["cases"]:
    total += 1
    result = verify_authority_delegation_chain(
        fixture["chain"],
        now=fixture["now"][vector["now"]],
        resolve_verification_key=resolve_verification_key,
        trust_root=lambda _root: True,
        resolve_revocation=resolver_for(vector["resolver"], index_by_id),
    )

    first = result.failures[0] if result.failures else None
    failure_code = first.code if first is not None else None
    failure_index = first.index if first is not None else None

    expected = vector["expected"]
    ok = (
        result.state == expected["state"]
        and failure_code == expected["failure_code"]
        and failure_index == expected["failure_index"]
    )

    if ok:
        passed += 1
        suffix = f" code={failure_code} index={failure_index}" if failure_code is not None else ""
        print(f"PASS {vector['id']} state={result.state}{suffix}")
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print("  expected: " + json.dumps(expected, sort_keys=True), file=sys.stderr)
        print(
            "  actual:   "
            + json.dumps(
                {
                    "state": result.state,
                    "failure_code": failure_code,
                    "failure_index": failure_index,
                    "failures": [
                        {"code": item.code, "message": item.message, "index": item.index, "facet": item.facet}
                        for item in result.failures
                    ],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )

print()
print(f"issuance-refusal-expiry Python: {passed}/{total} passed")
sys.exit(0 if passed == total else 1)
