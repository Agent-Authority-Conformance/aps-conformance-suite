#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from agent_passport.v2.authority_delegation import verify_authority_delegation_chain


HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chains.json")
vectors = read_json("vectors.json")

if (
    fixture.get("_placeholder")
    or not isinstance(fixture.get("now"), str)
    or not fixture["now"]
    or not isinstance(fixture.get("chains"), dict)
    or "OLD" not in fixture["chains"]
    or "NEW" not in fixture["chains"]
    or "OTHER" not in fixture["chains"]
    or not isinstance(fixture.get("verification_keys"), dict)
    or not fixture["verification_keys"]
    or not isinstance(fixture.get("roles"), dict)
):
    print(
        "sponsor-handover chains.json is still a placeholder or missing chains/roles. "
        "Mint OLD, NEW and OTHER with the SDK and populate now, verification_keys, roles "
        "and chains before running.",
        file=sys.stderr,
    )
    sys.exit(2)


role_by_delegation_id = {}
for role, delegation_id in fixture["roles"].items():
    role_by_delegation_id[delegation_id] = role

for chain_name, chain in fixture["chains"].items():
    for member in chain:
        delegation_id = member.get("delegation_id") if isinstance(member, dict) else None
        if not isinstance(delegation_id, str) or delegation_id not in role_by_delegation_id:
            print(f"sponsor-handover chain {chain_name} has a member with no registered role", file=sys.stderr)
            sys.exit(2)


def resolver_for(spec):
    values = spec["values"]

    def by_role(delegation):
        delegation_id = delegation.get("delegation_id")
        role = role_by_delegation_id.get(delegation_id)
        if role is None or role not in values:
            raise RuntimeError("sponsor-handover resolver received a delegation with no answer for its role")
        return values[role]

    return by_role


def actual_failure(result):
    first = result.failures[0] if result.failures else None
    return {
        "code": first.code if first is not None else None,
        "index": first.index if first is not None else None,
    }


def structural_independence():
    old_ids = {member["delegation_id"] for member in fixture["chains"]["OLD"]}
    shared_id = any(member["delegation_id"] in old_ids for member in fixture["chains"]["NEW"])
    shared_parent = any(
        member.get("parent_delegation_id") is not None and member["parent_delegation_id"] in old_ids
        for member in fixture["chains"]["NEW"]
    )
    ok = not shared_id and not shared_parent
    detail = f"shared_delegation_id={shared_id} new_member_parents_old_member={shared_parent}"
    return ok, detail


passed = 0

for vector in vectors["cases"]:
    resolve_revocation = resolver_for(vector["resolver"])
    results = {}

    for chain_name in vector["available_chains"]:
        results[chain_name] = verify_authority_delegation_chain(
            fixture["chains"][chain_name],
            now=fixture["now"],
            resolve_verification_key=lambda _issuer, verification_method, _issued_at:
                fixture["verification_keys"].get(verification_method),
            trust_root=lambda _root: True,
            resolve_revocation=resolve_revocation,
        )

    ok = True
    details = []

    for chain_name, expected in vector["expected"].items():
        result = results[chain_name]
        failure = actual_failure(result)
        chain_ok = (
            result.state == expected["state"]
            and result.valid == (expected["state"] == "valid")
            and failure["code"] == expected["failure_code"]
            and failure["index"] == expected["failure_index"]
            and (
                expected["failure_code"] is not None
                or len(result.failures) == 0
            )
        )
        ok = ok and chain_ok
        suffix = f"/{failure['code']}@{failure['index']}" if failure["code"] else ""
        details.append(f"{chain_name}={result.state}{suffix}")

    if vector.get("assert_no_valid_chain"):
        any_valid = any(results[name].state == "valid" for name in vector["available_chains"])
        ok = ok and not any_valid
        details.append(f"no_valid_chain={not any_valid}")

    if vector.get("structural_independence_check"):
        structural_ok, structural_detail = structural_independence()
        ok = ok and structural_ok
        details.append(structural_detail)

    if ok:
        passed += 1
        print(f"PASS {vector['id']} {' '.join(details)}")
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print(f"  expected: {json.dumps(vector['expected'], sort_keys=True)}", file=sys.stderr)
        print(f"  actual:   {' '.join(details)}", file=sys.stderr)

print(f"sponsor-handover Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if passed == len(vectors["cases"]) else 1)
