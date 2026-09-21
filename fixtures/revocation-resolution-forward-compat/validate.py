#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from agent_passport.v2.authority_delegation import verify_authority_delegation_chain


HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")

if (
    fixture.get("_placeholder")
    or not isinstance(fixture.get("now"), str)
    or not fixture["now"]
    or not isinstance(fixture.get("chain"), list)
    or len(fixture["chain"]) != 2
    or not isinstance(fixture.get("verification_keys"), dict)
    or not fixture["verification_keys"]
):
    print(
        "C19 chain.json is still a placeholder. Mint a valid two-member root->child "
        "chain with the SDK and populate now, verification_keys, and chain before running.",
        file=sys.stderr,
    )
    sys.exit(2)


index_by_id = {}
for index, delegation in enumerate(fixture["chain"]):
    delegation_id = delegation.get("delegation_id") if isinstance(delegation, dict) else None
    if not isinstance(delegation_id, str):
        print(f"C19 chain member {index} has no delegation_id", file=sys.stderr)
        sys.exit(2)
    index_by_id[delegation_id] = index


def resolver_for(spec):
    mode = spec["mode"]

    if mode == "throw":
        def throwing(_delegation):
            raise RuntimeError("C19 synthetic resolver failure")
        return throwing

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
                raise RuntimeError("C19 resolver received an unknown delegation")
            return values[index_by_id[delegation_id]]
        return by_index

    raise ValueError(f"unknown C19 resolver mode: {mode}")


def actual_failure(result):
    first = result.failures[0] if result.failures else None
    return {
        "code": first.code if first is not None else None,
        "index": first.index if first is not None else None,
    }


passed = 0

for vector in vectors["cases"]:
    result = verify_authority_delegation_chain(
        fixture["chain"],
        now=fixture["now"],
        resolve_verification_key=lambda _issuer, verification_method, _issued_at:
            fixture["verification_keys"].get(verification_method),
        trust_root=lambda _root: True,
        resolve_revocation=resolver_for(vector["resolver"]),
    )

    failure = actual_failure(result)
    expected = vector["expected"]

    ok = (
        result.state == expected["state"]
        and result.valid == (expected["state"] == "valid")
        and failure["code"] == expected["failure_code"]
        and failure["index"] == expected["failure_index"]
        and (
            expected["failure_code"] is not None
            or len(result.failures) == 0
        )
    )

    if ok:
        passed += 1
        suffix = (
            f" code={failure['code']} index={failure['index']}"
            if failure["code"] is not None
            else ""
        )
        print(f"PASS {vector['id']} state={result.state}{suffix}")
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print(
            "  expected: " + json.dumps(expected, sort_keys=True),
            file=sys.stderr,
        )
        print(
            "  actual:   " + json.dumps(
                {
                    "state": result.state,
                    "valid": result.valid,
                    "failure_code": failure["code"],
                    "failure_index": failure["index"],
                    "failures": [
                        {
                            "code": item.code,
                            "message": item.message,
                            "index": item.index,
                            "facet": item.facet,
                        }
                        for item in result.failures
                    ],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )

print(f"C19 Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if passed == len(vectors["cases"]) else 1)
