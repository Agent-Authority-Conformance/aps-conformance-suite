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
    or not isinstance(fixture.get("chain_1"), list)
    or not isinstance(fixture.get("chain_2"), list)
    or not isinstance(fixture.get("verification_keys"), dict)
    or not fixture["verification_keys"]
    or not isinstance(fixture.get("presented"), dict)
    or not fixture["presented"]
):
    print(
        "single-chain-selection chains.json is still a placeholder. Mint it with the SDK "
        "and populate now, verification_keys, chain_1, chain_2 and presented before running.",
        file=sys.stderr,
    )
    sys.exit(2)


def actual_failure(result):
    first = result.failures[0] if result.failures else None
    return {
        "code": first.code if first is not None else None,
        "index": first.index if first is not None else None,
    }


passed = 0

for vector in vectors["cases"]:
    presented_chain = fixture["presented"].get(vector["presented_chain"])
    if presented_chain is None:
        print(
            f"FAIL {vector['id']}: no presented chain named {vector['presented_chain']} in chains.json",
            file=sys.stderr,
        )
        continue

    result = verify_authority_delegation_chain(
        presented_chain,
        now=fixture["now"],
        resolve_verification_key=lambda _issuer, verification_method, _issued_at:
            fixture["verification_keys"].get(verification_method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: "active",
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

print(f"single-chain-selection Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if passed == len(vectors["cases"]) else 1)
