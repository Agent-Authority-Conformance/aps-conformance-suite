#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path

from agent_passport.v2.authority_delegation import (
    InMemoryAuthorityBudgetLedger,
    is_valid_scope_grant,
    scope_grant_covers,
    verify_authority_delegation_chain,
)


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


def action_ref_for(vector_id):
    return hashlib.sha256(vector_id.encode("utf-8")).hexdigest()


def run_primary_path(vector):
    """Decide chain state, scope coverage and spend headroom with the SDK's own
    real primitives, on the one chain the action presents, no synthetic hop
    involved. See the README's "Primary path" section."""
    primary_chain = vector.get("primary_chain")
    if primary_chain is None:
        return None
    chain = fixture[primary_chain]

    chain_result = verify_authority_delegation_chain(
        chain,
        now=fixture["now"],
        resolve_verification_key=lambda _issuer, verification_method, _issued_at:
            fixture["verification_keys"].get(verification_method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: "active",
    )
    if chain_result.state != "valid":
        failure = actual_failure(chain_result)
        return {"state": "invalid", "reason": failure["code"] or chain_result.state}

    leaf_grants = chain[-1]["authority"]["scope"]["grants"]
    needed_grants = vector["action"]["scope_needed"]
    scope_covered = all(
        is_valid_scope_grant(needed) and any(scope_grant_covers(grant, needed) for grant in leaf_grants)
        for needed in needed_grants
    )
    if not scope_covered:
        return {"state": "invalid", "reason": "scope_not_covered"}

    ledger = InMemoryAuthorityBudgetLedger()
    reservation = ledger.reserve(
        chain,
        action_ref_for(vector["id"]),
        vector["action"]["unit"],
        vector["action"]["amount"],
    )
    return {"state": "valid" if reservation.ok else "invalid", "reason": reservation.code}


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

    synthetic_ok = (
        result.state == expected["state"]
        and result.valid == (expected["state"] == "valid")
        and failure["code"] == expected["failure_code"]
        and failure["index"] == expected["failure_index"]
        and (
            expected["failure_code"] is not None
            or len(result.failures) == 0
        )
    )

    primary = run_primary_path(vector)
    primary_expected = vector.get("primary_expected")

    primary_ok = (
        primary is None
        or primary_expected is None
        or (primary["state"] == primary_expected["state"] and primary["reason"] == primary_expected["reason"])
    )

    agreement_ok = primary is None or primary["state"] == result.state

    ok = synthetic_ok and primary_ok and agreement_ok

    if ok:
        passed += 1
        suffix = (
            f" code={failure['code']} index={failure['index']}"
            if failure["code"] is not None
            else ""
        )
        primary_note = f" primary={primary['state']}({primary['reason']})" if primary is not None else ""
        print(f"PASS {vector['id']} state={result.state}{suffix}{primary_note}")
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print(
            "  synthetic expected: " + json.dumps(expected, sort_keys=True),
            file=sys.stderr,
        )
        print(
            "  synthetic actual:   " + json.dumps(
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
        if primary_expected is not None:
            print("  primary expected: " + json.dumps(primary_expected, sort_keys=True), file=sys.stderr)
        if primary is not None:
            print("  primary actual:   " + json.dumps(primary, sort_keys=True), file=sys.stderr)
        if not agreement_ok:
            print(
                f"  primary/synthetic disagreement: primary={primary['state'] if primary else None} synthetic={result.state}",
                file=sys.stderr,
            )

print(f"single-chain-selection Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if passed == len(vectors["cases"]) else 1)
