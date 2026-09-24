#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# chain-selection-no-union, Python runner. Independent reimplementation of the
# same four policies verify.ts runs, against the published PyPI
# agent-passport-system. Only the single_chain column is a claim about the SDK:
# it is built out of verify_authority_delegation_chain, is_valid_scope_grant,
# scope_grant_covers and InMemoryAuthorityBudgetLedger on the one chain each
# vector selected. The other three are this fixture's own models of specific
# non-conformant behaviors. See README.md, "Decision policies".
#
# No network. Run from the suite root:
#   /path/to/venv/bin/python fixtures/chain-selection-no-union/validate.py

import hashlib
import json
import sys
from pathlib import Path

from agent_passport.canonical import canonicalize_jcs
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
    or not isinstance(fixture.get("chains"), dict)
    or not fixture["chains"]
    or not isinstance(fixture.get("verification_keys"), dict)
    or not fixture["verification_keys"]
    or not isinstance(fixture.get("canonical_sha256"), dict)
    or not fixture["canonical_sha256"]
    or not isinstance(fixture.get("delegation_ids"), dict)
    or not fixture["delegation_ids"]
):
    print(
        "chain-selection-no-union chains.json is still a placeholder. Mint it with the SDK "
        "and populate now, seeds, verification_keys, chains and delegation_ids before running.",
        file=sys.stderr,
    )
    sys.exit(2)

# Recompute the published RFC 8785 JCS digest of every record before any vector
# is decided, so a verdict is never reported against bytes that drifted from the
# ones mint.py pinned.
for _name, _chain in fixture["chains"].items():
    if len(_chain) != 1:
        print(
            f"chain-selection-no-union: {_name} is {len(_chain)} records, every chain here is one root",
            file=sys.stderr,
        )
        sys.exit(2)
    _digest = hashlib.sha256(canonicalize_jcs(_chain[0]).encode("utf-8")).hexdigest()
    if _digest != fixture["canonical_sha256"][_name]:
        print(
            f"chain-selection-no-union: JCS canonical digest mismatch for {_name}\n"
            f"  declared:   {fixture['canonical_sha256'][_name]}\n"
            f"  recomputed: {_digest}",
            file=sys.stderr,
        )
        sys.exit(2)
print(
    f"chain-selection-no-union: {len(fixture['chains'])} JCS canonical digests recomputed and matched"
)

# Reverse the published name -> delegation id map: the SDK hands the resolver a
# delegation record, not a chain name.
CHAIN_NAME_BY_DELEGATION_ID = {v: k for k, v in fixture["delegation_ids"].items()}


def resolve_verification_key(_issuer, verification_method, _issued_at):
    return fixture["verification_keys"].get(verification_method)


def resolver_for(vector):
    """Fail loud: a vector that forgot to state an answer for a chain it
    presents must not silently read as active."""

    def by_chain_name(delegation):
        name = CHAIN_NAME_BY_DELEGATION_ID.get(delegation.get("delegation_id"))
        if name is None or name not in vector["revocation"]:
            raise RuntimeError(
                "chain-selection-no-union resolver received a delegation with no declared "
                f"answer (vector {vector['id']})"
            )
        return vector["revocation"][name]

    return by_chain_name


def first_failure_code(result):
    return result.failures[0].code if result.failures else None


def action_ref_for(vector_id):
    return hashlib.sha256(vector_id.encode("utf-8")).hexdigest()


def leaf_grants(chain):
    return chain[-1]["authority"]["scope"]["grants"]


def verify_chain(vector, chain_name):
    return verify_authority_delegation_chain(
        fixture["chains"][chain_name],
        now=fixture["now"],
        resolve_verification_key=resolve_verification_key,
        trust_root=lambda _root: True,
        resolve_revocation=resolver_for(vector),
    )


# ---------------------------------------------------------------------------
# Policy 1, single_chain. The conformant one, and the only one below whose
# result is a claim about the SDK.
# ---------------------------------------------------------------------------
def single_chain(vector, chain_name):
    chain = fixture["chains"][chain_name]

    chain_result = verify_chain(vector, chain_name)
    if chain_result.state != "valid":
        return {"state": "invalid", "reason": first_failure_code(chain_result) or chain_result.state}

    grants = leaf_grants(chain)
    covered = all(
        is_valid_scope_grant(needed) and any(scope_grant_covers(grant, needed) for grant in grants)
        for needed in vector["action"]["scope_needed"]
    )
    if not covered:
        return {"state": "invalid", "reason": "scope_not_covered"}

    ledger = InMemoryAuthorityBudgetLedger()
    reservation = ledger.reserve(
        chain,
        action_ref_for(vector["id"]),
        vector["action"]["unit"],
        vector["action"]["amount"],
    )
    return {"state": "valid" if reservation.ok else "invalid", "reason": reservation.code}


# ---------------------------------------------------------------------------
# Policies 2 and 3, the union models. Authored here, not by the SDK: no SDK
# entry point takes more than one chain, so a pooled budget has to be computed
# by this file's own arithmetic. That absence is part of the finding, not a
# workaround. See README.md, "What the SDKs do not support".
# ---------------------------------------------------------------------------
def pooled_grants_and_ceiling(vector):
    grants = []
    ceiling = 0
    any_valid = False
    for name in vector["stored_chains"]:
        if verify_chain(vector, name).state != "valid":
            continue
        any_valid = True
        chain = fixture["chains"][name]
        for grant in leaf_grants(chain):
            if grant not in grants:
                grants.append(grant)
        spend = chain[-1]["authority"]["spend"]
        if spend["mode"] == "bounded" and spend["unit"] == vector["action"]["unit"]:
            ceiling += int(spend["per_action"])
    return (grants, ceiling) if any_valid else None


def union_decision(vector, covers):
    pool = pooled_grants_and_ceiling(vector)
    if pool is None:
        return {"state": "invalid", "reason": "no_valid_chain"}
    grants, ceiling = pool

    covered = all(
        is_valid_scope_grant(needed) and covers(grants, needed)
        for needed in vector["action"]["scope_needed"]
    )
    if not covered:
        return {"state": "invalid", "reason": "scope_not_covered"}

    if int(vector["action"]["amount"]) > ceiling:
        return {"state": "invalid", "reason": "PER_ACTION_EXCEEDED_POOLED"}
    return {"state": "valid", "reason": "RESERVED_POOLED"}


def union_pooled(vector):
    return union_decision(
        vector,
        lambda grants, needed: any(scope_grant_covers(grant, needed) for grant in grants),
    )


def split_grant(grant):
    """Split at the last colon: everything before it is the resource, the final
    segment is the action."""
    resource, _, action = grant.rpartition(":")
    return resource, action


def union_axis(vector):
    def covers(grants, needed):
        resources = {split_grant(grant)[0] for grant in grants}
        actions = {split_grant(grant)[1] for grant in grants}
        want_resource, want_action = split_grant(needed)
        return want_resource in resources and want_action in actions

    return union_decision(vector, covers)


# ---------------------------------------------------------------------------
# Policy 4, silent_fallback. Also authored here. It reports no switch of its
# own: the only way to see the switch is to compare its chosen chain against
# the chain the action selected, which is what this runner asserts.
# ---------------------------------------------------------------------------
def silent_fallback(vector):
    selected = single_chain(vector, vector["selected_chain"])
    if selected["state"] == "valid":
        return {**selected, "chain": vector["selected_chain"], "switched": False}
    for name in vector["stored_chains"]:
        if name == vector["selected_chain"]:
            continue
        other = single_chain(vector, name)
        if other["state"] == "valid":
            return {**other, "chain": name, "switched": True}
    return {**selected, "chain": vector["selected_chain"], "switched": False}


# ---------------------------------------------------------------------------


def same_decision(actual, expected):
    return actual["state"] == expected["state"] and actual["reason"] == expected["reason"]


passed = 0

for vector in vectors["cases"]:
    problems = []

    if vector["status"] != "candidate_against_proposed":
        problems.append(
            f"status is {vector['status']}, every vector in this family is candidate_against_proposed"
        )
    for name in vector["stored_chains"]:
        if name not in fixture["chains"]:
            problems.append(f"no chain named {name} in chains.json")
    if vector["selected_chain"] not in vector["stored_chains"]:
        problems.append(
            f"selected_chain {vector['selected_chain']} is not among stored_chains"
        )

    actual = None
    if not problems:
        actual = {
            "single_chain": single_chain(vector, vector["selected_chain"]),
            "union_pooled": union_pooled(vector),
            "union_axis": union_axis(vector),
            "silent_fallback": silent_fallback(vector),
        }

        for policy in ("single_chain", "union_pooled", "union_axis"):
            if not same_decision(actual[policy], vector["expected"][policy]):
                problems.append(
                    f"{policy}: expected {json.dumps(vector['expected'][policy], sort_keys=True)}, "
                    f"got {json.dumps(actual[policy], sort_keys=True)}"
                )

        fb = actual["silent_fallback"]
        fb_expected = vector["expected"]["silent_fallback"]
        if (
            not same_decision(fb, fb_expected)
            or fb["chain"] != fb_expected["chain"]
            or fb["switched"] != fb_expected["switched"]
        ):
            problems.append(
                f"silent_fallback: expected {json.dumps(fb_expected, sort_keys=True)}, "
                f"got {json.dumps(fb, sort_keys=True)}"
            )
        # The property the L11 vectors turn on: the fallback model reports a
        # valid result only by acting under a chain the action did not select.
        if fb["switched"] != (fb["chain"] != vector["selected_chain"]):
            problems.append(
                f"silent_fallback switched flag {fb['switched']} disagrees with chain "
                f"{fb['chain']} against selected {vector['selected_chain']}"
            )

    if not problems:
        passed += 1
        fb = actual["silent_fallback"]
        print(
            f"PASS {vector['id']} [{','.join(vector['tests'])}] "
            f"single_chain={actual['single_chain']['state']}({actual['single_chain']['reason']}) "
            f"union_pooled={actual['union_pooled']['state']} union_axis={actual['union_axis']['state']} "
            f"silent_fallback={fb['state']} via {fb['chain']}"
            + (" (SWITCHED)" if fb["switched"] else "")
        )
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)

print(f"chain-selection-no-union Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if passed == len(vectors["cases"]) else 1)
