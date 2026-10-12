#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Second Python runner for the approval-authority-expiry family.

A second, separately written implementation of the boundary rules described in
README.md, built from vectors.json and chain.json rather than by porting harness.ts. It
does not import harness.ts and does not import the Python agent_passport SDK. The same
lab wrote both runners, so a run of this one is author-produced, not independent, in
the sense CONTRIBUTING.md defines.

What this runner does NOT do, unlike harness.ts: it does not call verifyReceiptV1 or
verifyAuthorityDelegationChain, so it re-verifies no Ed25519 signature and none of the
chain's structural checks. It reads chain.json's already-minted, already-SDK-verified
record fields (receipt_id, action_ref, issued_at, result.verdict, result.valid_until, and
the delegation's authority.time window) and vectors.json's declared `revocation` ground
truth for each presentation, and applies the half-open [not_before, not_after) rule of
draft-03 section 3.2 to the authority window itself. Agreement between this runner and
verify.ts is agreement on the boundary logic section 4.3 lines 914-918 require, not
independent corroboration of the TypeScript SDK's cryptography.

Run:
    python3 fixtures/approval-authority-expiry/verify.py

Exit 0 when the reference boundary matches every presentation and the defective boundary
fails exactly the declared set, 1 otherwise, and 2 on malformed or inconsistent input
(the same input checks verify.ts makes). Stdlib only. Not part of `npm test`, which
also runs on the Windows job with Node only. CI runs it as
`npm run verify:approval-authority-expiry:py` in the tests workflow's suite job,
the same way it runs fixtures/teardown-accounting/verify.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class ConsumptionBoundary:
    """recheck_authority_at is "consumption" (reference) or "decision_issued_at" (defective)."""

    def __init__(self, name, recheck_authority_at):
        self.name = name
        self.recheck_authority_at = recheck_authority_at
        self.consumed = set()

    def consume(self, decision, requested_action_ref, now, delegation, revocation):
        result = decision["result"]
        if result["verdict"] == "deny":
            return (False, "deny_terminal_not_approval", None)
        if decision["action_ref"] != requested_action_ref:
            return (False, "action_binding_mismatch", None)
        if not now < result["valid_until"]:
            return (False, "expired", None)
        if decision["receipt_id"] in self.consumed:
            return (False, "already_consumed", None)
        self.consumed.add(decision["receipt_id"])

        at = now if self.recheck_authority_at == "consumption" else decision["issued_at"]
        window = delegation["authority"]["time"]
        if at < window["not_before"]:
            return (False, "authority_chain_not_valid_at_consumption", "invalid/NOT_YET_VALID")
        if not at < window["not_after"]:
            return (False, "authority_chain_not_valid_at_consumption", "invalid/EXPIRED")
        if revocation != "active":
            return (False, "authority_chain_not_valid_at_consumption", "invalid/REVOKED")
        return (True, "dispatch_admitted", None)


def matches(actual, expected):
    admitted, reason, detail = actual
    if admitted != expected["admitted"] or reason != expected["reason"]:
        return False
    if "detail" in expected and detail != expected["detail"]:
        return False
    return True


def run(boundary, chain, vectors):
    results = {}
    for p in vectors["presentations"]:
        decision = chain["receipts"][p["decision"]]
        results[p["id"]] = boundary.consume(
            decision,
            chain["actions"][p["requested_action"]]["action_ref"],
            p["now"],
            chain["delegations"][p["chain"]],
            p["revocation"],
        )
    return results


def input_error(message):
    print(f"approval-authority-expiry (python): {message}", file=sys.stderr)
    sys.exit(2)


def check_inputs(chain, vectors):
    """Fail closed on malformed input before any boundary runs, mirroring verify.ts."""
    presentations = vectors.get("presentations")
    if not isinstance(presentations, list) or not presentations:
        input_error("vectors.json has no presentations")
    declared = vectors.get("declared_defective_fail_set")
    if not isinstance(declared, list):
        input_error("vectors.json has no declared_defective_fail_set array")
    ids = [p["id"] for p in presentations]
    if len(set(ids)) != len(ids):
        input_error("vectors.json repeats a presentation id")
    for earlier, later in zip(presentations, presentations[1:]):
        if later["now"] < earlier["now"]:
            input_error(f'{later["id"]} is earlier than the presentation before it')
    for declared_id in declared:
        if declared_id not in ids:
            input_error(f'declared_defective_fail_set names "{declared_id}", which is not presented')
    for p in presentations:
        decision = chain["receipts"].get(p["decision"])
        if decision is None or not p["decision"].startswith("decision_"):
            input_error(f'vectors.json names an unknown decision "{p["decision"]}"')
        delegation = chain["delegations"].get(p["chain"])
        if delegation is None:
            input_error(f'vectors.json names an unknown chain "{p["chain"]}"')
        if p["requested_action"] not in chain["actions"]:
            input_error(f'vectors.json names an unknown action "{p["requested_action"]}"')
        if decision["delegation_ref"] != delegation["delegation_id"]:
            input_error(f'{p["id"]} pairs {p["decision"]} with chain "{p["chain"]}", which its delegation_ref does not name')


def main():
    chain = read_json("chain.json")
    vectors = read_json("vectors.json")
    check_inputs(chain, vectors)
    presentations = vectors["presentations"]

    reference = ConsumptionBoundary("reference-boundary", "consumption")
    defective = ConsumptionBoundary("defective-boundary-authority-time-frozen-at-issuance", "decision_issued_at")
    ref_results = run(reference, chain, vectors)
    def_results = run(defective, chain, vectors)

    print(f"approval-authority-expiry (python): {len(presentations)} presentations")
    print()
    print(f"boundary: {reference.name}")
    ref_matched = 0
    for p in presentations:
        ok = matches(ref_results[p["id"]], p["expected"])
        ref_matched += ok
        admitted, reason, detail = ref_results[p["id"]]
        print(f"  {'MATCH' if ok else 'MISMATCH'} {p['id']}  admitted={str(admitted).lower()} reason={reason}" + (f" detail={detail}" if detail else ""))

    declared = set(vectors["declared_defective_fail_set"])
    defective_ok = len(declared) > 0 and declared <= set(ref_results)
    print()
    print(f"boundary: {defective.name}")
    for p in presentations:
        should_match = p["id"] not in declared
        actually = matches(def_results[p["id"]], p["expected"])
        ok = actually if should_match else not actually
        defective_ok = defective_ok and ok
        if should_match:
            label = "MATCH" if ok else "UNDECLARED MISMATCH"
        else:
            label = "DECLARED FAIL" if ok else "DEFECT DID NOT REPRODUCE"
        admitted, reason, detail = def_results[p["id"]]
        print(f"  {label} {p['id']}  admitted={str(admitted).lower()} reason={reason}" + (f" detail={detail}" if detail else ""))

    print()
    print(f"reference-boundary matched: {ref_matched}/{len(presentations)}")
    print(f"{defective.name} failed exactly the declared set: {str(defective_ok).lower()}")
    if ref_matched == len(presentations) and defective_ok:
        print("PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)")
        return 0
    print("FAILED", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
