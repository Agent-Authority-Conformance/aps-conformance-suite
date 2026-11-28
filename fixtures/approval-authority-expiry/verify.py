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
chain's structural checks (parent links, issuer continuity, facet narrowing). It reads
chain.json's already-minted, already-SDK-verified record fields (receipt_id, action_ref,
issued_at, result.verdict, result.valid_until, and each chain member's authority.time
window) and vectors.json's declared `revocation` answer for each presentation. It applies
the half-open [not_before, not_after) rule of draft-03 section 3.2 to every member of the
named root-to-leaf chain, then the revocation answer, in the order section 3.3 lists
them. Agreement between this runner and verify.ts is agreement on the boundary logic
section 4.3 lines 914-918 require, not independent corroboration of the TypeScript SDK's
cryptography.

Run:
    python3 fixtures/approval-authority-expiry/verify.py

Exit 0 when the reference boundary matches every presentation and the defective boundary
admits exactly the declared set with reason dispatch_admitted, 1 otherwise, and 2 on
malformed or inconsistent input (the same input checks verify.ts makes). Stdlib only. Not
part of `npm test`, which also runs on the Windows job with Node only. CI runs it as
`npm run verify:approval-authority-expiry:py` in the tests workflow's suite job,
the same way it runs fixtures/teardown-accounting/verify.py.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

PROFILE = "aps-approval-authority-expiry-v0"

# The family's case inventory, in presentation order. AEX-02 and AEX-03 are the controls
# that give the declared failing set its meaning, so a corpus without them is malformed.
REQUIRED_IDS = [
    "AEX-01-accept-authority-valid-at-consumption",
    "AEX-02-reject-authority-revoked-at-consumption",
    "AEX-03-reject-approval-expired",
    "AEX-05-reject-authority-at-exact-not-after",
    "AEX-04-reject-authority-expired-approval-unexpired",
]
REQUIRED_DECLARED = {
    "AEX-04-reject-authority-expired-approval-unexpired",
    "AEX-05-reject-authority-at-exact-not-after",
}

# The declared defect is wrongful admission. A refusal for any other reason is a mismatch.
DECLARED_DEFECT_OUTCOME = (True, "dispatch_admitted", None)

INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class ConsumptionBoundary:
    """recheck_authority_at is "consumption" (reference) or "decision_issued_at" (defective)."""

    def __init__(self, name, recheck_authority_at):
        self.name = name
        self.recheck_authority_at = recheck_authority_at
        self.consumed = set()

    def consume(self, decision, requested_action_ref, now, chain, revocation):
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
        for member in chain:
            window = member["authority"]["time"]
            if at < window["not_before"]:
                return (False, "authority_chain_not_valid_at_consumption", "invalid/NOT_YET_VALID")
            if not at < window["not_after"]:
                return (False, "authority_chain_not_valid_at_consumption", "invalid/EXPIRED")
        if revocation == "revoked":
            return (False, "authority_chain_not_valid_at_consumption", "invalid/REVOKED")
        return (True, "dispatch_admitted", None)


def matches(actual, expected):
    admitted, reason, detail = actual
    if admitted != expected["admitted"] or reason != expected["reason"]:
        return False
    if "detail" in expected and detail != expected["detail"]:
        return False
    return True


def input_error(message):
    print(f"approval-authority-expiry (python): {message}", file=sys.stderr)
    sys.exit(2)


def check_inputs(chain, vectors):
    """Fail closed on malformed input before any boundary runs, mirroring verify.ts.

    Returns the resolved root-to-leaf chain for each chain name the presentations use.
    """
    if not isinstance(chain, dict) or chain.get("profile") != PROFILE:
        input_error(f"chain.json profile is not {PROFILE}")
    if not isinstance(vectors, dict) or vectors.get("profile") != PROFILE:
        input_error(f"vectors.json profile is not {PROFILE}")
    presentations = vectors.get("presentations")
    if not isinstance(presentations, list) or not presentations:
        input_error("vectors.json has no presentations")
    declared = vectors.get("declared_defective_fail_set")
    if not isinstance(declared, list):
        input_error("vectors.json has no declared_defective_fail_set array")
    chains = chain.get("chains")
    if not isinstance(chains, dict):
        input_error("chain.json has no chains map")

    for index, p in enumerate(presentations):
        if not isinstance(p, dict):
            input_error(f"presentation {index} is not an object")
        if not isinstance(p.get("id"), str):
            input_error(f"presentation {index} has no string id")
        pid = p["id"]
        if "differs_from" not in p or not (p["differs_from"] is None or isinstance(p["differs_from"], str)):
            input_error(f"{pid} differs_from is neither null nor a string")
        for field in ("decision", "requested_action", "chain"):
            if not isinstance(p.get(field), str):
                input_error(f"{pid} has no string {field}")
        if not isinstance(p.get("now"), str) or not INSTANT.match(p["now"]):
            input_error(f"{pid} now is not a UTC millisecond instant")
        if p.get("revocation") not in ("active", "revoked"):
            input_error(f'{pid} revocation is neither "active" nor "revoked"')
        expected = p.get("expected")
        if not isinstance(expected, dict):
            input_error(f"{pid} has no expected object")
        if not isinstance(expected.get("admitted"), bool):
            input_error(f"{pid} expected.admitted is not a boolean")
        if not isinstance(expected.get("reason"), str):
            input_error(f"{pid} expected.reason is not a string")
        if "detail" in expected and not isinstance(expected["detail"], str):
            input_error(f"{pid} expected.detail is not a string")

    ids = [p["id"] for p in presentations]
    if ids != REQUIRED_IDS:
        input_error(f"vectors.json presents {ids}, not the required inventory {REQUIRED_IDS}")
    if len(declared) != len(REQUIRED_DECLARED) or set(declared) != REQUIRED_DECLARED:
        input_error(f"declared_defective_fail_set is not exactly {sorted(REQUIRED_DECLARED)}")
    for earlier, later in zip(presentations, presentations[1:]):
        if later["now"] < earlier["now"]:
            input_error(f'{later["id"]} is earlier than the presentation before it')

    resolved = {}
    for p in presentations:
        decision = chain["receipts"].get(p["decision"])
        if decision is None or not p["decision"].startswith("decision_"):
            input_error(f'vectors.json names an unknown decision "{p["decision"]}"')
        member_names = chains.get(p["chain"])
        if not isinstance(member_names, list) or not member_names:
            input_error(f'vectors.json names an unknown chain "{p["chain"]}"')
        members = []
        for name in member_names:
            delegation = chain["delegations"].get(name) if isinstance(name, str) else None
            if delegation is None:
                input_error(f'chain "{p["chain"]}" names an unknown delegation "{name}"')
            members.append(delegation)
        if p["requested_action"] not in chain["actions"]:
            input_error(f'vectors.json names an unknown action "{p["requested_action"]}"')
        if decision["delegation_ref"] != members[-1]["delegation_id"]:
            input_error(f'{p["id"]} pairs {p["decision"]} with chain "{p["chain"]}", whose leaf its delegation_ref does not name')
        evidence = chain.get("decision_evidence", {}).get(p["decision"], {})
        selected = evidence.get("authority_state", {}).get("selected_chain")
        if selected != [m["delegation_id"] for m in members]:
            input_error(f'{p["id"]} chain "{p["chain"]}" is not {p["decision"]}\'s selected_chain')
        resolved[p["chain"]] = members
    return resolved


def run(boundary, chain, vectors, resolved):
    results = {}
    for p in vectors["presentations"]:
        decision = chain["receipts"][p["decision"]]
        results[p["id"]] = boundary.consume(
            decision,
            chain["actions"][p["requested_action"]]["action_ref"],
            p["now"],
            resolved[p["chain"]],
            p["revocation"],
        )
    return results


def fmt(actual):
    admitted, reason, detail = actual
    return f"admitted={str(admitted).lower()} reason={reason}" + (f" detail={detail}" if detail else "")


def main():
    chain = read_json("chain.json")
    vectors = read_json("vectors.json")
    resolved = check_inputs(chain, vectors)
    presentations = vectors["presentations"]

    reference = ConsumptionBoundary("reference-boundary", "consumption")
    defective = ConsumptionBoundary("defective-boundary-authority-time-frozen-at-issuance", "decision_issued_at")
    ref_results = run(reference, chain, vectors, resolved)
    def_results = run(defective, chain, vectors, resolved)

    print(f"approval-authority-expiry (python): {len(presentations)} presentations")
    print()
    print(f"boundary: {reference.name}")
    ref_matched = 0
    for p in presentations:
        ok = matches(ref_results[p["id"]], p["expected"])
        ref_matched += ok
        print(f"  {'MATCH' if ok else 'MISMATCH'} {p['id']}  {fmt(ref_results[p['id']])}")

    declared = set(vectors["declared_defective_fail_set"])
    defective_ok = True
    print()
    print(f"boundary: {defective.name}")
    for p in presentations:
        actual = def_results[p["id"]]
        if p["id"] in declared:
            ok = actual == DECLARED_DEFECT_OUTCOME
            label = "DECLARED FAIL" if ok else "DEFECT DID NOT REPRODUCE"
        else:
            ok = matches(actual, p["expected"])
            label = "MATCH" if ok else "UNDECLARED MISMATCH"
        defective_ok = defective_ok and ok
        print(f"  {label} {p['id']}  {fmt(actual)}")

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
