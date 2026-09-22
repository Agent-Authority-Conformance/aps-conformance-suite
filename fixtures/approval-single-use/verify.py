#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Independent Python runner for the approval-single-use family.

This is a second, independently written implementation of the boundary rules described in
README.md and harness.ts's own comments, built from vectors.json and chain.json rather
than by porting harness.ts. It does not import harness.ts and does not import the Python
agent_passport SDK.

What this runner does NOT do, unlike harness.ts: it does not call verifyReceiptV1 or
verifyAuthorityDelegationChain, so it does not re-verify any Ed25519 signature and does
not re-derive the authority chain's own temporal or revocation state from first
principles. It reads chain.json's already-minted, already-SDK-verified record fields
(receipt_id, action_ref, result.verdict, result.valid_until) and vectors.json's declared
`revocation` ground truth for each presentation, the same way harness.ts's injected
resolveRevocation callback does, and applies the same single-use, expiry, binding and
deny-terminal rules an independent read of draft-03 section 5.3.2 lines 1093-1099
produces. Agreement between this runner and verify.ts is agreement on the boundary logic
those lines require, not independent corroboration of the TypeScript SDK's cryptography.

Run:
    python3 fixtures/approval-single-use/verify.py

Exit 0 when the reference boundary matches every presentation and the defective boundary
fails exactly the declared set, 1 otherwise. No third-party dependency, stdlib only. This
is a manual run, not part of `npm test`, the same convention
fixtures/runtime-authority-denial-continuity's verify.py and fixtures/ancestor-revocation-
chain's validate.py already follow for a Python side that stays out of the hermetic
Node-only CI gate.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


@dataclass
class Outcome:
    admitted: bool
    reason: str
    detail: str | None = None

    def as_tuple(self) -> tuple[bool, str, str | None]:
        return (self.admitted, self.reason, self.detail)


class DispatchBoundary:
    """Independently written twin of harness.ts's DispatchBoundary.

    consumes_receipt_ids and rechecks_revocation are the same two declared flaws
    verify.ts's defective boundary carries. Step 0 (signature/shape) is not reproduced
    here; see module docstring.
    """

    def __init__(self, name: str, consumes_receipt_ids: bool, rechecks_revocation: bool) -> None:
        self.name = name
        self.consumes_receipt_ids = consumes_receipt_ids
        self.rechecks_revocation = rechecks_revocation
        self._consumed: set[str] = set()

    def consume(self, decision: dict[str, Any], requested_action_ref: str, now: str, revocation: str) -> Outcome:
        result = decision["result"]

        # Step 1: line 1098, a deny is terminal and MUST NOT be consumed as an approval.
        if result["verdict"] == "deny":
            return Outcome(False, "deny_terminal_not_approval")

        # Step 2: line 1093, the approval is bound to its action_ref.
        if decision["action_ref"] != requested_action_ref:
            return Outcome(False, "action_binding_mismatch")

        # Step 3: line 1095, verify it has not expired. valid_until is never null here,
        # since verdict is permit or narrow (section 5.3.2 lines 1090-1091).
        valid_until = result["valid_until"]
        if not (now < valid_until):
            return Outcome(False, "expired")

        # Step 4, reference boundary only: line 1095-1096, atomically consume receipt_id.
        if self.consumes_receipt_ids:
            receipt_id = decision["receipt_id"]
            if receipt_id in self._consumed:
                return Outcome(False, "already_consumed")
            self._consumed.add(receipt_id)

        # Step 5, reference boundary only: line 1096, recheck revocation state. This
        # runner takes the presentation's declared ground truth rather than recomputing
        # it from the authority chain; see module docstring.
        if self.rechecks_revocation:
            if revocation != "active":
                return Outcome(False, "authority_chain_not_valid_at_consumption", "invalid/REVOKED")

        # Step 6: line 1097, complete any spend reservation. Not modeled; see README
        # "Does not claim".

        return Outcome(True, "dispatch_admitted")


def read_json(name: str) -> Any:
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def run_boundary(boundary: DispatchBoundary, fixture: dict[str, Any], vectors: dict[str, Any]) -> dict[str, Outcome]:
    results: dict[str, Outcome] = {}
    for presentation in vectors["presentations"]:
        decision = fixture["receipts"][presentation["decision"]]
        requested_action_ref = fixture["actions"][presentation["requested_action"]]["action_ref"]
        outcome = boundary.consume(
            decision,
            requested_action_ref,
            presentation["now"],
            presentation["revocation"],
        )
        results[presentation["id"]] = outcome
    return results


def expected_matches(actual: Outcome, expected: dict[str, Any]) -> bool:
    if actual.admitted != expected["admitted"]:
        return False
    if actual.reason != expected["reason"]:
        return False
    if "detail" in expected and actual.detail != expected["detail"]:
        return False
    return True


def main() -> int:
    fixture = read_json("chain.json")
    vectors = read_json("vectors.json")

    reference = DispatchBoundary("reference-boundary", consumes_receipt_ids=True, rechecks_revocation=True)
    defective = DispatchBoundary("defective-boundary-never-consumes-never-rechecks", consumes_receipt_ids=False, rechecks_revocation=False)

    reference_results = run_boundary(reference, fixture, vectors)
    defective_results = run_boundary(defective, fixture, vectors)

    declared_fail_set = set(vectors["declared_defective_fail_set"])

    print(f"approval-single-use: {len(vectors['presentations'])} presentations (python)")
    print()
    print("boundary: reference-boundary")
    reference_matched = 0
    for presentation in vectors["presentations"]:
        actual = reference_results[presentation["id"]]
        ok = expected_matches(actual, presentation["expected"])
        if ok:
            reference_matched += 1
        status = "PASS" if ok else "FAIL"
        print(f"  {status} {presentation['id']}  admitted={actual.admitted} reason={actual.reason}")

    print()
    print(f"boundary: {defective.name}")
    defective_ok = True
    for presentation in vectors["presentations"]:
        actual = defective_results[presentation["id"]]
        should_match_expected = presentation["id"] not in declared_fail_set
        actually_matches = expected_matches(actual, presentation["expected"])
        ok = actually_matches if should_match_expected else not actually_matches
        if not ok:
            defective_ok = False
        print(f"  {'ok' if ok else 'FAIL'} {presentation['id']}  admitted={actual.admitted} reason={actual.reason}")

    reference_ok = reference_matched == len(vectors["presentations"])

    print()
    print(f"reference-boundary matched: {reference_matched}/{len(vectors['presentations'])} (python)")
    print(f"{defective.name} failed exactly the declared set: {defective_ok} (python)")

    if reference_ok and defective_ok:
        print("PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)")
        return 0
    print("FAILED (python)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
