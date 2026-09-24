#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python reference-SDK runner for the lifecycle-purpose-exhaustion family.

Runs all twenty-one vectors, both tracks, over the same record bytes verify.ts runs, with
the PyPI SDK (`agent-passport-system`, pinned 4.1.0) rather than the npm one. For every
step where the Python SDK exposes an API it calls that API rather than reimplementing the
check:

    agent_passport.verify_authority_delegation_chain     chain state, both tracks
    agent_passport.receipt_core.verify_receipt_v1        a completion record's signature,
                                                         stage validity and the
                                                         enforcement-boundary identity axis
    agent_passport.InMemoryAuthorityBudgetLedger         budget reserve, dispatch, commit
    agent_passport.verify, agent_passport.canonicalize_jcs
                                                         the principal's signature over the
                                                         purpose bound

Steps with no Python SDK API are recorded as not_supported rather than faked:

    purpose membership       the TypeScript SDK exports isPurposePermitted. The Python SDK
                             exports no equivalent under any module. This runner applies
                             the same hierarchical-prefix rule itself and labels it.
    purpose, use-count,      neither SDK exposes an exhaustion API of any kind. Supplied by
    single-use and notch     this runner, the same way harness.ts supplies it on the
    exhaustion               TypeScript side.

The support table is printed at the end of every run, so the record of what came from an
SDK and what did not is produced by the run rather than written by hand.

The single-use boundary is implemented again here against the Python SDK rather than
ported from the TypeScript run, so a divergence between the two runners is a real
divergence between two implementations.

Run, with the pinned SDK installed into a virtual environment:

    python3 -m venv /tmp/aac-work/pyenv
    /tmp/aac-work/pyenv/bin/pip install agent-passport-system==4.1.0
    /tmp/aac-work/pyenv/bin/python fixtures/lifecycle-purpose-exhaustion/verify.py

Exit 0 when both reference boundaries match every event in their track and every defective
policy diverges on exactly its declared set, 1 otherwise, 2 on a malformed fixture. No
network. This is a manual run and not part of `npm test`, the same convention
fixtures/lifecycle-subdelegation-edges/verify.py and
fixtures/runtime-authority-denial-continuity/verify.py already follow for a Python side
kept out of the hermetic Node-only CI gate.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    import agent_passport as ap
    from agent_passport import receipt_core
except ImportError:  # pragma: no cover - environment problem, not a fixture problem
    print("verify.py: agent-passport-system is not installed in this interpreter")
    print("  python3 -m venv <venv> && <venv>/bin/pip install agent-passport-system==4.1.0")
    sys.exit(2)

HERE = Path(__file__).resolve().parent

# Kept byte for byte identical to harness.ts's exported constants. The two runners compare
# the same strings, so a drift between them is a test failure and not a formatting choice.
BASIS_FULFILLMENT_RECORD = "an authenticated fulfillment record from a party with standing"
BASIS_ADMISSION = "the admission itself"
BASIS_BUDGET_LEDGER = "the SDK budget ledger"

SDK_SUPPORT: dict[str, str] = {}


def record_support(concept: str, verdict: str) -> None:
    SDK_SUPPORT[concept] = verdict


def read_json(name: str) -> Any:
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Purpose membership. The one check the TypeScript SDK supplies and this one does not.
# ---------------------------------------------------------------------------


def is_purpose_permitted(requested: str, allowed: list[str]) -> bool:
    """Hierarchical prefix membership, matching the TypeScript SDK's documented rule.

    The TypeScript SDK's isPurposePermitted documents: "Supports wildcard matching:
    'research:*' permits 'research:academic'. Supports exact matching:
    'research:academic' only permits that exact purpose." The Python SDK exports no
    equivalent under any module, so this runner applies the same rule and records the
    step as not_supported. It is not an SDK result and the support table says so.
    """
    for entry in allowed:
        if entry == requested or entry == "*":
            return True
        if entry.endswith(":*") and (requested == entry[:-2] or requested.startswith(entry[:-1])):
            return True
    return False


# ---------------------------------------------------------------------------
# Track 1: bounds. Purpose, use count and budget, over records-bounds.json.
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    outcome: str
    reason: str
    bound_state: str
    exhaustion_basis: str | None
    chain_state: str | None
    detail: str | None = None

    def render(self) -> str:
        basis = "null" if self.exhaustion_basis is None else f'"{self.exhaustion_basis}"'
        base = (
            f"outcome={self.outcome} reason={self.reason} bound_state={self.bound_state} "
            f"basis={basis} chain_state={self.chain_state}"
        )
        return base if self.detail is None else f"{base} detail={self.detail}"


@dataclass
class BoundsBoundary:
    """The same three configurations verify.ts runs, with the same two declared flaws."""

    name: str
    enforces_bound_exhaustion: bool
    authenticates_completion_records: bool
    fixture: dict[str, Any]
    fulfilled: set[str] = field(default_factory=set)
    unestablished: set[str] = field(default_factory=set)
    uses: dict[str, int] = field(default_factory=dict)
    ledger: Any = field(default_factory=lambda: ap.InMemoryAuthorityBudgetLedger())

    # -- key resolution -----------------------------------------------------

    def resolve_receipt_key(self, signer: str, key_id: str, *args: Any, **kwargs: Any) -> str | None:
        return self.fixture["verification_keys"].get(key_id)

    def resolve_delegation_key(self, issuer: str, method: str, *args: Any, **kwargs: Any) -> str | None:
        return self.fixture["verification_keys"].get(method)

    # -- state --------------------------------------------------------------

    def bound_state(self, grant_key: str) -> str:
        # An established exhaustion is never downgraded by a later claim nobody could
        # authenticate. A later finding is a new record about an old one, never a rewrite.
        if grant_key in self.fulfilled:
            return "exhausted"
        if grant_key in self.unestablished:
            return "not_established"
        bound = self.fixture["purpose_bounds"][grant_key]["bound"]
        if bound["mode"] == "use_count":
            return "exhausted" if self.uses.get(grant_key, 0) >= bound["limit"] else "not_reached"
        if bound["mode"] == "budget":
            counter = self.ledger.counter(self.fixture["grants"][grant_key]["delegation_id"])
            used = int(counter["committed"]) + int(counter["reserved"])
            return "exhausted" if used >= int(bound["cumulative"]) else "not_reached"
        return "not_reached"

    def bound_basis(self, grant_key: str) -> str | None:
        """What the reported state turns on. Null for a state nobody could establish."""
        if grant_key in self.fulfilled:
            return BASIS_FULFILLMENT_RECORD
        if grant_key in self.unestablished:
            return None
        bound = self.fixture["purpose_bounds"][grant_key]["bound"]
        if bound["mode"] == "use_count":
            return BASIS_ADMISSION if self.uses.get(grant_key, 0) >= bound["limit"] else None
        if bound["mode"] == "budget":
            counter = self.ledger.counter(self.fixture["grants"][grant_key]["delegation_id"])
            used = int(counter["committed"]) + int(counter["reserved"])
            return BASIS_BUDGET_LEDGER if used >= int(bound["cumulative"]) else None
        return None

    # -- purpose bound ------------------------------------------------------

    def purpose_bound_authentic(self, grant_key: str) -> bool:
        bound = dict(self.fixture["purpose_bounds"][grant_key])
        signature = bound.pop("signature")
        payload = f"{self.fixture['purpose_bound_signature_domain']} {ap.canonicalize_jcs(bound)}"
        public_key = self.fixture["verification_keys"][bound["verification_method"]]
        record_support("purpose bound signature (agent_passport.verify, canonicalize_jcs)", "supported")
        return bool(ap.verify(payload, signature, public_key))

    # -- events -------------------------------------------------------------

    def handle(self, event: dict[str, Any]) -> Outcome:
        return self.present(event) if event["kind"] == "present" else self.observe(event)

    def present(self, event: dict[str, Any]) -> Outcome:
        grant_key = event["grant"]
        grant = self.fixture["grants"][grant_key]
        bound = self.fixture["purpose_bounds"][grant_key]["bound"]
        state_before = self.bound_state(grant_key)
        basis_before = self.bound_basis(grant_key)

        # Step 0: the grant's own chain state, from the Python SDK.
        record_support("chain state (verify_authority_delegation_chain)", "supported")
        chain_result = ap.verify_authority_delegation_chain(
            [grant],
            now=event["now"],
            resolve_verification_key=self.resolve_delegation_key,
            trust_root=lambda _root: True,
            resolve_revocation=lambda _d: event.get("revocation", "active"),
        )
        if chain_result.state != "valid":
            failures = list(chain_result.failures)
            detail = f"{chain_result.state}/{failures[0].code}" if failures else chain_result.state
            return Outcome("not_admitted", "grant_chain_not_valid", state_before, basis_before, chain_result.state, detail)

        # Step 1: purpose membership. No Python SDK API. See is_purpose_permitted above.
        record_support("purpose membership (no Python SDK API)", "not_supported")
        if not is_purpose_permitted(self.fixture["purpose"], grant["authority"]["scope"]["grants"]):
            return Outcome("not_admitted", "purpose_not_in_grant", state_before, basis_before, chain_result.state)

        # Step 2: the purpose bound is principal-signed, so its signature comes first.
        if not self.purpose_bound_authentic(grant_key):
            return Outcome("not_admitted", "purpose_bound_not_authentic", state_before, basis_before, chain_result.state, "signature_did_not_verify")

        if self.enforces_bound_exhaustion:
            if state_before == "not_established":
                return Outcome("not_admitted", "bound_state_not_established", state_before, basis_before, chain_result.state)

            # Step 4: budget, from the Python SDK's own ledger, before this runner's
            # bookkeeping gets a vote. The denial detail is the SDK's own code.
            if bound["mode"] == "budget":
                record_support("budget exhaustion (InMemoryAuthorityBudgetLedger)", "supported")
                amount = event.get("amount")
                if amount is None:
                    return Outcome("not_admitted", "budget_amount_missing", state_before, basis_before, chain_result.state)
                reservation = self.ledger.reserve([grant], self.action_ref(event), bound["unit"], amount)
                if not reservation.ok:
                    return Outcome("not_admitted", "budget_exhausted", "exhausted", BASIS_BUDGET_LEDGER, chain_result.state, reservation.code)
                self.ledger.mark_dispatched(self.action_ref(event))
                commit = self.ledger.commit(self.action_ref(event))
                if not commit.ok:
                    return Outcome("not_admitted", "budget_settlement_failed", state_before, basis_before, chain_result.state, commit.code)
            elif state_before == "exhausted":
                # Step 5: purpose and use-count exhaustion. Neither SDK implements either.
                record_support("purpose exhaustion (no SDK API, supplied by this runner)", "not_supported")
                record_support("use_count exhaustion (no SDK API, supplied by this runner)", "not_supported")
                reason = "use_count_exhausted" if bound["mode"] == "use_count" else "purpose_exhausted"
                return Outcome("not_admitted", reason, state_before, basis_before, chain_result.state)

        if self.enforces_bound_exhaustion and bound["mode"] == "use_count":
            self.uses[grant_key] = self.uses.get(grant_key, 0) + 1

        return Outcome("admitted", "dispatch_admitted", state_before, basis_before, chain_result.state)

    def observe(self, event: dict[str, Any]) -> Outcome:
        grant_key = event["grant"]
        grant = self.fixture["grants"][grant_key]
        purpose_bound = self.fixture["purpose_bounds"][grant_key]
        completion = self.fixture["receipts"][event["completion"]]

        if self.authenticates_completion_records:
            # Step 1: standing. A valid signature establishes who signed, never that the
            # signer was allowed to make this statement.
            if completion["issuer"] not in purpose_bound["fulfillment_attestors"]:
                self.mark_unestablished(grant_key)
                record_support("completion attestor standing (receipt_core.verify_receipt_v1 boundary_identity axis)", "supported")
                sdk_view = receipt_core.verify_receipt_v1(
                    completion,
                    self.resolve_receipt_key,
                    boundary_identity=purpose_bound["fulfillment_attestors"][0],
                )
                axis = (sdk_view.get("stage") or {}).get("boundary_identity", "unknown")
                return Outcome(
                    "completion_rejected",
                    "completion_attestor_without_standing",
                    self.bound_state(grant_key),
                    self.bound_basis(grant_key),
                    None,
                    f"sdk_boundary_identity={axis}",
                )

            # Step 2: authenticity, from the Python SDK.
            record_support("completion record authenticity (receipt_core.verify_receipt_v1)", "supported")
            verification = receipt_core.verify_receipt_v1(
                completion,
                self.resolve_receipt_key,
                boundary_identity=completion["issuer"],
            )
            if verification.get("status") != "valid":
                self.mark_unestablished(grant_key)
                detail = f"{verification.get('status')}/{json.dumps(verification.get('errors', []))}"
                return Outcome("completion_rejected", "completion_signature_invalid", self.bound_state(grant_key), self.bound_basis(grant_key), None, detail)

        if completion["delegation_ref"] != grant["delegation_id"]:
            return Outcome("completion_rejected", "completion_not_bound_to_grant", self.bound_state(grant_key), self.bound_basis(grant_key), None)
        if completion["result"]["status"] != "succeeded":
            return Outcome("completion_rejected", "completion_status_not_succeeded", self.bound_state(grant_key), self.bound_basis(grant_key), None)

        self.fulfilled.add(grant_key)
        return Outcome("completion_accepted", "fulfillment_recorded", self.bound_state(grant_key), self.bound_basis(grant_key), None)

    def mark_unestablished(self, grant_key: str) -> None:
        if grant_key not in self.fulfilled:
            self.unestablished.add(grant_key)

    def action_ref(self, event: dict[str, Any]) -> str:
        return self.fixture["actions"][event["action"]]["action_ref"]


# ---------------------------------------------------------------------------
# Track 2: single-use. LC-I-013 reuse cascade and LC-I-014 notch, over
# records-single-use.json. See harness.ts's ExhaustionBoundary for the model this mirrors
# and for the two axes the defective policies differ along.
# ---------------------------------------------------------------------------

SINGLE_USE_POLICIES = ("reference", "reuse-rejecting-only", "validity-window-only")
SINGLE_USE_FIELDS = (
    "outcome", "reason", "exhaustion_basis", "chain_verdict", "chain_failure_code",
    "bound_state", "records_written",
)


def single_use_result(outcome, reason, *, exhaustion_basis=None, chain_verdict=None,
                      chain_failure_code=None, bound_state="not_reached", records_written=1):
    return {
        "outcome": outcome,
        "reason": reason,
        "exhaustion_basis": exhaustion_basis,
        "chain_verdict": chain_verdict,
        "chain_failure_code": chain_failure_code,
        "bound_state": bound_state,
        "records_written": records_written,
    }


class ExhaustionBoundary:
    """One exhaustion ledger per grant, shared across an ordered event list."""

    def __init__(self, fixture: dict[str, Any], policy: str):
        self.fixture = fixture
        self.policy = policy
        self.role_by_id = {delegation_id: role for role, delegation_id in fixture["roles"].items()}
        self.grants = {
            role: {"bound": spec["bound"], "uses": 0, "bound_state": "not_reached", "reuse_detected": False}
            for role, spec in fixture["grant_bounds"].items()
        }

    def _chain_verdict(self, chain_name, now):
        record_support("chain state (verify_authority_delegation_chain)", "supported")
        outcome = ap.verify_authority_delegation_chain(
            self.fixture["chains"][chain_name],
            now=now,
            resolve_verification_key=lambda _issuer, method, _issued_at:
                self.fixture["verification_keys"].get(method),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _delegation: "active",
        )
        first = outcome.failures[0] if outcome.failures else None
        verdict = {"valid": "valid", "indeterminate": "not established"}.get(outcome.state, "invalid")
        return verdict, (first.code if first is not None else None)

    def _bound_grant_for(self, leaf_role):
        spec = self.fixture["grant_bounds"].get(leaf_role)
        if spec is None:
            return None
        if spec["bound"] != "none":
            return leaf_role, self.grants[leaf_role]
        if spec["issued_from"] is None:
            return None
        return spec["issued_from"], self.grants[spec["issued_from"]]

    def present(self, chain_name, now):
        chain = self.fixture["chains"][chain_name]
        leaf_role = self.role_by_id[chain[-1]["delegation_id"]]
        verdict, code = self._chain_verdict(chain_name, now)

        bound = self._bound_grant_for(leaf_role)

        if verdict != "valid":
            return single_use_result("not_admitted", "grant_chain_not_valid", chain_verdict=verdict,
                                     chain_failure_code=code,
                                     bound_state=(bound[1]["bound_state"] if bound else "not_reached"))

        if bound is None:
            return single_use_result("admitted", "admitted_no_bound_declared", chain_verdict=verdict)

        role, state = bound
        is_leaf_itself = role == leaf_role

        if self.policy == "validity-window-only":
            return single_use_result("admitted", "within_validity_window", chain_verdict=verdict)

        if not is_leaf_itself and state["reuse_detected"]:
            if self.policy == "reuse-rejecting-only":
                return single_use_result("admitted", "derived_artifact_chain_valid", chain_verdict=verdict,
                                         bound_state=state["bound_state"])
            record_support("single-use reuse cascade (no SDK API, supplied by this runner)", "not_supported")
            return single_use_result("not_admitted", "ancestor_invalidated_by_reuse", chain_verdict=verdict,
                                     bound_state=state["bound_state"])

        if not is_leaf_itself:
            return single_use_result("admitted", "derived_artifact_chain_valid", chain_verdict=verdict,
                                     bound_state=state["bound_state"])

        if state["bound_state"] == "invalid":
            return single_use_result("not_admitted", "single_use_reuse_detected", chain_verdict=verdict,
                                     bound_state="invalid")

        if state["bound_state"] == "exhausted":
            if state["bound"] == "single_use":
                state["reuse_detected"] = True
                state["bound_state"] = "invalid"
                record_support("single-use reuse detection (no SDK API, supplied by this runner)", "not_supported")
                return single_use_result("not_admitted", "single_use_reuse_detected", chain_verdict=verdict,
                                         bound_state="invalid")
            record_support("notch exhaustion (no SDK API, supplied by this runner)", "not_supported")
            return single_use_result("not_admitted", "purpose_exhausted",
                                     exhaustion_basis=BASIS_ADMISSION, chain_verdict=verdict,
                                     bound_state="exhausted")

        state["uses"] += 1
        state["bound_state"] = "exhausted"
        return single_use_result("admitted", "admitted_and_exhausted",
                                 exhaustion_basis=BASIS_ADMISSION, chain_verdict=verdict,
                                 bound_state="exhausted")

    def void_exhaustion(self, grant_role, signed_by):
        """A record asking to undo an exhaustion. It is never accepted. The two refusal
        reasons are kept apart so that "nobody may do this" is not reported as "you in
        particular may not"."""
        state = self.grants[grant_role]
        standing = self.fixture["void_standing"].get(grant_role)
        has_standing = standing is not None and signed_by in standing["has_standing"]
        record_support("irreversibility of an exhaustion (no SDK API, supplied by this runner)", "not_supported")
        if not has_standing:
            return single_use_result("void_refused", "void_attestor_without_standing",
                                     bound_state=state["bound_state"])
        return single_use_result("void_refused", "exhaustion_is_not_reversible",
                                 bound_state=state["bound_state"])


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

EXPECTED_TOTAL = 21
EXPECTED_PER_TRACK = {"bounds": 12, "single-use": 9}
TRACK_OF_POLICY = {
    "defective-boundary-chain-validity-only": "bounds",
    "defective-boundary-trusts-unauthenticated-completion": "bounds",
    "reuse-rejecting-only": "single-use",
    "validity-window-only": "single-use",
}
BOUNDS_FIELDS = ("outcome", "reason", "bound_state", "exhaustion_basis", "chain_state")


def bounds_matches(actual: Outcome, expected: dict[str, Any]) -> bool:
    for name in BOUNDS_FIELDS:
        if getattr(actual, name) != expected[name]:
            return False
    if "detail" in expected and actual.detail != expected["detail"]:
        return False
    return True


def run_bounds(make: Callable[[], BoundsBoundary], events: list[dict[str, Any]]) -> dict[str, Outcome]:
    boundary = make()
    return {e["id"]: boundary.handle(e) for e in events}


def check_structure(vectors: dict[str, Any]) -> int:
    """The merge guard. The family was reconciled from two builds, so a merge that dropped
    a vector, duplicated an id or pointed a fail set at the wrong track would otherwise
    still exit 0."""
    events = vectors["events"]
    if len(events) != EXPECTED_TOTAL:
        print(f"verify.py: vectors.json holds {len(events)} events, expected {EXPECTED_TOTAL}", file=sys.stderr)
        return 2
    seen: dict[str, str] = {}
    per_track = {"bounds": 0, "single-use": 0}
    for event in events:
        if event["id"] in seen:
            print(f"verify.py: duplicate vector id {event['id']}", file=sys.stderr)
            return 2
        if event["track"] not in per_track:
            print(f"verify.py: vector {event['id']} names an unknown track {event['track']}", file=sys.stderr)
            return 2
        if not isinstance(event.get("case_ids"), list):
            print(f"verify.py: vector {event['id']} carries no case_ids array", file=sys.stderr)
            return 2
        seen[event["id"]] = event["track"]
        per_track[event["track"]] += 1
    for track, count in EXPECTED_PER_TRACK.items():
        if per_track[track] != count:
            print(f"verify.py: track {track} holds {per_track[track]} events, expected {count}", file=sys.stderr)
            return 2
    for policy, declared in vectors["declared_fail_sets"].items():
        track = TRACK_OF_POLICY.get(policy)
        if track is None:
            print(f"verify.py: declared_fail_sets names an unknown policy {policy}", file=sys.stderr)
            return 2
        for vector_id in declared:
            if vector_id not in seen:
                print(f"verify.py: declared_fail_sets.{policy} names an unknown vector {vector_id}", file=sys.stderr)
                return 2
            if seen[vector_id] != track:
                print(f"verify.py: declared_fail_sets.{policy} names {vector_id}, on track {seen[vector_id]}", file=sys.stderr)
                return 2
    return 0


def main() -> int:
    vectors = read_json("vectors.json")
    bounds_fixture = read_json("records-bounds.json")
    single_use_fixture = read_json("records-single-use.json")

    structural = check_structure(vectors)
    if structural != 0:
        return structural

    if (
        single_use_fixture.get("_placeholder")
        or not isinstance(single_use_fixture.get("mint_now"), str)
        or len(single_use_fixture.get("chains") or {}) != 4
    ):
        print("verify.py: records-single-use.json is not minted. Run "
              "python3 fixtures/lifecycle-purpose-exhaustion/mint_single_use.py first.", file=sys.stderr)
        return 2
    if not bounds_fixture.get("grants"):
        print("verify.py: records-bounds.json is not minted. Run "
              "npx tsx fixtures/lifecycle-purpose-exhaustion/mint-bounds.ts first.", file=sys.stderr)
        return 2

    bounds_events = [e for e in vectors["events"] if e["track"] == "bounds"]
    single_use_events = [e for e in vectors["events"] if e["track"] == "single-use"]

    print(f"lifecycle-purpose-exhaustion (python SDK runner): {len(vectors['events'])} events "
          f"across 2 tracks, status label {vectors['status_label']}")
    print(f"  agent-passport-system (PyPI) version reported by the package: {getattr(ap, '__version__', 'unreported')}")
    print(f"  bounds {len(bounds_events)}, single-use {len(single_use_events)}")
    print("")

    # -- track 1 ------------------------------------------------------------

    print("=== track: bounds (records-bounds.json) ===")
    print("")
    print("boundary: reference-boundary")
    reference_results = run_bounds(
        lambda: BoundsBoundary("reference-boundary", True, True, bounds_fixture), bounds_events
    )
    bounds_matched = 0
    for event in bounds_events:
        actual = reference_results[event["id"]]
        ok = bounds_matches(actual, event["expected"])
        bounds_matched += 1 if ok else 0
        print(f"  {'MATCH' if ok else 'MISMATCH'} {event['id']}  {actual.render()}")
        if not ok:
            print(f"    expected: {json.dumps(event['expected'])}")
            print(f"    actual:   {actual.render()}")

    bounds_defectives_ok = True
    for name, enforces, authenticates in [
        ("defective-boundary-chain-validity-only", False, True),
        ("defective-boundary-trusts-unauthenticated-completion", True, False),
    ]:
        declared_set = set(vectors["declared_fail_sets"][name])
        results = run_bounds(lambda: BoundsBoundary(name, enforces, authenticates, bounds_fixture), bounds_events)
        ok_all = True
        print("")
        print(f"boundary: {name}")
        for event in bounds_events:
            actual = results[event["id"]]
            should_match = event["id"] not in declared_set
            actually_matches = bounds_matches(actual, event["expected"])
            entry_ok = actually_matches if should_match else not actually_matches
            ok_all = ok_all and entry_ok
            if should_match:
                label = "MATCH" if entry_ok else "UNDECLARED MISMATCH"
            else:
                label = "DECLARED FAIL" if entry_ok else "DEFECT DID NOT REPRODUCE"
            print(f"  {label} {event['id']}  {actual.render()}")
        print(f"  {name} diverged on exactly its declared set: {ok_all}")
        bounds_defectives_ok = bounds_defectives_ok and ok_all

    # -- track 2 ------------------------------------------------------------

    print("")
    print("=== track: single-use (records-single-use.json) ===")
    print("")

    def replay(policy: str) -> dict[str, Any]:
        boundary = ExhaustionBoundary(single_use_fixture, policy)
        out = {}
        for event in single_use_events:
            if event["kind"] == "void":
                out[event["id"]] = boundary.void_exhaustion(event["grant"], event["signed_by"])
            else:
                out[event["id"]] = boundary.present(event["chain"], event["now"])
        return out

    runs = {policy: replay(policy) for policy in SINGLE_USE_POLICIES}

    single_use_passed = 0
    single_use_failed = 0
    for event in single_use_events:
        actual = runs["reference"][event["id"]]
        mismatched = [f for f in SINGLE_USE_FIELDS if actual[f] != event["expected"][f]]
        ok = not mismatched
        details = [f"reference={actual['outcome']}/{actual['reason']}/bound={actual['bound_state']}"]

        for policy in SINGLE_USE_POLICIES:
            if policy == "reference":
                continue
            declared = vectors["declared_fail_sets"].get(policy, [])
            other = runs[policy][event["id"]]
            outcome_differs = other["outcome"] != actual["outcome"]
            record_differs = any(other[f] != actual[f] for f in SINGLE_USE_FIELDS)
            should_differ_outcome = event["id"] in declared
            should_differ_record = (event.get("record_divergence") or {}).get(policy) is True
            ok = ok and outcome_differs == should_differ_outcome and record_differs == should_differ_record
            details.append(
                f"{policy}={other['outcome']}/{other['reason']}"
                f"(outcome_differs={outcome_differs},record_differs={record_differs})"
            )

        if event.get("negative_control"):
            in_a_fail_set = any(event["id"] in ids for ids in vectors["declared_fail_sets"].values())
            ok = ok and in_a_fail_set
            details.append(f"negative_control={in_a_fail_set}")

        if ok:
            single_use_passed += 1
            print(f"  PASS {event['id']} {' '.join(details)}")
        else:
            single_use_failed += 1
            print(f"  FAIL {event['id']}", file=sys.stderr)
            for name in mismatched:
                print(f"    {name}: expected {json.dumps(event['expected'][name])} "
                      f"actual {json.dumps(actual[name])}", file=sys.stderr)
            print(f"    {' '.join(details)}", file=sys.stderr)

    # -- the cross-track overlap the reconciliation exists to keep honest ----

    pxe03 = reference_results.get("PXE-03-reject-second-purchase-wednesday")
    lci014b = runs["reference"].get("LC-I-014-b")
    overlap_ok = False
    if pxe03 is not None and lci014b is not None:
        same_verdict = (
            pxe03.outcome == lci014b["outcome"]
            and pxe03.reason == lci014b["reason"]
            and pxe03.bound_state == lci014b["bound_state"]
        )
        different_basis = pxe03.exhaustion_basis != lci014b["exhaustion_basis"]
        overlap_ok = same_verdict and different_basis
        print("")
        print("cross-track overlap check, PXE-03 against LC-I-014-b:")
        print(f"  same outcome, reason and bound_state: {same_verdict} "
              f"({pxe03.outcome}/{pxe03.reason}/{pxe03.bound_state})")
        print(f"  different exhaustion_basis:           {different_basis}")
        print(f"    PXE-03     basis: {json.dumps(pxe03.exhaustion_basis)}")
        print(f"    LC-I-014-b basis: {json.dumps(lci014b['exhaustion_basis'])}")
    else:
        print("cross-track overlap check: one of the two vectors is missing", file=sys.stderr)

    print("")
    print("Python SDK support, recorded by this run:")
    for concept in sorted(SDK_SUPPORT):
        print(f"  {SDK_SUPPORT[concept]:<14} {concept}")

    bounds_ok = bounds_matched == len(bounds_events)
    single_use_ok = single_use_failed == 0

    print("")
    print(f"bounds     reference-boundary matched: {bounds_matched}/{len(bounds_events)}")
    print(f"bounds     both defective boundaries diverged on exactly their declared sets: {bounds_defectives_ok}")
    print(f"single-use reference policy matched:   {single_use_passed}/{len(single_use_events)}")
    print(f"cross-track overlap check:             {overlap_ok}")

    if bounds_ok and bounds_defectives_ok and single_use_ok and overlap_ok:
        total = len(vectors["events"])
        print(f"PASSED: {total}/{total} vectors, both reference boundaries matched every event in their track, "
              "every defective policy diverged on exactly its declared set (python SDK)")
        return 0
    print("FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
