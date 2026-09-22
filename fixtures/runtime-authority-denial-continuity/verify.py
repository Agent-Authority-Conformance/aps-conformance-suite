#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Independent Python runner for the runtime-authority-denial-continuity family.

This is a second, independently written implementation of the harness described in
README.md, built from vectors.json and the README rather than by porting harness.ts. It
does not import anything from the TypeScript side. Where the two runners diverge in
internal structure that is expected; what must agree is every MATCH/MISMATCH verdict,
the two negative controls' fail sets, and the final resource-state checks.

Run:
    python3 fixtures/runtime-authority-denial-continuity/verify.py

Exit 0 when reference-gate matches every case it runs and both negative controls fail
exactly their declared set, 1 otherwise. No third-party dependency, stdlib only.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def effect_key(effect: dict[str, str]) -> tuple[str, str, str]:
    return (effect["resource"], effect["transition"], effect["domain"])


def canonical_key(effect: dict[str, str], context: str) -> tuple:
    return (*effect_key(effect), context)


@dataclass
class DenialRecord:
    key: tuple
    effect: dict[str, str]
    context: str
    denial_ref: str
    resolved: bool = False


@dataclass
class RecordState:
    content: str = "original content"
    flags: dict[str, bool] = field(default_factory=dict)
    linked: bool = True
    available: bool = True

    def copy(self) -> "RecordState":
        return RecordState(content=self.content, flags=dict(self.flags), linked=self.linked, available=self.available)


class ResourceStore:
    def __init__(self) -> None:
        self._records: dict[str, RecordState] = {}

    def get(self, resource_id: str) -> RecordState:
        if resource_id not in self._records:
            self._records[resource_id] = RecordState()
        return self._records[resource_id]

    def set(self, resource_id: str, state: RecordState) -> None:
        self._records[resource_id] = state


def classify_composed_effect(resource_id: str, state: RecordState) -> dict[str, str] | None:
    """The one composed-effect pattern this reference gate recognizes.

    Content emptied, flagged quarantined, and unlinked from the index together read as
    the same effect a direct delete or overwrite produces. A pattern match, one
    implementation's choice, not a general algorithm; see README.md.
    """
    if state.content == "" and state.flags.get("quarantined") is True and state.linked is False:
        return {"resource": f"record:{resource_id}", "transition": "unavailable", "domain": "records"}
    return None


def apply_write(state: RecordState, write: dict[str, Any]) -> RecordState:
    next_state = state.copy()
    kind = write["kind"]
    if kind == "set_content":
        next_state.content = write["content"]
    elif kind == "set_flag":
        next_state.flags[write["flag"]] = write["value"]
    elif kind == "unlink_index":
        next_state.linked = False
    else:
        raise ValueError(f"unknown decomposed write kind: {kind}")
    return next_state


def atomic_identity(resource_id: str, write: dict[str, Any]) -> dict[str, str]:
    resource = f"record:{resource_id}"
    kind = write["kind"]
    if kind == "set_content":
        return {"resource": resource, "transition": "content_updated", "domain": "records"}
    if kind == "set_flag":
        return {"resource": resource, "transition": f"flag_set:{write['flag']}", "domain": "records"}
    if kind == "unlink_index":
        return {"resource": resource, "transition": "unlinked", "domain": "records"}
    raise ValueError(f"unknown decomposed write kind: {kind}")


class Policy:
    def __init__(self, name: str, has_composed_effect_identification: bool, path_scoped: bool) -> None:
        self.name = name
        self.has_composed_effect_identification = has_composed_effect_identification
        self._path_scoped = path_scoped

    def ledger_key(self, tool: str, effect: dict[str, str], context: str) -> tuple:
        if self._path_scoped:
            return (tool, *effect_key(effect), context)
        return canonical_key(effect, context)


REFERENCE_GATE = Policy("reference-gate", has_composed_effect_identification=True, path_scoped=False)
FRESH_PATH_CONTROL = Policy("fresh-path-control", has_composed_effect_identification=True, path_scoped=True)
PER_WRITE_CONTROL = Policy("per-write-control", has_composed_effect_identification=False, path_scoped=False)


class EnforcementPoint:
    def __init__(self, policy: Policy, store: ResourceStore) -> None:
        self.policy = policy
        self.store = store
        self.ledger: dict[tuple, DenialRecord] = {}

    def deny(self, request_id: str, tool: str, effect: dict[str, str], context: str) -> tuple[str, str]:
        key = self.policy.ledger_key(tool, effect, context)
        self.ledger[key] = DenialRecord(key=key, effect=effect, context=context, denial_ref=request_id)
        return ("deny", "authority_denied")

    def attempt(self, tool: str, effect: dict[str, str], context: str) -> tuple[str, str]:
        key = self.policy.ledger_key(tool, effect, context)
        record = self.ledger.get(key)
        if record is not None and not record.resolved:
            return ("deny", "denied_effect_continuity")
        self._apply_direct_effect(effect)
        if record is not None and record.resolved:
            return ("allow", "reauthorized")
        return ("allow", "no_denial_on_effect")

    def reauthorize(self, effect: dict[str, str], context: str, denial_ref: str | None) -> tuple[str, str]:
        for record in self.ledger.values():
            if record.resolved:
                continue
            if effect_key(record.effect) != effect_key(effect):
                continue
            if record.context != context:
                continue
            if denial_ref is not None and record.denial_ref != denial_ref:
                raise ValueError(f"reauthorize: denial_ref {denial_ref} does not match record's {record.denial_ref}")
            record.resolved = True
        return ("allow", "reauthorized")

    def decompose_write(self, tool: str, resource_id: str, write: dict[str, Any], context: str) -> tuple[str, str]:
        before = self.store.get(resource_id)
        after = apply_write(before, write)

        check_effect = None
        if self.policy.has_composed_effect_identification:
            composed = classify_composed_effect(resource_id, after)
            if composed is not None:
                check_effect = composed
                key = canonical_key(composed, context)
            else:
                check_effect = atomic_identity(resource_id, write)
                key = self.policy.ledger_key(tool, check_effect, context)
        else:
            check_effect = atomic_identity(resource_id, write)
            key = self.policy.ledger_key(tool, check_effect, context)

        record = self.ledger.get(key)
        if record is not None and not record.resolved:
            reason = "composed_effect_denied_continuity" if check_effect["transition"] == "unavailable" else "denied_effect_continuity"
            return ("deny", reason)

        self.store.set(resource_id, after)
        return ("allow", "individually_permitted_write")

    def _apply_direct_effect(self, effect: dict[str, str]) -> None:
        if effect["transition"] != "unavailable":
            return
        resource_id = effect["resource"].split(":", 1)[1]
        state = self.store.get(resource_id)
        state.content = ""
        state.available = False


def run_case(case: dict[str, Any], policy: Policy) -> tuple[bool, list[str], list[str]]:
    """Returns (ok, failures, step_labels)."""
    store = ResourceStore()
    point = EnforcementPoint(policy, store)
    failures: list[str] = []
    labels: list[str] = []

    for step in case["timeline"]:
        event = step["event"]
        if event == "deny":
            observed = point.deny(step["request"], step["tool"], step["effect"], step["context"])
        elif event == "attempt":
            observed = point.attempt(step["tool"], step["effect"], step["context"])
        elif event == "reauthorize":
            observed = point.reauthorize(step["effect"], step["context"], step.get("denial_ref"))
        elif event == "decompose_write":
            observed = point.decompose_write(step["tool"], step["resource"], step["write"], step["context"])
        else:
            raise ValueError(f"unknown event: {event}")

        observed_outcome, observed_reason = observed
        expected = step["expected"]
        request = step["request"]

        requires_capability = expected.get("requires_capability")
        if requires_capability is not None:
            has = policy.has_composed_effect_identification if requires_capability == "composed_effect_identification" else False
            if not has:
                target = expected.get("capability_absent_outcome", expected["outcome"])
                flaw_matches = observed_outcome == target
                if not flaw_matches:
                    failures.append(
                        f"{request}: capability-absent outcome expected {target} (documented flaw), observed {observed_outcome}"
                    )
                failures.append(
                    f"{request}: not_identifiable -- composed_effect_identification absent, property not "
                    f"established (observed {observed_outcome}, documented flaw outcome {target})"
                )
                labels.append("not_identifiable")
                continue

        outcome_ok = observed_outcome == expected["outcome"]
        expected_reason = expected.get("reason")
        reason_ok = expected_reason is None or observed_reason == expected_reason
        if not outcome_ok:
            failures.append(f"{request}: outcome expected {expected['outcome']}, observed {observed_outcome}")
        if not reason_ok:
            failures.append(f"{request}: reason expected {expected_reason}, observed {observed_reason}")
        labels.append("MATCH" if outcome_ok and reason_ok else "MISMATCH")

    final_state = case.get("final_state")
    if final_state is not None:
        for resource_id, expected_partial in final_state.items():
            actual = store.get(resource_id)
            for field_name, expected_value in expected_partial.items():
                actual_value = getattr(actual, field_name)
                if actual_value != expected_value:
                    failures.append(
                        f"final_state record:{resource_id}.{field_name} expected {expected_value!r}, "
                        f"observed {actual_value!r}"
                    )

    return (len(failures) == 0, failures, labels)


def run_policy(vectors: dict[str, Any], policy: Policy, properties: list[str]) -> dict[str, tuple[bool, list[str]]]:
    results: dict[str, tuple[bool, list[str]]] = {}
    print(f"policy: {policy.name}  (properties: {', '.join(properties)})")
    for case in vectors["cases"]:
        if case["property"] not in properties:
            continue
        ok, failures, labels = run_case(case, policy)
        results[case["id"]] = (ok, failures)
        status = "MATCH   " if ok else "MISMATCH"
        print(f"  {status} {case['id']}  [{','.join(labels)}]")
        if not ok:
            for failure in failures:
                print(f"             {failure}")
    print()
    return results


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))

    print(f"runtime-authority-denial-continuity: {len(vectors['cases'])} candidate cases (python)")
    print(f"source: {vectors['source']['issue']} ({vectors['source']['status']})")
    print()

    reference_results = run_policy(vectors, REFERENCE_GATE, vectors["policies"]["reference_gate"]["runs_against_properties"])
    n1_results = run_policy(vectors, FRESH_PATH_CONTROL, vectors["policies"]["n1_fresh_path_control"]["runs_against_properties"])
    n2_results = run_policy(vectors, PER_WRITE_CONTROL, vectors["policies"]["n2_per_write_control"]["runs_against_properties"])

    failed = 0

    reference_mismatches = [case_id for case_id, (ok, _) in reference_results.items() if not ok]
    if reference_mismatches:
        failed += 1
        print(f"FAIL reference-gate did not match: {reference_mismatches}")
    else:
        print(f"ok   reference-gate matched all {len(reference_results)} cases it ran")

    def check_negative_control(name: str, results: dict[str, tuple[bool, list[str]]], expected_fail_ids: list[str]) -> int:
        nonlocal failed
        observed_fail_ids = [case_id for case_id, (ok, _) in results.items() if not ok]
        undeclared = [i for i in observed_fail_ids if i not in expected_fail_ids]
        stopped_failing = [i for i in expected_fail_ids if i not in observed_fail_ids]
        if undeclared:
            failed += 1
            print(f"FAIL {name} failed cases the fixture does not declare: {undeclared}")
        if stopped_failing:
            failed += 1
            print(f"FAIL {name} no longer fails declared cases: {stopped_failing}")
        if not undeclared and not stopped_failing:
            print(f"ok   {name} failed exactly the declared set: {expected_fail_ids}")
        return failed

    check_negative_control(
        "fresh-path-control (N1)", n1_results, vectors["policies"]["n1_fresh_path_control"].get("expected_fail_ids", [])
    )
    check_negative_control(
        "per-write-control (N2)", n2_results, vectors["policies"]["n2_per_write_control"].get("expected_fail_ids", [])
    )

    print()
    if failed > 0:
        print("FAILED")
        return 1
    print("PASSED: reference-gate matched every case, N1 and N2 each failed exactly their declared set")
    return 0


if __name__ == "__main__":
    sys.exit(main())
