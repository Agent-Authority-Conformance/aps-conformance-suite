#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Independent Python runner for the lifecycle-evidence-and-record candidate
# family.
#
# Written from README.md and vectors.json rather than ported from harness.ts.
# The retention clock here is computed with datetime.replace on the calendar
# year and the receipt group is a dispatch table keyed on (query, later
# evidence kind), neither of which mirrors the TypeScript file's shape, so the
# two implementations agreeing is evidence about the rules.
#
# The only third-party import is the published PyPI agent-passport-system, for
# its RFC 8785 (JCS) canonicalization primitive.
#
# Run:
#   /path/to/venv/bin/python fixtures/lifecycle-evidence-and-record/verify.py
#
# Exit 0 on success, 1 on any failure.

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_passport.canonical import canonicalize_jcs

HERE = Path(__file__).resolve().parent
VOCABULARY = {"valid", "invalid", "not_established", "not_yet_effective", "suspended", "restricted"}

problems: list[str] = []


def fail(message: str) -> None:
    problems.append(message)
    print(f"  FAIL {message}", file=sys.stderr)


def at(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)


# --------------------------------------------------------------------------
# retention_restriction
# --------------------------------------------------------------------------


def retention(inp: dict, *, own_clock: bool) -> tuple[str, str, str]:
    chain = inp["requester_chain_state"]
    record = inp["record"]

    if inp["requested_effect"] != "records:delete":
        return chain, "valid", "evidence_survives_authority_end"

    if record["trigger_occurred_at"] is None:
        return chain, "restricted", "retention_trigger_not_reached"

    if not own_clock:
        # The relationship ended, so a relationship-scoped duty is over.
        return chain, "valid", "retention_duty_elapsed"

    trigger = at(record["trigger_occurred_at"])
    # A duty stated in years advances the calendar year rather than adding a
    # fixed span, so it does not drift by a day per leap year. No date in this
    # family is 29 February.
    expiry = trigger.replace(year=trigger.year + record["retention_years"])
    if at(inp["evaluated_at"]) < expiry:
        return chain, "restricted", "retention_duty_unexpired"

    for hold in inp["external_holds"]:
        if not hold["released"]:
            return chain, "restricted", "external_hold_active"

    return chain, "valid", "retention_duty_elapsed"


# --------------------------------------------------------------------------
# receipt_immutability
# --------------------------------------------------------------------------

PRESENT_TENSE = {
    "new_information": ("invalid", "invalid", "new_record_references_prior"),
    "void_from_inception": ("invalid", "invalid", "ancestor_never_validly_issued"),
}


def receipt(inp: dict, *, honour_decision_time: bool) -> tuple[str, str, str]:
    prior = inp["prior_receipt"]
    kind = inp["later_evidence"]["kind"]

    if honour_decision_time:
        if prior["actual_bytes_sha256"] != prior["recorded_bytes_sha256"]:
            return "not_established", "not_established", "prior_receipt_bytes_do_not_match_digest"
        if inp["query"] == "verdict_at_decision_time":
            recorded = prior["recorded_verdict"]
            return recorded, recorded, "decided_on_the_record_then_available"
        if kind in PRESENT_TENSE:
            return PRESENT_TENSE[kind]
        recorded = prior["recorded_verdict"]
        return recorded, recorded, "no_later_record"

    # N2: answer everything against what is known now, never check the bytes.
    if kind in PRESENT_TENSE:
        return PRESENT_TENSE[kind]
    recorded = prior["recorded_verdict"]
    return recorded, recorded, "decided_on_the_record_then_available"


REFERENCE = {
    "retention_restriction": lambda i: retention(i, own_clock=True),
    "receipt_immutability": lambda i: receipt(i, honour_decision_time=True),
}

CONTROL = {
    "retention_restriction": lambda i: retention(i, own_clock=False),
    "receipt_immutability": lambda i: receipt(i, honour_decision_time=False),
}


def expected_triple(case: dict) -> tuple[str, str, str]:
    e = case["expected"]
    return e["chain_verdict"], e["verdict"], e["reason"]


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    pinned = json.loads((HERE / "input-digests.json").read_text())["inputs"]
    cases = vectors["cases"]

    print(f"{vectors['family']}: {len(cases)} cases, Python runner")

    if vectors["status"] != "candidate_against_proposed":
        fail(f"family status is {vectors['status']!r}")
    if not vectors.get("proposed_text", {}).get("commit"):
        fail("family does not name the proposed text it is a candidate against")

    ids = set()
    for case in cases:
        if case["id"] in ids:
            fail(f"{case['id']}: duplicate vector id")
        ids.add(case["id"])
        if case["label"] != "candidate_against_proposed":
            fail(f"{case['id']}: label is {case['label']!r}")
        if not case["id"].startswith(case["case_id"]):
            fail(f"{case['id']}: vector id does not carry its CASES.md case id")
        if not case.get("proposed_text", {}).get("sections"):
            fail(f"{case['id']}: names no proposed text")
        for field in ("chain_verdict", "verdict"):
            if case["expected"][field] not in VOCABULARY:
                fail(f"{case['id']}: {field} {case['expected'][field]!r} is outside the settled vocabulary")
    print(f"  ok   labelling: {len(cases)} cases carry candidate_against_proposed and name their proposed text")

    before = {}
    for case in cases:
        digest = hashlib.sha256(canonicalize_jcs(case["input"]).encode("utf-8")).hexdigest()
        before[case["id"]] = digest
        if pinned.get(case["id"]) is None:
            fail(f"{case['id']}: no pinned input digest")
        elif digest != pinned[case["id"]]:
            fail(f"{case['id']}: input digest {digest} does not match pinned {pinned[case['id']]}")
    if len(pinned) != len(cases):
        fail(f"input-digests.json pins {len(pinned)} inputs for {len(cases)} cases")
    print(f"  ok   canonical bytes: {len(cases)}/{len(cases)} JCS input digests match, via PyPI canonicalize_jcs")

    matched = 0
    for case in cases:
        got = REFERENCE[case["group"]](case["input"])
        want = expected_triple(case)
        if got != want:
            fail(f"{case['id']}: reference gave {'/'.join(got)}, expected {'/'.join(want)}")
        else:
            matched += 1
    print(f"  ok   reference model: {matched}/{len(cases)} matched")

    for control in vectors["policies"]["negative_controls"]:
        group = control["group"]
        in_group = [c for c in cases if c["group"] == group]
        observed = [c["id"] for c in in_group if CONTROL[group](c["input"]) != expected_triple(c)]
        declared = sorted(control["declared_fail_set"])
        if sorted(observed) != declared:
            fail(f"{control['id']}: declared fail set {declared}, observed {sorted(observed)}")
        else:
            print(
                f"  ok   {control['id']}: ran {len(in_group)} cases in group {group}, "
                f"failed exactly {len(declared)} declared ({', '.join(declared)})"
            )
        if not declared:
            fail(f"{control['id']}: a negative control with an empty declared fail set is not a control")

    unchanged = 0
    for case in cases:
        after = hashlib.sha256(canonicalize_jcs(case["input"]).encode("utf-8")).hexdigest()
        if after != before[case["id"]]:
            fail(f"{case['id']}: an evaluator mutated the input it was given")
        else:
            unchanged += 1
    print(f"  ok   input immutability: {unchanged}/{len(cases)} inputs unchanged after every evaluator ran")

    if problems:
        print(f"\nlifecycle-evidence-and-record Python: FAILED, {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print(f"\nlifecycle-evidence-and-record Python: {len(cases)}/{len(cases)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
