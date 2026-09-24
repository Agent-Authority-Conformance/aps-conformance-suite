#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Independent Python runner for the lifecycle-infrastructure-failure candidate
# family.
#
# Written from README.md and vectors.json, not by porting harness.ts. The
# evaluators here are ordered rule tables rather than the switch-and-early-
# return shape the TypeScript harness uses, so the two implementations agreeing
# is evidence about the rules and not about one file having been copied.
#
# The only third-party import is the published PyPI agent-passport-system, used
# for one thing: its RFC 8785 (JCS) canonicalization primitive, so the input
# digests this runner checks are produced by a different implementation from the
# one that produced the pins.
#
# Run:
#   python3 -m venv /path/to/venv
#   /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
#   /path/to/venv/bin/python fixtures/lifecycle-infrastructure-failure/verify.py
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
    """RFC 3339 instant. Raises on anything this family did not write itself."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)


def seconds(later: str, earlier: str) -> float:
    return (at(later) - at(earlier)).total_seconds()


# --------------------------------------------------------------------------
# status_artifact
# --------------------------------------------------------------------------


def status_artifact(inp: dict, *, honour_artifact_window: bool) -> tuple[str, str]:
    art = inp["artifact"]
    age = seconds(inp["evaluated_at"], art["this_update"])
    rules = []
    if honour_artifact_window:
        rules.append((age < 0, "not_established", "status_artifact_future_dated"))
    rules.append((art["answer"] == "revoked", "invalid", "status_revoked"))
    if honour_artifact_window:
        rules.append(
            (seconds(inp["evaluated_at"], art["next_update"]) > 0, "not_established", "status_artifact_past_next_update")
        )
    rules.append((max(age, 0.0) > inp["verifier_freshness_bound_s"], "not_established", "status_past_verifier_bound"))
    for holds, verdict, reason in rules:
        if holds:
            return verdict, reason
    return "valid", "status_active_within_both_windows"


# --------------------------------------------------------------------------
# status_correction
# --------------------------------------------------------------------------


def status_correction(inp: dict, *, check_standing: bool) -> tuple[str, str]:
    if inp["entry"]["answer"] != "revoked":
        return "valid", "status_entry_active"
    correction = inp["correction"]
    if correction is None:
        return "invalid", "status_entry_revoked"
    if not check_standing:
        return "valid", "publication_error_corrected"

    publishes_the_list = (
        correction["signer_key_id"] == inp["list_publisher_key_id"]
        and correction["list_id"] == inp["entry"]["list_id"]
    )
    if not publishes_the_list:
        return "invalid", "correction_without_publisher_standing"

    underlying = inp["underlying_revocation_record"]
    if underlying is not None and underlying["signer_has_lifecycle_standing"]:
        return "invalid", "correction_refused_underlying_revocation"

    low, high = correction["erroneous_versions"]
    if not (low <= inp["held_version"] <= high):
        return "invalid", "correction_does_not_cover_held_version"
    return "valid", "publication_error_corrected"


# --------------------------------------------------------------------------
# issuer_time_evidence
# --------------------------------------------------------------------------


def issuer_time(inp: dict, *, require_independent_evidence: bool) -> tuple[str, str]:
    issued = at(inp["issuer_claimed_issued_at"])

    if require_independent_evidence:
        for window in inp["declared_time_source_disagreement_windows"]:
            if at(window["from"]) <= issued <= at(window["to"]):
                return "not_established", "issuer_time_source_disputed"

    if not inp["ordering_is_load_bearing"] or inp["revocation_at"] is None:
        return "valid", "no_ordering_claim_rests_on_the_timestamp"

    if require_independent_evidence:
        evidence = inp["independent_time_evidence"]
        covered = evidence is not None and at(evidence["covers_from"]) <= issued <= at(evidence["covers_to"])
        if not covered:
            return "not_established", "issuer_timestamp_unattested"

    if issued >= at(inp["revocation_at"]):
        return "invalid", "issued_after_revocation"
    return "valid", "ordering_established_by_independent_time_evidence"


# --------------------------------------------------------------------------
# history_reconciliation
# --------------------------------------------------------------------------


def _writes(inp: dict) -> list[tuple[str, dict]]:
    out = [(f"a:{w['seq']}", w) for w in inp["side_a"]]
    out += [(f"b:{w['seq']}", w) for w in inp["side_b"]]
    return [(tag, w) for tag, w in out if w["delegation_id"] == inp["delegation_id"]]


def reconciliation(inp: dict, *, preserve_revocations: bool) -> tuple[str, str]:
    writes = _writes(inp)

    if not preserve_revocations:
        if not writes:
            return "not_established", "no_authority_write_on_reconciled_history"
        latest = max(writes, key=lambda pair: at(pair[1]["at"]))
        if latest[1]["kind"] == "revocation":
            return "invalid", "revoked_on_reconciled_history"
        return "valid", "grant_on_reconciled_history"

    record = inp["reconciliation_record"]
    if not record["present"]:
        return "not_established", "reconciliation_record_absent"

    kept_kinds = {w["kind"] for tag, w in writes if tag in record["kept"]}
    discarded_kinds = {w["kind"] for tag, w in writes if tag in record["discarded"]}
    if "revocation" in kept_kinds:
        return "invalid", "revoked_on_reconciled_history"
    if "grant" in kept_kinds:
        return "valid", "grant_on_reconciled_history"
    if "grant" in discarded_kinds:
        return "not_established", "grant_on_discarded_history"
    return "not_established", "no_authority_write_on_reconciled_history"


# --------------------------------------------------------------------------
# causal_read
# --------------------------------------------------------------------------


def causal_read(inp: dict, *, enforce_required_observation: bool) -> tuple[str, str]:
    required = inp["required_observation"]
    replica = inp["replica"]
    if enforce_required_observation and required is not None:
        if required["write_id"] not in replica["applied_writes"]:
            return "not_established", "required_write_not_observed"
    if replica["answer"] == "revoked":
        return "invalid", "status_revoked"
    if seconds(inp["evaluated_at"], replica["as_of"]) > inp["replica_lag_bound_s"]:
        return "not_established", "replica_past_bound"
    return "valid", "within_declared_replica_bound"


# --------------------------------------------------------------------------
# evidence_coverage
# --------------------------------------------------------------------------


def coverage(inp: dict, *, check_lag_and_consumers: bool) -> tuple[str, str]:
    if not check_lag_and_consumers:
        return "valid", "interval_settled_and_consumers_delivered"
    unsettled_by = seconds(inp["query_interval"]["to"], inp["evaluated_at"]) + inp["delivery_lag_bound_s"]
    if unsettled_by > 0:
        return "not_established", "interval_inside_delivery_lag"
    end = at(inp["query_interval"]["to"])
    for consumer in inp["consumers"]:
        if at(consumer["delivered_through"]) < end:
            return "not_established", "consumer_delivery_gap"
    return "valid", "interval_settled_and_consumers_delivered"


REFERENCE = {
    "status_artifact": lambda i: status_artifact(i, honour_artifact_window=True),
    "status_correction": lambda i: status_correction(i, check_standing=True),
    "issuer_time_evidence": lambda i: issuer_time(i, require_independent_evidence=True),
    "history_reconciliation": lambda i: reconciliation(i, preserve_revocations=True),
    "causal_read": lambda i: causal_read(i, enforce_required_observation=True),
    "evidence_coverage": lambda i: coverage(i, check_lag_and_consumers=True),
}

CONTROL = {
    "status_artifact": lambda i: status_artifact(i, honour_artifact_window=False),
    "status_correction": lambda i: status_correction(i, check_standing=False),
    "issuer_time_evidence": lambda i: issuer_time(i, require_independent_evidence=False),
    "history_reconciliation": lambda i: reconciliation(i, preserve_revocations=False),
    "causal_read": lambda i: causal_read(i, enforce_required_observation=False),
    "evidence_coverage": lambda i: coverage(i, check_lag_and_consumers=False),
}


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    pinned = json.loads((HERE / "input-digests.json").read_text())["inputs"]
    cases = vectors["cases"]

    print(f"{vectors['family']}: {len(cases)} cases, Python runner")

    if vectors["status"] != "candidate_against_proposed":
        fail(f"family status is {vectors['status']!r}, expected candidate_against_proposed")
    if not vectors.get("proposed_text", {}).get("commit"):
        fail("family does not name the proposed text it is a candidate against")

    ids = set()
    for case in cases:
        if case["id"] in ids:
            fail(f"{case['id']}: duplicate vector id")
        ids.add(case["id"])
        if case["label"] != "candidate_against_proposed":
            fail(f"{case['id']}: label is {case['label']!r}")
        if not case["id"].startswith(case.get("case_id_variant", case["case_id"])):
            fail(f"{case['id']}: vector id does not carry its CASES.md case id")
        if not case.get("proposed_text", {}).get("sections"):
            fail(f"{case['id']}: names no proposed text")
        if case["expected"]["verdict"] not in VOCABULARY:
            fail(f"{case['id']}: verdict {case['expected']['verdict']!r} is outside the settled vocabulary")
    print(f"  ok   labelling: {len(cases)} cases carry candidate_against_proposed and name their proposed text")

    checked = 0
    for case in cases:
        digest = hashlib.sha256(canonicalize_jcs(case["input"]).encode("utf-8")).hexdigest()
        want = pinned.get(case["id"])
        if want is None:
            fail(f"{case['id']}: no pinned input digest")
        elif digest != want:
            fail(f"{case['id']}: input digest {digest} does not match pinned {want}")
        else:
            checked += 1
    if len(pinned) != len(cases):
        fail(f"input-digests.json pins {len(pinned)} inputs for {len(cases)} cases")
    print(f"  ok   canonical bytes: {checked}/{len(cases)} JCS input digests match, via PyPI canonicalize_jcs")

    matched = 0
    for case in cases:
        verdict, reason = REFERENCE[case["group"]](case["input"])
        want = case["expected"]
        if (verdict, reason) != (want["verdict"], want["reason"]):
            fail(f"{case['id']}: reference gave {verdict}/{reason}, expected {want['verdict']}/{want['reason']}")
        else:
            matched += 1
    print(f"  ok   reference model: {matched}/{len(cases)} matched")

    for control in vectors["policies"]["negative_controls"]:
        group = control["group"]
        in_group = [c for c in cases if c["group"] == group]
        observed = []
        for case in in_group:
            verdict, reason = CONTROL[group](case["input"])
            want = case["expected"]
            if (verdict, reason) != (want["verdict"], want["reason"]):
                observed.append(case["id"])
        declared = sorted(control["declared_fail_set"])
        if sorted(observed) != declared:
            fail(f"{control['id']}: declared fail set {declared}, observed {sorted(observed)}")
        else:
            print(
                f"  ok   {control['id']}: ran {len(in_group)} cases in group {group}, "
                f"failed exactly {len(declared)} declared ({', '.join(declared) or 'none'})"
            )
        if not declared:
            fail(f"{control['id']}: a negative control with an empty declared fail set is not a control")

    if problems:
        print(f"\nlifecycle-infrastructure-failure Python: FAILED, {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print(f"\nlifecycle-infrastructure-failure Python: {len(cases)}/{len(cases)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
