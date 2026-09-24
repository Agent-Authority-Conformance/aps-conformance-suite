#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python runner for the suspension-cause-composition family.

Runs the same sixteen cases and five gate configurations as verify.ts, against
the PyPI reference SDK rather than the npm one.

WHAT THE SDK DECIDES HERE. Two things, and only two:

  * verify_authority_delegation_chain decides the grant's chain state at each
    case's evaluation instant, which is what produces CR-12 and CR-13 and the
    chain-valid precondition of every other case.
  * canonicalize_jcs plus verify rebuild each release record's RFC 8785 preimage
    and check its Ed25519 signature.

Everything else is this file's own code, because the PyPI SDK exposes no
suspension, restriction, release or lifecycle-standing API. Its revocation
resolver answers active, revoked or unknown, and nothing else. The verdict names
exercisable, suspended, restricted, not_established and invalid are this
family's local labels, not SDK or suite vocabulary.

This file is a second implementation of the gate rules stated in README.md and
vectors.json, written from those rather than by translating harness.ts line by
line. Both were written in this lab in one sitting, so agreement between the two
is agreement between two implementations by the same author, not independent
corroboration.

No network. No third-party dependency beyond the SDK itself.

Run, with the PyPI SDK importable:

    python3 fixtures/suspension-cause-composition/validate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

GATES = {
    "reference-gate": {},
    "N1-single-suspension-flag": {"single_suspension_flag": True},
    "N2-ignores-cause-standing": {"ignore_cause_standing": True},
    "N3-release-clears-revocation": {"release_clears_revocation": True},
    "N4-standing-is-authorship": {"standing_is_authorship": True},
}


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def record_preimage(record):
    body = {k: v for k, v in record.items() if k not in ("record_id", "signature")}
    return canonicalize_jcs(body)


def signature_verifies(fixture, record):
    method = record.get("verification_method")
    public_key = fixture["verification_keys"].get(method) if isinstance(method, str) else None
    if not isinstance(public_key, str):
        return False
    try:
        return verify_ed25519(record_preimage(record), record["signature"], public_key)
    except Exception:
        return False


def apply_release(fixture, release, cause_labels, evaluated_at, options):
    """Returns (released_labels, note). A record-level rejection releases nothing."""
    if not signature_verifies(fixture, release):
        return [], "release_signature_unverified"

    if not release["verification_method"].startswith(release["releaser"] + "#"):
        return [], "release_releaser_binding_mismatch"

    if release["released_at"] > evaluated_at:
        return [], "release_after_evaluation_instant"

    cause_id_to_label = {fixture["causes"][label]["cause_id"]: label for label in cause_labels}

    released = []
    per_cause = []
    for cause_id in release["released_causes"]:
        label = cause_id_to_label.get(cause_id)
        if label is None:
            per_cause.append(f"{cause_id}:cause_not_on_grant")
            continue
        cause = fixture["causes"][label]
        if release["released_at"] < cause["imposed_at"]:
            per_cause.append(f"{label}:release_precedes_imposition")
            continue
        if options.get("ignore_cause_standing"):
            has_standing = True
        elif options.get("standing_is_authorship"):
            has_standing = release["releaser"] == cause["imposed_by"]
        else:
            has_standing = release["releaser"] in fixture["cause_standing"].get(label, [])
        if not has_standing:
            per_cause.append(f"{label}:releaser_without_standing")
            continue
        released.append(label)
        per_cause.append(f"{label}:released")

    return released, ",".join(per_cause)


def cause_stage(fixture, grant_name, presented, evaluated_at, options, chain_state):
    cause_labels = fixture["cause_sets"].get(grant_name)
    if cause_labels is None:
        raise RuntimeError(f"suspension-cause-composition: no cause set declared for {grant_name}")

    notes = []
    released = set()

    if not cause_labels:
        for label in presented:
            notes.append(f"{label}=no_cause_on_grant")
        return {
            "verdict": "exercisable",
            "stage": "causes",
            "code": "no_cause_outstanding",
            "remaining_causes": [],
            "chain_state": chain_state,
            "chain_failure_index": None,
            "notes": notes,
        }

    for label in presented:
        release = fixture["releases"].get(label)
        if release is None:
            raise RuntimeError(f"suspension-cause-composition: unknown release {label}")
        cleared, note = apply_release(fixture, release, cause_labels, evaluated_at, options)
        released.update(cleared)
        notes.append(f"{label}={note}")

    if options.get("single_suspension_flag") and released:
        released.update(cause_labels)

    remaining = sorted(label for label in cause_labels if label not in released)

    if not remaining:
        return {
            "verdict": "exercisable",
            "stage": "causes",
            "code": "all_causes_released",
            "remaining_causes": [],
            "chain_state": chain_state,
            "chain_failure_index": None,
            "notes": notes,
        }

    any_suspension = any(fixture["causes"][label]["cause_kind"] == "suspension" for label in remaining)
    return {
        "verdict": "suspended" if any_suspension else "restricted",
        "stage": "causes",
        "code": "causes_outstanding",
        "remaining_causes": remaining,
        "chain_state": chain_state,
        "chain_failure_index": None,
        "notes": notes,
    }


def evaluate(fixture, grant_name, presented, evaluated_at, revocation, options):
    chain = fixture["chains"].get(grant_name)
    if chain is None:
        raise RuntimeError(f"suspension-cause-composition: unknown grant {grant_name}")

    result = verify_authority_delegation_chain(
        chain,
        now=evaluated_at,
        resolve_verification_key=lambda _issuer, method, _issued_at: fixture["verification_keys"].get(method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: revocation,
    )
    first = result.failures[0] if result.failures else None
    chain_failure_index = first.index if first is not None else None

    if result.state != "valid":
        if options.get("release_clears_revocation"):
            after_release = cause_stage(fixture, grant_name, presented, evaluated_at, options, result.state)
            if not after_release["remaining_causes"]:
                after_release["chain_failure_index"] = chain_failure_index
                return after_release
        return {
            "verdict": "invalid" if result.state == "invalid" else "not_established",
            "stage": "chain",
            "code": first.code if first is not None else "CHAIN_NOT_VALID",
            "remaining_causes": [],
            "chain_state": result.state,
            "chain_failure_index": chain_failure_index,
            "notes": [],
        }

    return cause_stage(fixture, grant_name, presented, evaluated_at, options, result.state)


def revocation_within_suspension_window(fixture, case):
    cause_labels = fixture["cause_sets"].get(case["grant"], [])
    if not cause_labels or not case["presented_releases"]:
        return False
    latest_imposition = max(fixture["causes"][label]["imposed_at"] for label in cause_labels)
    earliest_release = min(fixture["releases"][label]["released_at"] for label in case["presented_releases"])
    note = fixture["revocation_timeline_note"]
    return (
        note["grant_delegation_id"] == fixture["roles"]["PRINCIPAL_TO_AGENT"]
        and note["recorded_at"] > latest_imposition
        and note["recorded_at"] < earliest_release
    )


def matches(actual, expected):
    if actual["verdict"] != expected["verdict"]:
        return False
    if actual["stage"] != expected["stage"]:
        return False
    if actual["code"] != expected["code"]:
        return False
    if actual["remaining_causes"] != expected["remaining_causes"]:
        return False
    if "chain_state" in expected and actual["chain_state"] != expected["chain_state"]:
        return False
    if "chain_failure_index" in expected and actual["chain_failure_index"] != expected["chain_failure_index"]:
        return False
    return True


def main():
    fixture = read_json("chain.json")
    vectors = read_json("vectors.json")

    causes = fixture.get("causes", {})
    guards = [
        ("chain.json has a clock", isinstance(fixture.get("clock"), dict) and bool(fixture["clock"])),
        ("chain.json has verification keys", bool(fixture.get("verification_keys"))),
        (
            "chain.json has a cause-standing registry for all three causes",
            all(bool(fixture.get("cause_standing", {}).get(label)) for label in ("REG", "FIRM", "DECREE")),
        ),
        ("GRANT carries exactly three causes", len(fixture["cause_sets"].get("GRANT", [])) == 3),
        ("GRANT_CLEAN carries no cause", fixture["cause_sets"].get("GRANT_CLEAN") == []),
        (
            "chain.json has both chains",
            bool(fixture["chains"].get("GRANT")) and bool(fixture["chains"].get("GRANT_CLEAN")),
        ),
        ("chain.json has three cause records", len(causes) == 3),
        (
            "two causes are suspensions and one is a restriction",
            sum(1 for c in causes.values() if c["cause_kind"] == "suspension") == 2
            and sum(1 for c in causes.values() if c["cause_kind"] == "restriction") == 1,
        ),
        ("chain.json has eleven release records", len(fixture.get("releases", {})) == 11),
        (
            "every case is labelled candidate_against_proposed",
            all(case["status"] == "candidate_against_proposed" for case in vectors["cases"]),
        ),
        ("vectors.json is labelled candidate_against_proposed", vectors["status"] == "candidate_against_proposed"),
        (
            "vectors.json names the proposed text it tests",
            isinstance(vectors.get("proposed_text", {}).get("commit"), str),
        ),
    ]
    broken = [name for name, ok in guards if not ok]
    if broken:
        for name in broken:
            print(f"suspension-cause-composition structural guard failed: {name}", file=sys.stderr)
        return 2

    exit_code = 0
    summary = []

    for case in vectors["cases"]:
        if case.get("assert_revocation_within_suspension_window") is not True:
            continue
        if revocation_within_suspension_window(fixture, case):
            print(f"STRUCT  {case['id']}: revocation instant falls inside the suspension window")
        else:
            exit_code = 1
            print(
                f"STRUCT  FAIL {case['id']}: revocation instant is not inside the suspension window",
                file=sys.stderr,
            )
    print()

    for gate in vectors["gates"]:
        options = GATES.get(gate["name"])
        if options is None:
            print(
                f"suspension-cause-composition: vectors.json names gate {gate['name']}, this runner has no such gate",
                file=sys.stderr,
            )
            return 2

        observed = []
        for case in vectors["cases"]:
            evaluated_at = fixture["clock"].get(case["evaluated_at"])
            if not isinstance(evaluated_at, str):
                print(
                    f"suspension-cause-composition: no clock entry named {case['evaluated_at']}",
                    file=sys.stderr,
                )
                return 2
            actual = evaluate(
                fixture,
                case["grant"],
                case["presented_releases"],
                evaluated_at,
                case["revocation"],
                options,
            )
            ok = matches(actual, case["expected"])
            if not ok:
                observed.append(case["id"])
            label = "MATCH  " if ok else "DIVERGE"
            remaining = "+".join(actual["remaining_causes"]) if actual["remaining_causes"] else "none"
            note = f" [{' '.join(actual['notes'])}]" if actual["notes"] else ""
            print(
                f"{label} {gate['name']} {case['id']} -> "
                f"{actual['verdict']}/{actual['stage']}/{actual['code']} remaining={remaining}{note}"
            )
            if not ok:
                exp = case["expected"]
                exp_remaining = "+".join(exp["remaining_causes"]) if exp["remaining_causes"] else "none"
                print(
                    f"         expected {exp['verdict']}/{exp['stage']}/{exp['code']} remaining={exp_remaining}"
                )

        declared = sorted(gate["declared_failing_cases"])
        if declared == sorted(observed):
            failing = ", ".join(sorted(observed)) if observed else "empty"
            summary.append(
                f"  ok   {gate['name']}: {len(vectors['cases']) - len(observed)}/{len(vectors['cases'])} matched, "
                f"failing set {failing} as declared"
            )
        else:
            exit_code = 1
            summary.append(
                f"  FAIL {gate['name']}: declared [{', '.join(declared)}] observed [{', '.join(sorted(observed))}]"
            )
        print()

    print("suspension-cause-composition gate summary (python)")
    for line in summary:
        print(line)
    print()
    if exit_code == 0:
        print(
            "PASSED: reference-gate matched every case, N1, N2, N3 and N4 each failed "
            "exactly their declared set (python)"
        )
    else:
        print("FAILED: at least one gate diverged from its declared failing set (python)", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
