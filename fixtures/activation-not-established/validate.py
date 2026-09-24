#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python runner for the activation-not-established family.

Runs the same nineteen cases and five gate configurations as verify.ts, against
the PyPI reference SDK rather than the npm one.

v2. The family asserts two distinct negative verdicts:

  not_yet_effective  the verifier establishes, from evidence the model accepts,
                     that the condition had not been met at the action instant
  not_established    the verifier cannot tell whether it was met, because
                     nothing usable was presented, because the only evidence
                     comes from a source the model does not accept for the
                     condition, or because two acceptable records disagree

Neither is invalid and neither is exercisable. Gate N4 is the control that pins
them apart.

WHAT THE SDK DECIDES HERE. Two things, and only two:

  * verify_authority_delegation_chain decides the grant's chain state at each
    case's action instant, which is what produces AX-17, AX-18 and AX-19 and the
    chain-valid precondition of every other case.
  * canonicalize_jcs plus verify rebuild each attestation's RFC 8785 preimage and
    check its Ed25519 signature.

Everything else is this file's own code, because the PyPI SDK exposes no
activation-condition, attestor-role or attestation-acceptance API. The verdict
names exercisable, not_yet_effective, not_established and invalid are this
family's local labels, not SDK or suite vocabulary.

This file is a second implementation of the gate rules stated in README.md and
vectors.json, written from those rather than by translating harness.ts line by
line. Both were written in this lab by the same author, so agreement between the
two is agreement between two implementations by one author, not independent
corroboration.

No network. No third-party dependency beyond the SDK itself.

Run, with the PyPI SDK importable:

    python3 fixtures/activation-not-established/validate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

# Rejection reasons in check order. An attestation that fails one of these is
# not evidence in either direction. The reported code is the reason of the
# attestation that got furthest through the checks, ties broken by
# attestation_id ascending, so the answer does not depend on presentation order.
REASON_RANK = {
    "attestation_signature_unverified": 1,
    "attestation_attestor_binding_mismatch": 2,
    "attestation_role_claim_conflict": 3,
    "attestation_attestor_role_mismatch": 4,
    "attestation_condition_mismatch": 5,
    "attestation_unknown_assertion": 6,
    "attestation_does_not_reach_action": 7,
}

GATES = {
    "reference-gate": {},
    "N1-trusts-self-declared-role": {"trust_self_declared_role": True},
    "N2-keys-on-attestation-date": {"key_on_attestation_date": True},
    "N3-collapses-not-established-into-invalid": {"collapse_not_established_into_invalid": True},
    "N4-collapses-not-yet-effective-into-not-established": {
        "collapse_not_yet_effective_into_not_established": True
    },
}


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def attestation_preimage(attestation):
    body = {k: v for k, v in attestation.items() if k not in ("attestation_id", "signature")}
    return canonicalize_jcs(body)


def apply_collapses(verdict, options):
    if verdict == "not_established" and options.get("collapse_not_established_into_invalid"):
        return "invalid"
    if verdict == "not_yet_effective" and options.get("collapse_not_yet_effective_into_not_established"):
        if options.get("collapse_not_established_into_invalid"):
            return "invalid"
        return "not_established"
    return verdict


def classify(fixture, attestation, condition, action_at, options):
    """Return (finding, None) for accepted evidence, or (None, reason)."""
    public_key = fixture["verification_keys"].get(attestation["verification_method"])
    if not isinstance(public_key, str):
        return None, "attestation_signature_unverified"
    try:
        signature_ok = verify_ed25519(attestation_preimage(attestation), attestation["signature"], public_key)
    except Exception:
        signature_ok = False
    if not signature_ok:
        return None, "attestation_signature_unverified"

    if not attestation["verification_method"].startswith(attestation["attestor"] + "#"):
        return None, "attestation_attestor_binding_mismatch"

    # The registry is authoritative about a role. A source the model does not
    # accept for this condition is not evidence in either direction: it cannot
    # establish the condition and it cannot establish that the condition was
    # unmet.
    registered_role = fixture["attestor_role_registry"].get(attestation["attestor"])
    if options.get("trust_self_declared_role"):
        if attestation["attestor_role"] != condition["required_attestor_role"]:
            return None, "attestation_attestor_role_mismatch"
    else:
        if not isinstance(registered_role, str) or registered_role != attestation["attestor_role"]:
            return None, "attestation_role_claim_conflict"
        if registered_role != condition["required_attestor_role"]:
            return None, "attestation_attestor_role_mismatch"

    if (
        attestation["condition_id"] != condition["condition_id"]
        or attestation["event_type"] != condition["event_type"]
        or attestation["event_id"] != condition["event_id"]
    ):
        return None, "attestation_condition_mismatch"

    # What the record establishes, measured on the condition's own instants. The
    # instant the record was written is never compared with the action instant
    # by the reference gate.
    assertion = attestation.get("assertion")
    if assertion == "condition_occurred":
        if options.get("key_on_attestation_date"):
            written = attestation.get("attested_at")
            if not isinstance(written, str):
                return None, "attestation_unknown_assertion"
            if written > action_at:
                return None, "attestation_does_not_reach_action"
            return "occurred_by_action", None
        occurred_at = attestation.get("occurred_at")
        if not isinstance(occurred_at, str):
            return None, "attestation_unknown_assertion"
        if occurred_at <= action_at:
            return "occurred_by_action", None
        return "occurred_after_action", None

    if assertion == "condition_not_occurred_through":
        through = attestation.get("not_occurred_through")
        if not isinstance(through, str):
            return None, "attestation_unknown_assertion"
        if through < action_at:
            return None, "attestation_does_not_reach_action"
        return "not_occurred_through_action", None

    return None, "attestation_unknown_assertion"


def evaluate(fixture, grant_name, presented, action_at, revocation, options):
    chain = fixture["chains"].get(grant_name)
    if chain is None:
        raise RuntimeError(f"activation-not-established: unknown grant {grant_name}")

    result = verify_authority_delegation_chain(
        chain,
        now=action_at,
        resolve_verification_key=lambda _issuer, method, _issued_at: fixture["verification_keys"].get(method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: revocation,
    )
    first = result.failures[0] if result.failures else None
    chain_failure_index = first.index if first is not None else None

    if result.state != "valid":
        return {
            "verdict": "invalid" if result.state == "invalid" else "not_established",
            "stage": "chain",
            "code": first.code if first is not None else "CHAIN_NOT_VALID",
            "chain_state": result.state,
            "chain_failure_index": chain_failure_index,
            "notes": [],
        }

    condition = fixture["activation_conditions"].get(grant_name)
    if condition is None:
        return {
            "verdict": "exercisable",
            "stage": "activation",
            "code": "no_activation_condition",
            "chain_state": result.state,
            "chain_failure_index": None,
            "notes": [],
        }

    base = {
        "stage": "activation",
        "chain_state": result.state,
        "chain_failure_index": None,
    }

    # A date condition needs no evidence. The verifier reads the date and
    # compares it with the action instant, so an unreached date is a known
    # negative and never an unknown one.
    if condition.get("condition_type") == "date":
        reached = action_at >= condition["activation_date"]
        return dict(
            base,
            verdict=apply_collapses("exercisable" if reached else "not_yet_effective", options),
            code="activation_established" if reached else "condition_date_not_reached",
            notes=[f"{label}=not_consulted_date_condition" for label in presented],
        )

    notes = []
    rejections = []
    findings = set()
    for label in presented:
        attestation = fixture["attestations"].get(label)
        if attestation is None:
            raise RuntimeError(f"activation-not-established: unknown attestation {label}")
        finding, reason = classify(fixture, attestation, condition, action_at, options)
        if finding is not None:
            findings.add(finding)
            notes.append(f"{label}={finding}")
        else:
            rejections.append((attestation["attestation_id"], reason))
            notes.append(f"{label}={reason}")

    base["notes"] = notes

    # Two acceptable records that contradict each other about the action instant
    # leave the verifier unable to tell.
    if "occurred_by_action" in findings and "not_occurred_through_action" in findings:
        return dict(
            base,
            verdict=apply_collapses("not_established", options),
            code="condition_evidence_conflict",
        )

    if "occurred_by_action" in findings:
        return dict(base, verdict="exercisable", code="activation_established")

    if "not_occurred_through_action" in findings:
        return dict(
            base,
            verdict=apply_collapses("not_yet_effective", options),
            code="condition_established_not_yet_occurred",
        )

    if "occurred_after_action" in findings:
        return dict(
            base,
            verdict=apply_collapses("not_yet_effective", options),
            code="condition_first_occurred_after_action",
        )

    code = "no_attestation_presented"
    if rejections:
        code = sorted(rejections, key=lambda pair: (-REASON_RANK.get(pair[1], 0), pair[0]))[0][1]

    return dict(base, verdict=apply_collapses("not_established", options), code=code)


def matches(actual, expected):
    if actual["verdict"] != expected["verdict"]:
        return False
    if actual["stage"] != expected["stage"]:
        return False
    if actual["code"] != expected["code"]:
        return False
    if "chain_state" in expected and actual["chain_state"] != expected["chain_state"]:
        return False
    if "chain_failure_index" in expected and actual["chain_failure_index"] != expected["chain_failure_index"]:
        return False
    return True


def main():
    fixture = read_json("chain.json")
    vectors = read_json("vectors.json")

    conditions = fixture.get("activation_conditions", {})
    guards = [
        ("chain.json has a clock", isinstance(fixture.get("clock"), dict) and bool(fixture["clock"])),
        ("chain.json has verification keys", bool(fixture.get("verification_keys"))),
        ("chain.json has an attestor-role registry", bool(fixture.get("attestor_role_registry"))),
        (
            "chain.json declares a recorded-event activation condition for GRANT",
            (conditions.get("GRANT") or {}).get("condition_type") == "recorded_event",
        ),
        (
            "chain.json declares a date activation condition for GRANT_DATED",
            (conditions.get("GRANT_DATED") or {}).get("condition_type") == "date",
        ),
        (
            "chain.json declares no activation condition for GRANT_FUTURE_WINDOW",
            conditions.get("GRANT_FUTURE_WINDOW") is None,
        ),
        (
            "chain.json has all three chains",
            all(bool(fixture["chains"].get(name)) for name in ("GRANT", "GRANT_DATED", "GRANT_FUTURE_WINDOW")),
        ),
        ("chain.json has ten attestations", len(fixture.get("attestations", {})) == 10),
        (
            "every case is labelled candidate_against_proposed",
            all(case["status"] == "candidate_against_proposed" for case in vectors["cases"]),
        ),
        ("vectors.json is labelled candidate_against_proposed", vectors["status"] == "candidate_against_proposed"),
        # v2's whole point. A vectors.json that lost one of the two negative
        # verdicts, or the gate that pins them apart, must stop the run rather
        # than report a pass for the collapsed rule v1 encoded.
        (
            "vectors.json asserts at least one not_yet_effective case",
            any(case["expected"]["verdict"] == "not_yet_effective" for case in vectors["cases"]),
        ),
        (
            "vectors.json asserts at least one not_established case at the activation stage",
            any(
                case["expected"]["verdict"] == "not_established" and case["expected"]["stage"] == "activation"
                for case in vectors["cases"]
            ),
        ),
        (
            "vectors.json declares the gate that collapses not_yet_effective into not_established",
            any(
                gate["name"] == "N4-collapses-not-yet-effective-into-not-established"
                for gate in vectors["gates"]
            ),
        ),
    ]
    broken = [name for name, ok in guards if not ok]
    if broken:
        for name in broken:
            print(f"activation-not-established structural guard failed: {name}", file=sys.stderr)
        return 2

    exit_code = 0
    summary = []

    for gate in vectors["gates"]:
        options = GATES.get(gate["name"])
        if options is None:
            print(
                f"activation-not-established: vectors.json names gate {gate['name']}, this runner has no such gate",
                file=sys.stderr,
            )
            return 2

        observed = []
        for case in vectors["cases"]:
            action_at = fixture["clock"].get(case["action_at"])
            if not isinstance(action_at, str):
                print(f"activation-not-established: no clock entry named {case['action_at']}", file=sys.stderr)
                return 2
            actual = evaluate(
                fixture,
                case["grant"],
                case["presented_attestations"],
                action_at,
                case["revocation"],
                options,
            )
            ok = matches(actual, case["expected"])
            if not ok:
                observed.append(case["id"])
            label = "MATCH  " if ok else "DIVERGE"
            note = f" [{' '.join(actual['notes'])}]" if actual["notes"] else ""
            print(f"{label} {gate['name']} {case['id']} -> {actual['verdict']}/{actual['stage']}/{actual['code']}{note}")
            if not ok:
                exp = case["expected"]
                print(f"         expected {exp['verdict']}/{exp['stage']}/{exp['code']}")

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

    print("activation-not-established gate summary (python)")
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
