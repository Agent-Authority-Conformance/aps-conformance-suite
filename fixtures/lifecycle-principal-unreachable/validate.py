#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-principal-unreachable family.
#
#     python3 fixtures/lifecycle-principal-unreachable/validate.py
#     python3 fixtures/lifecycle-principal-unreachable/validate.py --sdk-support
#
# An independent reimplementation of the gate in harness.ts against the PyPI
# agent-passport-system package. It calls the real Python SDK for chain
# verification, RFC 8785 canonicalization and Ed25519 signature verification.

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent
FAMILY = "lifecycle-principal-unreachable"

UNSUPPORTED_CONCEPTS = [
    "a confirmation procedure declared on a grant for a named action class",
    "a per-action confirmation record naming a procedure and an order",
    "an unreachability observation, or a deadline-elapsed observation",
    "a not_established verdict for one action under an otherwise exercisable grant",
    "a not_established verdict distinct from invalid and indeterminate",
]

NAIVE_CONFIGURATIONS = {
    "defective-silence-after-deadline-is-approval": {"silence_after_deadline_is_approval": True},
    "defective-unreachable-is-denial": {"unreachable_is_denial": True},
    "defective-accepts-confirmation-from-any-party": {"accepts_confirmation_from_any_party": True},
    "defective-ignores-confirmation-binding": {"ignores_confirmation_binding": True},
    "defective-accepts-confirmation-after-the-action": {"accepts_confirmation_after_the_action": True},
}


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")


def record_preimage(record, drop_keys):
    return canonicalize_jcs({k: v for k, v in record.items() if k not in drop_keys})


def signature_ok(record, drop_keys):
    public_key = fixture["verification_keys"].get(record.get("verification_method"))
    if not isinstance(public_key, str):
        return False
    try:
        return bool(verify_ed25519(record_preimage(record, drop_keys), record["signature"], public_key))
    except Exception:
        return False


def classify(label, required_confirmer, options):
    event = fixture["events"].get(label)
    if event is None:
        return (False, "event_record_unknown")
    if not signature_ok(event, {"event_id", "signature"}):
        return (False, "event_signature_unverified")
    if not event["verification_method"].startswith(event["attestor"] + "#"):
        return (False, "event_attestor_binding_mismatch")
    required_role = fixture["event_standing"].get(event["event_type"])
    if not isinstance(required_role, str):
        return (False, "event_type_has_no_declared_standing")
    if required_role == "grant-principal":
        if (
            not options.get("accepts_confirmation_from_any_party")
            and event["attestor"] != required_confirmer
        ):
            return (False, "confirmation_source_not_accepted")
    else:
        registered = fixture["attestor_role_registry"].get(event["attestor"])
        if not isinstance(registered, str) or registered != event["attestor_role"]:
            return (False, "event_role_claim_conflict")
        if registered != required_role:
            return (False, "event_attestor_role_mismatch")
    return (True, event)


def gate(vector, options=None):
    options = options or {}
    chain = fixture["chains"][vector["grant"]]
    now = fixture["clock"][vector["action_at"]]
    notes = []

    chain_result = verify_authority_delegation_chain(
        chain,
        now=now,
        resolve_verification_key=lambda _i, m, _t: fixture["verification_keys"].get(m),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _d: vector["revocation"],
    )
    chain_state = chain_result.state
    first = chain_result.failures[0] if chain_result.failures else None

    def finish(verdict, stage, code):
        return {
            "verdict": verdict,
            "stage": stage,
            "code": code,
            "chain_state": chain_state,
            "chain_failure_index": first.index if first is not None else None,
            "notes": notes,
        }

    if chain_state != "valid":
        return finish(
            "invalid" if chain_state == "invalid" else "not_established",
            "chain",
            first.code if first is not None else "chain_" + chain_state,
        )

    terms_record = fixture["grant_terms"].get(fixture["terms_by_chain"].get(vector["grant"]))
    if terms_record is None:
        return finish("not_established", "terms", "grant_terms_unknown")
    if not signature_ok(terms_record, {"terms_id", "signature"}):
        return finish("not_established", "terms", "grant_terms_signature_unverified")
    named = next((m for m in chain if m["delegation_id"] == terms_record["delegation_id"]), None)
    if named is None or named["issuer"] != terms_record["issuer"]:
        return finish("not_established", "terms", "grant_terms_not_bound_to_chain")

    procedure = terms_record["terms"].get("confirmation_procedure")
    if not isinstance(procedure, dict) or vector["action_class"] not in procedure.get(
        "applies_to_action_classes", []
    ):
        return finish("valid", "confirmation", "no_confirmation_required")

    accepted = []
    for label in vector["presented_events"]:
        ok, payload = classify(label, procedure["required_confirmer"], options)
        if ok:
            accepted.append(payload)
            notes.append(label + "=accepted")
        else:
            notes.append(label + "=rejected:" + payload)

    def of(event_type):
        return [e for e in accepted if e["event_type"] == event_type]

    bound = [
        e
        for e in of("principal_confirmation")
        if options.get("ignores_confirmation_binding")
        or (
            e["payload"].get("procedure_id") == procedure["procedure_id"]
            and e["payload"].get("order_ref") == vector["order_ref"]
        )
    ]
    covering = [
        e
        for e in bound
        if options.get("accepts_confirmation_after_the_action")
        or e["payload"].get("confirmed_at") <= now
    ]
    if covering:
        return finish("valid", "confirmation", "confirmation_procedure_completed")
    if bound:
        return finish("not_established", "confirmation", "confirmation_after_action")

    deadline_passed = next(
        (
            e
            for e in of("deadline_elapsed_observation")
            if e["payload"].get("order_ref") == vector["order_ref"] and e["occurred_at"] <= now
        ),
        None,
    )
    if deadline_passed is not None and options.get("silence_after_deadline_is_approval"):
        notes.append("silence_after_deadline_is_approval=on")
        return finish("valid", "confirmation", "confirmation_procedure_completed")

    unreachable = next(
        (
            e
            for e in of("unreachability_observation")
            if e["payload"].get("order_ref") == vector["order_ref"] and e["occurred_at"] <= now
        ),
        None,
    )
    if unreachable is not None and options.get("unreachable_is_denial"):
        notes.append("unreachable_is_denial=on")
        return finish("invalid", "confirmation", "unreachable_principal_denied")
    if unreachable is not None:
        notes.append("unreachability_recorded")

    return finish("not_established", "confirmation", "confirmation_procedure_not_completed")


def matches(result, expected):
    return (
        result["verdict"] == expected["verdict"]
        and result["stage"] == expected["stage"]
        and result["code"] == expected["code"]
    )


def sdk_support():
    try:
        from importlib.metadata import version

        sdk_version = version("agent-passport-system")
    except Exception:
        sdk_version = "unknown"
    print("PyPI agent-passport-system " + sdk_version)
    print()
    for vector in vectors["cases"]:
        chain_result = verify_authority_delegation_chain(
            fixture["chains"][vector["grant"]],
            now=fixture["clock"][vector["action_at"]],
            resolve_verification_key=lambda _i, m, _t: fixture["verification_keys"].get(m),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _d: vector["revocation"],
        )
        code = chain_result.failures[0].code if chain_result.failures else "none"
        signatures = [
            label + "=" + str(signature_ok(fixture["events"][label], {"event_id", "signature"}))
            for label in vector["presented_events"]
        ]
        print(vector["id"])
        print(
            "  verify_authority_delegation_chain: supported, state="
            + chain_result.state + " code=" + code
        )
        print(
            "  verify + canonicalize_jcs over event bytes: supported, "
            + (" ".join(signatures) if signatures else "no event presented")
        )
        print("  lifecycle verdict: not_supported, no SDK API for: " + "; ".join(UNSUPPORTED_CONCEPTS))
    print()
    print(FAMILY + " PyPI SDK observations: " + str(len(vectors["cases"])) + " vectors recorded")
    return 0


def main():
    if "--sdk-support" in sys.argv:
        return sdk_support()
    failures = 0
    passed = 0
    for vector in vectors["cases"]:
        result = gate(vector)
        if matches(result, vector["expected"]):
            passed += 1
            print(
                "PASS " + vector["id"] + " " + result["verdict"] + "/" + result["stage"] + "/"
                + result["code"] + " chain=" + result["chain_state"]
            )
        else:
            failures += 1
            print("FAIL " + vector["id"], file=sys.stderr)
            print("  expected: " + json.dumps(vector["expected"], sort_keys=True), file=sys.stderr)
            print("  actual:   " + json.dumps(result, sort_keys=True), file=sys.stderr)
    print()
    print(FAMILY + " reference gate: " + str(passed) + "/" + str(len(vectors["cases"])) + " passed")

    control_failures = 0
    for name, options in NAIVE_CONFIGURATIONS.items():
        declared = vectors["declared_fail_sets"].get(name)
        if declared is None:
            print("FAIL negative-control " + name + ": no declared fail set", file=sys.stderr)
            control_failures += 1
            continue
        observed = sorted(
            v["id"] for v in vectors["cases"] if not matches(gate(v, options), v["expected"])
        )
        if observed == sorted(declared):
            print(
                "PASS negative-control " + name + " fails " + str(len(observed))
                + " vector(s) as declared"
            )
        else:
            control_failures += 1
            print("FAIL negative-control " + name, file=sys.stderr)
            print("  declared: " + json.dumps(sorted(declared)), file=sys.stderr)
            print("  observed: " + json.dumps(observed), file=sys.stderr)

    total = len(NAIVE_CONFIGURATIONS)
    print(
        FAMILY + " negative controls: " + str(total - control_failures) + "/" + str(total)
        + " behaved as declared"
    )
    print(
        FAMILY + " Python: " + str(passed) + "/" + str(len(vectors["cases"])) + " vectors, "
        + str(total - control_failures) + "/" + str(total) + " negative controls"
    )
    return 0 if failures == 0 and control_failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
