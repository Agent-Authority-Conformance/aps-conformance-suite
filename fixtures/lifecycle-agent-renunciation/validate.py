#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-agent-renunciation family.
#
#     python3 fixtures/lifecycle-agent-renunciation/validate.py
#     python3 fixtures/lifecycle-agent-renunciation/validate.py --sdk-support
#
# An independent reimplementation of the gate in harness.ts against the PyPI
# agent-passport-system package. It calls the real Python SDK for chain
# verification, RFC 8785 canonicalization and Ed25519 signature verification.

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent
FAMILY = "lifecycle-agent-renunciation"

UNSUPPORTED_CONCEPTS = [
    "a renunciation record from the subject of a grant",
    "a delivery instant distinct from an effective instant",
    "an effective date determined by a named recorded event",
    "a principal acceptance record, and the question of whether one is needed",
    "a not_established verdict distinct from invalid and indeterminate",
]

NAIVE_CONFIGURATIONS = {
    "defective-requires-principal-acceptance": {"requires_principal_acceptance": True},
    "defective-wrongful-renunciation-pends-liability": {"wrongful_renunciation_pends_liability": True},
    "defective-ignores-stated-effective-date": {"ignores_stated_effective_date": True},
    "defective-trusts-self-declared-role": {"trusts_self_declared_role": True},
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


def classify(label, leaf_subject, root_issuer, options):
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
    if required_role == "grant-subject":
        if event["attestor"] != leaf_subject:
            return (False, "not_from_grant_subject")
    elif required_role == "grant-principal":
        if event["attestor"] != root_issuer:
            return (False, "not_from_grant_principal")
    elif options.get("trusts_self_declared_role"):
        if event["attestor_role"] != required_role:
            return (False, "event_attestor_role_mismatch")
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

    leaf = chain[-1]
    leaf_subject = leaf["subject"]
    leaf_delegation_id = leaf["delegation_id"]
    root_issuer = chain[0]["issuer"]

    accepted = []
    for label in vector["presented_events"]:
        ok, payload = classify(label, leaf_subject, root_issuer, options)
        if ok:
            accepted.append(payload)
            notes.append(label + "=accepted")
        else:
            notes.append(label + "=rejected:" + payload)

    def of(event_type):
        return [e for e in accepted if e["event_type"] == event_type]

    renunciation = next(
        (
            e
            for e in of("agent_renunciation")
            if e["subject_ref"] == leaf_delegation_id and e["payload"].get("delivered_at") <= now
        ),
        None,
    )
    if renunciation is None:
        return finish("valid", "renunciation", "no_renunciation_presented")

    if options.get("requires_principal_acceptance"):
        acceptance = next(
            (
                e
                for e in of("principal_acceptance")
                if e["subject_ref"] == leaf_delegation_id and e["occurred_at"] <= now
            ),
            None,
        )
        if acceptance is None:
            notes.append("requires_principal_acceptance=on")
            return finish("valid", "renunciation", "no_renunciation_presented")

    if options.get("wrongful_renunciation_pends_liability"):
        agreement_ref = renunciation["payload"].get("agreement_ref")
        if isinstance(agreement_ref, str):
            agreement = next(
                (e for e in of("no_exit_agreement") if e["payload"].get("agreement_ref") == agreement_ref),
                None,
            )
            determination = next(
                (
                    e
                    for e in of("liability_determination")
                    if e["payload"].get("agreement_ref") == agreement_ref and e["occurred_at"] <= now
                ),
                None,
            )
            if agreement is not None and determination is None:
                notes.append("wrongful_renunciation_pends_liability=on")
                return finish("suspended", "renunciation", "renunciation_pending_liability")

    stated_date = renunciation["payload"].get("effective_date")
    if isinstance(stated_date, str) and not options.get("ignores_stated_effective_date"):
        if stated_date > now:
            return finish("valid", "renunciation", "renunciation_not_yet_effective")
        return finish("invalid", "renunciation", "renounced_on_stated_effective_date")

    stated_event = renunciation["payload"].get("effective_on_event")
    if isinstance(stated_event, str):
        trigger = next(
            (
                e
                for e in of(stated_event)
                if e["payload"].get("event_ref") == renunciation["payload"].get("event_ref")
                and e["occurred_at"] <= now
            ),
            None,
        )
        if trigger is None:
            return finish("valid", "renunciation", "renunciation_trigger_not_recorded")
        return finish("invalid", "renunciation", "renounced_on_recorded_event")

    return finish("invalid", "renunciation", "renounced_on_delivery")


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

    result_by_id = {v["id"]: gate(v) for v in vectors["cases"]}
    failures = 0
    passed = 0
    for vector in vectors["cases"]:
        result = result_by_id[vector["id"]]
        ok = matches(result, vector["expected"])
        details = [
            result["verdict"] + "/" + result["stage"] + "/" + result["code"]
            + " chain=" + result["chain_state"]
        ]
        if vector.get("assert_no_liability_field"):
            has_field = any(re.search("liab|fault|wrongful|breach", k, re.I) for k in result)
            ok = ok and not has_field
            details.append("no_liability_field=" + str(not has_field))
        other_id = vector.get("assert_same_code_as")
        if isinstance(other_id, str):
            other = result_by_id.get(other_id)
            same = (
                other is not None
                and other["code"] == result["code"]
                and other["verdict"] == result["verdict"]
            )
            ok = ok and same
            details.append("same_result_as_" + other_id + "=" + str(same))
        if ok:
            passed += 1
            print("PASS " + vector["id"] + " " + " ".join(details))
        else:
            failures += 1
            print("FAIL " + vector["id"], file=sys.stderr)
            print("  expected: " + json.dumps(vector["expected"], sort_keys=True), file=sys.stderr)
            print("  actual:   " + " ".join(details), file=sys.stderr)

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
