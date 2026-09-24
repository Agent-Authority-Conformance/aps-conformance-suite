#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-root-authority-succession family.
#
#     python3 fixtures/lifecycle-root-authority-succession/validate.py
#     python3 fixtures/lifecycle-root-authority-succession/validate.py --sdk-support
#
# An independent reimplementation of the gate in harness.ts against the PyPI
# agent-passport-system package. It calls the real Python SDK for chain
# verification, RFC 8785 canonicalization and Ed25519 signature verification,
# and implements everything the SDK has no API for.

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent
FAMILY = "lifecycle-root-authority-succession"

UNSUPPORTED_CONCEPTS = [
    "a subject-binding mode declared on a delegation (office bound against identity bound)",
    "an office-holder registry, or a lookup of who occupies an office at an instant",
    "an office-vacancy record",
    "an actor distinct from the delegation subject named in the record",
    "a not_established verdict distinct from invalid and indeterminate",
]

NAIVE_CONFIGURATIONS = {
    "defective-silent-binding-defaults-to-role": {"silent_binding_defaults_to_role": True},
    "defective-silent-binding-defaults-to-identity": {"silent_binding_defaults_to_identity": True},
    "defective-role-bound-needs-reissuance": {"role_bound_needs_reissuance": True},
    "defective-identity-bound-follows-the-office": {"identity_bound_follows_the_office": True},
    "defective-vacancy-defaults-to-last-known-holder": {"vacancy_defaults_to_last_known_holder": True},
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


def classify(label, options):
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
    if options.get("trusts_self_declared_role"):
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

    leaf_subject = chain[-1]["subject"]
    terms_record = fixture["grant_terms"].get(fixture["terms_by_chain"].get(vector["grant"]))
    if terms_record is None:
        return finish("not_established", "terms", "grant_terms_unknown")
    if not signature_ok(terms_record, {"terms_id", "signature"}):
        return finish("not_established", "terms", "grant_terms_signature_unverified")
    named = next((m for m in chain if m["delegation_id"] == terms_record["delegation_id"]), None)
    if named is None or named["issuer"] != terms_record["issuer"]:
        return finish("not_established", "terms", "grant_terms_not_bound_to_chain")
    terms = terms_record["terms"]

    accepted = []
    for label in vector["presented_events"]:
        ok, payload = classify(label, options)
        if ok:
            accepted.append(payload)
            notes.append(label + "=accepted")
        else:
            notes.append(label + "=rejected:" + payload)

    mode = terms.get("subject_binding_mode")
    if not isinstance(mode, str):
        if vector["actor"] == leaf_subject:
            return finish("valid", "binding", "actor_is_the_named_subject")
        if options.get("silent_binding_defaults_to_role"):
            mode = "role_bound"
            notes.append("silent_binding_defaults_to_role=on")
        elif options.get("silent_binding_defaults_to_identity"):
            mode = "identity_bound"
            notes.append("silent_binding_defaults_to_identity=on")
        else:
            return finish("not_established", "binding", "subject_binding_mode_not_declared")

    if mode == "identity_bound" and not options.get("identity_bound_follows_the_office"):
        if vector["actor"] == leaf_subject:
            return finish("valid", "binding", "identity_bound_subject_acting")
        return finish("invalid", "binding", "identity_bound_no_transfer")
    if mode == "role_bound" and options.get("role_bound_needs_reissuance"):
        if vector["actor"] == leaf_subject:
            return finish("valid", "binding", "identity_bound_subject_acting")
        return finish("invalid", "binding", "identity_bound_no_transfer")

    office_ref = terms.get("office_ref") or leaf_subject
    keep_last_known = bool(options.get("vacancy_defaults_to_last_known_holder"))
    vacancy = next(
        (
            e
            for e in accepted
            if e["event_type"] == "office_vacancy"
            and e["payload"].get("office_ref") == office_ref
            and e["payload"].get("from") <= now < e["payload"].get("through")
        ),
        None,
    )
    if vacancy is not None and not keep_last_known:
        return finish("not_established", "binding", "office_holder_not_established")
    covering = [
        e
        for e in accepted
        if e["event_type"] == "office_holder_record"
        and e["payload"].get("office_ref") == office_ref
        and e["payload"].get("from") <= now
        and (keep_last_known or e["payload"].get("through") > now)
    ]
    if not covering:
        return finish("not_established", "binding", "office_holder_not_established")
    if any(e["payload"].get("holder") == vector["actor"] for e in covering):
        return finish("valid", "binding", "role_bound_current_occupant")
    return finish("invalid", "binding", "not_the_current_office_holder")


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
