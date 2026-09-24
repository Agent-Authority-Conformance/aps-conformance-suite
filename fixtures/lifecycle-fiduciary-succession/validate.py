#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-fiduciary-succession family.
#
#     python3 fixtures/lifecycle-fiduciary-succession/validate.py
#     python3 fixtures/lifecycle-fiduciary-succession/validate.py --sdk-support
#
# An independent reimplementation of the gate in harness.ts against the PyPI
# agent-passport-system package, not a port that shares code with it. It calls
# the real Python SDK for chain verification, RFC 8785 canonicalization and
# Ed25519 signature verification, and implements everything the SDK has no API
# for; --sdk-support records exactly which concepts those are.

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent
FAMILY = "lifecycle-fiduciary-succession"

UNSUPPORTED_CONCEPTS = [
    "an instrument naming co-holders, and a quorum rule over the holders current at an instant",
    "a holder-vacancy record, or a distinction between named holders and current holders",
    "a mandate class narrower than the grant it sits on, ending on an external event",
    "ratification as a mechanism distinct from issuance and from revocation",
    "atomicity of a ratification over the components of one integrated act",
    "a capacity finding about the principal, bound to the instant of ratifying",
    "an intervening third-party interest record, or a restricted verdict for one",
    "an evaluation instant separate from the action instant",
    "a not_established verdict distinct from invalid and indeterminate",
]

NAIVE_CONFIGURATIONS = {
    "defective-counts-approval-from-vacated-holder": {"counts_approval_from_vacated_holder": True},
    "defective-requires-unanimity-of-named-holders": {"requires_unanimity_of_named_holders": True},
    "defective-requires-backfill-before-acting": {"requires_backfill_before_acting": True},
    "defective-temporary-admin-has-full-successor-powers": {
        "temporary_admin_has_full_successor_powers": True
    },
    "defective-revoke-only": {"revoke_only": True},
    "defective-ratification-reaches-intervening-interest": {
        "ratification_reaches_intervening_interest": True
    },
    "defective-accepts-partial-ratification": {"accepts_partial_ratification": True},
    "defective-ignores-capacity-at-ratification": {"ignores_capacity_at_ratification": True},
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


def classify(label, root_issuer, co_holders, evaluated_at, options):
    event = fixture["events"].get(label)
    if event is None:
        return (False, "event_record_unknown")
    if not signature_ok(event, {"event_id", "signature"}):
        return (False, "event_signature_unverified")
    if not event["verification_method"].startswith(event["attestor"] + "#"):
        return (False, "event_attestor_binding_mismatch")
    if event["recorded_at"] > evaluated_at:
        return (False, "event_recorded_after_evaluation")
    required_role = fixture["event_standing"].get(event["event_type"])
    if not isinstance(required_role, str):
        return (False, "event_type_has_no_declared_standing")
    if required_role == "grant-principal":
        if event["attestor"] != root_issuer:
            return (False, "not_from_grant_principal")
    elif required_role == "named-co-holder":
        if event["attestor"] not in co_holders:
            return (False, "not_a_named_co_holder")
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
    action_at = fixture["clock"][vector["action_at"]]
    evaluated_at = fixture["clock"][vector["evaluated_at"]]
    notes = ["action_at=" + vector["action_at"] + " evaluated_at=" + vector["evaluated_at"]]

    chain_result = verify_authority_delegation_chain(
        chain,
        now=action_at,
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
    root_issuer = chain[0]["issuer"]

    terms_record = fixture["grant_terms"].get(fixture["terms_by_chain"].get(vector["grant"]))
    if terms_record is None:
        return finish("not_established", "terms", "grant_terms_unknown")
    if not signature_ok(terms_record, {"terms_id", "signature"}):
        return finish("not_established", "terms", "grant_terms_signature_unverified")
    named = next((m for m in chain if m["delegation_id"] == terms_record["delegation_id"]), None)
    if named is None or named["issuer"] != terms_record["issuer"]:
        return finish("not_established", "terms", "grant_terms_not_bound_to_chain")
    terms = terms_record["terms"]
    co_holders = terms.get("co_holders") if isinstance(terms.get("co_holders"), list) else []

    accepted = []
    for label in vector["presented_events"]:
        ok, payload = classify(label, root_issuer, co_holders, evaluated_at, options)
        if ok:
            accepted.append(payload)
            notes.append(label + "=accepted")
        else:
            notes.append(label + "=rejected:" + payload)

    def of(event_type):
        return [e for e in accepted if e["event_type"] == event_type]

    # quorum over the co-holders of one instrument
    if co_holders:
        vacated = {e["subject_ref"] for e in of("holder_vacancy") if e["occurred_at"] <= action_at}
        if leaf_subject in vacated:
            return finish("invalid", "quorum", "acting_holder_vacated")
        if vacated and options.get("requires_backfill_before_acting"):
            return finish("not_established", "quorum", "vacancy_must_be_filled")
        current = [h for h in co_holders if h not in vacated]
        approvers = set()
        for event in of("co_holder_approval"):
            if event["payload"].get("action_ref") != terms.get("action_ref"):
                continue
            if event["occurred_at"] > action_at:
                continue
            if not options.get("counts_approval_from_vacated_holder") and event["attestor"] in vacated:
                continue
            approvers.add(event["attestor"])
        notes.append("current_holders=" + str(len(current)) + " approvals=" + str(len(approvers)))
        if options.get("requires_unanimity_of_named_holders"):
            if len(approvers) < len(co_holders):
                return finish("not_established", "quorum", "majority_not_reached")
        elif len(approvers) * 2 <= len(current):
            return finish("not_established", "quorum", "majority_not_reached")
        permitted = terms.get("permitted_action_classes")
        if isinstance(permitted, list) and vector["action_class"] not in permitted:
            return finish("invalid", "quorum", "action_class_outside_instrument")
        return finish("valid", "quorum", "majority_of_current_holders")

    # a temporary mandate
    mandate = terms.get("mandate")
    if isinstance(mandate, dict):
        if not options.get("revoke_only"):
            ends_on = mandate.get("ends_on_event")
            ending = next(
                (
                    e
                    for e in of(ends_on if isinstance(ends_on, str) else "__none__")
                    if e["occurred_at"] <= action_at
                    and e["payload"].get("dispute_ref") == mandate.get("dispute_ref")
                ),
                None,
            )
            if ending is not None:
                return finish("invalid", "mandate", "temporary_mandate_ended_on_resolution")
        else:
            notes.append("revoke_only=on")
        permitted = mandate.get("permitted_action_classes")
        if (
            not options.get("temporary_admin_has_full_successor_powers")
            and isinstance(permitted, list)
            and vector["action_class"] not in permitted
        ):
            return finish("invalid", "mandate", "outside_preservation_scope")
        return finish("valid", "mandate", "within_temporary_mandate")

    # an act outside the declared scope, and ratification
    permitted = terms.get("permitted_action_classes")
    if isinstance(permitted, list) and vector["action_class"] in permitted:
        return finish("valid", "ratification", "within_declared_scope")

    act = (terms.get("integrated_acts") or {}).get(fixture["act_id"])
    ratification = next(
        (
            e
            for e in of("principal_ratification")
            if e["payload"].get("act_id") == fixture["act_id"] and e["occurred_at"] >= action_at
        ),
        None,
    )
    if ratification is None or act is None:
        return finish("invalid", "ratification", "act_outside_declared_scope")

    if not options.get("ignores_capacity_at_ratification"):
        lacking = next(
            (
                e
                for e in of("principal_capacity_finding")
                if e["subject_ref"] == root_issuer
                and e["payload"].get("finding") == "lacks_capacity"
                and e["payload"].get("covers_from") <= ratification["occurred_at"]
                and e["payload"].get("covers_through") >= ratification["occurred_at"]
            ),
            None,
        )
        if lacking is not None:
            return finish(
                "invalid", "ratification", "ratification_ineffective_principal_lacked_capacity"
            )

    if not options.get("accepts_partial_ratification"):
        covered = set(ratification["payload"].get("covers_components") or [])
        if [c for c in act["components"] if c not in covered]:
            return finish("invalid", "ratification", "partial_ratification_ineffective")

    if not options.get("ratification_reaches_intervening_interest"):
        intervening = next(
            (
                e
                for e in of("intervening_interest")
                if e["payload"].get("target") == act["target"]
                and action_at < e["payload"].get("acquired_at") < ratification["occurred_at"]
            ),
            None,
        )
        if intervening is not None:
            return finish(
                "restricted", "ratification", "ratified_but_intervening_interest_not_reached"
            )

    return finish("valid", "ratification", "ratified_entirety")


def receipt_digest(result):
    body = {
        "verdict": result["verdict"],
        "stage": result["stage"],
        "code": result["code"],
        "chain_state": result["chain_state"],
        "chain_failure_index": result["chain_failure_index"],
    }
    return hashlib.sha256(canonicalize_jcs(body).encode("utf-8")).hexdigest()


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
        ok = matches(result, vector["expected"])
        details = [
            result["verdict"] + "/" + result["stage"] + "/" + result["code"]
            + " chain=" + result["chain_state"]
        ]
        prior = vector.get("prior_receipt")
        if prior is not None:
            prior_vector = dict(vector)
            prior_vector.update(
                {
                    "grant": prior["grant"],
                    "action_class": prior["action_class"],
                    "action_at": prior["action_at"],
                    "evaluated_at": prior["evaluated_at"],
                    "revocation": prior["revocation"],
                    "presented_events": prior["presented_events"],
                }
            )
            digest = receipt_digest(gate(prior_vector))
            digest_ok = digest == prior["digest"]
            ok = ok and digest_ok
            details.append("prior_receipt=" + ("unchanged" if digest_ok else "CHANGED:" + digest))
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
                "PASS negative-control " + name + " fails "
                + str(len(observed)) + " vector(s) as declared"
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
