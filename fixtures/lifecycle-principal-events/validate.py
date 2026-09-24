#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-principal-events family.
#
#     python3 fixtures/lifecycle-principal-events/validate.py
#     python3 fixtures/lifecycle-principal-events/validate.py --sdk-support
#
# This is an independent reimplementation of the gate in fixtures/
# lifecycle-principal-events/harness.ts against the PyPI agent-passport-system
# package, not a port that shares code with it. It calls the real Python SDK for
# chain verification, for RFC 8785 canonicalization and for Ed25519 signature
# verification. Everything the SDK has no API for is implemented here, and
# --sdk-support records exactly which concepts those are.

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, verify as verify_ed25519
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent
FAMILY = "lifecycle-principal-events"

UNSUPPORTED_CONCEPTS = [
    "grant terms outside the seven closed AuthorityVectorV1 facets "
    "(durability, relationship binding, coupled-interest claim, successor order)",
    "principal-event records (death, incapacity, dissolution filing or decree, "
    "forfeiture finding, guardian appointment, court order, agent exit)",
    "an attestor-role registry or an event-standing table",
    "notice, as an event separate from the event it is notice of",
    "retroactive forfeiture reaching an appointment rather than ending it going forward",
    "lifecycle standing held by a party that is neither issuer nor subject of the chain",
    "a suspended verdict distinct from invalid",
    "a not_established verdict distinct from invalid and indeterminate",
    "a not_yet_effective verdict for a successor whose predecessor has not exited",
]

NAIVE_CONFIGURATIONS = {
    "defective-durability-survives-death": {"durability_survives_death": True},
    "defective-revoke-only": {"revoke_only": True},
    "defective-forfeiture-forward-only": {"forfeiture_is_forward_only": True},
    "defective-guardian-appointment-is-revocation": {"guardian_appointment_is_revocation": True},
    "defective-trusts-self-declared-role": {"trusts_self_declared_role": True},
    "defective-trusts-self-declared-survival": {"trusts_self_declared_survival": True},
    "defective-silent-trigger-defaults-to-decree": {"silent_trigger_defaults_to_decree": True},
    "defective-successor-inherits-tree": {"successor_inherits_tree": True},
}


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")


def record_preimage(record, drop_keys):
    body = {key: value for key, value in record.items() if key not in drop_keys}
    return canonicalize_jcs(body)


def signature_ok(record, drop_keys):
    public_key = fixture["verification_keys"].get(record.get("verification_method"))
    if not isinstance(public_key, str):
        return False
    try:
        return bool(verify_ed25519(record_preimage(record, drop_keys), record["signature"], public_key))
    except Exception:
        return False


def classify(label, leaf_subject, now, options):
    event = fixture["events"].get(label)
    if event is None:
        return (False, label, "event_record_unknown")
    if not signature_ok(event, {"event_id", "signature"}):
        return (False, label, "event_signature_unverified")
    if not event["verification_method"].startswith(event["attestor"] + "#"):
        return (False, label, "event_attestor_binding_mismatch")
    required_role = fixture["event_standing"].get(event["event_type"])
    if not isinstance(required_role, str):
        return (False, label, "event_type_has_no_declared_standing")
    if required_role == "grant-subject":
        if event["attestor"] != leaf_subject:
            return (False, label, "notice_not_from_grant_subject")
    elif options.get("trusts_self_declared_role"):
        if event["attestor_role"] != required_role:
            return (False, label, "event_attestor_role_mismatch")
    else:
        registered = fixture["attestor_role_registry"].get(event["attestor"])
        if not isinstance(registered, str) or registered != event["attestor_role"]:
            return (False, label, "event_role_claim_conflict")
        if registered != required_role:
            return (False, label, "event_attestor_role_mismatch")
    return (True, event, event["occurred_at"] <= now)


def gate(vector, options=None):
    options = options or {}
    chain = fixture["chains"][vector["grant"]]
    now = fixture["clock"][vector["action_at"]]
    notes = []

    chain_result = verify_authority_delegation_chain(
        chain,
        now=now,
        resolve_verification_key=lambda _issuer, method, _issued_at:
            fixture["verification_keys"].get(method),
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: vector["revocation"],
    )
    chain_state = chain_result.state
    first = chain_result.failures[0] if chain_result.failures else None
    chain_failure_index = first.index if first is not None else None

    def finish(verdict, stage, code):
        return {
            "verdict": verdict,
            "stage": stage,
            "code": code,
            "chain_state": chain_state,
            "chain_failure_index": chain_failure_index,
            "notes": notes,
        }

    if chain_state != "valid":
        verdict = "invalid" if chain_state == "invalid" else "not_established"
        return finish(verdict, "chain", first.code if first is not None else "chain_" + chain_state)

    leaf = chain[-1]
    leaf_subject = leaf["subject"]
    leaf_delegation_id = leaf["delegation_id"]
    root_issuer = chain[0]["issuer"]

    terms_label = fixture["terms_by_chain"].get(vector["grant"])
    terms = {}
    if isinstance(terms_label, str):
        record = fixture["grant_terms"].get(terms_label)
        if record is None:
            return finish("not_established", "terms", "grant_terms_unknown")
        if not signature_ok(record, {"terms_id", "signature"}):
            return finish("not_established", "terms", "grant_terms_signature_unverified")
        named = next((m for m in chain if m["delegation_id"] == record["delegation_id"]), None)
        if named is None or named["issuer"] != record["issuer"]:
            return finish("not_established", "terms", "grant_terms_not_bound_to_chain")
        terms = record["terms"]
        notes.append("terms=" + terms_label)
    else:
        notes.append("terms=none")

    accepted = []
    for label in vector["presented_events"]:
        result = classify(label, leaf_subject, now, options)
        if result[0]:
            accepted.append({"event": result[1], "reaches_now": result[2]})
            notes.append(label + "=accepted" + ("" if result[2] else ":after_action"))
        else:
            notes.append(label + "=rejected:" + result[2])

    def find(event_type, predicate=None):
        for entry in accepted:
            if entry["event"]["event_type"] != event_type:
                continue
            if predicate is None or predicate(entry["event"]):
                return entry
        return None

    # 1. who may act under this grant
    actor = vector.get("actor") or leaf_subject
    if actor != leaf_subject:
        order = terms.get("successor_order")
        position = order.index(actor) if isinstance(order, list) and actor in order else -1
        if position <= 0:
            if options.get("successor_inherits_tree"):
                notes.append("successor_inherits_tree=on")
            else:
                return finish("invalid", "succession", "successor_scope_limited_to_instrument")
        else:
            still_serving = []
            for predecessor in order[:position]:
                exit_record = find("agent_exit", lambda e, p=predecessor: e["subject_ref"] == p)
                if exit_record is None or not exit_record["reaches_now"]:
                    still_serving.append(predecessor)
            if still_serving:
                return finish("not_yet_effective", "succession", "predecessor_still_serving")
            notes.append("successor_activated=" + actor)

    # 2. retroactive forfeiture
    chain_parties = set()
    for member in chain:
        chain_parties.add(member["issuer"])
        chain_parties.add(member["subject"])
    forfeiture = find("felonious_killing_finding", lambda e: e["subject_ref"] in chain_parties)
    if forfeiture is not None:
        if not options.get("forfeiture_is_forward_only") or forfeiture["reaches_now"]:
            return finish("invalid", "principal_event", "appointment_void_from_inception")
        notes.append("forfeiture_forward_only=on")

    # 3. lifecycle standing from outside the chain
    terminate_order = find(
        "court_order_terminate_delegation", lambda e: e["subject_ref"] == leaf_delegation_id
    )
    if terminate_order is not None and terminate_order["reaches_now"]:
        return finish("invalid", "standing", "terminated_by_external_order")
    suspend_order = find(
        "court_order_suspend_delegation", lambda e: e["subject_ref"] == leaf_delegation_id
    )
    if suspend_order is not None and suspend_order["reaches_now"]:
        return finish("suspended", "standing", "suspended_by_external_order")
    guardian = find("guardian_appointment", lambda e: e["subject_ref"] == root_issuer)
    if guardian is not None and guardian["reaches_now"]:
        if options.get("guardian_appointment_is_revocation"):
            return finish("invalid", "standing", "terminated_by_external_order")
        notes.append("guardian_appointed_delegation_continues")

    if options.get("revoke_only"):
        notes.append("revoke_only=on")
        return finish("valid", "principal_event", "no_terminating_event_established")

    # 4. the principal's death
    death = find("principal_death", lambda e: e["subject_ref"] == root_issuer)
    if death is not None and death["reaches_now"]:
        claims_survival = terms.get("survives_principal_death") is True
        durable = terms.get("durability") == "durable"
        if durable and options.get("durability_survives_death"):
            notes.append("durability_survives_death=on")
        elif claims_survival:
            if options.get("trusts_self_declared_survival"):
                notes.append("self_declared_survival=on")
            else:
                subject_matter = terms.get("subject_matter_ref")
                interest = find(
                    "collateral_interest_in_subject_matter",
                    lambda e: e["payload"].get("holder") == leaf_subject
                    and e["payload"].get("subject_matter_ref") == subject_matter,
                )
                if interest is None or not interest["reaches_now"]:
                    return finish(
                        "not_established", "principal_event", "coupled_interest_not_established"
                    )
                notes.append("coupled_interest_established")
        else:
            notice = find("notice_of_principal_death", lambda e: e["subject_ref"] == root_issuer)
            if notice is not None and notice["reaches_now"]:
                return finish("invalid", "principal_event", "terminated_on_notice_of_death")
            return finish("valid", "principal_event", "death_recorded_notice_not_established")

    # 5. the principal's incapacity
    incapacity = find("principal_incapacity", lambda e: e["subject_ref"] == root_issuer)
    if incapacity is not None and incapacity["reaches_now"]:
        if terms.get("durability") == "durable":
            notes.append("durable_survives_incapacity")
        else:
            return finish("invalid", "principal_event", "terminated_on_principal_incapacity")

    # 6. the relationship the designation depends on
    binding = terms.get("relationship_binding")
    if isinstance(binding, dict):
        relationship_events = [
            entry
            for entry in accepted
            if entry["event"]["event_type"]
            in ("marriage_dissolution_filing", "marriage_dissolution_decree")
            and entry["event"]["subject_ref"] == root_issuer
            and entry["event"]["payload"].get("counterparty") == leaf_subject
        ]
        trigger = binding.get("termination_trigger")
        if not isinstance(trigger, str):
            if options.get("silent_trigger_defaults_to_decree"):
                trigger = "marriage_dissolution_decree"
                notes.append("silent_trigger_defaults_to_decree=on")
            elif relationship_events:
                return finish(
                    "not_established", "principal_event", "termination_trigger_not_declared"
                )
        if isinstance(trigger, str):
            triggered = next(
                (
                    entry
                    for entry in relationship_events
                    if entry["event"]["event_type"] == trigger and entry["reaches_now"]
                ),
                None,
            )
            if triggered is not None:
                return finish(
                    "invalid", "principal_event", "relationship_terminated_no_revocation_record"
                )
            if relationship_events:
                return finish("valid", "principal_event", "termination_trigger_not_reached")

    return finish("valid", "principal_event", "no_terminating_event_established")


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
        now = fixture["clock"][vector["action_at"]]
        chain_result = verify_authority_delegation_chain(
            fixture["chains"][vector["grant"]],
            now=now,
            resolve_verification_key=lambda _i, m, _t: fixture["verification_keys"].get(m),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _d: vector["revocation"],
        )
        code = chain_result.failures[0].code if chain_result.failures else "none"
        signatures = []
        for label in vector["presented_events"]:
            event = fixture["events"][label]
            signatures.append(label + "=" + str(signature_ok(event, {"event_id", "signature"})))
        print(vector["id"])
        print(
            "  verify_authority_delegation_chain: supported, state="
            + chain_result.state
            + " code="
            + code
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
                    "actor": prior["actor"],
                    "action_at": prior["action_at"],
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

    total_controls = len(NAIVE_CONFIGURATIONS)
    print(
        FAMILY + " negative controls: " + str(total_controls - control_failures)
        + "/" + str(total_controls) + " behaved as declared"
    )
    print(
        FAMILY + " Python: " + str(passed) + "/" + str(len(vectors["cases"])) + " vectors, "
        + str(total_controls - control_failures) + "/" + str(total_controls) + " negative controls"
    )
    return 0 if failures == 0 and control_failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
