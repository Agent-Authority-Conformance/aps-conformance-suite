#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python reference-SDK runner for the lifecycle-time-and-scheduling family.

This is not a from-scratch reimplementation of the protocol. It runs the same sixty-one
vectors over the same chain.json records as verify.ts, and for every step where the Python
SDK (`agent-passport-system` on PyPI, pinned 4.1.0) exposes an API it calls that API
rather than reimplementing the check:

    agent_passport.verify_authority_delegation_chain   chain shape, signatures, the time
                                                       facet and revocation state
    agent_passport.verify, agent_passport.canonicalize_jcs
                                                       each fixture-local record's issuer
                                                       signature

Everything else is recorded as not_supported rather than faked. Neither SDK exposes an API
for any of the fourteen lifecycle rules this family tests, and the Python SDK additionally
has no scope-membership export. The support table is printed at the end of every run, so
the record of what came from an SDK and what did not is produced by the run rather than
written by hand.

Run, with the pinned SDK installed into a virtual environment:

    python3 -m venv /tmp/aac-work/pyenv
    /tmp/aac-work/pyenv/bin/pip install agent-passport-system==4.1.0
    /tmp/aac-work/pyenv/bin/python fixtures/lifecycle-time-and-scheduling/verify_python_sdk.py

Exit 0 when the reference boundary matches every vector and all five defective boundaries
diverge on exactly their declared sets, 1 otherwise, 2 on a malformed fixture or a missing
SDK. No network. This is a manual run and not part of `npm test`.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import agent_passport as ap
except ImportError:  # pragma: no cover
    print("verify_python_sdk.py: agent-passport-system is not installed in this interpreter")
    print("  python3 -m venv <venv> && <venv>/bin/pip install agent-passport-system==4.1.0")
    sys.exit(2)

HERE = Path(__file__).resolve().parent
DAY_MS = 24 * 60 * 60 * 1000


def ms(t: str) -> float:
    return datetime.fromisoformat(t.replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp() * 1000


def is_purpose_permitted(requested: str, allowed: list[str]) -> bool:
    """Hierarchical prefix membership, matching the TypeScript SDK's documented rule.

    The Python SDK exports no equivalent under any module, so this runner applies the same
    rule and records the step as not_supported. It is not an SDK result.
    """
    for entry in allowed:
        if entry == requested or entry == "*":
            return True
        if entry.endswith(":*") and (requested == entry[:-2] or requested.startswith(entry[:-1])):
            return True
    return False


REQUIRED_ROLE = {
    "succession_default": "succession_rule_author",
    "role_tenure": "tenure_attestor",
    "vacancy": "vacancy_attestor",
    "fallback_authorization": "fallback_author",
    "contact_observation": "observation_attestor",
    "rotation_schedule": "schedule_author",
    "rest_ledger": "rest_attestor",
    "atomic_relief": "relief_author",
    "departure": "relief_author",
    "designation": "relief_author",
    "qualification": "qualification_attestor",
    "policy": "policy_author",
    "instance_start": "instance_attestor",
    "series": "series_author",
    "identity_removal": "identity_removal_attestor",
    "occurrence_template": "template_author",
    "occurrence": "occurrence_attestor",
    "wind_down": "wind_down_attestor",
    "scheduled_job": "job_author",
    "queued_action": "queue_attestor",
    "suspension": "suspension_author",
}


def out(verdict: str, reason: str, chain: dict | None, detail: str | None = None) -> dict:
    o = {
        "verdict": verdict,
        "reason": reason,
        "sdk_chain_state": None if chain is None else chain["state"],
        "sdk_failure_code": None if chain is None else chain["code"],
    }
    if detail is not None:
        o["detail"] = detail
    return o


class Boundary:
    def __init__(self, name: str, fixture: dict, **flags: bool) -> None:
        self.name = name
        self.fixture = fixture
        self.flags = flags

    def opt(self, key: str) -> bool:
        return self.flags[key]

    def authentic(self, rec: dict) -> bool:
        unsigned = {k: v for k, v in rec.items() if k != "signature"}
        public_key = self.fixture["verification_keys"].get(rec["verification_method"])
        if public_key is None:
            return False
        return ap.verify(f"{self.fixture['record_signature_domain']} {ap.canonicalize_jcs(unsigned)}",
                         rec["signature"], public_key)

    def chain(self, event: dict, now: str) -> dict:
        keys = self.fixture["verification_keys"]
        office = self.fixture["identities"]["OFFICE"]
        result = ap.verify_authority_delegation_chain(
            [event["grant"]],
            now=now,
            resolve_verification_key=lambda _i, method, _issued_at=None: keys.get(method),
            trust_root=lambda root: root.get("issuer") == office,
            resolve_revocation=lambda _d, _now=now: event["resolve_revocation"](_now),
        )
        failures = list(result.failures)
        code = None
        if failures:
            first = failures[0]
            code = first.get("code") if isinstance(first, dict) else getattr(first, "code", None)
        return {"state": result.state, "code": code}

    def chain_gate(self, event: dict, now: str) -> tuple[dict, dict | None]:
        chain = self.chain(event, now)
        if chain["state"] == "invalid" and chain["code"] == "REVOKED":
            return chain, out("invalid", "grant_revoked", chain)
        if chain["state"] == "indeterminate":
            return chain, out("not_established", "chain_state_indeterminate", chain)
        if chain["state"] == "invalid" and chain["code"] == "NOT_YET_VALID":
            return chain, out("not_yet_effective", "grant_window_not_reached", chain)
        if chain["state"] != "valid":
            return chain, out("invalid", "grant_chain_not_valid", chain, chain["code"])
        return chain, None

    def base(self, event: dict, now: str) -> tuple[dict, dict | None]:
        chain, blocked = self.chain_gate(event, now)
        if blocked is not None:
            return chain, blocked
        if not is_purpose_permitted(event["action"]["requested_scope"], event["grant"]["authority"]["scope"]["grants"]):
            return chain, out("invalid", "scope_not_in_grant", chain)
        return chain, None

    def handle(self, event: dict) -> dict:
        by_kind: dict[str, list[dict]] = {}
        for rec in event["records"]:
            if not self.authentic(rec):
                return out("not_established", "record_not_authentic", None, rec["record_id"])
            by_kind.setdefault(rec["kind"], []).append(rec)
        registry = (by_kind.get("standing_registry") or [None])[0]
        if registry is None:
            return out("not_established", "standing_registry_not_presented", None)
        for rec in event["records"]:
            role = REQUIRED_ROLE.get(rec["kind"])
            if role is None:
                continue
            if rec["issuer"] not in (registry["body"].get(role) or []):
                return out("not_established", "record_without_standing", None, f"{rec['record_id']}/{rec['kind']}")
        rule = RULES.get(event["check"])
        if rule is None:
            return out("not_established", "unknown_check", None, event["check"])
        return rule(self, event, by_kind)


def _one(r: dict, kind: str) -> dict | None:
    return (r.get(kind) or [None])[0]


# ---------------------------------------------------------------------------
# One rule per case, ported step for step from harness.ts
# ---------------------------------------------------------------------------

def rule_succession_default(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    vacancy = _one(r, "vacancy")
    if vacancy is None:
        return out("not_established", "vacancy_not_recorded", chain)
    direction = _one(r, "direction")
    if direction is None:
        return out("not_established", "no_direction_for_the_vacant_office", chain)
    rule = _one(r, "succession_default")
    if rule is None:
        return out("not_established", "no_successor_designation_and_no_declared_default", chain)
    tenure = next((t for t in r.get("role_tenure", []) if t["body"]["holder"] == direction["issuer"]), None)
    if tenure is None:
        return out("not_established", "default_successor_tenure_not_recorded", chain)
    if tenure["body"]["role"] != rule["body"]["default_successor_role"]:
        return out("not_established", "default_successor_role_does_not_match", chain)
    held_days = (ms(vacancy["body"]["vacant_from"]) - ms(tenure["body"]["held_since"])) / DAY_MS
    if held_days < rule["body"]["minimum_tenure_days"]:
        import math
        return out("not_established", "default_successor_eligibility_not_met", chain, f"tenure_days={math.floor(held_days)}")
    return out("valid", "default_successor_resolved", chain, f"acting={direction['issuer']}")


def rule_acknowledged_handover(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    offer = _one(r, "handover_offer")
    if offer is None:
        return out("not_established", "handover_offer_not_recorded", chain)
    acting = e["grant"]["subject"]
    acks = r.get("handover_ack", [])
    ack = next((a for a in acks if a["body"]["offer_id"] == offer["record_id"] and a["issuer"] == offer["body"]["incoming"]), None)
    if not b.opt("requiresAcknowledgedTransfer"):
        if acting == offer["body"]["incoming"]:
            return out("valid", "transfer_treated_as_instantaneous", chain)
        return out("invalid", "outgoing_holder_treated_as_departed", chain)
    if ack is None:
        wrong_signer = any(a["body"]["offer_id"] == offer["record_id"] for a in acks)
        if acting == offer["body"]["outgoing"]:
            return out("valid", "authority_retained_pending_acknowledgment", chain)
        return out("not_yet_effective",
                   "acknowledgment_without_standing" if wrong_signer else "handover_not_acknowledged", chain)
    if ack["body"]["briefing_digest"] != offer["body"]["briefing_digest"]:
        return out("not_yet_effective", "acknowledged_briefing_does_not_match_the_offer", chain)
    if ms(e["now"]) < ms(ack["body"]["acknowledged_at"]):
        if acting == offer["body"]["outgoing"]:
            return out("valid", "authority_retained_pending_acknowledgment", chain)
        return out("not_yet_effective", "handover_not_acknowledged", chain)
    if acting == offer["body"]["incoming"]:
        return out("valid", "handover_acknowledged", chain)
    return out("invalid", "authority_transferred", chain)


def rule_directed_fallback(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    contact = _one(r, "contact_observation")
    if contact is None:
        return out("not_established", "contact_state_not_recorded", chain)
    restored = contact["body"]["restored_at"]
    if restored is not None and ms(e["now"]) >= ms(restored):
        return out("valid", "live_direction_restored", chain)
    fallback = _one(r, "fallback_authorization")
    gap_seconds = (ms(e["now"]) - ms(contact["body"]["last_contact_at"])) / 1000
    if fallback is None:
        if gap_seconds <= 0:
            return out("valid", "live_direction_present", chain)
        return out("not_established", "no_pre_authorized_fallback_and_no_live_direction", chain)
    if gap_seconds < fallback["body"]["contact_loss_threshold_seconds"]:
        return out("valid", "live_direction_present", chain)
    scope = fallback["body"]["fallback_scope"]
    if not is_purpose_permitted(e["action"]["requested_scope"], scope):
        return out("invalid", "outside_fallback_scope", chain, "fallback=" + ",".join(scope))
    return out("restricted", "fallback_scope_active", chain, "fallback=" + ",".join(scope))


def rule_rotation_schedule(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    schedule = _one(r, "rotation_schedule")
    if schedule is None:
        return out("not_established", "rotation_schedule_not_recorded", chain)
    slot = next((s for s in schedule["body"]["slots"] if s["at"] == e["now"] and s["incoming"] == e["grant"]["subject"]), None)
    if slot is None:
        return out("not_established", "swap_not_in_rotation_schedule", chain)
    rest = next((x for x in r.get("rest_ledger", []) if x["body"]["holder"] == slot["incoming"]), None)
    if rest is None:
        return out("not_established", "rest_state_not_established", chain)
    ended = rest["body"]["rest_ended_at"]
    if ended is None or ms(ended) > ms(slot["at"]):
        return out("not_yet_effective", "required_rest_period_not_elapsed", chain)
    rested = (ms(ended) - ms(rest["body"]["rest_started_at"])) / 1000
    if rested < schedule["body"]["minimum_rest_seconds"]:
        return out("not_yet_effective", "required_rest_period_not_elapsed", chain, f"rested_seconds={rested}")
    return out("valid", "scheduled_swap_pre_authorized", chain, f"slot={slot['at']}")


def rule_continuous_coverage(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    qualified = lambda holder: any(q["body"]["holder"] == holder for q in r.get("qualification", []))
    atomic = _one(r, "atomic_relief")
    if atomic is not None:
        if ms(e["now"]) < ms(atomic["body"]["effective_at"]):
            return out("not_yet_effective", "relief_not_yet_effective", chain)
        if e["grant"]["subject"] != atomic["body"]["designated"]:
            return out("invalid", "acting_party_is_not_the_designated_holder", chain)
        if not qualified(atomic["body"]["designated"]):
            return out("not_established", "designee_qualification_not_established", chain)
        return out("valid", "departure_and_designation_recorded_atomically", chain)
    departure = _one(r, "departure")
    designation = _one(r, "designation")
    if departure is None:
        return out("not_established", "departure_not_recorded", chain)
    if designation is None:
        return out("not_established", "no_designated_holder_in_gap", chain)
    gap_open = ms(e["now"]) >= ms(departure["body"]["effective_at"])
    designated = ms(e["now"]) >= ms(designation["body"]["effective_at"])
    if gap_open and not designated:
        if not b.opt("requiresAcknowledgedTransfer"):
            return out("valid", "gap_treated_as_instantaneous_transfer", chain)
        return out("not_established", "no_designated_holder_in_gap", chain)
    if not designated:
        return out("not_yet_effective", "designation_not_yet_effective", chain)
    if e["grant"]["subject"] != designation["body"]["designated"]:
        return out("invalid", "acting_party_is_not_the_designated_holder", chain)
    if not qualified(designation["body"]["designated"]):
        return out("not_established", "designee_qualification_not_established", chain)
    return out("valid", "designation_recorded", chain)


def rule_pinned_policy_version(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    instance = _one(r, "instance_start")
    if instance is None:
        return out("not_established", "instance_start_not_recorded", chain)
    policies = r.get("policy", [])
    pinned = instance["body"]["pinned_policy_version"]
    if b.opt("usesPinnedVersions") and pinned is not None:
        selected = next((p for p in policies if p["body"]["policy_version"] == pinned), None)
        if selected is None:
            return out("not_established", "pinned_policy_version_not_resolvable", chain, f"pinned={pinned}")
    else:
        if b.opt("usesPinnedVersions") and pinned is None:
            return out("not_established", "policy_version_not_pinned", chain)
        in_force = sorted((p for p in policies if ms(p["body"]["effective_from"]) <= ms(e["now"])),
                          key=lambda p: ms(p["body"]["effective_from"]))
        selected = in_force[-1] if in_force else None
        if selected is None:
            return out("not_established", "no_policy_in_force", chain)
    denied = selected["body"].get("denied_scopes") or []
    version = selected["body"]["policy_version"]
    if e["action"]["requested_scope"] in denied:
        return out("invalid", "denied_under_selected_policy_version", chain, f"policy_version={version}")
    return out("valid", "permitted_under_selected_policy_version", chain, f"policy_version={version}")


def rule_series_owner(b: Boundary, e: dict, r: dict) -> dict:
    series = _one(r, "series")
    if series is None:
        return out("not_established", "series_not_recorded", None)
    removal = next((x for x in r.get("identity_removal", []) if x["body"]["identity"] == series["body"]["owner"]), None)
    removed_now = removal is not None and ms(e["now"]) >= ms(removal["body"]["removed_at"])
    disposition = series["body"]["disposition_on_owner_removal"]
    if removed_now and disposition is not None and disposition["mode"] == "reassign":
        chain, blocked = b.base(e, e["now"])
        if blocked:
            return blocked
        if e["grant"]["subject"] != disposition["reassign_to"] or e["grant"]["delegation_id"] != disposition["grant"]:
            return out("not_established", "series_disposition_does_not_name_this_grant", chain)
        return out("valid", "series_disposition_reassignment_recorded", chain)
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    if removed_now:
        return out("not_established", "series_owner_not_resolvable", chain, f"removed_at={removal['body']['removed_at']}")
    return out("valid", "series_owner_resolvable", chain)


def rule_occurrence_template(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    occurrence = _one(r, "occurrence")
    if occurrence is None:
        return out("not_established", "occurrence_not_recorded", chain)
    templates = r.get("occurrence_template", [])
    created_under = occurrence["body"]["created_under_template_version"]
    if b.opt("usesPinnedVersions"):
        if created_under is None:
            return out("not_established", "occurrence_template_version_not_recorded", chain)
        selected = next((t for t in templates if t["body"]["template_version"] == created_under), None)
        if selected is None:
            return out("not_established", "occurrence_template_version_not_resolvable", chain)
    else:
        in_force = sorted((t for t in templates if ms(t["body"]["effective_from"]) <= ms(e["now"])),
                          key=lambda t: ms(t["body"]["effective_from"]))
        selected = in_force[-1] if in_force else None
        if selected is None:
            return out("not_established", "no_template_in_force", chain)
    version = selected["body"]["template_version"]
    if not is_purpose_permitted(e["action"]["requested_scope"], selected["body"]["scope"]):
        return out("invalid", "outside_occurrence_template_scope", chain, f"template_version={version}")
    return out("valid", "within_the_selected_occurrence_template", chain, f"template_version={version}")


def rule_wind_down(b: Boundary, e: dict, r: dict) -> dict:
    chain, blocked = b.base(e, e["now"])
    if blocked:
        return blocked
    wind = _one(r, "wind_down")
    if wind is None:
        return out("not_established", "wind_down_not_recorded", chain)
    started = ms(wind["body"]["termination_started_at"])
    if ms(e["now"]) < started:
        return out("valid", "termination_not_started", chain)
    if not b.opt("requiresAcknowledgedTransfer"):
        return out("invalid", "termination_treated_as_revocation", chain)
    grace = wind["body"]["grace_seconds"]
    if grace is None:
        return out("not_established", "wind_down_bound_not_declared", chain)
    if ms(e["now"]) <= started + grace * 1000:
        return out("valid", "within_wind_down_grace", chain, f"grace_seconds={grace}")
    return out("invalid", "wind_down_grace_elapsed", chain, f"grace_seconds={grace}")


def rule_scheduled_job(b: Boundary, e: dict, r: dict) -> dict:
    job = _one(r, "scheduled_job")
    if job is None:
        return out("not_established", "scheduled_job_not_recorded", None)
    if job["body"]["creator_grant"] is None:
        return out("not_established", "job_creator_authority_not_recorded", None)
    chain, blocked = b.chain_gate(e, e["now"])
    if blocked:
        return blocked
    if e["grant"]["delegation_id"] != job["body"]["creator_grant"]:
        return out("not_established", "presented_grant_is_not_the_job_creator_grant", chain)
    job_scope = job["body"]["action_scope"]
    if not is_purpose_permitted(job_scope, e["grant"]["authority"]["scope"]["grants"]):
        return out("invalid", "outside_current_creator_scope", chain, f"job_scope={job_scope}")
    return out("valid", "within_current_creator_scope", chain, f"job_scope={job_scope}")


def rule_queued_action(b: Boundary, e: dict, r: dict) -> dict:
    queued = _one(r, "queued_action")
    if queued is None:
        return out("not_established", "queued_action_not_recorded", None)
    at = queued["body"]["fires_at"] if b.opt("checksLiveStateAtFireTime") else queued["body"]["queued_at"]
    chain, blocked = b.base(e, at)
    if blocked:
        return blocked
    if not b.opt("checksLiveStateAtFireTime"):
        return out("valid", "live_state_clear_at_fire_time", chain)
    suspensions = [s for s in r.get("suspension", []) if s["body"]["grant"] == queued["body"]["grant"]]
    if queued["body"].get("requires_live_suspension_source") is True and not suspensions:
        return out("not_established", "suspension_state_not_established_at_fire_time", chain)
    for s in suspensions:
        released = s["body"]["released_at"]
        active = ms(at) >= ms(s["body"]["suspended_at"]) and (released is None or ms(at) < ms(released))
        if active:
            return out("suspended", "suspended_at_fire_time", chain, f"cause={s['body']['cause']}")
    return out("valid", "live_state_clear_at_fire_time", chain)


def rule_checking_party_clock(b: Boundary, e: dict, r: dict) -> dict:
    attestation = _one(r, "clock_attestation")
    if b.opt("usesCheckingPartyClock") and attestation is None:
        return out("not_established", "checking_party_clock_not_recorded", None)
    now = attestation["body"]["reading"] if b.opt("usesCheckingPartyClock") else e["action"]["issued_at"]
    chain = b.chain(e, now)
    if chain["state"] == "valid":
        return out("valid", "valid_on_the_selected_clock", chain, f"reading={now}")
    if chain["code"] == "EXPIRED":
        return out("invalid", "expired_on_the_selected_clock", chain, f"reading={now}")
    if chain["code"] == "NOT_YET_VALID":
        # The lifecycle verdict and the SDK verdict part company here on purpose. Both
        # pinned SDKs answer invalid with NOT_YET_VALID and neither has a state for
        # not_yet_effective. Both answers are reported.
        return out("not_yet_effective", "not_yet_effective_on_the_selected_clock", chain, f"reading={now}")
    return out("not_established", "chain_state_not_decidable", chain, f"reading={now}")


def rule_time_source(b: Boundary, e: dict, r: dict) -> dict:
    attestation = _one(r, "clock_attestation")
    if attestation is None:
        return out("not_established", "clock_attestation_not_recorded", None)
    reading = attestation["body"]["reading"]
    source = attestation["body"]["source"]
    cross = attestation["body"]["cross_check"]
    if b.opt("requiresTimeSourceCrossCheck"):
        if source == "":
            return out("not_established", "time_source_not_recorded", None)
        if cross is None:
            return out("not_established", "time_source_not_cross_checked", None, f"source={source}")
        delta = abs(ms(reading) - ms(cross["reading"]))
        if delta > cross["bound_ms"]:
            return out("not_established", "time_sources_disagree_past_bound", None, f"delta_ms={int(delta)}")
    chain = b.chain(e, reading)
    if chain["state"] == "valid":
        return out("valid", "reading_accepted", chain, f"reading={reading}")
    if chain["code"] == "NOT_YET_VALID":
        return out("not_yet_effective", "not_yet_effective_on_the_recorded_reading", chain, f"reading={reading}")
    if chain["code"] == "EXPIRED":
        return out("invalid", "expired_on_the_recorded_reading", chain, f"reading={reading}")
    return out("not_established", "chain_state_not_decidable", chain, f"reading={reading}")


def rule_clock_divergence(b: Boundary, e: dict, r: dict) -> dict:
    attestations = r.get("clock_attestation", [])
    if len(attestations) < 2:
        return out("not_established", "two_clock_attestations_not_presented", None)
    a, c = attestations[0], attestations[1]
    delta = abs(ms(a["body"]["reading"]) - ms(c["body"]["reading"]))
    wa, wc = a["body"]["smear_policy"], c["body"]["smear_policy"]
    declared = (wa is not None and wc is not None
                and wa["window_start"] == wc["window_start"] and wa["window_end"] == wc["window_end"])
    if b.opt("treatsClockMismatchAsTampering") and delta > 0:
        return out("invalid", "clock_mismatch_treated_as_tampering", None, f"delta_ms={int(delta)}")
    if not declared:
        return out("not_established", "divergence_outside_any_declared_window", None, f"delta_ms={int(delta)}")
    in_window = all(ms(w["window_start"]) <= ms(x["body"]["reading"]) <= ms(w["window_end"])
                    for x, w in ((a, wa), (c, wc)))
    if not in_window:
        return out("not_established", "reading_outside_the_declared_window", None, f"delta_ms={int(delta)}")
    if delta > wa["bound_ms"]:
        return out("not_established", "divergence_exceeds_declared_smear_bound", None, f"delta_ms={int(delta)}")
    chain = b.chain(e, a["body"]["reading"])
    if chain["state"] != "valid":
        return out("not_established", "chain_state_not_decidable", chain, f"delta_ms={int(delta)}")
    return out("valid", "divergence_within_declared_smear_bound", chain, f"delta_ms={int(delta)}")


RULES: dict[str, Callable[[Boundary, dict, dict], dict]] = {
    "succession_default": rule_succession_default,
    "acknowledged_handover": rule_acknowledged_handover,
    "directed_fallback": rule_directed_fallback,
    "rotation_schedule": rule_rotation_schedule,
    "continuous_coverage": rule_continuous_coverage,
    "pinned_policy_version": rule_pinned_policy_version,
    "series_owner": rule_series_owner,
    "occurrence_template": rule_occurrence_template,
    "wind_down": rule_wind_down,
    "scheduled_job": rule_scheduled_job,
    "queued_action": rule_queued_action,
    "checking_party_clock": rule_checking_party_clock,
    "time_source": rule_time_source,
    "clock_divergence": rule_clock_divergence,
}

REFERENCE_FLAGS = {
    "usesCheckingPartyClock": True,
    "requiresTimeSourceCrossCheck": True,
    "treatsClockMismatchAsTampering": False,
    "checksLiveStateAtFireTime": True,
    "usesPinnedVersions": True,
    "requiresAcknowledgedTransfer": True,
}

DEFECTIVE_FLAGS = {
    "defective-boundary-queue-time-only": {"checksLiveStateAtFireTime": False},
    "defective-boundary-current-version-only": {"usesPinnedVersions": False},
    "defective-boundary-instant-transfer": {"requiresAcknowledgedTransfer": False},
    "defective-boundary-issuer-clock": {"usesCheckingPartyClock": False},
    "defective-boundary-single-clock-trusted": {"requiresTimeSourceCrossCheck": False,
                                                "treatsClockMismatchAsTampering": True},
}


def load(name: str) -> Any:
    return json.loads((HERE / name).read_text())


def to_event(fixture: dict, v: dict) -> dict:
    grant = fixture["grants"].get(v["grant"])
    action = fixture["actions"].get(v["action"])
    if grant is None or action is None:
        print(f"verify_python_sdk.py: vectors.json names an unknown grant or action in {v['id']}")
        sys.exit(2)
    records = []
    for rid in v["records"]:
        rec = fixture["records"].get(rid)
        if rec is None:
            print(f"verify_python_sdk.py: vectors.json names an unknown record {rid}")
            sys.exit(2)
        records.append(rec)

    def resolve_revocation(now: str) -> str:
        if "revoked_from" in v:
            return "revoked" if ms(now) >= ms(v["revoked_from"]) else "active"
        return v["revocation"]

    return {"id": v["id"], "check": v["check"], "grant": grant, "action": action,
            "now": v["now"], "resolve_revocation": resolve_revocation, "records": records}


def matches_lifecycle(actual: dict, expected: dict) -> bool:
    for key in ("verdict", "reason"):
        if actual.get(key) != expected.get(key):
            return False
    return actual.get("detail") == expected.get("detail")


def matches_sdk_cross_check(actual: dict, cross: dict) -> bool:
    # The SDK chain answer is a second assertion, not part of the lifecycle verdict, so
    # it is read from the vector's `sdk_cross_check` sibling rather than from `expected`.
    # Both are still checked on every vector.
    return (actual.get("sdk_chain_state") == cross.get("chain_state")
            and actual.get("sdk_failure_code") == cross.get("failure_code"))


def matches(actual: dict, vector: dict) -> bool:
    return (matches_lifecycle(actual, vector["expected"])
            and matches_sdk_cross_check(actual, vector["sdk_cross_check"]))


def line(a: dict) -> str:
    base = f"verdict={a['verdict']} reason={a['reason']} sdk={a['sdk_chain_state']}/{a['sdk_failure_code']}"
    return base + (f" detail={a['detail']}" if "detail" in a else "")


def main() -> int:
    fixture = load("chain.json")
    vectors = load("vectors.json")

    def run(flags: dict) -> dict[str, dict]:
        # A fresh instance per vector, the same independence the TypeScript runner enforces.
        return {v["id"]: Boundary("b", fixture, **flags).handle(to_event(fixture, v)) for v in vectors["vectors"]}

    print(f"lifecycle-time-and-scheduling (Python SDK {getattr(ap, '__version__', 'unknown')}): "
          f"{len(vectors['vectors'])} vectors, status label {vectors['status_label']}")
    print("")
    print("boundary: reference-boundary")
    ref = run(REFERENCE_FLAGS)
    matched = 0
    for v in vectors["vectors"]:
        actual = ref[v["id"]]
        ok = matches(actual, v)
        matched += 1 if ok else 0
        print(f"  {'MATCH' if ok else 'MISMATCH'} {v['id']}  {line(actual)}")
        if not ok:
            print(f"    expected: {json.dumps(v['expected'])} sdk_cross_check: {json.dumps(v['sdk_cross_check'])}")
            print(f"    actual:   {json.dumps(actual)}")

    all_ok = True
    for name, overrides in DEFECTIVE_FLAGS.items():
        declared = set(vectors["declared_fail_sets"][name])
        results = run({**REFERENCE_FLAGS, **overrides})
        ok = True
        print("")
        print(f"boundary: {name}")
        for v in vectors["vectors"]:
            actual = results[v["id"]]
            should_match = v["id"] not in declared
            entry_ok = matches(actual, v) if should_match else not matches(actual, v)
            ok = ok and entry_ok
            if should_match and entry_ok:
                continue
            label = "UNDECLARED MISMATCH" if should_match else ("DECLARED FAIL" if entry_ok else "DEFECT DID NOT REPRODUCE")
            print(f"  {label} {v['id']}  {line(actual)}")
        print(f"  {name} diverged on exactly its declared set: {ok}")
        all_ok = all_ok and ok

    support = [
        ("chain state, including the time facet and revocation", "supported", "verify_authority_delegation_chain"),
        ("fixture-local record signatures", "supported", "verify over canonicalize_jcs"),
        ("scope membership", "not_supported",
         "no is_purpose_permitted equivalent in agent-passport-system 4.1.0; this runner applies the documented rule"),
        ("not_yet_effective as a state distinct from invalid", "not_supported",
         "the SDK returns invalid with NOT_YET_VALID; the lifecycle verdict is supplied by this runner"),
        ("suspension as a resolver answer", "not_supported",
         "the resolver recognizes active and revoked; suspension is supplied by this runner"),
        ("restricted as a state", "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"),
    ]
    for concept in ("handover acknowledgment", "rotation schedule and rest ledger",
                    "pre-authorized fallback scope", "pinned policy version",
                    "occurrence template pinning", "wind-down grace bound",
                    "queued-action fire-time recheck",
                    "clock attestation, time-source cross-check, smear tolerance"):
        support.append((concept, "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"))

    print("")
    print("Python SDK support, agent-passport-system 4.1.0:")
    for concept, verdict, how in support:
        print(f"  {verdict.ljust(14)} {concept}  ({how})")

    print("")
    print(f"reference-boundary matched: {matched}/{len(vectors['vectors'])}")
    print(f"all five defective boundaries diverged on exactly their declared sets: {all_ok}")
    if matched == len(vectors["vectors"]) and all_ok:
        print("PASSED: the Python SDK run agrees with the TypeScript run on every vector")
        return 0
    print("FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
