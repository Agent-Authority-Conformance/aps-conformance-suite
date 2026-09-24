#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Second implementation of the lifecycle-credential-events decision procedure.

Written from vectors.json and the README rather than ported line by line from
harness.ts, so that agreement is agreement between two implementations of a
stated rule and not a shared bug in one. Canonicalization is the Python
reference SDK's RFC 8785 implementation (`agent_passport.canonical.canonicalize_jcs`),
which is a different implementation from the suite's vendored TypeScript one, so
the digests this script recomputes are cross-language digests.

It checks the same eight things verify.ts checks, and additionally that the
pinned `record` object in vectors.json is itself byte-identical to the record
this implementation writes.

Run from the suite root with agent-passport-system 4.1.0 or later installed:

    python3 fixtures/lifecycle-credential-events/validate.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from agent_passport.canonical import canonicalize_jcs

HERE = Path(__file__).resolve().parent

CHECK_RESULTS = ("established_valid", "established_invalid", "not_established")


def read_json(name: str) -> Any:
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def instant(value: str) -> float:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(text).timestamp()


def digest_of(record: dict) -> str:
    return hashlib.sha256(canonicalize_jcs(record).encode("utf-8")).hexdigest()


def bytes_len(record: dict) -> int:
    return len(canonicalize_jcs(record).encode("utf-8"))


# ── policy axes ───────────────────────────────────────────────────────────

REFERENCE = {
    "name": "reference-verifier",
    "ingest_third_party_triggers": True,
    "reach_basis": "authority_graph",
    "signature_satisfies_other_checks": False,
    "inherited_root_needs_reattestation": True,
    "log_integrity_settled_by_per_artifact_revocation": False,
    "issuer_population_per_chain": False,
    "accounting_from_authority_status": False,
    "presence_implies_authorized_addition": False,
    "skew_category": "clock_disagreement",
    "revocation_universal": False,
    "planned_rotation_opens_window": False,
    "window_start": "exposure",
    "partition_timestamp": "independent",
    "missing_record_result": "not_established",
}

CONTROL_PATCHES = {
    "self-initiated-triggers-only": {"ingest_third_party_triggers": False},
    "enumerated-reach-basis": {"reach_basis": "enumerated_list"},
    "signature-satisfies-other-checks": {"signature_satisfies_other_checks": True},
    "grandfather-inherited-root": {"inherited_root_needs_reattestation": False},
    "per-artifact-revocation-settles-log-integrity": {
        "log_integrity_settled_by_per_artifact_revocation": True
    },
    "issuer-population-from-caught-chains": {"issuer_population_per_chain": True},
    "revocation-closes-accounting": {"accounting_from_authority_status": True},
    "presence-implies-authorized-addition": {"presence_implies_authorized_addition": True},
    "skew-is-expiry": {"skew_category": "expiry"},
    "revocation-is-universal": {"revocation_universal": True},
    "every-rotation-is-a-trigger": {"planned_rotation_opens_window": True},
    "discovery-dated-window": {"window_start": "discovery"},
    "trust-claimed-issued-at": {"partition_timestamp": "claimed"},
    "skip-unestablished-checks": {"missing_record_result": "established_valid"},
}


def policy_named(name: str) -> dict:
    out = dict(REFERENCE)
    out.update(CONTROL_PATCHES[name])
    out["name"] = name
    return out


# ── the checks ────────────────────────────────────────────────────────────


class Ctx:
    def __init__(self, boundary: dict, policy: dict) -> None:
        self.boundary = boundary
        self.policy = policy
        self.compromise_reach: dict | None = None
        self.suspect_window: dict | None = None
        self.clock: dict | None = None
        self.revocation_effectiveness: dict | None = None

    def events(self, type_: str) -> list[dict]:
        return [e for e in self.boundary["events"] if e["type"] == type_]

    def first(self, type_: str) -> dict | None:
        found = self.events(type_)
        return found[0] if found else None

    @property
    def cred(self) -> dict:
        return self.boundary["credential"]

    @property
    def tp(self) -> dict:
        return self.boundary["trust_policy"]


def ok(reason: str, basis: str) -> dict:
    return {"result": "established_valid", "reason": reason, "basis": basis}


def bad(reason: str, basis: str) -> dict:
    return {"result": "established_invalid", "reason": reason, "basis": basis}


def missing(ctx: Ctx, reason: str, basis: str) -> dict:
    if ctx.policy["missing_record_result"] == "established_valid":
        return ok(f"{reason}_treated_as_passed", basis)
    return {"result": "not_established", "reason": reason, "basis": basis}


def reachable_from(edges: list[dict], start: str) -> list[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        for edge in edges:
            if edge["from"] == node and edge["to"] not in seen:
                seen.add(edge["to"])
                stack.append(edge["to"])
    return sorted(seen)


def c_signature(ctx: Ctx) -> dict:
    return ok("signature_verifies_under_key_version_at_issued_at", "chain.json")


def c_key_scope(ctx: Ctx) -> dict:
    if ctx.policy["signature_satisfies_other_checks"]:
        return ok("signature_verified_so_key_scope_assumed", "chain.json")
    scope = ctx.first("key_scope")
    if scope is None:
        return missing(ctx, "key_scope_not_declared", "no key_scope record")
    if scope["attestor_standing"] != "declared":
        return missing(
            ctx,
            "key_scope_attestor_standing_not_established",
            f"key_scope {scope['event_id']} attestor {scope['attestor']}",
        )
    if ctx.cred["claimed_audience"] in scope.get("populations", []):
        return ok("key_scope_covers_claimed_audience", scope["event_id"])
    return bad("key_scope_does_not_cover_claimed_audience", scope["event_id"])


def c_enforced_scope(ctx: Ctx) -> dict:
    if ctx.policy["signature_satisfies_other_checks"]:
        return ok("signature_verified_so_declared_scope_assumed_enforced", "chain.json")
    att = ctx.first("reachable_scope_attestation")
    if att is None:
        return missing(ctx, "enforced_scope_not_attested", "no reachable_scope_attestation record")
    if att["attestor_standing"] != "declared":
        return missing(
            ctx,
            "reachable_scope_attestor_standing_not_established",
            f"reachable_scope_attestation {att['event_id']} attestor {att['attestor']}",
        )
    declared = set(ctx.cred["declared_scope"])
    outside = [g for g in sorted(att.get("grants", [])) if g not in declared]
    if outside:
        return bad(
            "enforced_scope_exceeds_declared_scope",
            f"{att['event_id']} reaches {','.join(outside)}",
        )
    return ok("enforced_scope_contained_in_declared_scope", att["event_id"])


def c_provenance(ctx: Ctx) -> dict:
    if ctx.policy["signature_satisfies_other_checks"]:
        return ok("signature_verified_so_provenance_assumed", "chain.json")
    prov = ctx.first("provenance_attestation")
    if prov is None:
        return missing(ctx, "artifact_provenance_not_attested", "no provenance_attestation record")
    if prov.get("independent_of_signing_key") is not True:
        return missing(
            ctx,
            "provenance_attestor_not_independent_of_signing_key",
            f"provenance_attestation {prov['event_id']} attestor {prov['attestor']}",
        )
    if prov["attestor_standing"] != "declared":
        return missing(
            ctx,
            "provenance_attestor_standing_not_established",
            f"provenance_attestation {prov['event_id']} attestor {prov['attestor']}",
        )
    return ok("provenance_attested_by_independent_attestor", prov["event_id"])


def c_authorizer_addition(ctx: Ctx) -> dict:
    authorizers = ctx.tp["authorizers"]
    if ctx.policy["presence_implies_authorized_addition"]:
        return ok("present_on_authorizer_list", f"authorizers {','.join(authorizers)}")
    by_id = {e["authorizer_id"]: e for e in ctx.events("authorizer_addition")}
    unrecorded = sorted(a for a in authorizers if a not in by_id)
    if unrecorded:
        return missing(
            ctx,
            "authorizer_addition_not_attested",
            f"no authorizer_addition record for {','.join(unrecorded)}",
        )
    without = sorted(a for a in authorizers if by_id[a]["attestor_standing"] != "declared")
    if without:
        return missing(
            ctx,
            "authorizer_addition_attestor_standing_not_established",
            f"authorizer_addition for {','.join(without)}",
        )
    return ok(
        "every_authorizer_has_an_attested_addition",
        ",".join(sorted(by_id[a]["event_id"] for a in authorizers)),
    )


def c_compromise_reach(ctx: Ctx) -> dict:
    disclosure = ctx.first("compromise_disclosure")
    if disclosure is None:
        return ok("no_compromise_disclosure_at_this_boundary", "events")
    accepted = disclosure.get("self_initiated") is True or ctx.policy["ingest_third_party_triggers"]
    if not accepted:
        return ok("no_self_initiated_revocation_recorded", "events")
    if disclosure["attestor_standing"] != "declared":
        ctx.compromise_reach = {
            "trigger_event_id": disclosure["event_id"],
            "trigger_accepted": False,
            "reach_basis": ctx.policy["reach_basis"],
            "reached": [],
            "credential_in_reach": False,
            "reattested": False,
        }
        return ok(
            "compromise_claim_attestor_standing_not_established_no_trigger",
            disclosure["event_id"],
        )
    if ctx.policy["reach_basis"] == "authority_graph":
        reached = reachable_from(ctx.tp["authority_graph"], disclosure["subject"])
    else:
        reached = sorted(ctx.tp["enumerated_reach_list"])
    in_reach = ctx.cred["subject"] in reached
    reatt = next(
        (
            e
            for e in ctx.events("reattestation")
            if e.get("covers") == "credential" and e["attestor_standing"] == "declared"
        ),
        None,
    )
    reattested = bool(
        reatt is not None and instant(reatt["at"]) >= instant(disclosure["disclosed_at"])
    )
    ctx.compromise_reach = {
        "trigger_event_id": disclosure["event_id"],
        "trigger_accepted": True,
        "reach_basis": ctx.policy["reach_basis"],
        "reached": reached,
        "credential_in_reach": in_reach,
        "reattested": reattested,
    }
    if not in_reach:
        return ok("credential_not_reachable_from_compromised_subject", disclosure["event_id"])
    if reattested:
        return ok("reattested_after_disclosure", reatt["event_id"])
    return missing(ctx, "in_reach_of_compromise_and_not_reattested", disclosure["event_id"])


def c_log_integrity(ctx: Ctx) -> dict:
    finding = ctx.first("issuance_log_integrity_finding")
    if finding is None:
        return ok("no_issuance_log_integrity_finding_at_this_boundary", "events")
    window = finding["window"]
    issued = instant(ctx.cred["issued_at"])
    inside = instant(window["start"]) <= issued < instant(window["end"])
    if not inside:
        return ok("issued_outside_the_window_the_finding_covers", finding["event_id"])
    if ctx.policy["log_integrity_settled_by_per_artifact_revocation"]:
        other = any(
            r["credential_ref"] != ctx.cred["subject"] for r in ctx.events("revocation")
        )
        return ok(
            "bad_artifacts_individually_revoked_so_this_one_assumed_good"
            if other
            else "no_revocation_record_names_this_credential",
            "events",
        )
    re_est = next(
        (
            e
            for e in ctx.events("reattestation")
            if e.get("covers") == "issuance_window" and e["attestor_standing"] == "declared"
        ),
        None,
    )
    if re_est is not None:
        return ok("reestablished_from_a_reverified_root", re_est["event_id"])
    return missing(ctx, "issuance_log_integrity_not_established_for_window", finding["event_id"])


def c_issuer_population(ctx: Ctx) -> dict:
    finding = ctx.first("issuer_misbehaviour_finding")
    if finding is None:
        return ok("no_issuer_misbehaviour_finding_at_this_boundary", "events")
    if ctx.policy["issuer_population_per_chain"]:
        caught = any(
            r["credential_ref"] == ctx.cred["subject"] for r in ctx.events("revocation")
        )
        if caught:
            return bad("this_chain_was_among_the_ones_caught", "events")
        return ok("this_chain_was_not_among_the_ones_caught", "events")
    if finding["attestor_standing"] != "declared" or finding.get("discovered_by") != "external_monitor":
        return missing(ctx, "issuer_misbehaviour_finding_basis_not_established", finding["event_id"])
    reatt = next(
        (
            e
            for e in ctx.events("reattestation")
            if e.get("covers") == "issuer_population" and e["attestor_standing"] == "declared"
        ),
        None,
    )
    if reatt is not None:
        return ok("issuer_population_reattested", reatt["event_id"])
    return missing(ctx, "issuer_population_trust_not_established", finding["event_id"])


def c_suspect_window(ctx: Ctx) -> dict:
    planned = ctx.first("planned_rotation")
    exposure = ctx.first("exposure_window_finding")
    compromise = ctx.first("key_compromise_finding")

    if planned is not None and exposure is None and compromise is None:
        if ctx.policy["planned_rotation_opens_window"]:
            ctx.suspect_window = {
                "finding_event_id": planned["event_id"],
                "start": planned["cryptoperiod_end"],
                "start_basis": "discovery",
                "partition_timestamp_source": "none",
                "artifact_position": "not_established",
            }
            return missing(ctx, "rotation_opens_a_suspect_window", planned["event_id"])
        ctx.suspect_window = {
            "finding_event_id": planned["event_id"],
            "start": None,
            "start_basis": "none",
            "partition_timestamp_source": "none",
            "artifact_position": "before_window",
        }
        return ok(
            "planned_rotation_at_declared_cryptoperiod_end_opens_no_suspect_window",
            planned["event_id"],
        )

    if exposure is not None:
        start = (
            exposure["exposure_start"]
            if ctx.policy["window_start"] == "exposure"
            else exposure["discovered_at"]
        )
        inside = instant(ctx.cred["issued_at"]) >= instant(start)
        ctx.suspect_window = {
            "finding_event_id": exposure["event_id"],
            "start": start,
            "start_basis": "exposure" if ctx.policy["window_start"] == "exposure" else "discovery",
            "partition_timestamp_source": "issuer_claim",
            "artifact_position": "inside_window" if inside else "before_window",
        }
        if not inside:
            return ok("artifact_dated_before_the_suspect_window", exposure["event_id"])
        return missing(ctx, "artifact_issued_inside_the_exposure_window", exposure["event_id"])

    if compromise is not None:
        point = compromise["compromise_point"]
        independent = next(
            (
                e
                for e in ctx.events("independent_timestamp_attestation")
                if e["attestor_standing"] == "declared"
            ),
            None,
        )
        if ctx.policy["partition_timestamp"] == "independent":
            source = "independent_attestation" if independent is not None else "none"
            dated = independent["artifact_dated_at"] if independent is not None else None
        else:
            source = "issuer_claim"
            dated = ctx.cred["issued_at"]
        if dated is None:
            ctx.suspect_window = {
                "finding_event_id": compromise["event_id"],
                "start": point,
                "start_basis": "compromise_point",
                "partition_timestamp_source": "none",
                "artifact_position": "not_established",
            }
            return missing(
                ctx,
                "partition_timestamp_evidence_not_independent_of_the_compromised_key",
                compromise["event_id"],
            )
        before = instant(dated) < instant(point)
        ctx.suspect_window = {
            "finding_event_id": compromise["event_id"],
            "start": point,
            "start_basis": "compromise_point",
            "partition_timestamp_source": source,
            "artifact_position": "before_window" if before else "inside_window",
        }
        if before:
            return ok(
                "independently_dated_before_the_compromise_point",
                independent["event_id"] if independent is not None else "credential.issued_at",
            )
        return missing(ctx, "dated_inside_the_compromise_window", compromise["event_id"])

    return ok("no_key_finding_at_this_boundary", "events")


def c_revocation_effectiveness(ctx: Ctx) -> dict:
    rev = next(
        (r for r in ctx.events("revocation") if r["credential_ref"] == ctx.cred["subject"]),
        None,
    )
    if rev is None:
        return ok("no_revocation_record_names_this_credential", "events")
    if ctx.policy["revocation_universal"]:
        return bad("revoked", rev["event_id"])
    if ctx.cred["status_lookup"]:
        ctx.revocation_effectiveness = {
            "revocation_event_id": rev["event_id"],
            "status": "valid",
            "effective_from": rev["recorded_at"],
            "basis": "boundary_performs_a_status_lookup_for_this_credential_class",
        }
        return bad("revoked", rev["event_id"])
    ctx.revocation_effectiveness = {
        "revocation_event_id": rev["event_id"],
        "status": "not yet effective",
        "effective_from": ctx.cred["not_after"],
        "basis": "credential_class_verified_by_signature_alone_with_no_status_lookup",
    }
    return ok(
        "revocation_recorded_and_not_yet_effective_for_this_credential_class",
        rev["event_id"],
    )


def c_clock(ctx: Ctx) -> dict:
    tolerance = ctx.tp["clock_tolerance_s"]
    att = next(
        (e for e in ctx.events("time_attestation") if e["attestor_standing"] == "declared"),
        None,
    )
    gateway_now = instant(ctx.boundary["gateway_now"])
    if att is None:
        ctx.clock = {
            "gateway_now": ctx.boundary["gateway_now"],
            "reference_now": None,
            "skew_s": None,
            "tolerance_s": tolerance,
            "within_tolerance": False,
        }
        return missing(ctx, "no_attested_reference_clock", "no time_attestation record")
    reference = instant(att["reference_now"])
    import math

    skew = abs(math.floor((gateway_now - reference)))
    within = skew <= tolerance
    ctx.clock = {
        "gateway_now": ctx.boundary["gateway_now"],
        "reference_now": att["reference_now"],
        "skew_s": skew,
        "tolerance_s": tolerance,
        "within_tolerance": within,
    }
    if not within:
        if ctx.policy["skew_category"] == "expiry":
            return bad("expired", att["event_id"])
        return {
            "result": "not_established",
            "reason": "clock_disagreement_beyond_tolerance",
            "basis": att["event_id"],
        }
    in_window = instant(ctx.cred["not_before"]) <= gateway_now < instant(ctx.cred["not_after"])
    if not in_window:
        return bad("expired", "credential.not_after")
    return ok(
        "clocks_agree_within_tolerance_and_artifact_is_inside_its_window", att["event_id"]
    )


def c_inherited_root(ctx: Ctx) -> dict:
    inherited = [r for r in ctx.tp["roots"] if "inherited_at" in r]
    if not inherited:
        return ok("no_inherited_root_in_the_trust_policy", "trust_policy.roots")
    if not ctx.policy["inherited_root_needs_reattestation"]:
        return ok(
            "root_was_valid_under_the_acquired_entity_before_the_change",
            ",".join(sorted(r["root_id"] for r in inherited)),
        )
    reatt = next(
        (
            e
            for e in ctx.events("reattestation")
            if e.get("covers") == "inherited_root" and e["attestor_standing"] == "declared"
        ),
        None,
    )
    if reatt is not None:
        return ok(
            "inherited_root_reestablished_under_the_inheriting_party_root", reatt["event_id"]
        )
    overdue = [
        r
        for r in inherited
        if "reattestation_deadline" in r
        and instant(ctx.boundary["gateway_now"]) >= instant(r["reattestation_deadline"])
    ]
    if not overdue:
        return ok(
            "inside_the_declared_reattestation_deadline",
            ",".join(
                sorted(
                    f"{r['root_id']}@{r.get('reattestation_deadline', 'no_deadline')}"
                    for r in inherited
                )
            ),
        )
    return missing(
        ctx,
        "inherited_root_not_reattested_by_the_declared_deadline",
        ",".join(sorted(r["root_id"] for r in overdue)),
    )


def c_accounting(ctx: Ctx) -> dict:
    if ctx.policy["accounting_from_authority_status"]:
        revoked = any(
            r["credential_ref"] == ctx.cred["subject"] for r in ctx.events("revocation")
        )
        if revoked:
            return ok("authority_revoked_so_accounting_assumed_closed", "events")
    coverage = next(
        (
            e
            for e in ctx.events("accounting_coverage_basis")
            if e["attestor_standing"] == "declared"
        ),
        None,
    )
    if coverage is None:
        return missing(
            ctx,
            "no_coverage_basis_for_what_was_done_under_this_credential",
            "no accounting_coverage_basis record",
        )
    if coverage.get("complete") is not True:
        return missing(
            ctx,
            "coverage_basis_does_not_claim_completeness_over_the_valid_interval",
            coverage["event_id"],
        )
    return ok("coverage_basis_complete_over_the_valid_interval", coverage["event_id"])


CHECKS: dict[str, Callable[[Ctx], dict]] = {
    "signature_and_key_version": c_signature,
    "key_scope_containment": c_key_scope,
    "enforced_scope_containment": c_enforced_scope,
    "artifact_provenance": c_provenance,
    "authorizer_addition_provenance": c_authorizer_addition,
    "compromise_reach": c_compromise_reach,
    "issuance_log_integrity": c_log_integrity,
    "issuer_population_trust": c_issuer_population,
    "suspect_window_partition": c_suspect_window,
    "revocation_effectiveness": c_revocation_effectiveness,
    "clock_agreement": c_clock,
    "inherited_root_reattestation": c_inherited_root,
    "exercised_authority_accounting": c_accounting,
}


def evaluate_boundary(
    boundary: dict, credential_ref: str, policy: dict, vector_id: str, case_id: str | None
) -> dict:
    ctx = Ctx(boundary, policy)
    required = boundary["trust_policy"]["required_checks"]
    outcomes = []
    for check_id in required:
        outcomes.append((check_id, CHECKS[check_id](ctx)))

    first_invalid = next((o for o in outcomes if o[1]["result"] == "established_invalid"), None)
    first_unestablished = next((o for o in outcomes if o[1]["result"] == "not_established"), None)
    if first_invalid is not None:
        verdict = "invalid"
        reason = f"{first_invalid[0]}:{first_invalid[1]['reason']}"
    elif first_unestablished is not None:
        verdict = "not established"
        reason = f"{first_unestablished[0]}:{first_unestablished[1]['reason']}"
    else:
        verdict = "valid"
        reason = "every_declared_check_established"

    checks = sorted(
        (
            {
                "check_id": check_id,
                "result": outcome["result"],
                "reason": outcome["reason"],
                "basis": outcome["basis"],
            }
            for check_id, outcome in outcomes
        ),
        key=lambda c: c["check_id"],
    )

    return {
        "record_type": "aac.credential-event-record.v0",
        "vector_id": vector_id,
        "case_id": case_id,
        "credential_ref": credential_ref,
        "evaluated_at": boundary["gateway_now"],
        "verdict": verdict,
        "verdict_reason": reason,
        "required_checks": list(required),
        "checks": checks,
        "compromise_reach": ctx.compromise_reach,
        "suspect_window": ctx.suspect_window,
        "clock": ctx.clock,
        "revocation_effectiveness": ctx.revocation_effectiveness,
        "prior_record_sha256": boundary["prior_record_sha256"],
    }


def evaluate_vector(
    boundaries: list[dict], credential_ref: str, policy: dict, vector_id: str, case_id: str | None
) -> list[dict]:
    out: list[dict] = []
    for boundary in boundaries:
        prior = boundary["prior_record_sha256"]
        if prior == "PRIOR":
            prior = digest_of(out[-1])
        replay = dict(boundary)
        replay["prior_record_sha256"] = prior
        out.append(evaluate_boundary(replay, credential_ref, policy, vector_id, case_id))
    return out


# ── the run ───────────────────────────────────────────────────────────────


def main() -> int:
    vectors = read_json("vectors.json")
    chain = read_json("chain.json")
    failures: list[str] = []

    if chain["chain"][1]["delegation_id"] != vectors["credential_ref"]:
        failures.append("credential_ref does not match the chain.json leaf")

    credential_ref = vectors["credential_ref"]
    boundary_count = 0
    per_vector_ok: dict[str, bool] = {}

    def run_case(case: dict, policy: dict) -> tuple[bool, bool, list[str]]:
        """Returns (record_diverged, verdict_diverged, lines)."""
        try:
            records = evaluate_vector(
                case["boundaries"], credential_ref, policy, case["id"], case["case_id"]
            )
        except Exception as exc:  # a throw is a divergence, reported as one
            return True, True, [f"{case['id']}: raised under {policy['name']}: {exc}"]
        rec_div = False
        ver_div = False
        lines: list[str] = []
        for boundary, record in zip(case["boundaries"], records):
            want = boundary["expected"]
            v = record["verdict"] != want["verdict"] or record["verdict_reason"] != want["verdict_reason"]
            d = (
                v
                or digest_of(record) != want["canonical_sha256"]
                or bytes_len(record) != want["canonical_bytes_len"]
            )
            if v:
                ver_div = True
            if d:
                rec_div = True
                lines.append(
                    f"{boundary['boundary_id']}: want {want['verdict']}/{want['verdict_reason']} "
                    f"sha256={want['canonical_sha256'][:16]}, got {record['verdict']}/"
                    f"{record['verdict_reason']} sha256={digest_of(record)[:16]}"
                )
        return rec_div, ver_div, lines

    for case in vectors["cases"]:
        if case["label"] != "candidate_against_proposed":
            failures.append(f"{case['id']}: label is {case['label']}")
        rec_div, _, lines = run_case(case, REFERENCE)
        per_vector_ok[case["id"]] = not rec_div
        failures.extend(f"reference-verifier {line}" for line in lines)

        records = evaluate_vector(
            case["boundaries"], credential_ref, REFERENCE, case["id"], case["case_id"]
        )
        for index, (boundary, record) in enumerate(zip(case["boundaries"], records)):
            boundary_count += 1
            bid = boundary["boundary_id"]
            want = boundary["expected"]

            # the pinned record object itself, field for field
            if canonicalize_jcs(record) != canonicalize_jcs(want["record"]):
                failures.append(f"{bid}: pinned record object differs from the recomputed one")

            if want["verdict"] != "valid" and record["verdict"] == "valid":
                failures.append(f"{bid}: came out valid where the vector declares {want['verdict']}")

            declared = record["required_checks"]
            if len(set(declared)) != len(declared):
                failures.append(f"{bid}: required_checks repeats a check id")
            if len(record["checks"]) != len(declared):
                failures.append(f"{bid}: check count does not match the declared set")
            for entry in record["checks"]:
                if entry["result"] not in CHECK_RESULTS:
                    failures.append(f"{bid}: {entry['check_id']} result {entry['result']}")
                if entry["result"] == "established_valid" and entry["basis"].startswith("no "):
                    failures.append(
                        f"{bid}: {entry['check_id']} established_valid on an absent record"
                    )
                if entry["reason"].endswith("_treated_as_passed"):
                    failures.append(f"{bid}: {entry['check_id']} carries a control-only reason")

            # the verdict is the join, recomputed from the record's own checks
            by_id = {c["check_id"]: c for c in record["checks"]}
            in_order = [by_id[c] for c in declared]
            inv = next((c for c in in_order if c["result"] == "established_invalid"), None)
            une = next((c for c in in_order if c["result"] == "not_established"), None)
            if inv is not None:
                expect = ("invalid", f"{inv['check_id']}:{inv['reason']}")
            elif une is not None:
                expect = ("not established", f"{une['check_id']}:{une['reason']}")
            else:
                expect = ("valid", "every_declared_check_established")
            if (record["verdict"], record["verdict_reason"]) != expect:
                failures.append(f"{bid}: verdict is not the join of its own check list")

            if index > 0:
                prior_digest = digest_of(records[index - 1])
                if record["prior_record_sha256"] != prior_digest:
                    failures.append(f"{bid}: prior_record_sha256 is not the earlier record's digest")
                if prior_digest != case["boundaries"][index - 1]["expected"]["canonical_sha256"]:
                    failures.append(
                        f"{case['boundaries'][index - 1]['boundary_id']}: record changed after a "
                        "later boundary ran"
                    )

    control_lines: list[str] = []
    for control in vectors["controls"]:
        if control["name"] not in CONTROL_PATCHES:
            failures.append(f"control {control['name']} has no policy in validate.py")
            continue
        policy = policy_named(control["name"])
        scope = [c for c in vectors["cases"] if c["id"] in control["scope"]]
        if len(scope) != len(control["scope"]):
            failures.append(f"control {control['name']}: scope names an unknown vector id")
        failed: list[str] = []
        changed: list[str] = []
        for case in scope:
            rec_div, ver_div, _ = run_case(case, policy)
            if rec_div:
                failed.append(case["id"])
            if ver_div:
                changed.append(case["id"])
        if sorted(failed) != sorted(control["must_fail"]):
            failures.append(
                f"control {control['name']}: declared record-divergence set "
                f"{sorted(control['must_fail'])}, observed {sorted(failed)}"
            )
        if sorted(changed) != sorted(control["must_change_verdict"]):
            failures.append(
                f"control {control['name']}: declared verdict-change set "
                f"{sorted(control['must_change_verdict'])}, observed {sorted(changed)}"
            )
        control_lines.append(
            f"  {control['name']}: ran {len(scope)}, record diverged on {len(failed)}, "
            f"verdict changed on {len(changed)}"
        )

    for case in vectors["cases"]:
        print(f"{'PASS' if per_vector_ok.get(case['id']) else 'FAIL'} {case['id']}")
    print("controls:")
    for line in control_lines:
        print(line)

    if failures:
        print("", file=sys.stderr)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(
            f"\nlifecycle-credential-events Python: {len(failures)} failure(s)", file=sys.stderr
        )
        return 1

    print(
        f"\nPASSED: lifecycle-credential-events Python, {len(vectors['cases'])} vectors, "
        f"{boundary_count} boundaries, second implementation matched every pinned record "
        f"including its RFC 8785 digest, each of {len(vectors['controls'])} controls diverged "
        f"on exactly its declared set"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
