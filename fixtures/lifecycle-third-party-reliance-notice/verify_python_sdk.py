#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python-side runner for the lifecycle-third-party-reliance-notice family.

Reads the same chain.json and vectors.json the TypeScript runner reads and decides every
vector again against the published Python reference SDK, agent-passport-system 4.x from
PyPI. The notice boundary below is a second, independent implementation of the same
reference model harness.ts implements: the two runners agree on every vector or this family
does not pass.

WHAT COMES FROM THE SDK HERE. Chain state (verify_authority_delegation_chain), revocation
verification and recording (verify_authority_revocation, record_authority_revocation),
revocation resolution including the 'unknown' a record that does not verify must produce
(create_authority_revocation_resolver over InMemoryAuthorityRevocationStore) and every
signature (verify over canonicalize_jcs). Notice, the prior-dealing register and the
two-tier notice rule come from this file: no Python SDK export covers any of them.

WHAT THIS RUNNER NEVER ANSWERS. Whether any outside party's reliance is protected. That is
a legal effect decided off the wire.

Not part of `npm test`. Run it as:

    python3 -m venv /tmp/aac-lc-g3-venv
    /tmp/aac-lc-g3-venv/bin/pip install 'agent-passport-system==4.1.0'
    /tmp/aac-lc-g3-venv/bin/python fixtures/lifecycle-third-party-reliance-notice/verify_python_sdk.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import (
    InMemoryAuthorityRevocationStore,
    canonicalize_jcs,
    create_authority_revocation_resolver,
    record_authority_revocation,
    verify,
)
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

VERDICT_VOCABULARY = {"valid", "invalid", "suspended", "restricted", "not established", "not yet effective"}
NOTICE_VOCABULARY = {"established", "not established"}


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


FIXTURE = read_json("chain.json")
VECTORS = read_json("vectors.json")

KEYS = FIXTURE["verification_keys"]
DOMAINS = FIXTURE["signature_domains"]
TRACKED_DELEGATION_IDS = [record["delegation_id"] for chain in FIXTURE["chains"].values() for record in chain]


def resolve_verification_key(_issuer, verification_method, _issued_at=None):
    return KEYS.get(verification_method)


def signed_body_verifies(record, domain) -> bool:
    body = {k: v for k, v in record.items() if k != "signature"}
    public_key = KEYS.get(record["verification_method"])
    if public_key is None:
        return False
    return verify(f"{domain} {canonicalize_jcs(body)}", record["signature"], public_key)


class AuthorityBoundary:
    """Second implementation of the same reference model harness.ts implements."""

    def __init__(
        self,
        name,
        answers_notice_separately=True,
        requires_individual_notice_for_prior_dealing=True,
        checks_notice_standing=True,
        treats_newer_grant_as_revocation=False,
    ):
        self.name = name
        self.answers_notice_separately = answers_notice_separately
        self.requires_individual_notice_for_prior_dealing = requires_individual_notice_for_prior_dealing
        self.checks_notice_standing = checks_notice_standing
        self.treats_newer_grant_as_revocation = treats_newer_grant_as_revocation

    # -- chain state, from the SDK ----------------------------------------

    def chain_state(self, request):
        store = InMemoryAuthorityRevocationStore()
        for delegation_id in TRACKED_DELEGATION_IDS:
            store.track(delegation_id)

        held_records = [record for chain in request["held_chains"] for record in chain]
        for revocation in request["revocations"]:
            target = next((r for r in held_records if r["delegation_id"] == revocation["delegation_id"]), None)
            if target is None:
                continue
            result = record_authority_revocation(store, target, revocation, resolve_verification_key=resolve_verification_key)
            if not result.recorded:
                # The supported entry point verified the record against its target and
                # refused. The raw persistence primitive is used anyway so that the
                # resolver, which re-verifies on the way out, is the thing that decides.
                store.insert_verified_revocation(revocation)

        resolve_revocation = create_authority_revocation_resolver(store, resolve_verification_key=resolve_verification_key)
        root_issuer = request["chain"][0]["issuer"]
        result = verify_authority_delegation_chain(
            request["chain"],
            now=request["now"],
            resolve_verification_key=resolve_verification_key,
            trust_root=lambda root: root["issuer"] == root_issuer,
            resolve_revocation=resolve_revocation,
        )
        first = result.failures[0] if result.failures else None
        return result.state, (first.code if first is not None else None)

    def authority_verdict(self, state, request):
        if state == "valid" and self.treats_newer_grant_as_revocation:
            presented = request["chain"][0]
            superseding = next(
                (
                    held[0]
                    for held in request["held_chains"]
                    if held[0]["delegation_id"] != presented["delegation_id"]
                    and held[0]["issuer"] == presented["issuer"]
                    and held[0]["subject"] == presented["subject"]
                    and held[0]["issued_at"] > presented["issued_at"]
                ),
                None,
            )
            if superseding is not None:
                return "invalid", "superseded_by_newer_grant"
        if state == "valid":
            return "valid", "chain_valid"
        if state == "indeterminate":
            return "not established", "chain_state_not_established"
        if state == "invalid":
            return "invalid", "chain_not_valid"
        return "not established", "chain_state_not_established"

    # -- notice state ------------------------------------------------------

    def reference_notice(self, request, state):
        presented_id = request["chain"][-1]["delegation_id"]
        revocation = next((r for r in request["revocations"] if r["delegation_id"] == presented_id), None)
        if revocation is None or state == "valid":
            return "not established", None, "no_termination_recorded"

        applicable = []
        for notice in request["notices"]:
            if notice["issued_at"] > request["now"]:
                continue
            if not signed_body_verifies(notice, DOMAINS["notice_record"]):
                continue
            if self.checks_notice_standing and notice["issuer"] != revocation["revoker"]:
                continue
            if notice["revocation_id"] != revocation["revocation_id"]:
                continue
            applicable.append(notice)

        individual = next(
            (n for n in applicable if n["mode"] == "individual" and n["counterparty"] == request["counterparty"]),
            None,
        )
        if individual is not None:
            return "established", "individual", "individual_notice_record"

        publication = next((n for n in applicable if n["mode"] == "publication"), None)
        if publication is not None:
            register = request["prior_dealing_register"]
            has_prior = signed_body_verifies(register, DOMAINS["prior_dealing_register"]) and request["counterparty"] in register["counterparties"]
            if has_prior and self.requires_individual_notice_for_prior_dealing:
                return "not established", None, "individual_notice_required_for_prior_dealing"
            return "established", "publication", "publication_notice_record"

        observed_but_unestablished = any(
            n["issued_at"] <= request["now"]
            and (not signed_body_verifies(n, DOMAINS["notice_record"]) or n["issuer"] != revocation["revoker"])
            for n in request["notices"]
        )
        if observed_but_unestablished:
            return "not established", None, "notice_issuer_without_standing"
        return "not established", None, "no_notice_record"

    def notice_state(self, request, state):
        collapsed_state, basis, reason = self.reference_notice(request, state)
        if not self.answers_notice_separately:
            return ("not established" if state == "valid" else "established"), basis, reason
        return collapsed_state, basis, reason

    def handle(self, request):
        state, code = self.chain_state(request)
        verdict, verdict_reason = self.authority_verdict(state, request)
        notice_state, notice_basis, notice_reason = self.notice_state(request, state)
        return {
            "authority_verdict": verdict,
            "authority_reason": verdict_reason,
            "chain_state": state,
            "chain_failure_code": code,
            "notice_state": notice_state,
            "notice_basis": notice_basis,
            "notice_reason": notice_reason,
            "counterparty": request["counterparty"],
            "held_grant_count": len(request["held_chains"]),
        }


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def fail(message):
    print(f"lifecycle-third-party-reliance-notice: {message}", file=sys.stderr)
    sys.exit(2)


def to_request(vector):
    chain = FIXTURE["chains"].get(vector["chain"])
    if chain is None:
        fail(f"{vector['id']} names an unknown chain {vector['chain']}")
    now = FIXTURE["timeline"].get(vector["now"])
    if now is None:
        fail(f"{vector['id']} names an unknown timeline point {vector['now']}")
    counterparty = FIXTURE["counterparties"].get(vector["counterparty"])
    if counterparty is None:
        fail(f"{vector['id']} names an unknown counterparty {vector['counterparty']}")
    return {
        "chain": chain,
        "held_chains": [FIXTURE["chains"][name] for name in VECTORS["held_sets"][vector["held"]]],
        "revocations": [FIXTURE["revocations"][name] for name in VECTORS["revocation_sets"][vector["revocation_set"]]],
        "notices": [FIXTURE["notices"][name] for name in VECTORS["notice_sets"][vector["notice_set"]]],
        "prior_dealing_register": FIXTURE["prior_dealing_register"],
        "counterparty": counterparty,
        "now": now,
    }


COMPARED = (
    "authority_verdict",
    "authority_reason",
    "chain_state",
    "chain_failure_code",
    "notice_state",
    "notice_basis",
    "notice_reason",
    "held_grant_count",
)


def matches(actual, expected):
    return all(actual[field] == expected[field] for field in COMPARED)


def line(actual):
    return (
        f'authority="{actual["authority_verdict"]}"/{actual["authority_reason"]} '
        f'chain={actual["chain_state"]}/{actual["chain_failure_code"]} '
        f'notice="{actual["notice_state"]}"/{actual["notice_reason"]} basis={actual["notice_basis"]} '
        f'counterparty={actual["counterparty"]} held={actual["held_grant_count"]}'
    )


def run_boundary(boundary):
    return {vector["id"]: boundary.handle(to_request(vector)) for vector in VECTORS["vectors"]}


print(f"lifecycle-third-party-reliance-notice: {len(VECTORS['vectors'])} vectors, status label {VECTORS['status_label']} (python SDK)")
print()
print("boundary: reference-boundary")

reference_results = run_boundary(AuthorityBoundary("reference-boundary"))
reference_matched = 0
for vector in VECTORS["vectors"]:
    actual = reference_results[vector["id"]]
    ok = matches(actual, vector["expected"])
    if ok:
        reference_matched += 1
    print(f"  {'MATCH' if ok else 'MISMATCH'} {vector['id']} ({vector['case']})  {line(actual)}")
    if not ok:
        print(f"    expected: {json.dumps(vector['expected'], sort_keys=True)}")
        print(f"    actual:   {json.dumps(actual, sort_keys=True)}")

print()
print("structural checks")
structural_ok = True


def check(label, ok, detail):
    global structural_ok
    if not ok:
        structural_ok = False
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {detail}")


verdicts = sorted({o["authority_verdict"] for o in reference_results.values()})
check("authority verdict vocabulary", all(v in VERDICT_VOCABULARY for v in verdicts), f"observed {verdicts}")
notice_states = sorted({o["notice_state"] for o in reference_results.values()})
check("notice state vocabulary", all(v in NOTICE_VOCABULARY for v in notice_states), f"observed {notice_states}")

notice_by_verdict = {}
verdict_by_notice = {}
for outcome in reference_results.values():
    notice_by_verdict.setdefault(outcome["authority_verdict"], set()).add(outcome["notice_state"])
    verdict_by_notice.setdefault(outcome["notice_state"], set()).add(outcome["authority_verdict"])
verdict_with_both = [v for v, states in notice_by_verdict.items() if len(states) > 1]
notice_with_several = [n for n, vs in verdict_by_notice.items() if len(vs) > 1]
check("notice state is not a function of the authority verdict", bool(verdict_with_both), f"verdict(s) appearing with both notice states: {verdict_with_both}")
check("authority verdict is not a function of the notice state", bool(notice_with_several), f"notice state(s) appearing with several verdicts: {notice_with_several}")

publication = FIXTURE["notices"]["publication_all"]
check(
    "the publication record names no counterparty",
    publication["counterparty"] is None and publication["mode"] == "publication",
    f'mode={publication["mode"]} counterparty={publication["counterparty"]}',
)

older = FIXTURE["chains"]["older"][0]
newer = FIXTURE["chains"]["newer"][0]
check(
    "the newer grant is a distinct, later, broader grant from the same issuer to the same subject",
    older["delegation_id"] != newer["delegation_id"]
    and older["issuer"] == newer["issuer"]
    and older["subject"] == newer["subject"]
    and newer["issued_at"] > older["issued_at"],
    f'older issued_at {older["issued_at"]}, newer issued_at {newer["issued_at"]}, newer grants {newer["authority"]["scope"]["grants"]}',
)

DEFECTIVE = [
    ("defective-boundary-single-notice-boolean", {"answers_notice_separately": False}),
    ("defective-boundary-publication-covers-everyone", {"requires_individual_notice_for_prior_dealing": False}),
    ("defective-boundary-notice-without-standing", {"checks_notice_standing": False}),
    ("defective-boundary-newest-wins", {"treats_newer_grant_as_revocation": True}),
]

all_defectives_ok = True
for name, flags in DEFECTIVE:
    results = run_boundary(AuthorityBoundary(name, **flags))
    declared = VECTORS["declared_fail_sets"].get(name)
    if declared is None:
        fail(f"vectors.json declares no fail set for {name}")
    declared_set = set(declared)
    ok = True
    print()
    print(f"boundary: {name}")
    for vector in VECTORS["vectors"]:
        actual = results[vector["id"]]
        should_match = vector["id"] not in declared_set
        actually_matches = matches(actual, vector["expected"])
        entry_ok = actually_matches if should_match else not actually_matches
        if not entry_ok:
            ok = False
        if not should_match or not entry_ok:
            label = "MATCH" if should_match and entry_ok else ("UNDECLARED MISMATCH" if should_match else ("DECLARED FAIL" if entry_ok else "DEFECT DID NOT REPRODUCE"))
            print(f"  {label} {vector['id']}  {line(actual)}")
    same_authority = all(
        results[v["id"]]["authority_verdict"] == reference_results[v["id"]]["authority_verdict"]
        and results[v["id"]]["authority_reason"] == reference_results[v["id"]]["authority_reason"]
        for v in VECTORS["vectors"]
    )
    print(f"  {name}: {len(declared)} declared, diverged on exactly its declared set: {ok}, reaches the reference authority verdict on every vector: {same_authority}")
    if not ok:
        all_defectives_ok = False

SDK_SUPPORT = [
    ("chain state, including time and root trust", "supported", "verify_authority_delegation_chain"),
    ("direct revocation by the delegation issuer", "supported", "record_authority_revocation, verify_authority_revocation"),
    ("revocation resolution, including unknown for a record that does not verify", "supported", "create_authority_revocation_resolver over InMemoryAuthorityRevocationStore"),
    ("notice record and register signatures", "supported", "verify over canonicalize_jcs"),
    ("revocation by a party other than the issuer", "not_supported", "issue_authority_revocation admits only the target delegation's issuer as revoker"),
    ("notice record", "not_supported", "no Python SDK export, supplied by this fixture"),
    ("notice state for a named counterparty", "not_supported", "no Python SDK export, supplied by this runner"),
    ("prior-dealing register", "not_supported", "no Python SDK export, supplied by this fixture"),
    ("two-tier notice sufficiency", "not_supported", "no Python SDK export, supplied by this runner"),
]

print()
try:
    from importlib.metadata import version as _version

    SDK_VERSION = _version("agent-passport-system")
except Exception:  # pragma: no cover
    SDK_VERSION = "unknown"
print(f"Python SDK support, agent-passport-system {SDK_VERSION}:")
for concept, verdict, how in SDK_SUPPORT:
    print(f"  {verdict:<14} {concept}  ({how})")

reference_ok = reference_matched == len(VECTORS["vectors"])
print()
print(f"reference-boundary matched: {reference_matched}/{len(VECTORS['vectors'])}")
print(f"structural checks passed: {structural_ok}")
print(f"all four defective boundaries diverged on exactly their declared sets: {all_defectives_ok}")

if reference_ok and structural_ok and all_defectives_ok:
    print("PASSED: reference-boundary matched every vector, all four defective boundaries diverged on exactly their declared sets (python SDK)")
    sys.exit(0)
print("FAILED", file=sys.stderr)
sys.exit(1)
