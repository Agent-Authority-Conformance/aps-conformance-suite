#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the lifecycle-organization-events candidate family.
#
# Both models are implemented again here against the Python SDK rather than
# ported from the TypeScript run, so a divergence between the two runners is a
# real divergence between two implementations.
#
# Exit 0 when everything matches, 1 otherwise, 2 when the fixture is not
# minted.

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport.crypto import verify as verify_detached_signature
from agent_passport.v2.authority_delegation import (
    verify_authority_delegation_chain,
    verify_authority_delegation_signature,
)

HERE = Path(__file__).resolve().parent

LINKAGE_CODES = {"PARENT_MISMATCH", "CHAIN_CONTINUITY"}

BOUNDARY_FIELDS = (
    "outcome", "authority_verdict", "reason", "failure_code", "failure_index",
    "principal_established",
)
FLOW_FIELDS = ("outcome", "order_state", "reason", "authority_verdict", "failure_code")

POLICY_PROFILES = {
    "reference": {
        "compares_parent_linkage": True,
        "treats_corporate_record_as_delegation_event": False,
        "enforces_external_restriction": True,
        "enforces_third_party_consent": True,
    },
    "successor-exists-in-role": {
        "compares_parent_linkage": False,
        "treats_corporate_record_as_delegation_event": False,
        "enforces_external_restriction": True,
        "enforces_third_party_consent": True,
    },
    "corporate-record-as-delegation-event": {
        "compares_parent_linkage": True,
        "treats_corporate_record_as_delegation_event": True,
        "enforces_external_restriction": True,
        "enforces_third_party_consent": True,
    },
    "restriction-blind": {
        "compares_parent_linkage": True,
        "treats_corporate_record_as_delegation_event": False,
        "enforces_external_restriction": False,
        "enforces_third_party_consent": True,
    },
    "internal-chain-only": {
        "compares_parent_linkage": True,
        "treats_corporate_record_as_delegation_event": False,
        "enforces_external_restriction": True,
        "enforces_third_party_consent": False,
    },
}


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def canonicalize_jcs(value) -> str:
    """RFC 8785 canonical form, for the flat signed objects this family holds."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: [ord(ch) for ch in kv[0]])
        return "{" + ",".join(f"{canonicalize_jcs(k)}:{canonicalize_jcs(v)}" for k, v in members) + "}"
    raise TypeError(f"canonicalize_jcs does not handle {type(value).__name__}")


fixture = read_json("chains.json")
vectors = read_json("vectors.json")

if (
    fixture.get("_placeholder")
    or not isinstance(fixture.get("mint_now"), str)
    or len(fixture.get("chains") or {}) != 8
    or not fixture.get("verification_keys")
    or not fixture.get("roles")
    or not fixture.get("principal_of_root")
    or not fixture.get("attestor_standing")
    or not fixture.get("external_records")
    or not fixture.get("refusals")
):
    print(
        "lifecycle-organization-events chains.json is not minted. Run "
        "python3 fixtures/lifecycle-organization-events/mint.py first.",
        file=sys.stderr,
    )
    sys.exit(2)

ROLE_BY_ID = {delegation_id: role for role, delegation_id in fixture["roles"].items()}


def resolve_key(_issuer, method, _issued_at):
    return fixture["verification_keys"].get(method)


def chain_result(chain, now, answer):
    outcome = verify_authority_delegation_chain(
        chain, now=now, resolve_verification_key=resolve_key,
        trust_root=lambda _root: True, resolve_revocation=answer,
    )
    first = outcome.failures[0] if outcome.failures else None
    verdict = {"valid": "valid", "indeterminate": "not established"}.get(outcome.state, "invalid")
    return {
        "verdict": verdict,
        "code": first.code if first is not None else None,
        "index": first.index if first is not None else None,
    }


class AuthorityBoundary:
    """See harness.ts for the model this mirrors and the four declared axes."""

    def __init__(self, policy: str):
        self.profile = POLICY_PROFILES[policy]

    @staticmethod
    def _answer_for(revocation):
        def answer(delegation):
            role = ROLE_BY_ID.get(delegation.get("delegation_id"))
            if role is None:
                raise RuntimeError(
                    "organization-events resolver received a delegation with no registered role"
                )
            return revocation.get(role, "active")

        return answer

    def _linkage_blind(self, chain, now, revocation):
        root_only = chain_result([chain[0]], now, self._answer_for(revocation))
        if root_only["verdict"] != "valid":
            return {"verdict": "invalid", "code": root_only["code"], "index": 0}
        answer = self._answer_for(revocation)
        for index in range(1, len(chain)):
            record = chain[index]
            key = fixture["verification_keys"].get(record["verification_method"])
            if not isinstance(key, str) or not verify_authority_delegation_signature(record, key):
                return {"verdict": "invalid", "code": "SIGNATURE_INVALID", "index": index}
            time_facet = record["authority"]["time"]
            if now < time_facet["not_before"]:
                return {"verdict": "invalid", "code": "NOT_YET_VALID", "index": index}
            if now > time_facet["not_after"]:
                return {"verdict": "invalid", "code": "EXPIRED", "index": index}
            if answer(record) == "revoked":
                return {"verdict": "invalid", "code": "REVOKED", "index": index}
        return {"verdict": "valid", "code": None, "index": None}

    @staticmethod
    def _authentic(record) -> bool:
        body = {key: value for key, value in record.items() if key != "signature"}
        key = fixture["verification_keys"].get(f"{record['attestor']}#key-1")
        signature = record.get("signature")
        if not isinstance(key, str) or not isinstance(signature, str):
            return False
        return verify_detached_signature(canonicalize_jcs(body), signature, key) is True

    @staticmethod
    def _has_standing(record) -> bool:
        rule = fixture["attestor_standing"].get(record["record_type"])
        if rule is None:
            return False
        if rule == "gate_holder":
            return record["attestor"] == record.get("gate_holder")
        return isinstance(rule, list) and record["attestor"] in rule

    def evaluate(self, request):
        revocation = request.get("revocation") or {}
        chain = fixture["chains"][request["chain"]]
        principal_of_root = fixture["principal_of_root"].get(chain[0]["delegation_id"])

        strict = chain_result(chain, request["now"], self._answer_for(revocation))
        if not self.profile["compares_parent_linkage"] and strict["code"] in LINKAGE_CODES:
            outcome = self._linkage_blind(chain, request["now"], revocation)
        else:
            outcome = strict

        if outcome["verdict"] != "valid":
            return {
                "outcome": "not_admitted", "authority_verdict": outcome["verdict"],
                "reason": "chain_not_valid", "failure_code": outcome["code"],
                "failure_index": outcome["index"], "principal_established": None,
            }

        presented = [fixture["external_records"][name] for name in (request.get("present_records") or [])]

        def denied(reason, principal):
            return {
                "outcome": "not_admitted", "authority_verdict": "not established",
                "reason": reason, "failure_code": None, "failure_index": None,
                "principal_established": principal,
            }

        principal_established = principal_of_root
        if request.get("required_principal") is not None and principal_established != request["required_principal"]:
            succession = next(
                (r for r in presented if r.get("record_type") == "aac:corporate-succession:v0"), None
            )
            if succession is None:
                return denied("principal_binding_not_established", principal_established)
            if not self._authentic(succession):
                return denied("attestation_signature_invalid", principal_established)
            if not self._has_standing(succession):
                return denied("attestation_attestor_without_standing", principal_established)
            if not self.profile["treats_corporate_record_as_delegation_event"]:
                return denied("corporate_record_is_not_a_delegation_event", principal_established)
            principal_established = succession["surviving"]

        verdict_so_far = "valid"
        if self.profile["enforces_external_restriction"]:
            for record in presented:
                if record.get("record_type") != "aac:external-restriction:v0":
                    continue
                if record["about_principal"] != principal_of_root:
                    continue
                if not self._authentic(record) or not self._has_standing(record):
                    continue
                if record["effective_at"] > request["now"]:
                    continue
                verdict_so_far = "restricted"
                operation = request.get("operation")
                if operation is not None and operation not in record["remaining_operations"]:
                    return {
                        "outcome": "not_admitted", "authority_verdict": "restricted",
                        "reason": "external_restriction_excludes_operation",
                        "failure_code": None, "failure_index": None,
                        "principal_established": principal_established,
                    }

        if self.profile["enforces_third_party_consent"] and request.get("target") is not None:
            consents = [r for r in presented if r.get("record_type") == "aac:third-party-consent:v0"]
            authentic = [r for r in consents if self._authentic(r)]
            for_target = [
                r for r in authentic
                if r["target"] == request["target"] and r["operation"] == request.get("operation")
            ]
            if not for_target:
                reason = "third_party_consent_absent" if not authentic else "consent_target_mismatch"
                return denied(reason, principal_established)
            if not any(self._has_standing(r) for r in for_target):
                return denied("consent_attestor_without_standing", principal_established)

        return {
            "outcome": "admitted", "authority_verdict": verdict_so_far,
            "reason": "admitted_within_remaining_scope" if verdict_so_far == "restricted" else "admitted",
            "failure_code": None, "failure_index": None,
            "principal_established": principal_established,
        }


class InFlightBoundary:
    """See harness.ts. One ordered timeline for one payment order."""

    def __init__(self, policy: str):
        self.policy = policy
        self.orders = {}
        self.revoked = set()

    def _chain(self, chain_name, now):
        return chain_result(
            fixture["chains"][chain_name], now,
            lambda delegation: "revoked"
            if ROLE_BY_ID.get(delegation.get("delegation_id")) in self.revoked
            else "active",
        )

    def step(self, event):
        kind = event["kind"]

        if kind == "submit" or kind == "present_new":
            outcome = self._chain(event["chain"], event["now"])
            if outcome["verdict"] != "valid":
                return {"outcome": "not_admitted", "order_state": "none", "reason": "chain_not_valid",
                        "authority_verdict": outcome["verdict"], "failure_code": outcome["code"]}
            if kind == "submit":
                self.orders[event["order"]] = {"state": "submitted"}
            return {"outcome": "admitted", "order_state": "submitted", "reason": "order_submitted",
                    "authority_verdict": "valid", "failure_code": None}

        if kind == "revoke":
            self.revoked.add(event["role"])
            return {"outcome": "recorded", "order_state": "n/a", "reason": "revocation_recorded",
                    "authority_verdict": None, "failure_code": None}

        if kind == "stop":
            order = self.orders[event["order"]]
            if self.policy == "approval-time-check-only":
                return {"outcome": "stop_not_effective", "order_state": order["state"],
                        "reason": "authorization_settled_at_submission",
                        "authority_verdict": None, "failure_code": None}
            if order["state"] == "submitted":
                order["state"] = "stopped"
                return {"outcome": "stop_effective", "order_state": "stopped",
                        "reason": "stop_received_before_acceptance",
                        "authority_verdict": None, "failure_code": None}
            return {"outcome": "stop_not_effective", "order_state": order["state"],
                    "reason": "stop_received_after_acceptance",
                    "authority_verdict": None, "failure_code": None}

        if kind == "accept":
            order = self.orders[event["order"]]
            if order["state"] == "stopped":
                return {"outcome": "not_accepted", "order_state": "stopped",
                        "reason": "stopped_before_acceptance",
                        "authority_verdict": None, "failure_code": None}
            outcome = self._chain(event["chain"], event["now"])
            if outcome["verdict"] != "valid":
                order["state"] = "not_accepted"
                return {"outcome": "not_accepted", "order_state": "not_accepted",
                        "reason": "authority_ended_before_acceptance",
                        "authority_verdict": outcome["verdict"], "failure_code": outcome["code"]}
            order["state"] = "accepted"
            return {"outcome": "accepted", "order_state": "accepted",
                    "reason": "accepted_by_receiving_institution",
                    "authority_verdict": "valid", "failure_code": None}

        if kind == "settle":
            order = self.orders[event["order"]]
            if order["state"] == "accepted":
                if self.policy == "revocation-halts-everything" and self.revoked:
                    order["state"] = "not_settled"
                    return {"outcome": "not_settled", "order_state": "not_settled",
                            "reason": "revocation_halts_submitted_orders",
                            "authority_verdict": None, "failure_code": None}
                order["state"] = "settled"
                return {"outcome": "settled", "order_state": "settled",
                        "reason": "accepted_order_proceeds",
                        "authority_verdict": None, "failure_code": None}
            reason = "stopped_before_acceptance" if order["state"] == "stopped" else "never_accepted"
            order["state"] = "not_settled"
            return {"outcome": "not_settled", "order_state": "not_settled", "reason": reason,
                    "authority_verdict": None, "failure_code": None}

        raise RuntimeError(f"unknown in-flight event kind {kind}")


BOUNDARY_POLICIES = list(vectors["policies"]["boundary"].keys())
FLOW_POLICIES = list(vectors["policies"]["flow"].keys())

for name in BOUNDARY_POLICIES:
    if name not in POLICY_PROFILES:
        print(
            f"FAIL vectors.json names boundary policy {name}, which verify.py does not implement",
            file=sys.stderr,
        )
        sys.exit(1)

boundary_runs = {}
for policy in BOUNDARY_POLICIES:
    instance = AuthorityBoundary(policy)
    boundary_runs[policy] = {
        vector["id"]: instance.evaluate(vector["request"])
        for vector in vectors["cases"] if vector["kind"] == "boundary"
    }

BY_ID = {vector["id"]: vector for vector in vectors["cases"]}
flow_runs = {}
for policy in FLOW_POLICIES:
    out = {}
    for ids in vectors["timelines"].values():
        instance = InFlightBoundary(policy)
        for vector_id in ids:
            out[vector_id] = instance.step(BY_ID[vector_id]["event"])
    flow_runs[policy] = out

passed = 0
failed = 0

for vector in vectors["cases"]:
    ok = True
    details = []
    mismatched = []

    if vector["kind"] == "issuance":
        refusal = fixture["refusals"].get(vector["refusal"])
        ok = (
            refusal is not None
            and refusal["raised"] == vector["expected"]["raised"]
            and refusal["code"] == vector["expected"]["code"]
        )
        details.append(f"raised={refusal and refusal['raised']} code={refusal and refusal['code']}")
    else:
        is_boundary = vector["kind"] == "boundary"
        policies = BOUNDARY_POLICIES if is_boundary else FLOW_POLICIES
        runs = boundary_runs if is_boundary else flow_runs
        fields = BOUNDARY_FIELDS if is_boundary else FLOW_FIELDS

        actual = runs["reference"][vector["id"]]
        mismatched = [field for field in fields if actual[field] != vector["expected"][field]]
        ok = not mismatched
        details.append(f"reference={actual['outcome']}/{actual['reason']}")

        for policy in policies:
            if policy == "reference":
                continue
            declared = vectors["declared_fail_sets"].get(policy, [])
            other = runs[policy][vector["id"]]
            outcome_differs = other["outcome"] != actual["outcome"]
            record_differs = any(other[field] != actual[field] for field in fields)
            should_differ_outcome = vector["id"] in declared
            should_differ_record = should_differ_outcome or (
                vector["id"] in (vectors.get("record_divergence", {}).get(policy, {}))
            )
            ok = ok and outcome_differs == should_differ_outcome and record_differs == should_differ_record
            if record_differs or should_differ_record:
                details.append(
                    f"{policy}={other['outcome']}/{other['reason']}"
                    f"(outcome_differs={outcome_differs},record_differs={record_differs})"
                )

        if vector.get("negative_control"):
            in_a_fail_set = any(vector["id"] in ids for ids in vectors["declared_fail_sets"].values())
            ok = ok and in_a_fail_set
            details.append(f"negative_control={in_a_fail_set}")

    if ok:
        passed += 1
        print(f"PASS {vector['id']} {' '.join(details)}")
    else:
        failed += 1
        print(f"FAIL {vector['id']}", file=sys.stderr)
        for field in mismatched:
            runs = boundary_runs if vector["kind"] == "boundary" else flow_runs
            print(
                f"  {field}: expected {json.dumps(vector['expected'][field])} "
                f"actual {json.dumps(runs['reference'][vector['id']][field])}",
                file=sys.stderr,
            )
        print(f"  {' '.join(details)}", file=sys.stderr)

all_ids = {vector["id"] for vector in vectors["cases"]}
for policy, ids in vectors["declared_fail_sets"].items():
    for vector_id in ids:
        if vector_id not in all_ids:
            print(f"FAIL declared_fail_sets.{policy} names an unknown vector {vector_id}", file=sys.stderr)
            failed += 1
for policy, entries in vectors.get("record_divergence", {}).items():
    for vector_id in entries:
        if vector_id not in all_ids:
            print(f"FAIL record_divergence.{policy} names an unknown vector {vector_id}", file=sys.stderr)
            failed += 1

print(f"lifecycle-organization-events Python: {passed}/{len(vectors['cases'])} passed")
sys.exit(0 if failed == 0 else 1)
