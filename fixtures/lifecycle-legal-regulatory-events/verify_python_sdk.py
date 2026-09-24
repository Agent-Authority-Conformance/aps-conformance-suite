#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python-side runner for the lifecycle-legal-regulatory-events family.

Reads the same chain.json and vectors.json the TypeScript runner reads and decides every
vector again against the published Python reference SDK, agent-passport-system 4.x from
PyPI. The external-event boundary below is a second, independent implementation of the same
reference model harness.ts implements: the two runners agree on every vector or this family
does not pass.

WHAT COMES FROM THE SDK HERE. Chain state including time and root trust
(verify_authority_delegation_chain), revocation resolution including the 'unknown' a store
that does not cover a delegation must answer (create_authority_revocation_resolver over
InMemoryAuthorityRevocationStore), the gate's scope match (scope_grant_covers) and every
signature (verify over canonicalize_jcs). Suspension, restriction, external authority
events, dependency bindings, ratification and lifecycle standing come from this file: no
Python SDK export covers any of them, and each is recorded not_supported below.

Not part of `npm test`, the same convention fixtures/ancestor-revocation-chain/validate.py
and fixtures/runtime-authority-denial-continuity/verify.py already follow for a Python side
kept out of the hermetic Node-only CI gate. Run it as:

    python3 -m venv /tmp/aac-lc-g3-venv
    /tmp/aac-lc-g3-venv/bin/pip install 'agent-passport-system==4.1.0'
    /tmp/aac-lc-g3-venv/bin/python fixtures/lifecycle-legal-regulatory-events/verify_python_sdk.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agent_passport import (
    InMemoryAuthorityRevocationStore,
    canonicalize_jcs,
    create_authority_revocation_resolver,
    verify,
)
from agent_passport.v2.authority_delegation import (
    scope_grant_covers,
    verify_authority_delegation_chain,
)

HERE = Path(__file__).resolve().parent

VERDICT_VOCABULARY = {"valid", "invalid", "suspended", "restricted", "not established", "not yet effective"}


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


FIXTURE = read_json("chain.json")
VECTORS = read_json("vectors.json")

KEYS = FIXTURE["verification_keys"]
DOMAINS = FIXTURE["signature_domains"]
POLICY = FIXTURE["verifier_trust_policy"]

LABEL_BY_EVENT_ID = {event["event_id"]: label for label, event in FIXTURE["external_events"].items()}

TRACKED_DELEGATION_IDS = [record["delegation_id"] for chain in FIXTURE["chains"].values() for record in chain]
PRUNED_DELEGATION_IDS = [
    FIXTURE["chains"][entry["chain"]][entry["index"]]["delegation_id"]
    for entry in VECTORS["pruned_evidence_delegations"]
]


def labels_of(event_ids):
    return sorted(LABEL_BY_EVENT_ID.get(event_id, f"unknown:{event_id}") for event_id in event_ids)


def resolve_verification_key(_issuer, verification_method, _issued_at=None):
    return KEYS.get(verification_method)


def event_is_authentic(event) -> bool:
    body = {k: v for k, v in event.items() if k not in ("event_id", "signature")}
    preimage = f"{DOMAINS['external_authority_event']} {canonicalize_jcs(body)}"
    recomputed = "sha256:" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    if recomputed != event["event_id"]:
        return False
    public_key = KEYS.get(event["verification_method"])
    if public_key is None:
        return False
    return verify(preimage, event["signature"], public_key)


def dependency_binding_is_authentic(binding) -> bool:
    body = {k: v for k, v in binding.items() if k != "signature"}
    public_key = KEYS.get(binding["verification_method"])
    if public_key is None:
        return False
    return verify(f"{DOMAINS['dependency_binding']} {canonicalize_jcs(body)}", binding["signature"], public_key)


def certification_satisfies(certification, gate, action_ref):
    """Whether a gate's named certifier certified this exact action. Mirrors harness.ts."""
    if certification is None:
        return False, "no_certification"
    if certification["gate_event_id"] != gate["event_id"]:
        return False, "certification_names_another_gate"
    if certification["action_ref"] != action_ref:
        return False, "certification_names_another_action"
    if certification["certifier"] != gate["parameters"]["certifier"]:
        return False, "certifier_not_named_by_gate"
    body = {k: v for k, v in certification.items() if k != "signature"}
    public_key = KEYS.get(certification["verification_method"])
    if public_key is None:
        return False, "no_key_for_certifier"
    if not verify(f"{DOMAINS['gate_certification']} {canonicalize_jcs(body)}", certification["signature"], public_key):
        return False, "certification_signature_invalid"
    return True, "certified"


class AuthorityBoundary:
    """Second implementation of the same reference model harness.ts implements.

    The four configuration flags are the same four, with the same meanings, so a divergence
    between the two runners is a disagreement about the model and never about wiring.
    """

    def __init__(
        self,
        name,
        enforces_external_events=True,
        checks_lifecycle_standing=True,
        reports_non_terminal_states_separately=True,
        tracks_suspension_causes_independently=True,
    ):
        self.name = name
        self.enforces_external_events = enforces_external_events
        self.checks_lifecycle_standing = checks_lifecycle_standing
        self.reports_non_terminal_states_separately = reports_non_terminal_states_separately
        self.tracks_suspension_causes_independently = tracks_suspension_causes_independently

    # -- status observation ------------------------------------------------

    def observe(self, events, now):
        """recorded_at gates observation, effective_at gates force. See harness.ts."""
        effective, pending, unestablished = [], [], []
        for event in events:
            if event["recorded_at"] > now:
                continue
            if not event_is_authentic(event):
                unestablished.append(event)
                continue
            if self.checks_lifecycle_standing:
                permitted = POLICY["lifecycle_standing"].get(event["effect"], [])
                if event["issuer"] not in permitted:
                    unestablished.append(event)
                    continue
            if event["effective_at"] > now:
                pending.append(event)
                continue
            effective.append(event)
        return effective, pending, unestablished

    @staticmethod
    def released_by(effective, event_id):
        return any(
            e["effect"] == "release_restriction" and e["target"]["kind"] == "event" and e["target"]["id"] == event_id
            for e in effective
        )

    def suspension_causes(self, effective, principals):
        causes = set()
        for event in effective:
            if event["effect"] == "suspend_principal" and event["target"]["kind"] == "principal" and event["target"]["id"] in principals:
                causes.add(event["parameters"]["cause_id"])
        if not causes:
            return []
        for event in effective:
            if event["effect"] != "release_suspension":
                continue
            if event["target"]["kind"] != "principal" or event["target"]["id"] not in principals:
                continue
            if self.tracks_suspension_causes_independently:
                causes.discard(event["parameters"]["cause_id"])
            else:
                causes.clear()
        return sorted(causes)

    # -- chain state, from the SDK ----------------------------------------

    def chain_state(self, chain, now, trust_root_basis, evidence_set, effective):
        store = InMemoryAuthorityRevocationStore()
        for delegation_id in TRACKED_DELEGATION_IDS:
            if evidence_set == "pruned" and delegation_id in PRUNED_DELEGATION_IDS:
                continue
            store.track(delegation_id)
        resolve_revocation = create_authority_revocation_resolver(store, resolve_verification_key=resolve_verification_key)

        base = list(POLICY["trust_roots"].get(trust_root_basis, []))
        if trust_root_basis == "accepts_established_roots":
            base += [e["target"]["id"] for e in effective if e["effect"] == "establish_trust_root"]

        result = verify_authority_delegation_chain(
            chain,
            now=now,
            resolve_verification_key=resolve_verification_key,
            trust_root=lambda root: root["issuer"] in base,
            resolve_revocation=resolve_revocation,
        )
        first = result.failures[0] if result.failures else None
        return result.state, (first.code if first is not None else None)

    # -- the two request kinds --------------------------------------------

    def present(self, request):
        effective, pending, unestablished = self.observe(request["events"], request["now"])
        state, code = self.chain_state(
            request["chain"], request["now"], request["trust_root_basis"], request["evidence_set"], effective
        )
        principals = [record["issuer"] for record in request["chain"]]
        causes = self.suspension_causes(effective, principals) if self.enforces_external_events else []

        base = {
            "chain_state": state,
            "chain_failure_code": code,
            "effective_event_ids": sorted(e["event_id"] for e in effective),
            "pending_event_ids": sorted(e["event_id"] for e in pending),
            "unestablished_event_ids": sorted(e["event_id"] for e in unestablished),
            "suspension_causes": causes,
            "receipt_digest": None,
        }

        def out(verdict, reason, detail=None):
            result = {"verdict": verdict, "reason": reason, **base}
            if detail is not None:
                result["detail"] = detail
            return result

        def non_terminal(verdict, reason, detail):
            return out(verdict if self.reports_non_terminal_states_separately else "invalid", reason, detail)

        if state == "indeterminate":
            return out("not established", "chain_state_not_established")
        if state == "invalid":
            if code == "NOT_YET_VALID":
                return out("not yet effective", "grant_not_yet_effective")
            return out("invalid", "chain_not_valid")
        if state != "valid":
            return out("not established", "chain_state_not_established")

        if not self.enforces_external_events:
            return out("valid", "no_effective_restriction")

        terminated = next(
            (e for e in effective if e["effect"] == "terminate_principal_authority" and e["target"]["kind"] == "principal" and e["target"]["id"] in principals),
            None,
        )
        if terminated is not None:
            return out("invalid", "principal_authority_terminated_externally", terminated["event_id"])

        replaced = next(
            (e for e in effective if e["effect"] == "replace_principal" and e["target"]["kind"] == "principal" and e["target"]["id"] in principals),
            None,
        )
        if replaced is not None:
            return out("invalid", "principal_replaced_externally", f"successor={replaced['parameters']['successor']}")

        binding = request["dependency_binding"]
        if binding is not None:
            if not dependency_binding_is_authentic(binding):
                return out("not established", "dependency_binding_not_authentic")
            revoked = next(
                (e for e in effective if e["effect"] == "revoke_dependency" and e["target"]["kind"] == "dependency" and e["target"]["id"] in binding["depends_on"]),
                None,
            )
            if revoked is not None:
                return out("invalid", "declared_dependency_revoked", revoked["target"]["id"])

        target_id = request["action_target_id"]
        if target_id is not None:
            transferred = next(
                (e for e in effective if e["effect"] == "transfer_resource_ownership" and e["target"]["kind"] == "resource" and e["target"]["id"] == target_id),
                None,
            )
            if transferred is not None:
                return out("invalid", "target_owner_changed", f"new_owner={transferred['parameters']['new_owner']}")

        if causes:
            return non_terminal("suspended", "suspended_by_cause", ",".join(causes))

        if target_id is not None:
            blocking = [
                e
                for e in effective
                if e["effect"] == "restrict_execution"
                and e["target"]["kind"] in ("counterparty", "resource")
                and e["target"]["id"] == target_id
                and not self.released_by(effective, e["event_id"])
            ]
            if blocking:
                return non_terminal("restricted", "external_restriction_in_force", ",".join(sorted(e["event_id"] for e in blocking)))

        for gate in effective:
            if gate["effect"] != "add_approval_gate":
                continue
            if gate["target"]["kind"] != "principal" or gate["target"]["id"] not in principals:
                continue
            if self.released_by(effective, gate["event_id"]):
                continue
            sunset = gate["parameters"].get("sunset")
            if sunset is not None and sunset <= request["now"]:
                continue
            if not scope_grant_covers(gate["parameters"]["gate_scope"], request["action_scope"]):
                continue
            threshold = gate["parameters"].get("threshold_minor")
            if threshold is not None:
                if request["amount_minor"] is None:
                    return non_terminal("restricted", "gate_amount_not_established", gate["event_id"])
                if int(request["amount_minor"]) < int(threshold):
                    continue
            ok, why = certification_satisfies(request["certification"], gate, request["action_ref"])
            if not ok:
                return non_terminal("restricted", "external_approval_gate_unsatisfied", f"{gate['event_id']}/{why}")

        if unestablished:
            return out("valid", "external_claim_not_established")
        return out("valid", "no_effective_restriction")

    def assess_act(self, request):
        effective, pending, unestablished = self.observe(request["events"], request["now"])
        state, code = self.chain_state(
            request["chain"], request["now"], request["trust_root_basis"], request["evidence_set"], effective
        )
        digest = "sha256:" + hashlib.sha256(canonicalize_jcs(request["receipt"]).encode("utf-8")).hexdigest()

        base = {
            "chain_state": state,
            "chain_failure_code": code,
            "effective_event_ids": sorted(e["event_id"] for e in effective),
            "pending_event_ids": sorted(e["event_id"] for e in pending),
            "unestablished_event_ids": sorted(e["event_id"] for e in unestablished),
            "suspension_causes": [],
            "receipt_digest": digest,
        }

        def out(verdict, reason, detail=None):
            result = {"verdict": verdict, "reason": reason, **base}
            if detail is not None:
                result["detail"] = detail
            return result

        if self.enforces_external_events:
            ratification = next(
                (e for e in effective if e["effect"] == "ratify_action" and e["target"]["kind"] == "action" and e["target"]["id"] == request["action_ref"]),
                None,
            )
            if ratification is not None:
                return out("valid", "ratified_by_record", ratification["event_id"])
            claimed = next(
                (e for e in unestablished if e["effect"] == "ratify_action" and e["target"]["kind"] == "action" and e["target"]["id"] == request["action_ref"]),
                None,
            )
            if claimed is not None and state != "valid":
                return out("not established", "ratification_standing_not_established", claimed["event_id"])

        if state == "valid":
            return out("valid", "chain_valid_at_act")
        if state == "indeterminate":
            return out("not established", "chain_state_not_established")
        return out("invalid", "chain_not_valid")

    def handle(self, request):
        return self.present(request) if request["kind"] == "present" else self.assess_act(request)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def fail(message):
    print(f"lifecycle-legal-regulatory-events: {message}", file=sys.stderr)
    sys.exit(2)


def to_request(vector):
    chain = FIXTURE["chains"].get(vector["chain"])
    if chain is None:
        fail(f"{vector['id']} names an unknown chain {vector['chain']}")
    action = FIXTURE["actions"].get(vector["action"])
    if action is None:
        fail(f"{vector['id']} names an unknown action {vector['action']}")
    now = FIXTURE["timeline"].get(vector["now"])
    if now is None:
        fail(f"{vector['id']} names an unknown timeline point {vector['now']}")
    labels = VECTORS["event_sets"].get(vector["event_set"])
    if labels is None:
        fail(f"{vector['id']} names an unknown event_set {vector['event_set']}")
    events = [FIXTURE["external_events"][label] for label in labels]

    if vector["kind"] == "assess_act":
        return {
            "kind": "assess_act",
            "events": events,
            "chain": chain,
            "receipt": FIXTURE["historical_receipt"],
            "action_ref": action["action_ref"],
            "trust_root_basis": vector["trust_root_basis"],
            "evidence_set": vector["evidence_set"],
            "now": now,
        }

    binding_name = vector.get("dependency_binding")
    certification_name = vector.get("certification")
    target_name = vector.get("action_target")
    return {
        "kind": "present",
        "events": events,
        "chain": chain,
        "dependency_binding": FIXTURE["dependency_bindings"][binding_name] if binding_name else None,
        "action_ref": action["action_ref"],
        "action_scope": action["input"]["scope_required"][0],
        "action_target_id": FIXTURE["off_graph_targets"][target_name] if target_name else None,
        "amount_minor": vector.get("amount_minor"),
        "certification": FIXTURE["certifications"][certification_name] if certification_name else None,
        "trust_root_basis": vector["trust_root_basis"],
        "evidence_set": vector["evidence_set"],
        "now": now,
    }


def matches(actual, expected):
    return (
        actual["verdict"] == expected["verdict"]
        and actual["reason"] == expected["reason"]
        and actual["chain_state"] == expected["chain_state"]
        and actual["chain_failure_code"] == expected["chain_failure_code"]
        and labels_of(actual["effective_event_ids"]) == expected["effective_events"]
        and labels_of(actual["pending_event_ids"]) == expected["pending_events"]
        and labels_of(actual["unestablished_event_ids"]) == expected["unestablished_events"]
        and actual["suspension_causes"] == expected["suspension_causes"]
    )


def line(actual):
    parts = [
        f'verdict="{actual["verdict"]}"',
        f'reason={actual["reason"]}',
        f'chain={actual["chain_state"]}/{actual["chain_failure_code"]}',
        f'effective=[{" ".join(labels_of(actual["effective_event_ids"]))}]',
    ]
    if actual["pending_event_ids"]:
        parts.append(f'pending=[{" ".join(labels_of(actual["pending_event_ids"]))}]')
    if actual["unestablished_event_ids"]:
        parts.append(f'unestablished=[{" ".join(labels_of(actual["unestablished_event_ids"]))}]')
    if actual["suspension_causes"]:
        parts.append(f'causes=[{" ".join(actual["suspension_causes"])}]')
    return " ".join(parts)


def run_boundary(boundary):
    return {vector["id"]: boundary.handle(to_request(vector)) for vector in VECTORS["vectors"]}


print(f"lifecycle-legal-regulatory-events: {len(VECTORS['vectors'])} vectors, status label {VECTORS['status_label']} (python SDK)")
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
        print(f"    actual:   {json.dumps({k: v for k, v in actual.items() if k != 'detail'}, sort_keys=True)}")

print()
print("structural checks")
structural_ok = True


def check(label, ok, detail):
    global structural_ok
    if not ok:
        structural_ok = False
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {detail}")


observed_verdicts = sorted({outcome["verdict"] for outcome in reference_results.values()})
check("verdict vocabulary", all(v in VERDICT_VOCABULARY for v in observed_verdicts), f"observed {observed_verdicts}")

assess_ids = [v["id"] for v in VECTORS["vectors"] if v["kind"] == "assess_act"]
digests = {reference_results[vid]["receipt_digest"] for vid in assess_ids}
check(
    "historical receipt unchanged across ratification",
    len(digests) == 1 and FIXTURE["historical_receipt_digest"] in digests,
    f"{len(assess_ids)} assessments, {len(digests)} distinct digest(s), matches chain.json: {FIXTURE['historical_receipt_digest'] in digests}",
)

for vector in VECTORS["vectors"]:
    other_id = vector.get("same_chain_as")
    if other_id is None:
        continue
    other = next(v for v in VECTORS["vectors"] if v["id"] == other_id)
    ids = [r["delegation_id"] for r in FIXTURE["chains"][vector["chain"]]]
    other_ids = [r["delegation_id"] for r in FIXTURE["chains"][other["chain"]]]
    check(f"{vector['id']} presents the same delegation_ids as {other_id}", ids == other_ids, f"{len(ids)} record(s)")

resource_ids = [r["delegation_id"] for r in FIXTURE["chains"]["resource"]]
regrant_ids = [r["delegation_id"] for r in FIXTURE["chains"]["resource_regrant"]]
check("resource_regrant is a distinct grant from resource", resource_ids != regrant_ids, f"{resource_ids[0][:23]}... against {regrant_ids[0][:23]}...")

DEFECTIVE = [
    ("defective-boundary-chain-validity-only", {"enforces_external_events": False}),
    ("defective-boundary-collapses-restricted-into-revoked", {"reports_non_terminal_states_separately": False}),
    ("defective-boundary-single-suspension-flag", {"tracks_suspension_causes_independently": False}),
    ("defective-boundary-trusts-event-without-standing", {"checks_lifecycle_standing": False}),
]

all_defectives_ok = True
for name, flags in DEFECTIVE:
    boundary = AuthorityBoundary(name, **flags)
    results = run_boundary(boundary)
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
    print(f"  {name}: {len(declared)} declared, diverged on exactly its declared set: {ok}")
    if not ok:
        all_defectives_ok = False

SDK_SUPPORT = [
    ("chain state, including time and root trust", "supported", "verify_authority_delegation_chain"),
    ("revocation resolution, including unknown for uncovered evidence", "supported", "create_authority_revocation_resolver over InMemoryAuthorityRevocationStore"),
    ("gate scope match", "supported", "scope_grant_covers"),
    ("external event, dependency binding and certification signatures", "supported", "verify over canonicalize_jcs"),
    ("revocation by a party other than the issuer", "not_supported", "issue_authority_revocation admits only the target delegation's issuer as revoker"),
    ("suspension state", "not_supported", "no Python SDK export, supplied by this runner"),
    ("restricted state", "not_supported", "no Python SDK export, supplied by this runner"),
    ("external authority event record", "not_supported", "no Python SDK export, supplied by this fixture"),
    ("off-graph dependency binding", "not_supported", "no Python SDK export, supplied by this fixture"),
    ("ratification of a past act", "not_supported", "no Python SDK export, supplied by this runner"),
    ("lifecycle standing registry", "not_supported", "no Python SDK export, supplied by this fixture"),
]

print()
try:
    from importlib.metadata import version as _version

    SDK_VERSION = _version("agent-passport-system")
except Exception:  # pragma: no cover - only reachable without installed metadata
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
