#!/usr/bin/env python3
"""Generate vectors.json for the lifecycle-organization-events family.

The vector list is written here rather than by hand so that the thirty-five
cases stay consistent in shape, and so the file can be regenerated rather than
only replayed, which is what CONTRIBUTING.md asks of a vector contribution.
Nothing here computes an expected outcome: every expectation below is written
out, and the two runners are what check it.

Run from the suite root:

    python3 fixtures/lifecycle-organization-events/generate_vectors.py

Then `git diff` on vectors.json shows exactly what changed.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

COMPANY_A = "did:aps:example:oev-company-a"
COMPANY_B = "did:aps:example:oev-company-b"
VENDOR_C = "did:aps:example:oev-vendor-c"
ORG = "did:aps:example:oev-org"
ORG_OPS = "did:aps:example:oev-org-ops"


def boundary(vector_id, case_id, sign, tests, differs_from, request, expected,
             negative_control=False):
    entry = {
        "id": vector_id,
        "case_id": case_id,
        "kind": "boundary",
        "sign": sign,
        "tests": tests,
        "differs_from": differs_from,
        "request": request,
        "expected": expected,
    }
    if negative_control:
        entry["negative_control"] = True
    return entry


def flow(vector_id, case_id, sign, tests, differs_from, timeline, event, expected,
         negative_control=False):
    entry = {
        "id": vector_id,
        "case_id": case_id,
        "kind": "flow",
        "sign": sign,
        "tests": tests,
        "differs_from": differs_from,
        "timeline": timeline,
        "event": event,
        "expected": expected,
    }
    if negative_control:
        entry["negative_control"] = True
    return entry


ADMITTED = lambda principal=None, verdict="valid", reason="admitted": {
    "outcome": "admitted", "authority_verdict": verdict, "reason": reason,
    "failure_code": None, "failure_index": None, "principal_established": principal,
}


def denied(verdict, reason, code=None, index=None, principal=None):
    return {
        "outcome": "not_admitted", "authority_verdict": verdict, "reason": reason,
        "failure_code": code, "failure_index": index, "principal_established": principal,
    }


cases = []

# ---- LC-B-004. A successor's fresh grant is bounded by the successor's own
#      ceiling, not the predecessor's. ---------------------------------------
cases.append(boundary(
    "LC-B-004-a", "LC-B-004", "positive",
    "positive control. The interim officer issues a fresh grant inside the interim "
    "officer's own narrower ceiling. Valid. Nothing about the departed officer's "
    "broader scope is reachable through it.",
    None,
    {"chain": "SUCC_WITHIN", "now": "2026-09-22T12:00:00.000Z", "required_principal": None,
     "operation": "contracts:settle", "target": None, "present_records": []},
    ADMITTED(principal=ORG),
))
cases.append(boundary(
    "LC-B-004-b", "LC-B-004", "negative",
    "the interim officer signing a grant that claims the departed officer's broader "
    "scope. Invalid, and the reported failure names the widening rather than anything "
    "about who signed it: the interim officer's signature is genuine, and the ceiling "
    "is what the grant exceeded.",
    "LC-B-004-a: the leaf claims contracts:sign:new, which the interim officer's own "
    "root does not carry",
    {"chain": "SUCC_WIDE", "now": "2026-09-22T12:00:00.000Z", "required_principal": None,
     "operation": "contracts:sign:new", "target": None, "present_records": []},
    denied("invalid", "chain_not_valid", "SCOPE_WIDENING", 1),
))
cases.append(boundary(
    "LC-B-004-c", "LC-B-004", "negative",
    "the family's first negative control. The departed officer's existing child record, "
    "byte for byte unchanged, presented under the interim officer's root. Nothing was "
    "re-issued: the child still names the predecessor's root as its parent. The "
    "reference boundary returns invalid with PARENT_MISMATCH at index 1. A boundary "
    "that checks only whether the role has a currently valid holder, and then evaluates "
    "the old child against that answer, admits, and in doing so hands the agent the "
    "predecessor's broader scope under a successor who never held it.",
    "LC-B-004-b: the leaf is the predecessor's original child rather than anything the "
    "interim officer signed",
    {"chain": "REPARENT_STALE", "now": "2026-09-22T12:00:00.000Z", "required_principal": None,
     "operation": "contracts:settle", "target": None, "present_records": []},
    denied("invalid", "chain_not_valid", "PARENT_MISMATCH", 1),
    negative_control=True,
))
cases.append(boundary(
    "LC-B-004-d", "LC-B-004", "negative",
    "the other re-parenting shape, kept separate because it fails for a different "
    "reason. The child now names the interim officer's root as its parent and was "
    "re-signed, but the signer is still the departed officer, who is not the parent's "
    "subject. The failure is continuity, not a parent mismatch, and the two are not "
    "collapsed into one code.",
    "LC-B-004-c: parent_delegation_id was updated and the record re-signed by the "
    "departed officer",
    {"chain": "REPARENT_RESIGNED", "now": "2026-09-22T12:00:00.000Z", "required_principal": None,
     "operation": "contracts:settle", "target": None, "present_records": []},
    denied("invalid", "chain_not_valid", "CHAIN_CONTINUITY", 1),
))
cases.append({
    "id": "LC-B-004-e", "case_id": "LC-B-004", "kind": "issuance", "sign": "negative",
    "tests": "the issuance layer for the same ceiling question. The SDK's child issuer "
             "was asked to mint the over-broad successor grant and refused before "
             "signing. Recorded as observed implementation behavior: the proposed text "
             "states no issuance-time ceiling rule.",
    "differs_from": "LC-B-004-b: this is the mint-time refusal, not a verification",
    "refusal": "succ_wide",
    "expected": {"raised": True, "code": "SCOPE_WIDENING"},
})

# ---- LC-B-012 and LC-B-013. Corporate succession and the delegation layer --
cases.append(boundary(
    "LC-B-012-a", "LC-B-012", "positive",
    "positive control, before any succession. The agent's chain roots in the "
    "constituent company's officer and the action requires that company as principal. "
    "Admitted, principal established.",
    None,
    {"chain": "A_CHAIN", "now": "2026-09-22T08:00:00.000Z", "required_principal": COMPANY_A,
     "operation": "orders:place", "target": None, "present_records": []},
    ADMITTED(principal=COMPANY_A),
))
cases.append(boundary(
    "LC-B-012-b", "LC-B-012", "negative",
    "the corporate record on its own. A succession attestation naming the surviving "
    "company is presented, it is authentic, and it comes from a party the trust policy "
    "accepts. The chain still roots in the constituent company's officer and nobody at "
    "the surviving company has issued the agent anything. The verdict is not "
    "established, which is not the same as invalid: the chain verifies, and what has "
    "not been shown is the binding to the required principal.",
    "LC-B-012-a: the action requires the surviving company as principal, and a "
    "succession attestation is presented",
    {"chain": "A_CHAIN", "now": "2026-09-22T09:00:00.000Z", "required_principal": COMPANY_B,
     "operation": "orders:place", "target": None,
     "present_records": ["SUCCESSION_WITH_STANDING"]},
    denied("not established", "corporate_record_is_not_a_delegation_event", principal=COMPANY_A),
))
cases.append(boundary(
    "LC-B-012-c", "LC-B-012", "positive",
    "the delegation-layer event that does establish it. An officer of the surviving "
    "company issues the agent a fresh root. Admitted, and the principal established is "
    "the surviving company. This is what the record in LC-B-012-b was missing, and it "
    "is an issuance, not a consequence of the succession attestation.",
    "LC-B-012-b: a fresh delegation from the surviving company's officer is presented "
    "instead of the constituent company's chain",
    {"chain": "B_CHAIN", "now": "2026-09-22T12:00:00.000Z", "required_principal": COMPANY_B,
     "operation": "orders:place", "target": None, "present_records": []},
    ADMITTED(principal=COMPANY_B),
))
cases.append(boundary(
    "LC-B-013-a", "LC-B-013", "negative",
    "the family's second negative control, and the whole of LC-B-013. The same inputs "
    "as LC-B-012-b. A boundary that reads the succession attestation as a "
    "delegation-layer succession event re-points the principal and admits. The "
    "attestation is authentic and its signer has standing, so authenticity and standing "
    "are not what separate the two answers: what separates them is that a corporate "
    "record is not an issuance.",
    "LC-B-012-b: identical inputs. This vector is about which policies admit them",
    {"chain": "A_CHAIN", "now": "2026-09-22T09:10:00.000Z", "required_principal": COMPANY_B,
     "operation": "orders:place", "target": None,
     "present_records": ["SUCCESSION_WITH_STANDING"]},
    denied("not established", "corporate_record_is_not_a_delegation_event", principal=COMPANY_A),
    negative_control=True,
))
cases.append(boundary(
    "LC-B-013-b", "LC-B-013", "negative",
    "the standing route, kept apart from the layer route. The same succession "
    "attestation, genuinely signed, by the constituent company's former officer rather "
    "than by a party the trust policy accepts for this record type. Still not "
    "established, and under a different reason, so a reader cannot mistake 'a corporate "
    "record is not an issuance' for 'this one was signed by the wrong person'.",
    "LC-B-013-a: the attestation is signed by a party with no standing for this record "
    "type",
    {"chain": "A_CHAIN", "now": "2026-09-22T09:20:00.000Z", "required_principal": COMPANY_B,
     "operation": "orders:place", "target": None,
     "present_records": ["SUCCESSION_WITHOUT_STANDING"]},
    denied("not established", "attestation_attestor_without_standing", principal=COMPANY_A),
))

# ---- LC-B-016. An external restriction narrows scope without revoking ------
cases.append(boundary(
    "LC-B-016-a", "LC-B-016", "positive",
    "positive control, before the restriction takes effect. The operating chain is "
    "valid and the action is signing a new customer contract. Admitted.",
    None,
    {"chain": "OPS", "now": "2026-09-22T08:00:00.000Z", "required_principal": None,
     "operation": "contracts:sign:new", "target": None, "present_records": []},
    ADMITTED(principal=ORG_OPS),
))
cases.append(boundary(
    "LC-B-016-b", "LC-B-016", "negative",
    "the headline. A restriction record from a party the trust policy accepts declares "
    "what remains exercisable, and signing new contracts is not on that list. The "
    "action is not admitted and the verdict is restricted: the chain still verifies "
    "valid, nothing was revoked, and the not_after is eight days away, so neither "
    "revocation nor expiry is doing any work. A model with only valid and revoked "
    "cannot express this state at all.",
    "LC-B-016-a: the restriction record is presented and its effective_at has passed",
    {"chain": "OPS", "now": "2026-09-22T12:00:00.000Z", "required_principal": None,
     "operation": "contracts:sign:new", "target": None,
     "present_records": ["DISSOLUTION_RESTRICTION"]},
    denied("restricted", "external_restriction_excludes_operation", principal=ORG_OPS),
    negative_control=True,
))
cases.append(boundary(
    "LC-B-016-c", "LC-B-016", "positive",
    "the other half of the same restriction. Settling an existing obligation is on the "
    "remaining list, so it is admitted. The recorded verdict is still restricted rather "
    "than valid: the authority continues and what it covers has narrowed, and an "
    "admitted action does not erase that.",
    "LC-B-016-b: the action is contracts:settle, which the restriction leaves in place",
    {"chain": "OPS", "now": "2026-09-22T12:05:00.000Z", "required_principal": None,
     "operation": "contracts:settle", "target": None,
     "present_records": ["DISSOLUTION_RESTRICTION"]},
    ADMITTED(principal=ORG_OPS, verdict="restricted", reason="admitted_within_remaining_scope"),
))
cases.append(boundary(
    "LC-B-016-d", "LC-B-016", "negative",
    "the restriction presented before its own effective_at. It does not apply yet, so "
    "signing a new contract is admitted and the verdict is plain valid. This is the "
    "pair-mate that stops LC-B-016-b from passing for the wrong reason: the presence of "
    "the record is not what restricts, its effective instant is.",
    "LC-B-016-b: the boundary is at 08:00:00Z, before the restriction's 08:30:00Z "
    "effective_at",
    {"chain": "OPS", "now": "2026-09-22T08:00:00.000Z", "required_principal": None,
     "operation": "contracts:sign:new", "target": None,
     "present_records": ["DISSOLUTION_RESTRICTION"]},
    ADMITTED(principal=ORG_OPS),
))

# ---- LC-B-030. A third party's own consent gate ---------------------------
cases.append(boundary(
    "LC-B-030-a", "LC-B-030", "positive",
    "positive control. The internal chain is valid and the third party whose contract "
    "holds the gate has consented for this exact target and operation. Admitted.",
    None,
    {"chain": "OPS", "now": "2026-09-22T12:00:00.000Z", "required_principal": None,
     "operation": "orders:place", "target": VENDOR_C,
     "present_records": ["CONSENT_VENDOR_C"]},
    ADMITTED(principal=ORG_OPS),
))
cases.append(boundary(
    "LC-B-030-b", "LC-B-030", "negative",
    "the family's third negative control. The internal chain is valid, nothing about "
    "the organization's own authority is in question, and no consent record exists for "
    "this target. Not established, not invalid: the gate is held by someone outside the "
    "chain and nobody inside it can supply what is missing. A boundary that checks only "
    "the internal chain admits.",
    "LC-B-030-a: no consent record is presented",
    {"chain": "OPS", "now": "2026-09-22T12:05:00.000Z", "required_principal": None,
     "operation": "orders:place", "target": VENDOR_C, "present_records": []},
    denied("not established", "third_party_consent_absent", principal=ORG_OPS),
    negative_control=True,
))
cases.append(boundary(
    "LC-B-030-c", "LC-B-030", "negative",
    "a consent record for the right target and operation, genuinely signed, by the "
    "acquiring company rather than by the party whose own contract holds the gate. "
    "Authentic and without standing are two different failures and this vector keeps "
    "them apart from the absent case above.",
    "LC-B-030-b: a consent record is presented, and its signer does not hold the gate",
    {"chain": "OPS", "now": "2026-09-22T12:10:00.000Z", "required_principal": None,
     "operation": "orders:place", "target": VENDOR_C,
     "present_records": ["CONSENT_FROM_ACQUIRER"]},
    denied("not established", "consent_attestor_without_standing", principal=ORG_OPS),
))
cases.append(boundary(
    "LC-B-030-d", "LC-B-030", "negative",
    "consent exists, from a party with standing over its own gate, for a different "
    "counterparty. The action targets the first counterparty. Not established, under a "
    "target-mismatch reason: a gate is bound to the relationship it was given for, and "
    "holding one consent is not holding consent.",
    "LC-B-030-c: the presented consent is authentic and its signer holds that gate, "
    "but it names a different target",
    {"chain": "OPS", "now": "2026-09-22T12:15:00.000Z", "required_principal": None,
     "operation": "orders:place", "target": VENDOR_C,
     "present_records": ["CONSENT_VENDOR_D"]},
    denied("not established", "consent_target_mismatch", principal=ORG_OPS),
))

# ---- LC-B-028. A stop against the acceptance boundary ----------------------
STOP_BEFORE = "TL_STOP_BEFORE"
STOP_AFTER = "TL_STOP_AFTER"
REV_BEFORE = "TL_REVOKE_BEFORE"
REV_AFTER = "TL_REVOKE_AFTER"

cases.append(flow(
    "LC-B-028-a", "LC-B-028", "positive",
    "positive control. A payment order is submitted under a valid chain and accepted "
    "for processing by the sending side. Nothing has been stopped and nothing has "
    "reached the receiving institution yet.",
    None, STOP_BEFORE,
    {"kind": "submit", "order": "O1", "chain": "OPS", "now": "2026-09-22T09:00:00.000Z"},
    {"outcome": "admitted", "order_state": "submitted", "reason": "order_submitted",
     "authority_verdict": "valid", "failure_code": None},
))
cases.append(flow(
    "LC-B-028-b", "LC-B-028", "positive",
    "the stop arrives before the receiving institution has acted on the order. It is "
    "effective. This is the vector a boundary that checked for a stop only when the "
    "order was authorized passes wrongly: it reports the same stop as having done "
    "nothing.",
    "LC-B-028-a: a stop instruction on the same order, five minutes later",
    STOP_BEFORE,
    {"kind": "stop", "order": "O1", "now": "2026-09-22T09:05:00.000Z"},
    {"outcome": "stop_effective", "order_state": "stopped",
     "reason": "stop_received_before_acceptance", "authority_verdict": None, "failure_code": None},
    negative_control=True,
))
cases.append(flow(
    "LC-B-028-c", "LC-B-028", "negative",
    "the receiving institution's action on a stopped order. It does not accept it. The "
    "stop reached the boundary first and the boundary is an event, not a duration.",
    "LC-B-028-b: the acceptance attempt following the effective stop",
    STOP_BEFORE,
    {"kind": "accept", "order": "O1", "chain": "OPS", "now": "2026-09-22T09:10:00.000Z"},
    {"outcome": "not_accepted", "order_state": "stopped", "reason": "stopped_before_acceptance",
     "authority_verdict": None, "failure_code": None},
))
cases.append(flow(
    "LC-B-028-d", "LC-B-028", "negative",
    "the order does not settle. The outcome of the timeline whose stop landed before "
    "the boundary.",
    "LC-B-028-c: the settlement step of the same timeline",
    STOP_BEFORE,
    {"kind": "settle", "order": "O1", "now": "2026-09-22T09:15:00.000Z"},
    {"outcome": "not_settled", "order_state": "not_settled", "reason": "stopped_before_acceptance",
     "authority_verdict": None, "failure_code": None},
))
cases.append(flow(
    "LC-B-028-e", "LC-B-028", "positive",
    "the second timeline opens identically. Same chain, same order shape, same "
    "instant. Everything that follows differs only in the order of two events.",
    "LC-B-028-a: a separate timeline and a separate order",
    STOP_AFTER,
    {"kind": "submit", "order": "O2", "chain": "OPS", "now": "2026-09-22T09:00:00.000Z"},
    {"outcome": "admitted", "order_state": "submitted", "reason": "order_submitted",
     "authority_verdict": "valid", "failure_code": None},
))
cases.append(flow(
    "LC-B-028-f", "LC-B-028", "positive",
    "the receiving institution accepts. This is the boundary event, and it is what the "
    "next vector lands on the far side of.",
    "LC-B-028-c: acceptance succeeds here because no stop preceded it",
    STOP_AFTER,
    {"kind": "accept", "order": "O2", "chain": "OPS", "now": "2026-09-22T09:05:00.000Z"},
    {"outcome": "accepted", "order_state": "accepted",
     "reason": "accepted_by_receiving_institution", "authority_verdict": "valid", "failure_code": None},
))
cases.append(flow(
    "LC-B-028-g", "LC-B-028", "negative",
    "the identical stop instruction, five minutes later than in LC-B-028-b, landing "
    "after the boundary event instead of before it. It does nothing. The instruction, "
    "the order, the chain and the authority are the same in both timelines: only which "
    "side of the acceptance the stop fell on is different.",
    "LC-B-028-b: the same stop instruction, after acceptance rather than before it",
    STOP_AFTER,
    {"kind": "stop", "order": "O2", "now": "2026-09-22T09:10:00.000Z"},
    {"outcome": "stop_not_effective", "order_state": "accepted",
     "reason": "stop_received_after_acceptance", "authority_verdict": None, "failure_code": None},
))
cases.append(flow(
    "LC-B-028-h", "LC-B-028", "positive",
    "the order settles. Recorded so the pair b/g resolves to two observable outcomes "
    "rather than to two boundary answers with no consequence attached.",
    "LC-B-028-d: the settlement step of the timeline whose stop arrived too late",
    STOP_AFTER,
    {"kind": "settle", "order": "O2", "now": "2026-09-22T09:15:00.000Z"},
    {"outcome": "settled", "order_state": "settled", "reason": "accepted_order_proceeds",
     "authority_verdict": None, "failure_code": None},
))

# ---- LC-B-029. The delegated authority itself changing mid-flight ----------
cases.append(flow(
    "LC-B-029-a", "LC-B-029", "positive",
    "positive control for the revocation timelines. A treasury order is submitted under "
    "a valid delegation.",
    None, REV_BEFORE,
    {"kind": "submit", "order": "O3", "chain": "OPS", "now": "2026-09-22T09:00:00.000Z"},
    {"outcome": "admitted", "order_state": "submitted", "reason": "order_submitted",
     "authority_verdict": "valid", "failure_code": None},
))
cases.append(flow(
    "LC-B-029-b", "LC-B-029", "negative",
    "the authorizing delegation's root is revoked. This is a recorded event, not a "
    "verdict about the order: what it does to the order is decided at the next "
    "authorization boundary, which is the following vector.",
    "LC-B-029-a: a revocation of the root the submitted order depends on",
    REV_BEFORE,
    {"kind": "revoke", "role": "OPS_ROOT", "now": "2026-09-22T09:05:00.000Z"},
    {"outcome": "recorded", "order_state": "n/a", "reason": "revocation_recorded",
     "authority_verdict": None, "failure_code": None},
))
cases.append(flow(
    "LC-B-029-c", "LC-B-029", "negative",
    "the receiving institution's acceptance is the next authorization boundary, and the "
    "chain no longer verifies there. The order is not accepted. Before the boundary "
    "event, revoking the authorizing delegation stops the order.",
    "LC-B-028-c: the order is unaccepted for a revoked ancestor rather than for a stop",
    REV_BEFORE,
    {"kind": "accept", "order": "O3", "chain": "OPS", "now": "2026-09-22T09:10:00.000Z"},
    {"outcome": "not_accepted", "order_state": "not_accepted",
     "reason": "authority_ended_before_acceptance", "authority_verdict": "invalid",
     "failure_code": "REVOKED"},
))
cases.append(flow(
    "LC-B-029-d", "LC-B-029", "negative",
    "the order does not settle.",
    "LC-B-029-c: the settlement step of the same timeline",
    REV_BEFORE,
    {"kind": "settle", "order": "O3", "now": "2026-09-22T09:15:00.000Z"},
    {"outcome": "not_settled", "order_state": "not_settled", "reason": "never_accepted",
     "authority_verdict": None, "failure_code": None},
))
cases.append(flow(
    "LC-B-029-e", "LC-B-029", "positive",
    "the fourth timeline opens identically to the third.",
    "LC-B-029-a: a separate timeline and a separate order",
    REV_AFTER,
    {"kind": "submit", "order": "O4", "chain": "OPS", "now": "2026-09-22T09:00:00.000Z"},
    {"outcome": "admitted", "order_state": "submitted", "reason": "order_submitted",
     "authority_verdict": "valid", "failure_code": None},
))
cases.append(flow(
    "LC-B-029-f", "LC-B-029", "positive",
    "the receiving institution accepts, before any revocation.",
    "LC-B-029-c: acceptance succeeds here because the revocation has not happened yet",
    REV_AFTER,
    {"kind": "accept", "order": "O4", "chain": "OPS", "now": "2026-09-22T09:05:00.000Z"},
    {"outcome": "accepted", "order_state": "accepted",
     "reason": "accepted_by_receiving_institution", "authority_verdict": "valid", "failure_code": None},
))
cases.append(flow(
    "LC-B-029-g", "LC-B-029", "negative",
    "the same revocation as LC-B-029-b, five minutes later in its timeline, landing "
    "after the boundary event.",
    "LC-B-029-b: the same revocation, after acceptance rather than before it",
    REV_AFTER,
    {"kind": "revoke", "role": "OPS_ROOT", "now": "2026-09-22T09:10:00.000Z"},
    {"outcome": "recorded", "order_state": "n/a", "reason": "revocation_recorded",
     "authority_verdict": None, "failure_code": None},
))
cases.append(flow(
    "LC-B-029-h", "LC-B-029", "positive",
    "the accepted order settles despite the revocation. This is the vector a boundary "
    "that treats a revocation as halting anything already submitted passes wrongly, and "
    "it is the half of this case that is easy to get backwards: an unaccepted order "
    "stays fully stoppable and an accepted one does not.",
    "LC-B-029-d: the order settles here because the revocation landed after acceptance",
    REV_AFTER,
    {"kind": "settle", "order": "O4", "now": "2026-09-22T09:15:00.000Z"},
    {"outcome": "settled", "order_state": "settled", "reason": "accepted_order_proceeds",
     "authority_verdict": None, "failure_code": None},
    negative_control=True,
))
cases.append(flow(
    "LC-B-029-i", "LC-B-029", "negative",
    "the other half of the same instant, and the reason this case is not simply 'a "
    "revocation does not matter once an order is accepted'. A new order presented on "
    "the same chain after the revocation is not admitted. One accepted order proceeding "
    "and the agent's authority having ended are both true at 09:20, and a family that "
    "recorded only one of them would misread the case in one direction or the other.",
    "LC-B-029-h: a new order rather than the already accepted one",
    REV_AFTER,
    {"kind": "present_new", "chain": "OPS", "now": "2026-09-22T09:20:00.000Z"},
    {"outcome": "not_admitted", "order_state": "none", "reason": "chain_not_valid",
     "authority_verdict": "invalid", "failure_code": "REVOKED"},
))

vectors = {
    "profile": "aac-lifecycle-organization-events-v0",
    "status_label": "candidate_against_proposed",
    "proposed_text": {
        "repository": "aeoess/agent-authority-lifecycle",
        "commit": "2bf5c7e",
        "earliest_commit_for_these_concepts": "7796e22",
        "documents": ["AUTHORITY-LIFECYCLE.md", "CASES.md", "OPEN-QUESTIONS.md"],
        "version_in_document": "0.1.2-draft (AUTHORITY-LIFECYCLE.md), 0.2-draft (CASES.md)",
        "named_text": [
            "Lifecycle concepts are separate > Parties and standing > Principal binding",
            "Lifecycle concepts are separate > Parties and standing > Issuer standing",
            "Lifecycle concepts are separate > Parties and standing > Lifecycle standing",
            "Lifecycle concepts are separate > Authority lifecycle state > External restriction",
            "Lifecycle concepts are separate > Decisions and effects > In-flight state",
            "Lifecycle concepts are separate > Verification and evidence > Evidence",
            "Invariants > L1. Revoking an ancestor invalidates the authority that depends on it",
            "Invariants > L3. Reauthorization creates new authority",
            "Invariants > L4. A successor does not inherit the predecessor's delegation tree",
            "Invariants > L6. An earlier approval is not current authority",
            "Invariants > L8. Suspension is not revocation",
            "Operational cases > An action already in flight when authority changes",
            "OPEN-QUESTIONS.md > Work in flight",
            "CASES.md > Organization events > LC-B-004",
            "CASES.md > Organization events > LC-B-012",
            "CASES.md > Organization events > LC-B-013",
            "CASES.md > Organization events > LC-B-016",
            "CASES.md > Organization events > LC-B-028",
            "CASES.md > Organization events > LC-B-029",
            "CASES.md > Organization events > LC-B-030",
        ],
    },
    "description": (
        "Seven of the eight cases in CASES.md's Organization events section, as vectors "
        "at two layers. A boundary layer asks what one authorization boundary returns "
        "for a presented chain once principal binding, an external restriction and a "
        "third party's own consent gate are taken into account. An in-flight layer runs "
        "four ordered timelines for one payment order, where the only difference between "
        "a pair of timelines is which side of the receiving institution's acceptance an "
        "event fell on. Every vector is candidate_against_proposed. Nothing here is a "
        "draft-pidlisnyi-aps-03 conformance claim: draft-03 states no rule for principal "
        "binding across a corporate succession, for an external restriction that narrows "
        "scope, for a third-party consent gate, or for an acceptance boundary. Where the "
        "reference SDKs decide something anyway, which is every chain verdict below, the "
        "vector records it as observed implementation behavior."
    ),
    "not_built_here": {
        "LC-B-002": (
            "Two live, reachable status sources disagreeing about the same delegation is "
            "tested by the conflicting-status-sources family, vectors "
            "CSS-04-fresh-conflict-denies-with-conflict-reason, "
            "CSS-05-stale-revoked-against-fresh-active-denies and "
            "CSS-08-no-usable-answer-not-established. This family does not re-test it."
        ),
    },
    "policies": {
        "boundary": {
            "reference": "The boundary in harness.ts, with all four axes set the strict way.",
            "successor-exists-in-role": "Does not compare a presented child against the parent it names. Where the strict path failed on linkage, it verifies the root as its own chain and checks the leaf on its own. One axis.",
            "corporate-record-as-delegation-event": "Treats an authentic corporate succession record from a party with standing as establishing principal binding to the surviving company. One axis.",
            "restriction-blind": "Ignores external restriction records entirely. One axis.",
            "internal-chain-only": "Ignores third-party consent gates entirely. One axis.",
        },
        "flow": {
            "reference": "The in-flight model in harness.ts.",
            "approval-time-check-only": "Checks for a stop only when the order was authorized, so a stop that arrives later is never effective, on either side of acceptance. One axis.",
            "revocation-halts-everything": "Treats any recorded revocation as halting every submitted order, accepted or not. One axis.",
        },
    },
    # declared_fail_sets names the vectors where a defective policy reaches a
    # different OUTCOME from the reference. record_divergence names the vectors
    # where it reaches the same outcome and records something different about
    # it. Both are checked, so neither can drift, and keeping them apart stops
    # a same-outcome record difference from reading as a wrong decision.
    "declared_fail_sets": {
        "successor-exists-in-role": ["LC-B-004-c", "LC-B-004-d"],
        "corporate-record-as-delegation-event": ["LC-B-012-b", "LC-B-013-a"],
        "restriction-blind": ["LC-B-016-b"],
        "internal-chain-only": ["LC-B-030-b", "LC-B-030-c", "LC-B-030-d"],
        "approval-time-check-only": ["LC-B-028-b", "LC-B-028-c", "LC-B-028-d"],
        "revocation-halts-everything": ["LC-B-029-h"],
    },
    "record_divergence": {
        "restriction-blind": {
            "LC-B-016-c": "Both boundaries admit settling an existing obligation. The "
                          "reference records the verdict as restricted, because the "
                          "authority continues and what it covers has narrowed. The "
                          "restriction-blind boundary records it as plain valid. The "
                          "admission is the same and the recorded lifecycle state is "
                          "not, which is the difference a fixture that compared only "
                          "admit-or-deny would never see.",
        },
        "approval-time-check-only": {
            "LC-B-028-g": "Both boundaries report the late stop as ineffective. The "
                          "reference says it arrived after acceptance. The defective "
                          "boundary says authorization was settled at submission, which "
                          "is the same answer reached from a rule that also produces the "
                          "wrong answer in LC-B-028-b.",
        },
    },
    "timelines": {
        "TL_STOP_BEFORE": ["LC-B-028-a", "LC-B-028-b", "LC-B-028-c", "LC-B-028-d"],
        "TL_STOP_AFTER": ["LC-B-028-e", "LC-B-028-f", "LC-B-028-g", "LC-B-028-h"],
        "TL_REVOKE_BEFORE": ["LC-B-029-a", "LC-B-029-b", "LC-B-029-c", "LC-B-029-d"],
        "TL_REVOKE_AFTER": ["LC-B-029-e", "LC-B-029-f", "LC-B-029-g", "LC-B-029-h", "LC-B-029-i"],
    },
    "cases": cases,
}

(HERE / "vectors.json").write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(cases)} vectors")
