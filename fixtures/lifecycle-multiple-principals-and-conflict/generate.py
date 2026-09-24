#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Emit vectors.json for the lifecycle-multiple-principals-and-conflict family, byte for byte.

Every vector is labelled candidate_against_proposed. It tests proposed text in
aeoess/agent-authority-lifecycle at commit 7796e22 or later, never a published
specification, and names the case id in CASES.md v0.2 it comes from.

There is no randomness here. The file is a deterministic function of this script, so the
vector bytes are regenerable rather than only replayable:

    python3 fixtures/lifecycle-multiple-principals-and-conflict/generate.py

Then `git diff` on vectors.json should be empty.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

AT = "2026-09-20T12:00:00.000Z"

PROPOSED = {
    "repo": "aeoess/agent-authority-lifecycle",
    "commit_floor": "7796e22",
    "cases_version": "CASES.md v0.2 (local branch cases-v0.2, commit 2bf5c7e)",
    "section": "Multiple principals and conflict",
}

# --- reasons for an absent SDK API, written once each ---------------------------------

NO_GATE_API_PY = (
    "the PyPI SDK at 4.x exposes no charter, office, approval-request or "
    "multi-class-threshold module; dir(agent_passport) has no name matching charter, "
    "office, quorum or approval threshold"
)
NO_DIRECTION_API = (
    "no API in either SDK takes the direction of an action as an input to which threshold "
    "applies; MultiClassThresholdPolicy is one conjunction of key classes with no "
    "originate-versus-cancel axis"
)
NO_CONTEST_API = (
    "no API represents two live claims to one authority position with a declared default "
    "holder, a hard deadline and a reversion on silence; evaluateThreshold counts "
    "signatures and has no deadline-reversion behaviour"
)
NO_PRIORITY_API = (
    "no API orders two independently valid authority sources against each other; "
    "resolveSuccessor walks one charter's successionOrder and cannot see a rival source"
)
NO_PRIORITY_API_PY = NO_GATE_API_PY
NO_VOID_API = (
    "neither SDK has a status distinct from revoked for a grant void from issuance; the "
    "chain verifier's resolveRevocation answers active, revoked or an unrecognized value, "
    "and an unrecognized value becomes indeterminate under REVOCATION_UNKNOWN"
)
NO_OBJECTIVE_API = (
    "no API represents a signed joint objective binding independently rooted chains "
    "without pooling their scopes"
)
NO_AD_HOC_API = (
    "no API creates an authority position at the moment of a triggering event with its "
    "first holder decided by an eligibility rule and no grant record"
)
NO_RATIFICATION_API = (
    "no API has a state between an initiated suspension and its ratification; the chain "
    "verifier has no suspended state at all, and a resolver answer of \"suspended\" "
    "becomes indeterminate under REVOCATION_UNKNOWN"
)
NO_CAVEAT_API = (
    "no API attaches a per-source restriction on top of a delegated subset that is "
    "checkable per contributing source rather than pooled across contributors"
)
NO_OVERRIDE_API = (
    "no API represents a standing, cause-free override held above a concurrently "
    "exercised grant; ending a grant goes through a revocation record"
)
NO_DIVISIBLE_API = (
    "AuthorityDelegationV1 has exactly one issuer per record, so a grant divisible along "
    "co-issuer contribution share is not representable, and no API revokes part of a grant"
)
NO_PRECEDENCE_API = (
    "no API resolves two contradictory instructions from equally authorized co-principals "
    "by a named asymmetric default"
)
NO_REVIVAL_API = (
    "no API represents a targeted revival of one ended obligation gated by an ordering "
    "rule and a standing rescission window; draft-03 makes revocation irreversible and "
    "the SDKs have no revival record at all"
)

CHAIN_NOTE_VALID = "the chain verifies valid on its own records, which is the gap: the records this case turns on are not inputs the chain verifier takes"


def unsupported(reason: str, layer: str) -> dict:
    return {"supported": False, "layer": layer, "reason": reason}


def chain_probe(chain: str, state: str, code=None, index=None, note: str | None = None) -> dict:
    probe = {
        "supported": True,
        "layer": "chain_state",
        "chain": chain,
        "expected": {"state": state, "failure_code": code, "failure_index": index},
    }
    if note is not None:
        probe["note"] = note
    return probe


def chain_run(claim: str, chain: str, state: str, code=None, index=None, revoked=None,
              note: str | None = None) -> dict:
    entry = {
        "layer": "chain_state",
        "claim": claim,
        "revoked_roles": revoked or [],
        "npm": chain_probe(chain, state, code, index, note),
        "pypi": chain_probe(chain, state, code, index, note),
    }
    return entry


def threshold_probe(subject_key: str, requirements: list[dict], signature_refs: list[str],
                    expected: dict, note: str) -> dict:
    """An evaluateThreshold call the npm SDK really performs over minted signatures."""
    return {
        "supported": True,
        "layer": "multi_class_threshold",
        "api": "evaluateThreshold (npm agent-passport-system 7.1.0)",
        "subject_key": subject_key,
        "requirements": requirements,
        "signature_refs": signature_refs,
        "expected": expected,
        "note": note,
    }


VECTORS: list[dict] = []


def add(case: str, suffix: str, concept: str, polarity: str, proposed_text: str,
        description: str, records: dict, expected: dict, npm: dict, pypi: dict,
        control_fails: list[str], also_runs: list[dict] | None = None, at: str = AT) -> None:
    VECTORS.append(
        {
            "id": f"{case}-{suffix}",
            "case": case,
            "concept": concept,
            "label": "candidate_against_proposed",
            "polarity": polarity,
            "proposed_text": proposed_text,
            "description": description,
            "at": at,
            "records": records,
            "expected": expected,
            "sdk": {"npm": npm, "pypi": pypi},
            "also_runs": also_runs or [],
            "control_fails": control_fails,
        }
    )


# =====================================================================================
# LC-C-011. A concurrence gate at the next authorization boundary.
# =====================================================================================

C011_TEXT = (
    "AUTHORITY-LIFECYCLE.md L5 (\"An agent holding two valid chains cannot use them "
    "together to create a grant broader than either chain allows\") and the Approval "
    "concept, extended by CASES.md LC-C-011 to a gate requiring two separate, "
    "independently valid authorizations present together. L5 forbids unioning scope; this "
    "is the opposite failure, refusing to act on one chain alone whatever its scope."
)

C011_REGISTRY = {
    "alpha-1": "role_alpha",
    "alpha-2": "role_alpha",
    "beta-1": "role_beta",
    "senior-1": "role_senior",
}
C011_GATE = {"required_roles": ["role_alpha", "role_beta"], "freshness_seconds": 3600}
C011_REQS = [
    {"role": "role_alpha", "requiredSignatures": 1, "actors": ["alpha-1", "alpha-2"]},
    {"role": "role_beta", "requiredSignatures": 1, "actors": ["beta-1"]},
]


def conf(role: str, actor: str, decision: str, at: str, ref: str) -> dict:
    return {"role": role, "actor": actor, "decision": decision, "at": at, "signature_ref": ref}


FRESH = "2026-09-20T11:45:00.000Z"
STALE = "2026-09-20T10:00:00.000Z"

add(
    "LC-C-011", "a", "concurrence_gate", "positive", C011_TEXT,
    "Both required roles affirm inside the freshness bound. The gate is satisfied and the "
    "action is valid at the next authorization boundary.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [
            conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1"),
            conf("role_beta", "beta-1", "affirm", FRESH, "concurrence-1:beta-1"),
        ],
    },
    {
        "verdict": "valid", "code": "CONCURRENCE_PRESENT",
        "role_status": {"role_alpha": "affirmed", "role_beta": "affirmed"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1", "concurrence-1:beta-1"],
        {"met": True, "unsatisfied_roles": []},
        "evaluateThreshold supplies the conjunction across key classes and the eligibility "
        "check on each signing key. It has no freshness bound and no dissent, so the stale "
        "and refusal vectors of this case are decided by this fixture, not by the SDK.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    [],
)

add(
    "LC-C-011", "b", "concurrence_gate", "negative", C011_TEXT,
    "Only the first role affirms. The second has recorded nothing, so the gate is not "
    "satisfied and the verdict is not established, not invalid: no record says the second "
    "role refused.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1")],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {"role_alpha": "affirmed", "role_beta": "silent"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1"],
        {"met": False, "unsatisfied_roles": ["role_beta"]},
        "the SDK agrees the conjunction is unmet. It reports met false with no verdict "
        "name, so whether an unmet gate is invalid or not established is this fixture's "
        "call and is recorded as a vagueness finding.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-011", "c", "concurrence_gate", "negative", C011_TEXT,
    "Two actors in the first role affirm and the second role is silent. Count within one "
    "role never substitutes for the missing second concurrence.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [
            conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1"),
            conf("role_alpha", "alpha-2", "affirm", FRESH, "concurrence-1:alpha-2"),
        ],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {"role_alpha": "affirmed", "role_beta": "silent"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1", "concurrence-1:alpha-2"],
        {"met": False, "unsatisfied_roles": ["role_beta"]},
        "two eligible signatures in one class do not satisfy the other class.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-011", "d", "concurrence_gate", "negative", C011_TEXT,
    "Both roles affirm, but the second role's affirmation is older than the freshness "
    "bound. The two concurrences are not present and fresh at the same moment, so the "
    "gate is not satisfied.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [
            conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1"),
            conf("role_beta", "beta-1", "affirm", STALE, "concurrence-1:beta-1"),
        ],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_STALE",
        "role_status": {"role_alpha": "affirmed", "role_beta": "stale"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1", "concurrence-1:beta-1"],
        {"met": True, "unsatisfied_roles": []},
        "the SDK answers met true here, because MultiClassThresholdPolicy has a collection "
        "timeout on the request but no per-signature freshness bound. The divergence "
        "between the SDK answer and this fixture's verdict is the point of the vector and "
        "is recorded as a vagueness finding, not as an SDK defect.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-011", "e", "concurrence_gate", "negative", C011_TEXT,
    "The first role affirms and the second records a dissent. A recorded refusal is a fact "
    "about that role's position, so the verdict is invalid rather than not established.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [
            conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1"),
            conf("role_beta", "beta-1", "dissent", FRESH, "concurrence-1:beta-1"),
        ],
    },
    {
        "verdict": "invalid", "code": "CONCURRENCE_REFUSED",
        "role_status": {"role_alpha": "affirmed", "role_beta": "refused"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1", "concurrence-1:beta-1"],
        {"met": True, "unsatisfied_roles": []},
        "ApprovalSignature has no decision member, so a dissent and an affirmation are the "
        "same object to the SDK and it answers met true. Recorded as a vagueness finding.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-011", "f", "concurrence_gate", "negative", C011_TEXT,
    "Negative control target. A more senior principal affirms and the second required role "
    "is silent. A longer or more senior chain never substitutes for a missing concurrence, "
    "and the senior role is not one the gate names.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [
            conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1"),
            conf("role_senior", "senior-1", "affirm", FRESH, "concurrence-1:senior-1"),
        ],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {"role_alpha": "affirmed", "role_beta": "silent"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1", "concurrence-1:senior-1"],
        {"met": False, "unsatisfied_roles": ["role_beta"]},
        "the senior signer's key is not in role_beta's eligibleKeys, so the SDK does not "
        "count it toward the missing class either.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-011", "g", "concurrence_gate", "negative", C011_TEXT,
    "A confirmation from the second role whose own declared role is role_beta but whose "
    "actor the registry places in role_senior. A record's claim about its author's role is "
    "not what decides the role, so the second role is still silent.",
    {
        "gate": C011_GATE,
        "registry": C011_REGISTRY,
        "confirmations": [
            conf("role_alpha", "alpha-1", "affirm", FRESH, "concurrence-1:alpha-1"),
            conf("role_beta", "senior-1", "affirm", FRESH, "concurrence-1:senior-1"),
        ],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {"role_alpha": "affirmed", "role_beta": "silent"},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "concurrence-1", C011_REQS, ["concurrence-1:alpha-1", "concurrence-1:senior-1"],
        {"met": False, "unsatisfied_roles": ["role_beta"]},
        "the SDK reaches the same answer by a different route: it checks the signing key "
        "against the class's eligibleKeys rather than against a claimed role.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

# =====================================================================================
# LC-C-018. A variable-size unanimous role set where silence blocks.
# =====================================================================================

C018_TEXT = (
    "AUTHORITY-LIFECYCLE.md, the Approval concept (\"It is an input to authorization, with "
    "its own scope, expiry and use count\") and L5, extended by CASES.md LC-C-018 to an "
    "enumerated role set where every named role must affirmatively confirm and a missing "
    "confirmation blocks the action rather than being read as consent."
)

C018_ROLES = ["role_equipment", "role_identity", "role_procedure", "role_site"]
C018_REGISTRY = {
    "ident-1": "role_identity",
    "site-1": "role_site",
    "proc-1": "role_procedure",
    "equip-1": "role_equipment",
    "lead-1": "role_lead",
}
C018_GATE = {"required_roles": C018_ROLES, "freshness_seconds": 3600}
C018_REQS = [
    {"role": "role_equipment", "requiredSignatures": 1, "actors": ["equip-1"]},
    {"role": "role_identity", "requiredSignatures": 1, "actors": ["ident-1"]},
    {"role": "role_procedure", "requiredSignatures": 1, "actors": ["proc-1"]},
    {"role": "role_site", "requiredSignatures": 1, "actors": ["site-1"]},
]
C018_ALL = [
    conf("role_identity", "ident-1", "affirm", FRESH, "unanimous-1:ident-1"),
    conf("role_site", "site-1", "affirm", FRESH, "unanimous-1:site-1"),
    conf("role_procedure", "proc-1", "affirm", FRESH, "unanimous-1:proc-1"),
    conf("role_equipment", "equip-1", "affirm", FRESH, "unanimous-1:equip-1"),
]

add(
    "LC-C-018", "a", "unanimous_role_set", "positive", C018_TEXT,
    "All four named roles affirm, each logged individually. The gate is satisfied.",
    {"gate": C018_GATE, "registry": C018_REGISTRY, "confirmations": C018_ALL},
    {
        "verdict": "valid", "code": "CONCURRENCE_PRESENT",
        "role_status": {r: "affirmed" for r in C018_ROLES},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "unanimous-1", C018_REQS,
        ["unanimous-1:ident-1", "unanimous-1:site-1", "unanimous-1:proc-1", "unanimous-1:equip-1"],
        {"met": True, "unsatisfied_roles": []},
        "a four-class conjunction with one required signature each is exactly what "
        "MultiClassThresholdPolicy expresses, so the SDK supplies the all-must-affirm "
        "arithmetic for the positive case.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    [],
)

add(
    "LC-C-018", "b", "unanimous_role_set", "negative", C018_TEXT,
    "Three of four roles affirm and the fourth is absent. Silence is not consent, so the "
    "action is blocked, and the verdict is not established because no record says that "
    "role objected.",
    {"gate": C018_GATE, "registry": C018_REGISTRY, "confirmations": C018_ALL[:3]},
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {
            "role_equipment": "silent", "role_identity": "affirmed",
            "role_procedure": "affirmed", "role_site": "affirmed",
        },
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "unanimous-1", C018_REQS,
        ["unanimous-1:ident-1", "unanimous-1:site-1", "unanimous-1:proc-1"],
        {"met": False, "unsatisfied_roles": ["role_equipment"]},
        "the SDK names the unsatisfied class, which is the useful half of the answer.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-018", "c", "unanimous_role_set", "negative", C018_TEXT,
    "The fourth role records an unresolved objection. Blocked, and invalid rather than not "
    "established, because the objection is on the record.",
    {
        "gate": C018_GATE, "registry": C018_REGISTRY,
        "confirmations": C018_ALL[:3] + [
            conf("role_equipment", "equip-1", "dissent", FRESH, "unanimous-1:equip-1")
        ],
    },
    {
        "verdict": "invalid", "code": "CONCURRENCE_REFUSED",
        "role_status": {
            "role_equipment": "refused", "role_identity": "affirmed",
            "role_procedure": "affirmed", "role_site": "affirmed",
        },
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "unanimous-1", C018_REQS,
        ["unanimous-1:ident-1", "unanimous-1:site-1", "unanimous-1:proc-1", "unanimous-1:equip-1"],
        {"met": True, "unsatisfied_roles": []},
        "the SDK answers met true, because a dissent and an affirmation are the same "
        "ApprovalSignature to it. Recorded as a vagueness finding.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-018", "d", "unanimous_role_set", "negative", C018_TEXT,
    "The fourth role's confirmation is present and well formed, and its signature does not "
    "verify under the key its actor is registered with. Unusable evidence is not evidence, "
    "so that role is still silent and the action is blocked.",
    {
        "gate": C018_GATE, "registry": C018_REGISTRY,
        "confirmations": C018_ALL[:3] + [
            conf("role_equipment", "equip-1", "affirm", FRESH, "unanimous-1:equip-1:tampered")
        ],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {
            "role_equipment": "silent", "role_identity": "affirmed",
            "role_procedure": "affirmed", "role_site": "affirmed",
        },
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "unanimous-1", C018_REQS,
        ["unanimous-1:ident-1", "unanimous-1:site-1", "unanimous-1:proc-1",
         "unanimous-1:equip-1:tampered"],
        {"met": False, "unsatisfied_roles": ["role_equipment"]},
        "evaluateThreshold verifies each signature over the supplied content and "
        "contributes zero for one that does not verify, so the SDK supplies this layer.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

add(
    "LC-C-018", "e", "unanimous_role_set", "negative", C018_TEXT,
    "Negative control target. A single lead authorizer signs off and no per-role "
    "confirmation is recorded at all. A one-authorizer sign-off is not a collected, "
    "per-role, explicit confirmation set.",
    {
        "gate": C018_GATE, "registry": C018_REGISTRY,
        "confirmations": [conf("role_lead", "lead-1", "affirm", FRESH, "unanimous-1:lead-1")],
    },
    {
        "verdict": "not_established", "code": "CONCURRENCE_MISSING",
        "role_status": {r: "silent" for r in C018_ROLES},
        "silence_treated_as_consent": False,
    },
    threshold_probe(
        "unanimous-1", C018_REQS, ["unanimous-1:lead-1"],
        {"met": False, "unsatisfied_roles": C018_ROLES},
        "the lead's key is in no class's eligibleKeys, so all four classes stay unsatisfied.",
    ),
    unsupported(NO_GATE_API_PY, "multi_class_threshold"),
    ["signature-suffices"],
)

# =====================================================================================
# LC-C-016. Asymmetric thresholds by direction.
# =====================================================================================

C016_TEXT = (
    "AUTHORITY-LIFECYCLE.md L5 and the Authorization decision concept, extended by "
    "CASES.md LC-C-016 to a two-principal relationship whose threshold differs by "
    "direction: origination and continuation need both principals' current concurrence "
    "while cancellation or restriction needs one. Distinct from the symmetric gate of "
    "LC-C-011."
)
C016_REGISTRY = {"pic-1": "role_pic", "disp-1": "role_dispatcher"}
C016_GATE = {
    "directions": {
        "originate": {"mode": "all", "roles": ["role_dispatcher", "role_pic"]},
        "continue": {"mode": "all", "roles": ["role_dispatcher", "role_pic"]},
        "cancel": {"mode": "any", "roles": ["role_dispatcher", "role_pic"]},
        "restrict": {"mode": "any", "roles": ["role_dispatcher", "role_pic"]},
    },
    "freshness_seconds": 3600,
}


def c016(suffix, polarity, desc, direction, confirmations, verdict, code, status,
         control_fails, npm):
    add(
        "LC-C-016", suffix, "asymmetric_threshold", polarity, C016_TEXT, desc,
        {
            "gate": C016_GATE, "registry": C016_REGISTRY, "direction": direction,
            "confirmations": confirmations,
        },
        {
            "verdict": verdict, "code": code, "role_status": status,
            "silence_treated_as_consent": False,
        },
        npm, unsupported(NO_DIRECTION_API, "direction_threshold"), control_fails,
    )


BOTH_OK = "the direction axis is supplied by this fixture. evaluateThreshold can express the origination conjunction, and it has no way to express a one-of-two veto for the same pair, so only the all-mode directions are checked against the SDK."

c016(
    "a", "positive",
    "Origination with both principals' current concurrence. Valid.",
    "originate",
    [
        conf("role_pic", "pic-1", "affirm", FRESH, "originate-1:pic-1"),
        conf("role_dispatcher", "disp-1", "affirm", FRESH, "originate-1:disp-1"),
    ],
    "valid", "THRESHOLD_MET_ALL",
    {"role_dispatcher": "affirmed", "role_pic": "affirmed"},
    [],
    threshold_probe(
        "originate-1",
        [
            {"role": "role_dispatcher", "requiredSignatures": 1, "actors": ["disp-1"]},
            {"role": "role_pic", "requiredSignatures": 1, "actors": ["pic-1"]},
        ],
        ["originate-1:pic-1", "originate-1:disp-1"],
        {"met": True, "unsatisfied_roles": []},
        BOTH_OK,
    ),
)

c016(
    "b", "negative",
    "Origination with only one principal's concurrence. Not established, because the "
    "other has recorded nothing.",
    "originate",
    [conf("role_pic", "pic-1", "affirm", FRESH, "originate-1:pic-1")],
    "not_established", "THRESHOLD_MISSING",
    {"role_dispatcher": "silent", "role_pic": "affirmed"},
    [],
    threshold_probe(
        "originate-1",
        [
            {"role": "role_dispatcher", "requiredSignatures": 1, "actors": ["disp-1"]},
            {"role": "role_pic", "requiredSignatures": 1, "actors": ["pic-1"]},
        ],
        ["originate-1:pic-1"],
        {"met": False, "unsatisfied_roles": ["role_dispatcher"]},
        BOTH_OK,
    ),
)

c016(
    "c", "positive",
    "Cancellation with one principal's affirmation and the other silent. One is enough in "
    "the stopping direction, so this is valid. The symmetric-threshold control gets it "
    "wrong by applying the origination policy here.",
    "cancel",
    [conf("role_pic", "pic-1", "affirm", FRESH, "cancel-1:pic-1")],
    "valid", "THRESHOLD_MET_ANY",
    {"role_dispatcher": "silent", "role_pic": "affirmed"},
    ["symmetric-threshold"],
    unsupported(NO_DIRECTION_API, "direction_threshold"),
)

c016(
    "d", "positive",
    "Restriction by the other principal alone, with the first silent. Also valid: the "
    "asymmetry runs both ways between the two principals, not in favour of one of them.",
    "restrict",
    [conf("role_dispatcher", "disp-1", "affirm", FRESH, "restrict-1:disp-1")],
    "valid", "THRESHOLD_MET_ANY",
    {"role_dispatcher": "affirmed", "role_pic": "silent"},
    ["symmetric-threshold"],
    unsupported(NO_DIRECTION_API, "direction_threshold"),
)

c016(
    "e", "negative",
    "Continuation where one principal affirms and the other records a dissent. Invalid: "
    "continuation needs both, and a recorded objection is not silence.",
    "continue",
    [
        conf("role_pic", "pic-1", "affirm", FRESH, "continue-1:pic-1"),
        conf("role_dispatcher", "disp-1", "dissent", FRESH, "continue-1:disp-1"),
    ],
    "invalid", "THRESHOLD_REFUSED",
    {"role_dispatcher": "refused", "role_pic": "affirmed"},
    [],
    unsupported(NO_DIRECTION_API, "direction_threshold"),
)

c016(
    "f", "positive",
    "Cancellation where one principal affirms the stop and the other dissents from it. "
    "Still valid: in the stopping direction one party's stop is enough and the co-party "
    "cannot force continuation over it.",
    "cancel",
    [
        conf("role_pic", "pic-1", "affirm", FRESH, "cancel-1:pic-1"),
        conf("role_dispatcher", "disp-1", "dissent", FRESH, "cancel-1:disp-1"),
    ],
    "valid", "THRESHOLD_MET_ANY",
    {"role_dispatcher": "refused", "role_pic": "affirmed"},
    ["symmetric-threshold"],
    unsupported(NO_DIRECTION_API, "direction_threshold"),
)

c016(
    "g", "negative",
    "Cancellation with neither principal recording anything. Not established, so the "
    "asymmetry lowers the bar to one and does not remove it.",
    "cancel", [],
    "not_established", "THRESHOLD_MISSING",
    {"role_dispatcher": "silent", "role_pic": "silent"},
    [],
    unsupported(NO_DIRECTION_API, "direction_threshold"),
)

# =====================================================================================
# LC-C-002. A live contest over one seat, with a default holder, deadline and override.
# =====================================================================================

C002_TEXT = (
    "AUTHORITY-LIFECYCLE.md, the Principal, Lifecycle standing and Suspension concepts, "
    "and OPEN-QUESTIONS.md \"Office vacancy and succession\", extended by CASES.md LC-C-002 "
    "to two live competing claims to one authority position with a declared default "
    "holder for the contested window, a hard deadline, and a supermajority that can flip "
    "the default. Distinct from L5, which is about unioning scope across chains."
)

OPENED = "2026-09-20T10:00:00.000Z"
DEADLINE = "2026-09-20T11:00:00.000Z"
INSIDE = "2026-09-20T10:30:00.000Z"
AFTER = "2026-09-20T12:00:00.000Z"

C002_OVERRIDE = [
    {"class": "chamber_a", "required": 2, "eligible": ["ca-1", "ca-2", "ca-3"]},
    {"class": "chamber_b", "required": 2, "eligible": ["cb-1", "cb-2", "cb-3"]},
]


def contest(default_holder="party_default") -> dict:
    return {
        "seat_id": "seat:one",
        "challenged_party": "party_challenged",
        "asserting_party": "party_asserting",
        "default_holder": default_holder,
        "opened_at": OPENED,
        "deadline_at": DEADLINE,
        "override": C002_OVERRIDE,
    }


def vote(actor: str, cls: str, at: str) -> dict:
    return {"actor": actor, "class": cls, "at": at, "signature_ref": f"contest-1:{actor}"}


BY_DEADLINE = "2026-09-20T10:50:00.000Z"
PAST_DEADLINE = "2026-09-20T11:30:00.000Z"
FULL_VOTES_BY_DEADLINE = [
    vote("ca-1", "chamber_a", BY_DEADLINE), vote("ca-2", "chamber_a", BY_DEADLINE),
    vote("cb-1", "chamber_b", BY_DEADLINE), vote("cb-2", "chamber_b", BY_DEADLINE),
]
FULL_VOTES_PAST_DEADLINE = [
    vote("ca-1", "chamber_a", PAST_DEADLINE), vote("ca-2", "chamber_a", PAST_DEADLINE),
    vote("cb-1", "chamber_b", PAST_DEADLINE), vote("cb-2", "chamber_b", PAST_DEADLINE),
]


def c002(suffix, polarity, desc, contest_rec, votes, actor, at, verdict, code,
         threshold_met, governing, control_fails):
    add(
        "LC-C-002", suffix, "contested_seat", polarity, C002_TEXT, desc,
        {"contest": contest_rec, "votes": votes, "actor": actor},
        {
            "verdict": verdict, "code": code,
            "threshold_met_by_deadline": threshold_met, "governing_party": governing,
        },
        unsupported(NO_CONTEST_API, "contested_seat"),
        unsupported(NO_CONTEST_API, "contested_seat"),
        control_fails, at=at,
    )


c002("a", "positive",
     "Inside the contested window, the declared default holder acts. Valid for the whole "
     "window, so the actions that cannot wait are not blocked.",
     contest(), [], "party_default", INSIDE,
     "valid", "CONTEST_WINDOW_DEFAULT", False, "party_default", [])

c002("b", "positive",
     "Inside the same window, the challenged party acts. Suspended, not invalid and not "
     "not established: the default holder governs the window and the challenged party's "
     "own authority is paused rather than ended.",
     contest(), [], "party_challenged", INSIDE,
     "suspended", "CONTEST_WINDOW_CHALLENGED", False, "party_default", [])

c002("c", "positive",
     "After the deadline with the supermajority recorded in both classes by the deadline. "
     "The default holder continues.",
     contest(), FULL_VOTES_BY_DEADLINE, "party_default", AFTER,
     "valid", "OVERRIDE_SUSTAINED", True, "party_default", [])

c002("d", "positive",
     "After the deadline with no supermajority. The seat reverts to the challenged party, "
     "which is the direction silence resolves in. The default-continues control gets this "
     "backwards.",
     contest(), [], "party_challenged", AFTER,
     "valid", "CONTEST_REVERTED", False, "party_challenged", ["default-continues"])

c002("e", "negative",
     "The same reversion seen from the other side: after the deadline with no "
     "supermajority, the default holder's own action is invalid.",
     contest(), [], "party_default", AFTER,
     "invalid", "CONTEST_REVERTED", False, "party_challenged", ["default-continues"])

c002("f", "negative",
     "A full supermajority in both classes, every vote recorded after the deadline. The "
     "deadline is hard, so the votes do not count and the seat still reverts.",
     contest(), FULL_VOTES_PAST_DEADLINE, "party_challenged", AFTER,
     "valid", "CONTEST_REVERTED", False, "party_challenged", ["default-continues"])

c002("g", "negative",
     "One class reaches its threshold by the deadline and the other does not. The override "
     "is a conjunction across classes, so it is not met and the seat reverts.",
     contest(),
     [vote("ca-1", "chamber_a", BY_DEADLINE), vote("ca-2", "chamber_a", BY_DEADLINE),
      vote("cb-1", "chamber_b", BY_DEADLINE)],
     "party_default", AFTER,
     "invalid", "CONTEST_REVERTED", False, "party_challenged", ["default-continues"])

c002("h", "negative",
     "A contest record that declares no default holder. Neither party's action is "
     "established, which is the outcome the case says a verifier must avoid by declaring "
     "one in advance.",
     contest(default_holder=None), [], "party_default", INSIDE,
     "not_established", "NO_DEFAULT_HOLDER", False, None, [])

c002("i", "negative",
     "A vote from an actor the record does not list as eligible for its class, alongside "
     "one eligible vote. The ineligible vote does not count, so the threshold is unmet.",
     contest(),
     [vote("ca-1", "chamber_a", BY_DEADLINE), vote("cb-1", "chamber_b", BY_DEADLINE),
      vote("ca-3", "chamber_b", BY_DEADLINE)],
     "party_challenged", AFTER,
     "valid", "CONTEST_REVERTED", False, "party_challenged", ["default-continues"])

# =====================================================================================
# LC-C-005. Two independently valid succession sources, one seat.
# =====================================================================================

C005_TEXT = (
    "AUTHORITY-LIFECYCLE.md L5 and the Verifier trust policy concept, plus "
    "OPEN-QUESTIONS.md \"Office vacancy and succession\", extended by CASES.md LC-C-005 to "
    "one seat with two independently sourced, individually valid chains disagreeing about "
    "who holds it. Nothing in L1 to L12 orders competing valid sources against each other."
)

SOURCES = [
    {"source_id": "source_general", "chain": "SEAT_P", "names_holder": "holder_p"},
    {"source_id": "source_specific", "chain": "SEAT_Q", "names_holder": "holder_q"},
]
SOURCES_REVERSED = [
    {"source_id": "source_specific", "chain": "SEAT_Q", "names_holder": "holder_q"},
    {"source_id": "source_general", "chain": "SEAT_P", "names_holder": "holder_p"},
]
SAME_HOLDER = [
    {"source_id": "source_general", "chain": "SEAT_P", "names_holder": "holder_p"},
    {"source_id": "source_specific", "chain": "SEAT_Q", "names_holder": "holder_p"},
]

C005_RUNS = [
    chain_run("each claimed source chain verifies valid on its own records, so the "
              "conflict is not a chain-verification question", "SEAT_P", "valid",
              note=CHAIN_NOTE_VALID),
    chain_run("and the same for the rival source chain", "SEAT_Q", "valid",
              note=CHAIN_NOTE_VALID),
]


def c005(suffix, polarity, desc, sources, rule, verdict, code, holder, per_chain,
         control_fails):
    add(
        "LC-C-005", suffix, "competing_succession_sources", polarity, C005_TEXT, desc,
        {"sources": sources, "priority_rule": rule, "seat_id": "seat:one"},
        {"verdict": verdict, "code": code, "governing_holder": holder, "per_chain": per_chain},
        unsupported(NO_PRIORITY_API, "source_priority"),
        unsupported(NO_PRIORITY_API_PY, "source_priority"),
        control_fails, also_runs=C005_RUNS,
    )


c005("a", "negative",
     "Two independently valid sources naming different holders and no declared priority "
     "between them. It is not established which holder governs, and neither chain is "
     "valid or invalid for the seat. The first-presented-wins control answers anyway.",
     SOURCES, None, "not_established", "NO_SOURCE_PRIORITY", None,
     {"SEAT_P": "not_established", "SEAT_Q": "not_established"},
     ["first-presented-wins"])

c005("b", "positive",
     "The same two sources with a declared priority rule putting the specific source "
     "ahead of the general one. The answer is deterministic and does not depend on which "
     "chain a relying party submitted.",
     SOURCES, {"ordered_source_ids": ["source_specific", "source_general"]},
     "valid", "SOURCE_PRIORITY_APPLIED", "holder_q",
     {"SEAT_P": "invalid", "SEAT_Q": "valid"},
     ["first-presented-wins"])

c005("c", "positive",
     "The same two records with the priority rule reversed, and presented in the opposite "
     "order so that the rule demotes the source a relying party submitted first. The rule, "
     "not the order of presentation, decides.",
     SOURCES_REVERSED, {"ordered_source_ids": ["source_general", "source_specific"]},
     "valid", "SOURCE_PRIORITY_APPLIED", "holder_p",
     {"SEAT_P": "valid", "SEAT_Q": "invalid"},
     ["first-presented-wins"])

c005("d", "negative",
     "A priority rule that orders only one of the two sources presented. It does not "
     "decide between them, so the question stays not established.",
     SOURCES, {"ordered_source_ids": ["source_specific"]},
     "not_established", "PRIORITY_RULE_INCOMPLETE", None,
     {"SEAT_P": "not_established", "SEAT_Q": "not_established"},
     ["first-presented-wins"])

c005("e", "positive",
     "Two independently valid sources that name the same holder. There is no conflict to "
     "order, so no priority rule is needed.",
     SAME_HOLDER, None, "valid", "NO_CONFLICT", "holder_p",
     {"SEAT_P": "valid", "SEAT_Q": "valid"},
     [])

# =====================================================================================
# LC-C-006. An ancestor void from issuance, discovered late.
# =====================================================================================

C006_TEXT = (
    "AUTHORITY-LIFECYCLE.md L1 (\"Once a verifier can establish, under the applicable "
    "status and freshness rules, that an ancestor delegation is revoked, a chain that "
    "depends on that ancestor is invalid\") and the Issuance and Evidence concepts, "
    "extended by CASES.md LC-C-006 to an ancestor that was never valid, discovered long "
    "after the fact. L1 assumes the ancestor was once valid and was later revoked."
)

C006_REGISTRY = {"finders_with_standing": ["auditor:independent"]}
FOUND_AT = "2026-09-20T11:00:00.000Z"
EARLIER_RECEIPTS = [
    {"receipt_id": "rcpt-1", "at": "2026-09-20T09:40:00.000Z", "verdict": "valid", "code": None},
    {"receipt_id": "rcpt-2", "at": "2026-09-20T10:20:00.000Z", "verdict": "valid", "code": None},
]


def finding(by="auditor:independent", ref="audit:2026-09-20", found_at=FOUND_AT) -> dict:
    return {
        "kind": "void_from_issuance",
        "target_role": "DEPUTY_TO_AGENT_T",
        "found_at": found_at,
        "by": by,
        "standing_ref": ref,
    }


C006_RUNS = [
    chain_run("the three-hop chain verifies valid on its own records with nothing revoked, "
              "which is the gap: no revocation happened and the SDK has no void-from-"
              "issuance status to return", "TAINTED", "valid", note=CHAIN_NOTE_VALID),
    chain_run("for contrast, the same chain with the middle record revoked is invalid with "
              "REVOKED at index 1, which is the verdict this case says must not be reused "
              "for a grant that was never valid", "TAINTED", "invalid", "REVOKED", 1,
              revoked=["DEPUTY_TO_AGENT_T"]),
]


def c006(suffix, polarity, desc, finding_rec, at, verdict, code, receipts, control_fails):
    add(
        "LC-C-006", suffix, "void_from_issuance_finding", polarity, C006_TEXT, desc,
        {
            "chain": "TAINTED", "finding": finding_rec, "registry": C006_REGISTRY,
            "earlier_receipts": EARLIER_RECEIPTS,
        },
        {
            "verdict": verdict, "code": code, "no_revocation_record": True,
            "earlier_receipts": receipts,
        },
        unsupported(NO_VOID_API, "void_from_issuance"),
        unsupported(NO_VOID_API, "void_from_issuance"),
        control_fails, also_runs=C006_RUNS, at=at,
    )


c006("a", "positive",
     "Before the finding is recorded, the chain verdict is what chain verification says on "
     "the records available then. The two earlier receipts stand unchanged.",
     finding(), "2026-09-20T10:30:00.000Z", "valid", "FINDING_NOT_YET_RECORDED",
     EARLIER_RECEIPTS, ["retroactive-finding"])

c006("b", "positive",
     "From the finding onward, the dependent chain is invalid under a code distinct from "
     "REVOKED, and no revocation record exists anywhere in the set. The earlier receipts "
     "are still unchanged: the finding is a new record that references them.",
     finding(), AT, "invalid", "VOID_FROM_ISSUANCE",
     EARLIER_RECEIPTS, ["retroactive-finding"])

c006("c", "negative",
     "A finding from a party the registry does not place standing with. It does not "
     "establish that the ancestor was void, and it does not make the chain invalid either.",
     finding(by="blogger:anonymous"), AT, "valid", "FINDING_STANDING_NOT_ESTABLISHED",
     EARLIER_RECEIPTS, ["retroactive-finding"])

c006("d", "negative",
     "A finding from a party with standing that carries no standing_ref a verifier could "
     "follow. Naming yourself as the finder is not standing.",
     finding(ref=None), AT, "valid", "FINDING_STANDING_NOT_ESTABLISHED",
     EARLIER_RECEIPTS, ["retroactive-finding"])

c006("e", "positive",
     "Negative control target, and the central assertion of this case. No finding exists "
     "at all, so the chain verdict is chain verification's and the receipts are untouched. "
     "The retroactive-finding control rewrites the receipts even here, because it applies "
     "the relabelling before it looks at whether a finding exists.",
     None, AT, "valid", "CHAIN_VERIFIED", EARLIER_RECEIPTS, ["retroactive-finding"])

# =====================================================================================
# LC-C-012. Independently rooted chains committing to a shared objective.
# =====================================================================================

C012_TEXT = (
    "AUTHORITY-LIFECYCLE.md L5 (\"a verifier MUST NOT union scopes or budgets from "
    "multiple chains\"), extended by CASES.md LC-C-012 to the case L5 leaves undescribed: "
    "independently rooted chains legitimately coordinating on a shared objective while "
    "each keeps its own scope fully separate. That is not a union and should be permitted "
    "rather than left looking like the anti-pattern L5 forbids."
)

OBJECTIVE = {
    "objective_id": "obj:incident-1",
    "parties": [
        {"party": "agency_a", "chain": "UNIT_A", "signature_verifies": True},
        {"party": "agency_b", "chain": "UNIT_B", "signature_verifies": True},
    ],
}
OBJECTIVE_UNSIGNED = {
    "objective_id": "obj:incident-1",
    "parties": [
        {"party": "agency_a", "chain": "UNIT_A", "signature_verifies": True},
        {"party": "agency_b", "chain": "UNIT_B", "signature_verifies": False},
    ],
}
WITHDRAWAL = {"by": "agency_b", "at": "2026-09-20T11:00:00.000Z"}

C012_RUNS = [
    chain_run("the first chain verifies valid on its own records", "UNIT_A", "valid"),
    chain_run("the second chain verifies valid on its own records, shares the same leaf "
              "subject, and shares no delegation_id and no parent with the first",
              "UNIT_B", "valid"),
]


def c012(suffix, polarity, desc, objective, action, withdrawal, verdict, code,
         objective_state, bound, control_fails, at=AT):
    add(
        "LC-C-012", suffix, "joint_objective_no_union", polarity, C012_TEXT, desc,
        {"objective": objective, "action": action, "withdrawal": withdrawal},
        {
            "verdict": verdict, "code": code, "objective_state": objective_state,
            "bound_parties": bound,
        },
        unsupported(NO_OBJECTIVE_API, "joint_objective"),
        unsupported(NO_OBJECTIVE_API, "joint_objective"),
        control_fails, also_runs=C012_RUNS, at=at,
    )


BOTH_BOUND = ["agency_a", "agency_b"]

c012("a", "positive",
     "An action over the first party's own resource under the first party's own chain, "
     "with the joint objective record in force. Valid, and the objective record is what "
     "records the coordination.",
     OBJECTIVE, {"needs_grants": ["alpha:write"], "under_chain": "UNIT_A"}, None,
     "valid", "SCOPE_COVERED_BY_SELECTED_CHAIN", "valid", BOTH_BOUND, [])

c012("b", "negative",
     "Negative control target. An action needing a grant only the second party's chain "
     "holds, requested under the first party's chain, with the objective in force. The "
     "objective record commits the parties and adds no scope, so this is invalid.",
     OBJECTIVE, {"needs_grants": ["beta:write"], "under_chain": "UNIT_A"}, None,
     "invalid", "SCOPE_NOT_COVERED", "valid", BOTH_BOUND, ["objective-unions-scope"])

c012("c", "negative",
     "An action needing one grant from each chain, requested under one of them. Also "
     "invalid, and for the same reason: each grant follows one parent chain.",
     OBJECTIVE, {"needs_grants": ["alpha:write", "beta:write"], "under_chain": "UNIT_A"}, None,
     "invalid", "SCOPE_NOT_COVERED", "valid", BOTH_BOUND, ["objective-unions-scope"])

c012("d", "positive",
     "The second party withdraws. The first party's own action under its own chain stays "
     "valid, and the objective is restricted to the remaining party rather than "
     "invalidated.",
     OBJECTIVE, {"needs_grants": ["alpha:write"], "under_chain": "UNIT_A"}, WITHDRAWAL,
     "valid", "SCOPE_COVERED_BY_SELECTED_CHAIN", "restricted", BOTH_BOUND, [])

c012("e", "negative",
     "After that withdrawal, an action under the withdrawing party's own chain, taken as "
     "part of the joint objective, is invalid.",
     OBJECTIVE, {"needs_grants": ["beta:write"], "under_chain": "UNIT_B"}, WITHDRAWAL,
     "invalid", "PARTY_WITHDRAWN", "restricted", BOTH_BOUND, [])

c012("f", "positive",
     "Before the withdrawal instant, the same action under the same chain is still valid. "
     "A withdrawal recorded later does not reach back.",
     OBJECTIVE, {"needs_grants": ["beta:write"], "under_chain": "UNIT_B"}, WITHDRAWAL,
     "valid", "SCOPE_COVERED_BY_SELECTED_CHAIN", "valid", BOTH_BOUND, [],
     at="2026-09-20T10:30:00.000Z")

c012("g", "negative",
     "An objective record one of the named parties has not signed. That party is not "
     "bound, so the objective itself is not established, while each chain's own actions "
     "are unaffected.",
     OBJECTIVE_UNSIGNED, {"needs_grants": ["alpha:write"], "under_chain": "UNIT_A"}, None,
     "valid", "SCOPE_COVERED_BY_SELECTED_CHAIN", "not_established", ["agency_a"], [])

# =====================================================================================
# LC-C-020. A position created on the fly by an eligibility rule.
# =====================================================================================

C020_TEXT = (
    "AUTHORITY-LIFECYCLE.md, the Principal binding and Activation condition concepts, and "
    "OPEN-QUESTIONS.md \"Office vacancy and succession\", extended by CASES.md LC-C-020 to "
    "a position whose first holder is decided by an eligibility rule evaluated live, with "
    "no grant record naming anyone in advance, and which dissolves rather than reverting "
    "when its triggering condition ends."
)

C020_RULE = {
    "position_id": "pos:response-lead",
    "eligible_roles": ["role_advanced_practice", "role_physician"],
    "trigger_event_id": "evt:arrest-1",
}
C020_REGISTRY = {
    "resp-1": "role_physician",
    "resp-2": "role_advanced_practice",
    "porter-1": "role_porter",
}
TRIGGER_OPEN = {"event_id": "evt:arrest-1", "opened_at": OPENED, "closed_at": None}
TRIGGER_CLOSED = {"event_id": "evt:arrest-1", "opened_at": OPENED, "closed_at": "2026-09-20T11:00:00.000Z"}
TRIGGER_OTHER = {"event_id": "evt:other", "opened_at": OPENED, "closed_at": None}


def c020(suffix, polarity, desc, trigger, claims, handovers, at, verdict, code, holder,
         reverts_to, control_fails):
    add(
        "LC-C-020", suffix, "ad_hoc_position", polarity, C020_TEXT, desc,
        {
            "rule": C020_RULE, "trigger": trigger, "claims": claims,
            "handovers": handovers, "registry": C020_REGISTRY,
        },
        {"verdict": verdict, "code": code, "holder": holder, "reverts_to": reverts_to},
        unsupported(NO_AD_HOC_API, "ad_hoc_position"),
        unsupported(NO_AD_HOC_API, "ad_hoc_position"),
        control_fails, at=at,
    )


CLAIM_1 = {"actor": "resp-1", "at": "2026-09-20T10:05:00.000Z"}
CLAIM_2 = {"actor": "resp-2", "at": "2026-09-20T10:15:00.000Z"}
CLAIM_INELIGIBLE = {"actor": "porter-1", "at": "2026-09-20T10:02:00.000Z"}

c020("a", "positive",
     "The first eligible responder to claim the position during an open trigger leads. "
     "There is no grant record naming them and none is needed.",
     TRIGGER_OPEN, [CLAIM_1], [], "2026-09-20T10:30:00.000Z",
     "valid", "FIRST_ELIGIBLE_CLAIM", "resp-1", None, [])

c020("b", "negative",
     "A claim from an actor the registry does not place in any eligible role, with no "
     "eligible claim alongside it. Invalid, because the eligibility rule is a record the "
     "verifier can check and this actor fails it.",
     TRIGGER_OPEN, [CLAIM_INELIGIBLE], [], "2026-09-20T10:30:00.000Z",
     "invalid", "NOT_ELIGIBLE", None, None, [])

c020("c", "positive",
     "An ineligible claim arriving first and an eligible claim arriving second. The first "
     "eligible claimant holds the position; arriving earliest does not help an actor the "
     "rule excludes.",
     TRIGGER_OPEN, [CLAIM_INELIGIBLE, CLAIM_1], [], "2026-09-20T10:30:00.000Z",
     "valid", "FIRST_ELIGIBLE_CLAIM", "resp-1", None, [])

c020("d", "negative",
     "A second, more senior eligible actor is named in a handover the first holder has not "
     "had acknowledged. It is not established that the position moved, and the first "
     "holder still holds it.",
     TRIGGER_OPEN, [CLAIM_1, CLAIM_2],
     [{"from": "resp-1", "to": "resp-2", "accepted_at": None}], "2026-09-20T10:30:00.000Z",
     "not_established", "HANDOVER_NOT_ACCEPTED", "resp-1", None, [])

c020("e", "positive",
     "The same handover with an accept-and-acknowledge record. The position moves, through "
     "the same explicit step a planned handover uses.",
     TRIGGER_OPEN, [CLAIM_1, CLAIM_2],
     [{"from": "resp-1", "to": "resp-2", "accepted_at": "2026-09-20T10:20:00.000Z"}],
     "2026-09-20T10:30:00.000Z",
     "valid", "HANDOVER_ACCEPTED", "resp-2", None, [])

c020("f", "negative",
     "Negative control target. After the triggering condition closes, the position "
     "dissolves: there is no holder and it reverts to nobody. The "
     "pre-named-default-holder control hands it back to the first claimant.",
     TRIGGER_CLOSED, [CLAIM_1], [], AT,
     "invalid", "POSITION_DISSOLVED", None, None, ["pre-named-default-holder"])

c020("g", "negative",
     "No trigger record matching the rule's event. The position does not exist, so it is "
     "not established rather than invalid.",
     TRIGGER_OTHER, [CLAIM_1], [], "2026-09-20T10:30:00.000Z",
     "not_established", "POSITION_NOT_TRIGGERED", None, None, [])

c020("h", "negative",
     "Evaluated before the trigger opens. The position is not yet effective, which is a "
     "different answer from not established: the rule and the trigger are both on record.",
     TRIGGER_OPEN, [CLAIM_1], [], "2026-09-20T09:30:00.000Z",
     "not_yet_effective", "TRIGGER_NOT_OPEN", None, None, [])

c020("i", "negative",
     "An open trigger with no claim recorded yet. Nobody holds the position and that is "
     "not established rather than invalid.",
     TRIGGER_OPEN, [], [], "2026-09-20T10:30:00.000Z",
     "not_established", "NO_CLAIM", None, None, [])

# =====================================================================================
# LC-C-022. A revocation pending ratification.
# =====================================================================================

C022_TEXT = (
    "AUTHORITY-LIFECYCLE.md L8 (\"Suspension stops the use of authority and of everything "
    "that depends on it, and can be lifted. Revocation is terminal for the artifact it "
    "names.\") and OPEN-QUESTIONS.md \"Release from suspension\", extended by CASES.md "
    "LC-C-022 to an external, unilateral suspension by a superior that becomes a final "
    "revocation only on a separate approval, with the record saying the action was "
    "provisional throughout if that approval never comes."
)

C022_REGISTRY = {"class_members": {"class_general_officer": ["go-1"]}}
RELIEF = {
    "action_id": "act:relief-1",
    "by": "commander:immediate",
    "target_role": "DEPT_TO_DEPUTY",
    "at": "2026-09-20T10:00:00.000Z",
    "requires_ratification_by_class": "class_general_officer",
}
C022_RECEIPTS = [
    {"receipt_id": "rcpt-susp-1", "at": "2026-09-20T10:00:00.000Z", "verdict": "suspended",
     "code": "RATIFICATION_PENDING"},
]


def ratification(decision, by="go-1", at="2026-09-20T11:00:00.000Z") -> dict:
    return {"action_id": "act:relief-1", "decision": decision, "at": at, "by": by}


def c022(suffix, polarity, desc, rat, at, verdict, code, action_state, characterisation,
         reversed_claim, control_fails):
    add(
        "LC-C-022", suffix, "pending_ratification", polarity, C022_TEXT, desc,
        {
            "relief": RELIEF, "ratification": rat, "registry": C022_REGISTRY,
            "earlier_receipts": C022_RECEIPTS,
        },
        {
            "verdict": verdict, "code": code, "action_state": action_state,
            "action_characterisation": characterisation,
            "claims_revocation_reversed": reversed_claim,
            "earlier_receipts": C022_RECEIPTS,
        },
        unsupported(NO_RATIFICATION_API, "pending_ratification"),
        unsupported(NO_RATIFICATION_API, "pending_ratification"),
        control_fails, at=at,
    )


c022("a", "positive",
     "Negative control target. After the relief is initiated and before any ratification, "
     "the target is suspended and the relief is not yet effective as a revocation. That is "
     "neither revoked nor not revoked. The finalize-on-initiation control calls it invalid.",
     None, "2026-09-20T10:30:00.000Z",
     "suspended", "RATIFICATION_PENDING", "not_yet_effective", "provisional", False,
     ["finalize-on-initiation"])

c022("b", "positive",
     "Ratification granted by a member of the required class. The target is invalid from "
     "the ratification instant, and the earlier suspension receipt is unchanged.",
     ratification("granted"), AT,
     "invalid", "REVOKED_AFTER_RATIFICATION", "valid", "final_from_ratification", False, [])

c022("c", "positive",
     "Ratification denied. The target returns to valid, and the record characterises the "
     "action as provisional throughout rather than as a final revocation later reversed. "
     "The finalize-on-initiation control has to say a revocation was reversed.",
     ratification("denied"), AT,
     "valid", "RATIFICATION_DENIED", "invalid", "provisional_throughout", False,
     ["finalize-on-initiation"])

c022("d", "negative",
     "A ratification from an officer the registry does not place in the required class. It "
     "does not finalise anything, so the target stays suspended and the action stays "
     "provisional.",
     ratification("granted", by="maj-1"), AT,
     "suspended", "RATIFIER_STANDING_NOT_ESTABLISHED", "not_yet_effective", "provisional",
     False, ["finalize-on-initiation"])

c022("e", "positive",
     "Evaluated before the ratification instant, with a granted ratification already in "
     "the record set. The target is suspended at that instant: a later ratification does "
     "not backdate the revocation.",
     ratification("granted"), "2026-09-20T10:30:00.000Z",
     "suspended", "RATIFICATION_PENDING", "not_yet_effective", "provisional", False,
     ["finalize-on-initiation"])

c022("f", "positive",
     "Evaluated before the relief itself was recorded. The target is valid and the action "
     "is not yet effective, so the suspension does not reach back either.",
     ratification("granted"), "2026-09-20T09:30:00.000Z",
     "valid", "ACTION_NOT_YET_RECORDED", "not_yet_effective", "not_initiated", False, [])

# =====================================================================================
# LC-C-029. Per-contributor caveats on a shared coalition grant.
# =====================================================================================

C029_TEXT = (
    "AUTHORITY-LIFECYCLE.md, the monotonic narrowing principle and the Target binding and "
    "Action or capability binding concepts, extended by CASES.md LC-C-029 to a "
    "per-contributor restriction layered onto a shared coalition grant and checkable per "
    "source rather than pooled across contributors. Distinct from LC-C-012, which is "
    "same-level coordination rather than a narrower-scope delegation."
)

CONTRIBUTIONS = [
    {"contributor": "nation_x", "chain": "CONTRIB_X", "grants": ["force:move", "force:screen"]},
    {"contributor": "nation_y", "chain": "CONTRIB_Y", "grants": ["force:move", "force:screen"]},
]
CAVEATS = [
    {"contributor": "nation_x", "forbids": ["force:screen"], "targets": []},
    {"contributor": "nation_y", "forbids": [], "targets": []},
]

C029_RUNS = [
    chain_run("the first contributor's delegated subset verifies valid and its two grants "
              "are a strict narrowing of the contributor's own full authority",
              "CONTRIB_X", "valid"),
    chain_run("the second contributor's subset verifies valid with the same two grants, so "
              "the difference between the two contributions lives in the caveat records "
              "and not in the delegated scope", "CONTRIB_Y", "valid"),
]


def c029(suffix, polarity, desc, action, verdict, code, forbidden_by, control_fails):
    add(
        "LC-C-029", suffix, "per_contributor_caveat", polarity, C029_TEXT, desc,
        {"contributions": CONTRIBUTIONS, "caveats": CAVEATS, "action": action},
        {"verdict": verdict, "code": code, "forbidden_by": forbidden_by},
        unsupported(NO_CAVEAT_API, "per_contributor_caveat"),
        unsupported(NO_CAVEAT_API, "per_contributor_caveat"),
        control_fails, also_runs=C029_RUNS,
    )


c029("a", "positive",
     "An action inside the coalition subset that the acting contributor's own caveat does "
     "not forbid. Valid.",
     {"grant": "force:move", "target": "sector:1", "under_contributor": "nation_x"},
     "valid", "WITHIN_CONTRIBUTED_SUBSET", [], [])

c029("b", "negative",
     "Negative control target. The same kind of action, inside the same subset, forbidden "
     "by the acting contributor's own caveat. Invalid. The pooled-caveats control admits "
     "it because the other contributor does not forbid it.",
     {"grant": "force:screen", "target": "sector:1", "under_contributor": "nation_x"},
     "invalid", "CAVEAT_FORBIDS", ["nation_x"], ["pooled-caveats"])

c029("c", "positive",
     "The identical action under the other contributor, whose caveat does not forbid it. "
     "Valid, which is what makes the caveats per source rather than pooled.",
     {"grant": "force:screen", "target": "sector:1", "under_contributor": "nation_y"},
     "valid", "WITHIN_CONTRIBUTED_SUBSET", [], [])

c029("d", "negative",
     "An action naming a grant inside the contributor's full authority but outside the "
     "subset delegated to the coalition. Invalid on scope before any caveat is consulted.",
     {"grant": "force:strike", "target": "sector:1", "under_contributor": "nation_x"},
     "invalid", "SCOPE_NOT_COVERED", [], [])

c029("e", "negative",
     "An action that names no contributing source. It is not established which caveat set "
     "applies, so the action is not admitted and is not called invalid either.",
     {"grant": "force:move", "target": "sector:1", "under_contributor": None},
     "not_established", "CONTRIBUTOR_NOT_NAMED", [], [])

c029("f", "negative",
     "An action naming a contributor with no contribution on record. Not established.",
     {"grant": "force:move", "target": "sector:1", "under_contributor": "nation_z"},
     "not_established", "NO_SUCH_CONTRIBUTION", [], [])

# =====================================================================================
# LC-C-031. A standing, cause-free override above a concurrently exercised authority.
# =====================================================================================

C031_TEXT = (
    "AUTHORITY-LIFECYCLE.md L11 (\"Changing which authority an agent acts under should be "
    "a visible decision\") and the Delegated authority and Revocation concepts, extended "
    "by CASES.md LC-C-031 to a standing, always-live override that ends a delegate's "
    "operational role instantly, with no process, notice or cause, and without any "
    "revocation record. Distinct from ordinary revocable delegation and from the "
    "mandatory-concurrence cases."
)

STANDING = {"override_right_holder": "did:aps:example:mpc-master"}
OVERRIDE_AT = "2026-09-20T11:00:00.000Z"

C031_RUNS = [
    chain_run("the master-to-pilot delegation verifies valid on its own records with "
              "nothing revoked, at every instant this case evaluates, which is the gap: an "
              "override leaves no revocation record for the chain verifier to see",
              "PILOTAGE", "valid", note=CHAIN_NOTE_VALID),
]


def override(by="did:aps:example:mpc-master", at=OVERRIDE_AT, cause=None) -> dict:
    return {"by": by, "at": at, "cause": cause}


def c031(suffix, polarity, desc, override_rec, at, verdict, code, control_fails):
    add(
        "LC-C-031", suffix, "standing_override", polarity, C031_TEXT, desc,
        {
            "standing": STANDING, "override": override_rec, "chain": "PILOTAGE",
            "revocation_record_present": False,
        },
        {
            "verdict": verdict, "code": code, "cause_required": False,
            "no_revocation_record": True,
        },
        unsupported(NO_OVERRIDE_API, "standing_override"),
        unsupported(NO_OVERRIDE_API, "standing_override"),
        control_fails, also_runs=C031_RUNS, at=at,
    )


c031("a", "positive",
     "No override has been exercised. The delegate's authority is concurrently exercised "
     "and valid, while the override sits live above it.",
     None, "2026-09-20T10:30:00.000Z", "valid", "CONCURRENT_EXERCISE", [])

c031("b", "positive",
     "Before the override instant, with the override already in the record set. Still "
     "valid: the override takes effect when exercised, not when written.",
     override(), "2026-09-20T10:30:00.000Z", "valid", "OVERRIDE_NOT_YET_EXERCISED", [])

c031("c", "negative",
     "Negative control target. At and after the override instant the delegate's action is "
     "invalid, with no revocation record anywhere and no cause field set. The "
     "revocation-channel-only control leaves the delegate valid because the chain verifier "
     "still says valid.",
     override(), AT, "invalid", "STANDING_OVERRIDE_EXERCISED", ["revocation-channel-only"])

c031("d", "negative",
     "An override recorded by a party the standing record does not name as the override "
     "right holder. Not established, and the delegate stays valid.",
     override(by="did:aps:example:mpc-pilot"), AT,
     "valid", "OVERRIDE_STANDING_NOT_ESTABLISHED", [])

c031("e", "negative",
     "The same effective override carrying a cause string. The verdict is identical to the "
     "one with a null cause, which is how the fixture states that cause is not a "
     "precondition rather than merely omitting it.",
     override(cause="weather"), AT, "invalid", "STANDING_OVERRIDE_EXERCISED",
     ["revocation-channel-only"])

# =====================================================================================
# LC-H-001. A joint grant divisible by contributed share.
# =====================================================================================

H001_TEXT = (
    "AUTHORITY-LIFECYCLE.md L1 (\"If an authority artifact the grant currently depends on "
    "is revoked, the dependent authority is invalid\"), which assumes revoking an ancestor "
    "is a single binary event, extended by CASES.md LC-H-001 to an ancestor already "
    "fractional along contribution share, where one co-issuer's revocation reaches only "
    "their own share and amendment carries a different threshold from revocation."
)

JOINT_GRANT = {
    "grant_id": "grant:joint-1",
    "shares": [
        {
            "issuer": "did:aps:example:mpc-settlor-a", "share_id": "share_a",
            "chain": "SHARE_A", "grants": ["estate:a:manage"],
        },
        {
            "issuer": "did:aps:example:mpc-settlor-b", "share_id": "share_b",
            "chain": "SHARE_B", "grants": ["estate:b:manage"],
        },
    ],
    "amendment_policy": "joint_action",
}

H001_RUNS = [
    chain_run("the first co-issuer's contributed share verifies valid on its own records",
              "SHARE_A", "valid"),
    chain_run("the second co-issuer's share verifies valid, reaches the same trustee "
              "subject, and carries a disjoint scope prefix, so a revocation reaching one "
              "share is visible as a scope the trustee can no longer exercise",
              "SHARE_B", "valid"),
    chain_run("for contrast, the first share verified with its own record revoked is "
              "invalid with REVOKED at index 0, which is the per-share effect this case "
              "says a co-issuer's revocation should have", "SHARE_A", "invalid", "REVOKED", 0,
              revoked=["SHARE_A_GRANT"]),
]


def h001(suffix, polarity, desc, revocation, amendment, action, verdict, code, grant_state,
         per_share, reached, control_fails):
    add(
        "LC-H-001", suffix, "divisible_grant_revocation", polarity, H001_TEXT, desc,
        {"joint_grant": JOINT_GRANT, "revocation": revocation, "amendment": amendment,
         "action": action},
        {
            "verdict": verdict, "code": code, "grant_state": grant_state,
            "per_share": per_share, "reached_shares": reached,
        },
        unsupported(NO_DIVISIBLE_API, "divisible_grant"),
        unsupported(NO_DIVISIBLE_API, "divisible_grant"),
        control_fails, also_runs=H001_RUNS,
    )


BOTH_VALID = {"share_a": "valid", "share_b": "valid"}
A_GONE = {"share_a": "invalid", "share_b": "valid"}
BOTH_GONE = {"share_a": "invalid", "share_b": "invalid"}
REV_A = {"by": "did:aps:example:mpc-settlor-a", "scope": "own_share"}
REV_A_WHOLE = {"by": "did:aps:example:mpc-settlor-a", "scope": "whole_grant"}

h001("a", "positive",
     "No revocation. An action needing both shares' grants is valid and the joint grant is "
     "valid as a whole.",
     None, None, {"needs_grants": ["estate:a:manage", "estate:b:manage"]},
     "valid", "SHARE_COVERS_ACTION", "valid", BOTH_VALID, [], [])

h001("b", "negative",
     "Negative control target. The first co-issuer revokes their own share. An action "
     "needing both shares is invalid, the joint grant is restricted rather than invalid, "
     "and the revocation reached exactly one share. The indivisible-grant control reaches "
     "both.",
     REV_A, None, {"needs_grants": ["estate:a:manage", "estate:b:manage"]},
     "invalid", "SHARE_REVOKED", "restricted", A_GONE, ["share_a"], ["indivisible-grant"])

h001("c", "positive",
     "After the same revocation, an action needing only the surviving co-issuer's share is "
     "valid. The part attributable to a co-issuer who never acted is untouched. This is "
     "the vector the indivisible-grant control gets most visibly wrong.",
     REV_A, None, {"needs_grants": ["estate:b:manage"]},
     "valid", "SHARE_COVERS_ACTION", "restricted", A_GONE, ["share_a"], ["indivisible-grant"])

h001("d", "negative",
     "One co-issuer revokes naming the whole grant. It still reaches only their own share, "
     "so an action needing only the other share stays valid.",
     REV_A_WHOLE, None, {"needs_grants": ["estate:b:manage"]},
     "valid", "SHARE_COVERS_ACTION", "restricted", A_GONE, ["share_a"], ["indivisible-grant"])

h001("e", "negative",
     "An amendment signed by one co-issuer where the grant's policy requires joint action. "
     "Not established, so revocation and amendment carry different thresholds over the same "
     "object.",
     None, {"by": ["did:aps:example:mpc-settlor-a"]}, {"needs_grants": ["estate:a:manage"]},
     "not_established", "AMENDMENT_NOT_JOINT", "valid", BOTH_VALID, [], [])

h001("f", "positive",
     "The same amendment signed by both co-issuers. The joint-action threshold is met, so "
     "the action is decided on scope as usual.",
     None,
     {"by": ["did:aps:example:mpc-settlor-a", "did:aps:example:mpc-settlor-b"]},
     {"needs_grants": ["estate:a:manage"]},
     "valid", "SHARE_COVERS_ACTION", "valid", BOTH_VALID, [], [])

h001("g", "negative",
     "A revocation from a party who contributed no share. It reaches no share, so both "
     "shares stay valid and the joint grant is unchanged. The indivisible-grant control "
     "kills the whole grant on it.",
     {"by": "did:aps:example:mpc-trustee", "scope": "whole_grant"}, None,
     {"needs_grants": ["estate:a:manage", "estate:b:manage"]},
     "valid", "SHARE_COVERS_ACTION", "valid", BOTH_VALID, [], ["indivisible-grant"])

# =====================================================================================
# LC-H-002. A named asymmetric default between contradictory instructions.
# =====================================================================================

H002_TEXT = (
    "AUTHORITY-LIFECYCLE.md L5 and the Authorization decision concept, extended by CASES.md "
    "LC-H-002 to two equally valid single-principal instructions in direct conflict, "
    "resolved by a named asymmetric default rather than by unioning, by requiring "
    "concurrence, or by comparing timestamps."
)

ACCOUNT = {"required_signers": 2, "signer_set": ["signer_1", "signer_2"]}
ITEM = "item:draft-9"


def instr(kind, by, at, item=ITEM) -> dict:
    return {"kind": kind, "by": by, "at": at, "item": item}


EARLY = "2026-09-20T10:00:00.000Z"
LATE = "2026-09-20T11:00:00.000Z"


def h002(suffix, polarity, desc, instructions, verdict, code, controlling, control_fails):
    add(
        "LC-H-002", suffix, "instruction_precedence", polarity, H002_TEXT, desc,
        {"account": ACCOUNT, "instructions": instructions, "item": ITEM},
        {"verdict": verdict, "code": code, "controlling_instruction": controlling},
        unsupported(NO_PRECEDENCE_API, "instruction_precedence"),
        unsupported(NO_PRECEDENCE_API, "instruction_precedence"),
        control_fails,
    )


h002("a", "positive",
     "A pay instruction from one required signer and no stop. The item is payable.",
     [instr("pay", "signer_1", EARLY)], "valid", "PAY_AUTHORIZED", "pay", [])

h002("b", "negative",
     "A stop from one required signer and a contradictory pay from the co-signer recorded "
     "earlier. The stop controls.",
     [instr("pay", "signer_2", EARLY), instr("stop", "signer_1", LATE)],
     "invalid", "STOP_CONTROLS", "stop", [])

h002("c", "negative",
     "Negative control target. The same conflict with the pay recorded after the stop. The "
     "stop still controls, because the default does not depend on arrival order and needs "
     "no concurrence or notice from the co-signer. The last-write-wins control pays it.",
     [instr("stop", "signer_1", EARLY), instr("pay", "signer_2", LATE)],
     "invalid", "STOP_CONTROLS", "stop", ["last-write-wins"])

h002("d", "negative",
     "A stop from an actor the account does not list as a required signer, with a pay from "
     "one who is. The stop's standing is not established, so the record does not resolve "
     "the item either way.",
     [instr("pay", "signer_1", EARLY), instr("stop", "outsider_1", LATE)],
     "not_established", "INSTRUCTION_STANDING_NOT_ESTABLISHED", None, ["last-write-wins"])

h002("e", "negative",
     "A stop from a required signer that names no item. It is not established which item it "
     "reaches, so no item is decided from it.",
     [instr("pay", "signer_1", EARLY), instr("stop", "signer_2", LATE, item=None)],
     "not_established", "INSTRUCTION_ITEM_NOT_BOUND", None, [])

h002("f", "negative",
     "Two stops, one from each required signer. Still one answer and the same one: the "
     "default does not become stronger or weaker with a second stop.",
     [instr("stop", "signer_1", EARLY), instr("stop", "signer_2", LATE)],
     "invalid", "STOP_CONTROLS", "stop", [])

h002("g", "negative",
     "No instruction bound to this item at all. Not established.",
     [instr("pay", "signer_1", EARLY, item="item:other")],
     "not_established", "NO_INSTRUCTION", None, [])

# =====================================================================================
# LC-H-003. A sequencing rule plus a standing rescission window.
# =====================================================================================

H003_TEXT = (
    "AUTHORITY-LIFECYCLE.md L3 (\"Continuity after revocation means a new grant from a "
    "principal who currently holds authority. It never means reversing the revocation\") "
    "and L10, extended by CASES.md LC-H-003 to a targeted revival of one specific ended "
    "obligation gated by an ordering rule and a standing rescission window, rather than a "
    "fresh grant in the L3 sense."
)

TERMINATION = {"target": "obligation:1", "effective_at": "2026-09-20T11:00:00.000Z"}
WINDOW = 3600


def revival(made_at, filed_at) -> dict:
    return {"target": "obligation:1", "made_at": made_at, "filed_at": filed_at,
            "window_seconds": WINDOW}


# filed_at + 3600s = 2026-09-20T11:30:00Z, which is after the termination, so the window
# end is the filing plus the window rather than the termination instant.
IN_SEQUENCE = revival("2026-09-20T10:00:00.000Z", "2026-09-20T10:30:00.000Z")
# filed early enough that filed_at + 3600s falls before the termination, so the window end
# is the termination instant instead. This is the branch that makes the window "the later
# of the two" rather than just the filing plus the window.
IN_SEQUENCE_EARLY_FILING = revival("2026-09-20T09:00:00.000Z", "2026-09-20T09:30:00.000Z")
OUT_OF_SEQUENCE = revival("2026-09-20T11:30:00.000Z", "2026-09-20T11:40:00.000Z")

WINDOW_END = "2026-09-20T11:30:00.000Z"
WINDOW_END_EARLY = "2026-09-20T11:00:00.000Z"


def h003(suffix, polarity, desc, rev, rescission, at, verdict, code, window_end,
         rescission_status, control_fails):
    add(
        "LC-H-003", suffix, "sequenced_revival_window", polarity, H003_TEXT, desc,
        {"termination": TERMINATION, "revival": rev, "rescission": rescission},
        {
            "verdict": verdict, "code": code, "window_end": window_end,
            "rescission_status": rescission_status,
        },
        unsupported(NO_REVIVAL_API, "sequenced_revival"),
        unsupported(NO_REVIVAL_API, "sequenced_revival"),
        control_fails, at=at,
    )


h003("a", "positive",
     "A revival made before the termination took effect, evaluated after the rescission "
     "window closed and with no rescission on record. Effective.",
     IN_SEQUENCE, None, "2026-09-20T12:00:00.000Z",
     "valid", "REVIVAL_EFFECTIVE", WINDOW_END, None, [])

h003("b", "negative",
     "Negative control target. A revival made after the termination took effect, carrying "
     "the later timestamp of the two. Out of sequence and therefore ineffective, whatever "
     "its timestamp says. The sequence-ignored control admits it.",
     OUT_OF_SEQUENCE, None, "2026-09-20T13:00:00.000Z",
     "invalid", "REVIVAL_OUT_OF_SEQUENCE", "2026-09-20T12:40:00.000Z", None,
     ["sequence-ignored"])

h003("c", "negative",
     "An in-sequence revival evaluated inside the rescission window. Not yet effective, "
     "which is a different answer from invalid: it is still undoable.",
     IN_SEQUENCE, None, "2026-09-20T11:15:00.000Z",
     "not_yet_effective", "RESCISSION_WINDOW_OPEN", WINDOW_END, None, ["window-ignored"])

h003("d", "negative",
     "A rescission recorded inside the window. The revival is undone.",
     IN_SEQUENCE, {"at": "2026-09-20T11:20:00.000Z"}, AT,
     "invalid", "RESCINDED", WINDOW_END, "valid", [])

h003("e", "negative",
     "A rescission recorded after the window closed. It is not established that it reaches "
     "the revival, and the record does not say the rescission never happened.",
     IN_SEQUENCE, {"at": "2026-09-20T13:00:00.000Z"}, "2026-09-20T14:00:00.000Z",
     "valid", "RESCISSION_OUT_OF_WINDOW", WINDOW_END, "not_established", ["window-ignored"])

h003("f", "positive",
     "An in-sequence revival filed early enough that the filing plus the window falls "
     "before the termination. The window end is then the termination instant, so the window "
     "is the later of the two rather than the filing plus the window alone.",
     IN_SEQUENCE_EARLY_FILING, None, "2026-09-20T11:30:00.000Z",
     "valid", "REVIVAL_EFFECTIVE", WINDOW_END_EARLY, None, [])

h003("g", "negative",
     "No revival record at all. The obligation is simply ended.",
     None, None, AT, "invalid", "TERMINATED", None, None, [])

# =====================================================================================
# Negative controls. One dropped part of the proposed text each, so a divergence is
# attributable to the part it dropped rather than to a blend of defects.
# =====================================================================================

CONTROLS = {
    "signature-suffices": {
        "defect": (
            "Treats one properly signed affirmation from a principal the registry knows as "
            "satisfying any multi-party gate, whatever role it came from and however many "
            "named roles are silent. This is the failure LC-C-011 and LC-C-018 name, and it "
            "is the opposite of the scope-union failure L5 already forbids."
        ),
        "runs_against_concepts": ["concurrence_gate", "unanimous_role_set"],
    },
    "symmetric-threshold": {
        "defect": (
            "Uses one threshold, taken from the origination direction, in every direction. "
            "Stopping becomes as hard as starting, which is the failure LC-C-016 names: a "
            "framework built only on the symmetric pattern gets the veto direction "
            "backwards."
        ),
        "runs_against_concepts": ["asymmetric_threshold"],
    },
    "pooled-caveats": {
        "defect": (
            "Pools the contributors' caveats into one ruleset and forbids something only "
            "where every contributor forbids it, so the most permissive contributor's rules "
            "reach forces another contributor supplied. The failure LC-C-029 names."
        ),
        "runs_against_concepts": ["per_contributor_caveat"],
    },
    "objective-unions-scope": {
        "defect": (
            "Reads a signed joint objective as pooling the parties' scopes, so an action no "
            "single chain covers is admitted because a co-party's chain covers it. The "
            "failure LC-C-012 names, and the one L5 forbids outright."
        ),
        "runs_against_concepts": ["joint_objective_no_union"],
    },
    "last-write-wins": {
        "defect": (
            "Resolves contradictory instructions from co-signers by taking the latest "
            "counted one, and ignores an instruction from outside the signer set rather "
            "than leaving the item undecided. The failure LC-H-002 names."
        ),
        "runs_against_concepts": ["instruction_precedence"],
    },
    "sequence-ignored": {
        "defect": (
            "Drops the ordering rule, so a revival made after the terminating record took "
            "effect is admitted on the strength of its later timestamp. One half of the "
            "failure LC-H-003 names, isolated from the window half."
        ),
        "runs_against_concepts": ["sequenced_revival_window"],
    },
    "window-ignored": {
        "defect": (
            "Keeps the ordering rule and drops the standing rescission window, so an "
            "in-sequence revival is effective at once and a rescission recorded at any time "
            "reaches it. The other half of the failure LC-H-003 names."
        ),
        "runs_against_concepts": ["sequenced_revival_window"],
    },
    "retroactive-finding": {
        "defect": (
            "Lets a later finding relabel every earlier receipt, so the record no longer "
            "shows what a verifier could establish at the time it acted. The failure "
            "LC-C-006 names. This control diverges on every vector of its concept, "
            "including the one with no finding at all, because it applies the relabelling "
            "before it looks at whether a finding exists."
        ),
        "runs_against_concepts": ["void_from_issuance_finding"],
    },
    "revocation-channel-only": {
        "defect": (
            "Ends a delegate's authority only through a revocation record, so a standing "
            "override exercised by the party holding that right changes nothing. The "
            "failure LC-C-031 names."
        ),
        "runs_against_concepts": ["standing_override"],
    },
    "finalize-on-initiation": {
        "defect": (
            "Treats the initiating principal's action as final at once, so there is no "
            "state between initiation and ratification, a denial has to be expressed as a "
            "revocation being reversed, and the ratifier's standing is never an input. The "
            "failure LC-C-022 names."
        ),
        "runs_against_concepts": ["pending_ratification"],
    },
    "indivisible-grant": {
        "defect": (
            "Treats a joint grant as one indivisible object, so any co-issuer's revocation "
            "reaches every share including the part attributable to a co-issuer who never "
            "acted, and a revocation from a non-contributor reaches everything. The failure "
            "LC-H-001 names."
        ),
        "runs_against_concepts": ["divisible_grant_revocation"],
    },
    "default-continues": {
        "defect": (
            "Lets the default holder simply continue past the contest deadline, so silence "
            "resolves in favour of the party asserting the challenge. LC-C-002 says the "
            "reversion runs the other way, and this control gets it backwards."
        ),
        "runs_against_concepts": ["contested_seat"],
    },
    "first-presented-wins": {
        "defect": (
            "Verifies whichever succession source a relying party presented first and calls "
            "it the answer, with no standing priority rule between sources. The failure "
            "LC-C-005 names: the same vacant authority is then exercised by two different "
            "actors depending only on which document was checked."
        ),
        "runs_against_concepts": ["competing_succession_sources"],
    },
    "pre-named-default-holder": {
        "defect": (
            "Assumes every authority position has a standing holder, so when the triggering "
            "condition ends the position reverts to whoever claimed it rather than ceasing "
            "to exist. The failure LC-C-020 names."
        ),
        "runs_against_concepts": ["ad_hoc_position"],
    },
}


def main() -> None:
    for name, ctrl in CONTROLS.items():
        ctrl["name"] = name
        ctrl["expected_fail_ids"] = sorted(
            v["id"] for v in VECTORS if name in v["control_fails"]
        )
    concepts = sorted({v["concept"] for v in VECTORS})
    cases = sorted({v["case"] for v in VECTORS})
    doc = {
        "family": "lifecycle-multiple-principals-and-conflict",
        "profile": "aac-lifecycle-multiple-principals-and-conflict-v0",
        "label": "candidate_against_proposed",
        "proposed_text_source": PROPOSED,
        "verdict_vocabulary": [
            "valid", "invalid", "not_established", "not_yet_effective", "suspended",
            "restricted",
        ],
        "description": (
            "More than one principal with a claim on the same authority, and the ways those "
            "claims conflict: a gate needing two or more independent concurrences present "
            "together, a threshold that differs by direction, a live contest over one seat "
            "with a deadline and a reversion, two valid succession sources naming different "
            "holders, an ancestor void from issuance discovered late, independently rooted "
            "chains coordinating without pooling scope, a position created live by an "
            "eligibility rule, a revocation pending ratification, per-contributor caveats "
            "on a shared grant, a standing cause-free override, a grant divisible by "
            "co-issuer share, a named asymmetric default between contradictory "
            "instructions, and a revival gated by sequence and a rescission window. Every "
            "vector is candidate against proposed text in "
            "aeoess/agent-authority-lifecycle, never against a published specification."
        ),
        "generated_by": "fixtures/lifecycle-multiple-principals-and-conflict/generate.py",
        "seed": "see chain.json seed_prefix; no randomness is used in this file",
        "cases_covered": cases,
        "concepts": concepts,
        "controls": CONTROLS,
        "vectors": VECTORS,
    }
    (HERE / "vectors.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(VECTORS)} vectors across {len(cases)} cases and {len(concepts)} concepts")


if __name__ == "__main__":
    main()
