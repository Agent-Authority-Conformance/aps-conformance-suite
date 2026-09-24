#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Emit vectors.json for the lifecycle-outside-the-chain-standing family, byte for byte.

Every vector in this family is labelled candidate_against_proposed. It tests proposed
text in aeoess/agent-authority-lifecycle at commit 7796e22 or later, never a published
specification, and names the case id in CASES.md v0.2 that it comes from.

There is no randomness here. The file is a deterministic function of this script, so the
vector bytes are regenerable rather than only replayable:

    python3 fixtures/lifecycle-outside-the-chain-standing/generate.py

Then `git diff` on vectors.json should be empty.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

AT = "2026-09-20T12:00:00.000Z"
CHAIN_API_NPM = "verifyAuthorityDelegationChain (npm agent-passport-system 7.1.0)"
CHAIN_API_PY = "verify_authority_delegation_chain (PyPI agent-passport-system 4.1.0)"

# Reason strings reused wherever an SDK has no API for a layer. Written once so that a
# not_supported record always states the same reason for the same absent API.
NO_STANDING_API = (
    "no API in this SDK takes an issuing body's own composition as an input to the "
    "validity of what the body issued; the chain verifier's resolveRevocation answers "
    "only active, revoked or an unrecognized value per delegation"
)
NO_PY_CHARTER_API = (
    "the PyPI SDK at 4.1.0 exposes no charter, office, quorum or approval-threshold "
    "module; dir(agent_passport) has no name matching quorum, charter, office or "
    "threshold, and no submodule under agent_passport/ mentions quorum"
)
NO_HOLD_API = (
    "neither SDK has a verdict for authority held pending a neutral forum; the chain "
    "verifier's state vocabulary is valid, invalid and indeterminate only"
)
NO_ORDER_API = (
    "no API represents a grant issued by a body outside the original chain under a "
    "conditional order, nor a predicate that has to hold before the order issues"
)


def chain_probe(chain: str, state: str, code, index, note: str | None = None) -> dict:
    probe = {
        "supported": True,
        "layer": "chain_state",
        "chain": chain,
        "expected": {"state": state, "failure_code": code, "failure_index": index},
    }
    if note is not None:
        probe["note"] = note
    return probe


def unsupported(reason: str, layer: str) -> dict:
    return {"supported": False, "layer": layer, "reason": reason}


def quorum_probe(holders: int, required: int, has_quorum: bool, note: str) -> dict:
    return {
        "supported": True,
        "layer": "office_holder_count",
        "api": "checkQuorum (npm agent-passport-system 7.1.0)",
        "expected": {"hasQuorum": has_quorum, "holders": holders, "required": required},
        "note": note,
    }


PROPOSED = {
    "repo": "aeoess/agent-authority-lifecycle",
    "commit_floor": "7796e22",
    "cases_version": "CASES.md v0.2 (local branch cases-v0.2, commit 2bf5c7e)",
    "section": "Outside-the-chain standing",
}

# ---------------------------------------------------------------------------
# LC-H-004. An issuing body's own composition as a precondition for what it issues.
# ---------------------------------------------------------------------------

SEATED = ["dir-1", "dir-2", "dir-3", "dir-4", "dir-5", "dir-6", "dir-7"]


def body(total_seats: int, bylaw, participants: list[str], seated: list[str] | None = None) -> dict:
    return {
        "body_id": "body:board",
        "total_seats": total_seats,
        "bylaw_quorum": bylaw,
        "seated_directors": seated if seated is not None else SEATED[:total_seats],
        "participants": participants,
    }


def suspension(signed_by: list[str]) -> dict:
    return {
        "suspension_id": "susp:1",
        "target_role": "BODY_TO_OFFICER",
        "by_body": "body:board",
        "at": "2026-09-20T11:00:00.000Z",
        "signed_by": signed_by,
    }


H004_PROPOSED_TEXT = (
    "AUTHORITY-LIFECYCLE.md, Lifecycle concepts are separate: Issuer standing (\"A valid "
    "signature establishes who signed. It does not by itself establish standing.\") and "
    "Lifecycle standing (\"Who may suspend, revoke, replace or reaffirm an authority "
    "artifact.\"), extended by CASES.md LC-H-004 to a collective body's own internal "
    "standing requirement. Also AUTHORITY-LIFECYCLE.md L8, Suspension is not revocation."
)


def h004(suffix, polarity, desc, b, s, verdict, code, target_verdict, body_action,
         npm_quorum, control_fails):
    return {
        "id": f"LC-H-004-{suffix}",
        "case": "LC-H-004",
        "concept": "issuing_body_quorum",
        "label": "candidate_against_proposed",
        "polarity": polarity,
        "proposed_text": H004_PROPOSED_TEXT,
        "description": desc,
        "at": AT,
        "records": {"body": b, "suspension": s, "target_chain": "OFFICER"},
        "expected": {
            "verdict": verdict,
            "code": code,
            "target_chain_verdict": target_verdict,
            "body_action_exists": body_action,
        },
        "sdk": {
            "npm": npm_quorum,
            "pypi": unsupported(NO_PY_CHARTER_API, "office_holder_count"),
        },
        "also_runs": [
            {
                "layer": "chain_state",
                "claim": "the targeted chain verifies valid on its own records, so the "
                         "suspension question is not a chain-verification question",
                "npm": chain_probe("OFFICER", "valid", None, None),
                "pypi": chain_probe("OFFICER", "valid", None, None),
            }
        ],
        "control_fails": control_fails,
    }


H004 = [
    h004(
        "a", "positive",
        "Seven seats, no bylaw number, four seated directors participating, all four "
        "signing. Quorum is the majority default of four, so there is a body action and "
        "the targeted delegation is suspended.",
        body(7, None, SEATED[:4]), suspension(SEATED[:4]),
        "suspended", "SUSPENDED_BY_BODY", "suspended", True,
        quorum_probe(
            4, 4, True,
            "checkQuorum is run with an Office whose holderSet is the four participating "
            "seated directors and a QuorumFailurePolicy whose minimumHolders is the "
            "effective quorum this fixture computed. It counts holders against a supplied "
            "minimum; it does not itself derive a majority-of-total-seats default, and it "
            "does not take a suspension record as an input.",
        ),
        [],
    ),
    h004(
        "b", "negative",
        "Seven seats, no bylaw number, three seated directors participating. Three is "
        "below the majority default of four, so there is no valid body action to "
        "evaluate. The verdict is not established, not invalid, and the targeted "
        "delegation stays valid.",
        body(7, None, SEATED[:3]), suspension(SEATED[:3]),
        "not_established", "ISSUING_BODY_QUORUM_NOT_ESTABLISHED", "valid", False,
        quorum_probe(
            3, 4, False,
            "the false answer here comes from a minimumHolders this fixture supplied, not "
            "from any majority-of-total-seats rule inside the SDK.",
        ),
        ["well-formed-record-suffices"],
    ),
    h004(
        "c", "negative",
        "Seven seats, bylaws requiring five, four participating. The greater number the "
        "bylaws require governs, so four is not quorum and there is no body action.",
        body(7, 5, SEATED[:4]), suspension(SEATED[:4]),
        "not_established", "ISSUING_BODY_QUORUM_NOT_ESTABLISHED", "valid", False,
        quorum_probe(4, 5, False, "minimumHolders supplied as the bylaw number five."),
        ["well-formed-record-suffices"],
    ),
    h004(
        "d", "positive",
        "Seven seats, bylaws requiring five, five participating and signing. The bylaw "
        "number is met, so the targeted delegation is suspended.",
        body(7, 5, SEATED[:5]), suspension(SEATED[:5]),
        "suspended", "SUSPENDED_BY_BODY", "suspended", True,
        quorum_probe(5, 5, True, "minimumHolders supplied as the bylaw number five."),
        [],
    ),
    h004(
        "e", "negative",
        "Seven seats, no bylaw number, four participants of whom one is not a seated "
        "director. Only seated directors count, so three count and quorum is not "
        "established.",
        body(7, None, SEATED[:3] + ["observer-1"]), suspension(SEATED[:3] + ["observer-1"]),
        "not_established", "ISSUING_BODY_QUORUM_NOT_ESTABLISHED", "valid", False,
        quorum_probe(
            3, 4, False,
            "the fixture filters participants against seated_directors before building "
            "holderSet; checkQuorum has no notion of a participant who is not a holder.",
        ),
        ["well-formed-record-suffices"],
    ),
    h004(
        "f", "negative",
        "Quorum is met, but the suspension record is signed only by someone who was not "
        "a counted participant. A body action needs a signature from the body that met "
        "quorum, so the record does not establish one.",
        body(7, None, SEATED[:4]), suspension(["observer-1"]),
        "not_established", "BODY_ACTION_NOT_SIGNED_BY_PARTICIPANT", "valid", False,
        quorum_probe(
            4, 4, True,
            "checkQuorum answers true here, which is the point: holder count alone does "
            "not establish that the record in hand is that body's action.",
        ),
        # No control diverges here. Both controls keep the signature-and-roster check,
        # which is the check this vector defeats, so a naive boundary that only verifies
        # the record gets this one right for the wrong reason and the fixture says so
        # rather than claiming a divergence it does not observe.
        [],
    ),
    h004(
        "g", "negative",
        "Seven seats, bylaws naming three, three participating. A declared number lower "
        "than the majority default does not lower it, so quorum is not established.",
        body(7, 3, SEATED[:3]), suspension(SEATED[:3]),
        "not_established", "ISSUING_BODY_QUORUM_NOT_ESTABLISHED", "valid", False,
        quorum_probe(
            3, 4, False,
            "minimumHolders supplied as the effective quorum four, not as the declared "
            "three; checkQuorum would answer true if handed the declared three, which is "
            "why the floor is applied by this fixture and not by the SDK.",
        ),
        ["well-formed-record-suffices", "bylaw-number-wins"],
    ),
    h004(
        "h", "negative",
        "Negative control target. Seven seats, no bylaw number, one seated director "
        "participating and signing. A single director produces a properly formed, "
        "properly signed suspension record and nothing else.",
        body(7, None, SEATED[:1]), suspension(SEATED[:1]),
        "not_established", "ISSUING_BODY_QUORUM_NOT_ESTABLISHED", "valid", False,
        quorum_probe(
            1, 4, False,
            "with no policy argument at all checkQuorum answers hasQuorum true and "
            "required 1 for this same office, recorded under What the SDKs do not support.",
        ),
        ["well-formed-record-suffices"],
    ),
]

# ---------------------------------------------------------------------------
# LC-H-005. A grant issued by a body outside the original relationship.
# ---------------------------------------------------------------------------

H005_PROPOSED_TEXT = (
    "AUTHORITY-LIFECYCLE.md L3 (\"Continuity after revocation means a new grant from a "
    "principal who currently holds authority. It never means reversing the revocation or "
    "re-parenting the old chain.\") and L4, extended by CASES.md LC-H-005 to a fresh grant "
    "issued by a body with standing from outside the original principal-agent "
    "relationship. Also the Issuer standing and Lifecycle standing concepts."
)

REGISTRY_H005 = {"bodies_with_standing": ["body:labor-board"]}


def order(by_body="body:labor-board", standing_ref="reg:labor-board:2026-09-20",
          for_cause=False):
    return {
        "order_id": "order:1",
        "by_body": by_body,
        "standing_ref": standing_ref,
        "at": "2026-09-20T11:00:00.000Z",
        "terms": {"chain": "REINSTATED", "extra_grants": ["backpay:read"]},
        "predicate": {"discharged_for_cause": for_cause},
    }


def h005(suffix, polarity, desc, order_rec, new_chain, verdict, code, extra_expected,
         control_fails):
    expected = {
        "verdict": verdict,
        "code": code,
        "old_chain_verdict": "invalid",
        "old_chain_failure_code": "REVOKED",
        "old_chain_verdict_unchanged_by_order": True,
    }
    expected.update(extra_expected)
    return {
        "id": f"LC-H-005-{suffix}",
        "case": "LC-H-005",
        "concept": "external_reinstatement_grant",
        "label": "candidate_against_proposed",
        "polarity": polarity,
        "proposed_text": H005_PROPOSED_TEXT,
        "description": desc,
        "at": AT,
        "records": {
            "old_chain": "TERMINATED",
            "revoked_roles": ["EMPLOYER_ROOT"],
            "order": order_rec,
            "new_chain": new_chain,
            "registry": REGISTRY_H005,
        },
        "expected": expected,
        "sdk": {
            "npm": unsupported(NO_ORDER_API, "external_order"),
            "pypi": unsupported(NO_ORDER_API, "external_order"),
        },
        "also_runs": [
            {
                "layer": "chain_state",
                "claim": "the terminated chain stays invalid with REVOKED at index 0 "
                         "whatever the order says, and the order is not an input the "
                         "chain verifier takes",
                "npm": chain_probe("TERMINATED", "invalid", "REVOKED", 0),
                "pypi": chain_probe("TERMINATED", "invalid", "REVOKED", 0),
            }
        ] + (
            [
                {
                    "layer": "chain_state",
                    "claim": "the replacement chain verifies valid on its own records, "
                             "rooted in a different issuer, and carries backpay:read "
                             "which no record of the terminated chain carries",
                    "npm": chain_probe("REINSTATED", "valid", None, None),
                    "pypi": chain_probe("REINSTATED", "valid", None, None),
                }
            ]
            if new_chain is not None
            else []
        ),
        "control_fails": control_fails,
    }


H005 = [
    h005(
        "a", "positive",
        "An order from a body the registry places standing with, its predicate not met "
        "for the exception, and a replacement chain rooted in that body's designee. The "
        "replacement is valid, the terminated chain stays invalid, and the replacement "
        "carries a grant the original relationship never had.",
        order(), "REINSTATED", "valid", "NEW_GRANT_FROM_EXTERNAL_ISSUER",
        {
            "new_chain_verdict": "valid",
            "new_chain_root_issuer_differs": True,
            "new_chain_carries_grant_absent_from_old": ["backpay:read"],
        },
        ["revival-restores"],
    ),
    h005(
        "b", "negative",
        "The same order with its record stating the discharge was for cause. The order "
        "does not issue, so replacement authority is not established. That is not the "
        "same as saying the order is invalid.",
        order(for_cause=True), None, "not_established", "ORDER_PREDICATE_NOT_MET",
        {"new_chain_verdict": None},
        [],
    ),
    h005(
        "c", "negative",
        "An order from a body the registry does not place standing with. Replacement "
        "authority is not established, and the record does not claim the body acted "
        "without authority, only that standing was not shown.",
        order(by_body="body:unregistered"), "REINSTATED",
        "not_established", "ORDER_STANDING_NOT_ESTABLISHED",
        {"new_chain_verdict": "not_established"},
        [],
    ),
    h005(
        "d", "negative",
        "An order with standing and its predicate met, but no replacement chain has been "
        "issued yet. An order is not itself a grant, so replacement authority is not "
        "established and the terminated chain stays invalid.",
        order(), None, "not_established", "NO_REPLACEMENT_GRANT",
        {"new_chain_verdict": None},
        [],
    ),
    h005(
        "e", "negative",
        "An order that carries standing but no standing_ref a verifier could follow. "
        "Standing is not established from the order naming itself.",
        order(standing_ref=None), "REINSTATED",
        "not_established", "ORDER_STANDING_NOT_ESTABLISHED",
        {"new_chain_verdict": "not_established"},
        [],
    ),
    h005(
        "f", "negative",
        "Negative control target. No order at all, only the terminated chain. Nothing "
        "establishes replacement authority, and the naive boundary that treats any "
        "later record about the same subject as a revival has nothing to revive.",
        None, None, "not_established", "NO_REPLACEMENT_GRANT",
        {"new_chain_verdict": None},
        [],
    ),
]

# ---------------------------------------------------------------------------
# LC-H-006. A disputed root held by a neutral forum.
# ---------------------------------------------------------------------------

H006_PROPOSED_TEXT = (
    "AUTHORITY-LIFECYCLE.md L7 (\"A revocation answer that is unavailable or stale is "
    "indeterminate. It does not become active\") and the Status observation concept, "
    "extended by CASES.md LC-H-006 to an acknowledged dispute over which of two claimed "
    "roots is authoritative. Also OPEN-QUESTIONS.md, Notice and relying parties."
)

CLAIMS = [
    {"claimant": "claimant:p", "chain": "CLAIM_P"},
    {"claimant": "claimant:q", "chain": "CLAIM_Q"},
]


def deposit(secured_by="deposit", forum="forum:court-1"):
    return {
        "deposit_id": "dep:1",
        "subject": "did:aps:example:ocs-agent-d",
        "forum_id": forum,
        "deposited_at": "2026-09-20T10:00:00.000Z",
        "claimants": ["claimant:p", "claimant:q"],
        "secured_by": secured_by,
    }


def determination(chosen, forum="forum:court-1", at="2026-09-20T11:30:00.000Z"):
    return {"forum_id": forum, "chosen_claimant": chosen, "at": at}


def h006(suffix, polarity, desc, dep, det, verdict, code, p_verdict, q_verdict,
         holder_must_choose, control_fails, sdk_note=None):
    also = [
        {
            "layer": "chain_state",
            "claim": "each claimed chain verifies valid on its own records in both SDKs, "
                     "which is the gap this case is about: neither SDK has a state for a "
                     "root held pending a forum",
            "npm": chain_probe("CLAIM_P", "valid", None, None, sdk_note),
            "pypi": chain_probe("CLAIM_P", "valid", None, None, sdk_note),
        },
        {
            "layer": "chain_state",
            "claim": "and the same for the rival claimed chain",
            "npm": chain_probe("CLAIM_Q", "valid", None, None, sdk_note),
            "pypi": chain_probe("CLAIM_Q", "valid", None, None, sdk_note),
        },
    ]
    return {
        "id": f"LC-H-006-{suffix}",
        "case": "LC-H-006",
        "concept": "disputed_root_held",
        "label": "candidate_against_proposed",
        "polarity": polarity,
        "proposed_text": H006_PROPOSED_TEXT,
        "description": desc,
        "at": AT,
        "records": {"claims": CLAIMS, "deposit": dep, "determination": det},
        "expected": {
            "verdict": verdict,
            "code": code,
            "per_chain": {"CLAIM_P": p_verdict, "CLAIM_Q": q_verdict},
            "holder_must_choose": holder_must_choose,
        },
        "sdk": {
            "npm": unsupported(NO_HOLD_API, "held_pending_forum"),
            "pypi": unsupported(NO_HOLD_API, "held_pending_forum"),
        },
        "also_runs": also,
        "control_fails": control_fails,
    }


H006 = [
    h006(
        "a", "negative",
        "A secured deposit with the named forum and no determination yet. It is not "
        "established which claimant governs. Neither chain is valid and neither is "
        "invalid, and the holder is discharged from choosing.",
        deposit(), None, "not_established", "HELD_PENDING_FORUM",
        "not_established", "not_established", False,
        ["forced-binary"],
        "both SDKs answer valid at this instant; the hold is not a state either one has",
    ),
    h006(
        "b", "positive",
        "A determination from the forum named in the deposit choosing the first "
        "claimant. That claimant's chain is valid and the rival's is invalid for the "
        "same subject.",
        deposit(), determination("claimant:p"), "valid", "FORUM_DETERMINED",
        "valid", "invalid", False,
        [],
    ),
    h006(
        "c", "negative",
        "A determination from a forum other than the one the deposit names. It does not "
        "resolve the hold, so the question stays not established and the hold continues.",
        deposit(), determination("claimant:p", forum="forum:other"),
        "not_established", "DETERMINATION_FORUM_MISMATCH",
        "not_established", "not_established", False,
        ["forced-binary"],
    ),
    h006(
        "d", "negative",
        "A deposit record that names a forum but records neither a deposit nor a bond. "
        "The hold is not established, and the holder is not discharged from choosing.",
        deposit(secured_by=None), None, "not_established", "HOLD_NOT_SECURED",
        "not_established", "not_established", True,
        ["forced-binary"],
    ),
    h006(
        "e", "negative",
        "Two rival claimed roots and no deposit record at all. The dispute is "
        "unresolved with no mechanism holding it open, so the holder still faces the "
        "choice the deposit would have discharged.",
        None, None, "not_established", "DISPUTE_UNRESOLVED_NO_FORUM",
        "not_established", "not_established", True,
        ["forced-binary"],
    ),
    h006(
        "f", "negative",
        "A determination from the named forum naming a claimant the deposit does not "
        "list as a party. It does not resolve the hold.",
        deposit(), determination("claimant:r"),
        "not_established", "DETERMINATION_CLAIMANT_NOT_A_PARTY",
        "not_established", "not_established", False,
        ["forced-binary"],
    ),
    h006(
        "g", "positive",
        "The bond alternative is equally effective as a secured hold. With a bond and a "
        "determination choosing the second claimant, that chain is valid and the first "
        "is invalid.",
        deposit(secured_by="bond"), determination("claimant:q"),
        "valid", "FORUM_DETERMINED", "invalid", "valid", False,
        [],
    ),
    h006(
        "h", "negative",
        "A determination dated before the deposit was made. It cannot be the forum's "
        "answer to a question that was not yet before it, so the hold continues.",
        deposit(), determination("claimant:p", at="2026-09-20T09:30:00.000Z"),
        "not_established", "DETERMINATION_PRECEDES_DEPOSIT",
        "not_established", "not_established", False,
        ["forced-binary"],
    ),
]

CONTROLS = {
    "well-formed-record-suffices": {
        "name": "well-formed-record-suffices",
        "defect": (
            "Verifies that the suspension record is well formed and signed by somebody "
            "the body's roster lists, and never asks whether the body that purported to "
            "act had quorum to transact business. This is the defect LC-H-004 names: it "
            "lets a rump minority suspend a principal's authority with no real body "
            "action behind it."
        ),
        "runs_against_concepts": ["issuing_body_quorum"],
    },
    "bylaw-number-wins": {
        "name": "bylaw-number-wins",
        "defect": (
            "Takes whatever number the bylaws declare as the quorum, in either "
            "direction, so a declared number below the majority default silently lowers "
            "the floor. Isolated from well-formed-record-suffices because the defect is "
            "arithmetic on the threshold rather than a missing standing check."
        ),
        "runs_against_concepts": ["issuing_body_quorum"],
    },
    "revival-restores": {
        "name": "revival-restores",
        "defect": (
            "Treats an order from an external body as switching the terminated chain "
            "back to valid, rather than as a distinct new grant from a different issuer. "
            "This is the defect LC-H-005 names: the replacement's terms come from the "
            "reinstating body, and a revival model loses that."
        ),
        "runs_against_concepts": ["external_reinstatement_grant"],
    },
    "forced-binary": {
        "name": "forced-binary",
        "defect": (
            "Forces a binary answer when no forum determination exists, by honouring "
            "whichever claimed root was issued first. This is the defect LC-H-006 names: "
            "the correct state is a third one, held pending resolution, with the holder "
            "relieved of the decision."
        ),
        "runs_against_concepts": ["disputed_root_held"],
    },
}


def main() -> None:
    vectors = H004 + H005 + H006
    for control in CONTROLS.values():
        control["expected_fail_ids"] = sorted(
            v["id"] for v in vectors if control["name"] in v["control_fails"]
        )
    doc = {
        "family": "lifecycle-outside-the-chain-standing",
        "profile": "aac-lifecycle-outside-the-chain-standing-v0",
        "label": "candidate_against_proposed",
        "proposed_text_source": PROPOSED,
        "verdict_vocabulary": [
            "valid", "invalid", "not_established", "not_yet_effective", "suspended",
            "restricted",
        ],
        "description": (
            "Standing held from outside the chain a grant runs through. A collective "
            "body's own composition as a precondition for the validity of what it "
            "issued, a replacement grant issued by a body outside the original "
            "principal-agent relationship, and a disputed root held by a neutral forum "
            "with no claimant yet established. Every vector is candidate against "
            "proposed text in aeoess/agent-authority-lifecycle, never against a "
            "published specification."
        ),
        "generated_by": "fixtures/lifecycle-outside-the-chain-standing/generate.py",
        "seed": "see chain.json seed_prefix; no randomness is used in this file",
        "controls": CONTROLS,
        "vectors": vectors,
    }
    (HERE / "vectors.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(vectors)} vectors")


if __name__ == "__main__":
    main()
