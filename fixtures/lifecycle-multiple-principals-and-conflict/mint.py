#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Mint chain.json for the lifecycle-multiple-principals-and-conflict family, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file carries no
secret material and anyone can regenerate it. This follows the minting, key-resolution
and role-keyed resolver pattern of fixtures/sponsor-handover/mint.py and
fixtures/ancestor-revocation-chain/mint.py.

Ten AuthorityDelegationV1 chains. Nine cases in the "Multiple principals and conflict"
section of CASES.md v0.2 rest on real signed records; the other six in that section are
decided entirely from non-delegation records and need no chain here.

  TAINTED    dept -> deputy -> agent_t    LC-C-006, three hops, middle later found void
  SEAT_P     source_1 -> holder_p         LC-C-005, one claimed succession source
  SEAT_Q     source_2 -> holder_q         LC-C-005, the rival source, same seat
  UNIT_A     agency_a -> a_ops -> joint   LC-C-012, one independently rooted chain
  UNIT_B     agency_b -> b_ops -> joint   LC-C-012, the other, same leaf subject
  CONTRIB_X  nation_x -> coalition        LC-C-029, one contributor's narrowed subset
  CONTRIB_Y  nation_y -> coalition        LC-C-029, the other contributor's subset
  SHARE_A    settlor_a -> trustee         LC-H-001, one co-settlor's contributed share
  SHARE_B    settlor_b -> trustee         LC-H-001, the other share, same trustee
  PILOTAGE   master -> pilot              LC-C-031, the concurrently exercised grant

Three facts are readable off the bytes rather than asserted in prose. UNIT_A and UNIT_B
share the leaf subject `joint` and share no delegation_id and no parent, so they are
independently rooted chains held by one agent. CONTRIB_X and CONTRIB_Y each narrow a
`force:*` root to the same two-grant coalition subset, so the caveat difference between
them lives in separate caveat records and not in the delegated scope. SHARE_A and
SHARE_B carry disjoint scope prefixes into the same trustee, so a revocation reaching one
share is visible as a scope the trustee can no longer exercise.

This file also mints the approval-gate material the six record-only cases need: one
Ed25519 public key per named actor, and one real signature per (actor, gate subject) pair
over the exact bytes `approvalSignContent` produces, which is `<request_id>:<subject>`.
The runners verify those signatures with the SDK rather than trusting a boolean in the
vector, so "this confirmation's signature does not verify" is a fact about bytes. One
deliberately tampered signature is minted for that vector by flipping the final hex digit
of a real one.

Both SDKs produce byte-identical Ed25519 signatures over the same content, which the
runners recompute, so the gate material is not a TypeScript-only or Python-only artifact.

Delegation nonces are supplied, not generated, which the Python SDK documents as the path
that keeps issuance deterministic.

Run from the suite root with a Python interpreter that has PyPI
agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-multiple-principals-and-conflict/mint.py

Then `git diff` on chain.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation, sign
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent
NOW = "2026-09-20T12:00:00.000Z"
NOT_AFTER = "2026-09-30T00:00:00.000Z"

SEED_PREFIX = "aps-conformance-suite:lifecycle-multiple-principals-and-conflict:"

# label -> DID. One label per signing party, used for both the seed and the DID so the
# two can never drift apart.
PARTIES = [
    "dept", "deputy", "agent-t",
    "source-1", "holder-p", "source-2", "holder-q",
    "agency-a", "a-ops", "agency-b", "b-ops", "joint",
    "nation-x", "nation-y", "coalition",
    "settlor-a", "settlor-b", "trustee",
    "master", "pilot",
]
DID = {label: f"did:aps:example:mpc-{label}" for label in PARTIES}


def _seed(label: str) -> str:
    return hashlib.sha256((SEED_PREFIX + label).encode()).hexdigest()


PRIV = {label: _seed(f"{label}:v1") for label in PARTIES}
KEYS = {DID[label] + "#key-1": public_key_from_private(PRIV[label]) for label in PARTIES}

RESOLVE_KEY = lambda _issuer, method, _issued_at: KEYS.get(method)
ALWAYS_ACTIVE = lambda _delegation: "active"

# Named actors for the gate, contest and ratification records. These never issue a
# delegation; they sign approval content, so they need a key but no DID.
GATE_SUBJECTS = {
    # LC-C-011, a two-role concurrence gate plus a second actor in the first role and a
    # more senior principal whose chain is longer.
    "concurrence-1": ["alpha-1", "alpha-2", "beta-1", "senior-1"],
    # LC-C-018, an enumerated role set of four plus a single lead authorizer.
    "unanimous-1": ["ident-1", "site-1", "proc-1", "equip-1", "lead-1"],
    # LC-C-016, the same two principals across four directions of one action.
    "originate-1": ["pic-1", "disp-1"],
    "continue-1": ["pic-1", "disp-1"],
    "cancel-1": ["pic-1", "disp-1"],
    "restrict-1": ["pic-1", "disp-1"],
    # LC-C-002, two classes of three eligible voters each.
    "contest-1": ["ca-1", "ca-2", "ca-3", "cb-1", "cb-2", "cb-3"],
    # LC-C-022, one member of the ratifying class and one non-member.
    "ratify-1": ["go-1", "maj-1"],
}
GATE_ACTORS = sorted({actor for actors in GATE_SUBJECTS.values() for actor in actors})
GATE_PRIV = {actor: _seed(f"gate:{actor}:v1") for actor in GATE_ACTORS}


def approval_content(subject_key: str) -> str:
    """The exact bytes approvalSignContent produces for this fixture's requests.

    The npm SDK's approvalSignContent({requestId, subject}) returns
    `${requestId}:${subject}`. Both are fixed strings derived from the subject key here,
    so nothing about the signed bytes depends on a clock or a generated identifier.
    """
    return f"approval_{subject_key}:action:{subject_key}"


def mint_approvals() -> dict:
    actors = {actor: public_key_from_private(GATE_PRIV[actor]) for actor in GATE_ACTORS}
    subjects = {
        key: {"request_id": f"approval_{key}", "subject": f"action:{key}", "content": approval_content(key)}
        for key in sorted(GATE_SUBJECTS)
    }
    signatures = {}
    for subject_key in sorted(GATE_SUBJECTS):
        content = approval_content(subject_key)
        for actor in sorted(GATE_SUBJECTS[subject_key]):
            signatures[f"{subject_key}:{actor}"] = {
                "actor": actor,
                "subject_key": subject_key,
                "signature": sign(content, GATE_PRIV[actor]),
            }
    # One tampered signature, for the vector where a confirmation carries a signature that
    # does not verify under the key its actor is registered with. The final hex digit is
    # advanced by one, so the record is well formed and the signature is not the signer's.
    real = signatures["unanimous-1:equip-1"]["signature"]
    tampered = real[:-1] + format((int(real[-1], 16) + 1) % 16, "x")
    signatures["unanimous-1:equip-1:tampered"] = {
        "actor": "equip-1",
        "subject_key": "unanimous-1",
        "signature": tampered,
    }
    return {"actors": actors, "subjects": subjects, "signatures": signatures}



def _authority(depth: int, grants: list[str], at: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": grants},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": depth},
        "time": {"not_before": at, "not_after": NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def root(issuer: str, subject: str, grants: list[str], at: str, depth: int) -> dict:
    return issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": DID[issuer],
            "subject": DID[subject],
            "verification_method": DID[issuer] + "#key-1",
            "issued_at": at,
            "nonce": _seed(f"{issuer}->{subject}-nonce:v1")[:32],
            "authority": _authority(depth, grants, at),
        },
        PRIV[issuer],
    )


def child(parent: dict, issuer: str, subject: str, grants: list[str], at: str, depth: int) -> dict:
    return issue_sub_authority_delegation(
        parent,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": parent["delegation_id"],
            "issuer": DID[issuer],
            "subject": DID[subject],
            "verification_method": DID[issuer] + "#key-1",
            "issued_at": at,
            "nonce": _seed(f"{issuer}->{subject}-nonce:v1")[:32],
            "authority": _authority(depth, grants, at),
        },
        PRIV[issuer],
        now=NOW,
        resolve_verification_key=RESOLVE_KEY,
        resolve_revocation=ALWAYS_ACTIVE,
    )


def main() -> None:
    T0 = "2026-09-20T09:00:00.000Z"
    T1 = "2026-09-20T09:10:00.000Z"
    T2 = "2026-09-20T09:20:00.000Z"

    # LC-C-006. Three hops. The middle record is the one a later finding calls void from
    # issuance; the leaf depends on it and has no record of its own.
    dept_to_deputy = root("dept", "deputy", ["dept:*"], T0, 2)
    deputy_to_agent_t = child(dept_to_deputy, "deputy", "agent-t", ["dept:orders"], T1, 1)
    # A fourth party is not needed: the leaf is a further sub-delegation issued by the
    # agent the middle record named, so the dependency is a real parent link.
    agent_t_leaf = child(deputy_to_agent_t, "agent-t", "joint", ["dept:orders"], T2, 0)

    # LC-C-005. Two independently valid sources, one seat, different named holders.
    source_1 = root("source-1", "holder-p", ["seat:act"], T0, 0)
    source_2 = root("source-2", "holder-q", ["seat:act"], T0, 0)

    # LC-C-012. Two independently rooted chains reaching the same leaf agent.
    agency_a = root("agency-a", "a-ops", ["alpha:*"], T0, 1)
    a_to_joint = child(agency_a, "a-ops", "joint", ["alpha:write"], T1, 0)
    agency_b = root("agency-b", "b-ops", ["beta:*"], T0, 1)
    b_to_joint = child(agency_b, "b-ops", "joint", ["beta:write"], T1, 0)

    # LC-C-029. Two contributors narrow a full root to the same coalition subset. The
    # per-contributor difference is not in these records; it is in the caveat records the
    # vectors carry.
    nation_x = root("nation-x", "coalition", ["force:move", "force:screen"], T0, 0)
    nation_y = root("nation-y", "coalition", ["force:move", "force:screen"], T0, 0)

    # LC-H-001. Two co-settlors' shares into one trustee, disjoint scope prefixes.
    share_a = root("settlor-a", "trustee", ["estate:a:manage"], T0, 0)
    share_b = root("settlor-b", "trustee", ["estate:b:manage"], T0, 0)

    # LC-C-031. The concurrently exercised grant the master can override at any instant.
    master_to_pilot = root("master", "pilot", ["vessel:steer"], T0, 0)

    roles = {
        "DEPT_TO_DEPUTY": dept_to_deputy,
        "DEPUTY_TO_AGENT_T": deputy_to_agent_t,
        "AGENT_T_LEAF": agent_t_leaf,
        "SOURCE_1": source_1,
        "SOURCE_2": source_2,
        "AGENCY_A": agency_a,
        "A_TO_JOINT": a_to_joint,
        "AGENCY_B": agency_b,
        "B_TO_JOINT": b_to_joint,
        "NATION_X": nation_x,
        "NATION_Y": nation_y,
        "SHARE_A_GRANT": share_a,
        "SHARE_B_GRANT": share_b,
        "MASTER_TO_PILOT": master_to_pilot,
    }

    fixture = {
        "_placeholder": False,
        "now": NOW,
        "seed_prefix": SEED_PREFIX,
        "verification_keys": KEYS,
        "roles": {name: record["delegation_id"] for name, record in roles.items()},
        "approvals": mint_approvals(),
        "chains": {
            "TAINTED": [dept_to_deputy, deputy_to_agent_t, agent_t_leaf],
            "SEAT_P": [source_1],
            "SEAT_Q": [source_2],
            "UNIT_A": [agency_a, a_to_joint],
            "UNIT_B": [agency_b, b_to_joint],
            "CONTRIB_X": [nation_x],
            "CONTRIB_Y": [nation_y],
            "SHARE_A": [share_a],
            "SHARE_B": [share_b],
            "PILOTAGE": [master_to_pilot],
        },
    }
    (HERE / "chain.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
