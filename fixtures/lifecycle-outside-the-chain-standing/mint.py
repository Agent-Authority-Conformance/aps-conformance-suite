#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Mint chain.json for the lifecycle-outside-the-chain-standing family, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file carries no
secret material and anyone can regenerate it. This follows the minting, key-resolution
and role-keyed resolver pattern of fixtures/sponsor-handover/mint.py and
fixtures/ancestor-revocation-chain/mint.py.

Five two-hop AuthorityDelegationV1 chains, one set per case in the
"Outside-the-chain standing" section of CASES.md v0.2:

  OFFICER     body -> officer -> agent_o        LC-H-004, the chain a board suspension targets
  TERMINATED  employer -> employer_hr -> agent_r  LC-H-005, the chain the termination ends
  REINSTATED  order_root -> designee -> agent_r   LC-H-005, the chain the external order creates
  CLAIM_P     claimant_p -> p_ops -> agent_d      LC-H-006, one claimed root
  CLAIM_Q     claimant_q -> q_ops -> agent_d      LC-H-006, the rival claimed root

agent_r is the same subject DID with the same generated key in TERMINATED and
REINSTATED, so the family states rather than asserts that the reinstated chain is a new
grant to the same identity and not a revival of the old one. agent_d is likewise the
same subject under both claimed roots. REINSTATED's root scope carries a grant
TERMINATED's root never carried (`backpay:read`), so the "terms come from the
reinstating body" claim is readable off the bytes.

Delegation nonces are supplied, not generated, which the Python SDK documents as the
path that keeps issuance deterministic.

Run from the suite root with a Python interpreter that has PyPI
agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-outside-the-chain-standing/mint.py

Then `git diff` on chain.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent
NOW = "2026-09-20T12:00:00.000Z"
NOT_AFTER = "2026-09-30T00:00:00.000Z"

BODY = "did:aps:example:ocs-body"
OFFICER = "did:aps:example:ocs-officer"
AGENT_O = "did:aps:example:ocs-agent-o"
EMPLOYER = "did:aps:example:ocs-employer"
EMPLOYER_HR = "did:aps:example:ocs-employer-hr"
ORDER_ROOT = "did:aps:example:ocs-order-root"
DESIGNEE = "did:aps:example:ocs-designee"
AGENT_R = "did:aps:example:ocs-agent-r"
CLAIMANT_P = "did:aps:example:ocs-claimant-p"
P_OPS = "did:aps:example:ocs-p-ops"
CLAIMANT_Q = "did:aps:example:ocs-claimant-q"
Q_OPS = "did:aps:example:ocs-q-ops"
AGENT_D = "did:aps:example:ocs-agent-d"

# The single published seed derivation. Recorded in the README as the fixture's seed.
SEED_PREFIX = "aps-conformance-suite:lifecycle-outside-the-chain-standing:"


def _seed(label: str) -> str:
    return hashlib.sha256((SEED_PREFIX + label).encode()).hexdigest()


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


def main() -> None:
    privs = {
        name: _seed(f"{name}:v1")
        for name in (
            "body", "officer", "employer", "employer-hr", "order-root", "designee",
            "claimant-p", "p-ops", "claimant-q", "q-ops",
            "agent-o", "agent-r", "agent-d",
        )
    }
    keys = {
        BODY + "#key-1": public_key_from_private(privs["body"]),
        OFFICER + "#key-1": public_key_from_private(privs["officer"]),
        EMPLOYER + "#key-1": public_key_from_private(privs["employer"]),
        EMPLOYER_HR + "#key-1": public_key_from_private(privs["employer-hr"]),
        ORDER_ROOT + "#key-1": public_key_from_private(privs["order-root"]),
        DESIGNEE + "#key-1": public_key_from_private(privs["designee"]),
        CLAIMANT_P + "#key-1": public_key_from_private(privs["claimant-p"]),
        P_OPS + "#key-1": public_key_from_private(privs["p-ops"]),
        CLAIMANT_Q + "#key-1": public_key_from_private(privs["claimant-q"]),
        Q_OPS + "#key-1": public_key_from_private(privs["q-ops"]),
        # The three leaf agents never issue a further delegation here, so no
        # verification resolves these keys. They are published so the fixture states,
        # not merely asserts, that agent_r has one identity across TERMINATED and
        # REINSTATED and agent_d has one identity under both claimed roots.
        AGENT_O + "#key-1": public_key_from_private(privs["agent-o"]),
        AGENT_R + "#key-1": public_key_from_private(privs["agent-r"]),
        AGENT_D + "#key-1": public_key_from_private(privs["agent-d"]),
    }

    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)
    always_active = lambda _delegation: "active"

    def root(issuer: str, subject: str, grants: list[str], at: str, label: str) -> dict:
        return issue_authority_delegation(
            {
                "record_type": "aps:authority-delegation:v1",
                "version": "1.0",
                "parent_delegation_id": None,
                "issuer": issuer,
                "subject": subject,
                "verification_method": issuer + "#key-1",
                "issued_at": at,
                "nonce": _seed(f"{label}-nonce:v1")[:32],
                "authority": _authority(1, grants, at),
            },
            privs[label.split("->")[0]],
        )

    def child(parent: dict, issuer: str, subject: str, grants: list[str], at: str, label: str) -> dict:
        return issue_sub_authority_delegation(
            parent,
            {
                "record_type": "aps:authority-delegation:v1",
                "version": "1.0",
                "parent_delegation_id": parent["delegation_id"],
                "issuer": issuer,
                "subject": subject,
                "verification_method": issuer + "#key-1",
                "issued_at": at,
                "nonce": _seed(f"{label}-nonce:v1")[:32],
                "authority": _authority(0, grants, at),
            },
            privs[label.split("->")[0]],
            now=NOW,
            resolve_verification_key=resolve_key,
            resolve_revocation=always_active,
        )

    # LC-H-004. The chain a board suspension targets.
    body_to_officer = root(BODY, OFFICER, ["payroll:*"], "2026-09-20T09:00:00.000Z", "body->officer")
    officer_to_agent_o = child(
        body_to_officer, OFFICER, AGENT_O, ["payroll:read"], "2026-09-20T09:10:00.000Z", "officer->agent-o"
    )

    # LC-H-005. The terminated chain, then the chain the external order creates. The
    # reinstated root grants backpay:read, which no record in TERMINATED carries.
    employer_root = root(EMPLOYER, EMPLOYER_HR, ["records:*"], "2026-09-20T09:00:00.000Z", "employer->employer-hr")
    employer_to_agent_r = child(
        employer_root, EMPLOYER_HR, AGENT_R, ["records:read"], "2026-09-20T09:10:00.000Z", "employer-hr->agent-r"
    )
    order_root = root(
        ORDER_ROOT, DESIGNEE, ["backpay:read", "records:*"], "2026-09-20T11:00:00.000Z", "order-root->designee"
    )
    designee_to_agent_r = child(
        order_root, DESIGNEE, AGENT_R, ["backpay:read", "records:read"], "2026-09-20T11:10:00.000Z",
        "designee->agent-r",
    )

    # LC-H-006. Two claimed roots, same subject, same target scope.
    claimant_p_root = root(CLAIMANT_P, P_OPS, ["ledger:*"], "2026-09-20T09:00:00.000Z", "claimant-p->p-ops")
    p_to_agent_d = child(
        claimant_p_root, P_OPS, AGENT_D, ["ledger:write"], "2026-09-20T09:10:00.000Z", "p-ops->agent-d"
    )
    claimant_q_root = root(CLAIMANT_Q, Q_OPS, ["ledger:*"], "2026-09-20T09:05:00.000Z", "claimant-q->q-ops")
    q_to_agent_d = child(
        claimant_q_root, Q_OPS, AGENT_D, ["ledger:write"], "2026-09-20T09:15:00.000Z", "q-ops->agent-d"
    )

    fixture = {
        "_placeholder": False,
        "now": NOW,
        "seed_prefix": SEED_PREFIX,
        "verification_keys": keys,
        # Stable role name -> the delegation_id computed for it, so the runners key a
        # revocation resolver by role rather than by chain-local index.
        "roles": {
            "BODY_TO_OFFICER": body_to_officer["delegation_id"],
            "OFFICER_TO_AGENT_O": officer_to_agent_o["delegation_id"],
            "EMPLOYER_ROOT": employer_root["delegation_id"],
            "EMPLOYER_TO_AGENT_R": employer_to_agent_r["delegation_id"],
            "ORDER_ROOT": order_root["delegation_id"],
            "DESIGNEE_TO_AGENT_R": designee_to_agent_r["delegation_id"],
            "CLAIMANT_P_ROOT": claimant_p_root["delegation_id"],
            "P_TO_AGENT_D": p_to_agent_d["delegation_id"],
            "CLAIMANT_Q_ROOT": claimant_q_root["delegation_id"],
            "Q_TO_AGENT_D": q_to_agent_d["delegation_id"],
        },
        "chains": {
            "OFFICER": [body_to_officer, officer_to_agent_o],
            "TERMINATED": [employer_root, employer_to_agent_r],
            "REINSTATED": [order_root, designee_to_agent_r],
            "CLAIM_P": [claimant_p_root, p_to_agent_d],
            "CLAIM_Q": [claimant_q_root, q_to_agent_d],
        },
    }
    (HERE / "chain.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
