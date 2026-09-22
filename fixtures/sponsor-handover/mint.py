#!/usr/bin/env python3
"""Mint chains.json for the sponsor-handover fixture, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. This mirrors the
fixtures/revocation-resolution-forward-compat/mint.py and
fixtures/ancestor-revocation-chain/mint.py minting, key-resolution and
by-index-style resolver pattern, extended to three independent two-hop
AuthorityDelegationV1 chains that share one delegation and one subject:

  OLD   org -> employee -> agent_x
  NEW   org -> successor -> agent_x        (independent of OLD)
  OTHER org -> employee -> agent_y         (shares org -> employee with OLD)

agent_x is the same subject DID with the same generated key in both OLD and
NEW. org -> employee is the exact same signed record (same delegation_id,
same signature) in both OLD and OTHER, produced by minting it once and using
it as the parent for two independent children. Delegation nonces are
supplied, not generated, which the Python SDK documents as the path that
keeps issuance deterministic.

Run from the suite root with agent-passport-system 4.0.0 or later installed:

    python3 fixtures/sponsor-handover/mint.py

Then `git diff` on chains.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent
NOW = "2026-09-20T12:00:00.000Z"

ORG = "did:aps:example:shp-org"
EMPLOYEE = "did:aps:example:shp-employee"
SUCCESSOR = "did:aps:example:shp-successor"
AGENT_X = "did:aps:example:shp-agent-x"
AGENT_Y = "did:aps:example:shp-agent-y"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:shp:{label}".encode()).hexdigest()


def _authority(depth: int, not_before: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["calendar:write"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": depth},
        "time": {"not_before": not_before, "not_after": "2026-09-21T00:00:00.000Z"},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def main() -> None:
    org_priv = _seed("org:v1")
    employee_priv = _seed("employee:v1")
    successor_priv = _seed("successor:v1")
    agent_x_priv = _seed("agent-x:v1")
    agent_y_priv = _seed("agent-y:v1")

    keys = {
        ORG + "#key-1": public_key_from_private(org_priv),
        EMPLOYEE + "#key-1": public_key_from_private(employee_priv),
        SUCCESSOR + "#key-1": public_key_from_private(successor_priv),
        # agent_x and agent_y never issue a further delegation in this
        # fixture, so no verification ever resolves these two keys. They are
        # included so the fixture states, not merely asserts, that agent_x
        # has one identity and one key reused unchanged across OLD and NEW.
        AGENT_X + "#key-1": public_key_from_private(agent_x_priv),
        AGENT_Y + "#key-1": public_key_from_private(agent_y_priv),
    }

    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)
    always_active = lambda _delegation: "active"

    org_to_employee = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": ORG,
            "subject": EMPLOYEE,
            "verification_method": ORG + "#key-1",
            "issued_at": "2026-09-20T09:00:00.000Z",
            "nonce": _seed("org-to-employee-nonce:v1")[:32],
            "authority": _authority(1, "2026-09-20T09:00:00.000Z"),
        },
        org_priv,
    )

    # Two independent children of the same org -> employee delegation. This
    # is the shared parent behind OLD (agent_x) and OTHER (agent_y).
    employee_to_x = issue_sub_authority_delegation(
        org_to_employee,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": org_to_employee["delegation_id"],
            "issuer": EMPLOYEE,
            "subject": AGENT_X,
            "verification_method": EMPLOYEE + "#key-1",
            "issued_at": "2026-09-20T09:30:00.000Z",
            "nonce": _seed("employee-to-x-nonce:v1")[:32],
            "authority": _authority(0, "2026-09-20T09:30:00.000Z"),
        },
        employee_priv,
        now=NOW,
        resolve_verification_key=resolve_key,
        resolve_revocation=always_active,
    )
    employee_to_y = issue_sub_authority_delegation(
        org_to_employee,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": org_to_employee["delegation_id"],
            "issuer": EMPLOYEE,
            "subject": AGENT_Y,
            "verification_method": EMPLOYEE + "#key-1",
            "issued_at": "2026-09-20T09:35:00.000Z",
            "nonce": _seed("employee-to-y-nonce:v1")[:32],
            "authority": _authority(0, "2026-09-20T09:35:00.000Z"),
        },
        employee_priv,
        now=NOW,
        resolve_verification_key=resolve_key,
        resolve_revocation=always_active,
    )

    # A second root delegation, independent of org -> employee: no field of
    # this record or its child names any OLD or OTHER delegation as parent.
    org_to_successor = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": ORG,
            "subject": SUCCESSOR,
            "verification_method": ORG + "#key-1",
            "issued_at": "2026-09-20T10:00:00.000Z",
            "nonce": _seed("org-to-successor-nonce:v1")[:32],
            "authority": _authority(1, "2026-09-20T10:00:00.000Z"),
        },
        org_priv,
    )
    successor_to_x = issue_sub_authority_delegation(
        org_to_successor,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": org_to_successor["delegation_id"],
            "issuer": SUCCESSOR,
            "subject": AGENT_X,
            "verification_method": SUCCESSOR + "#key-1",
            "issued_at": "2026-09-20T10:30:00.000Z",
            "nonce": _seed("successor-to-x-nonce:v1")[:32],
            "authority": _authority(0, "2026-09-20T10:30:00.000Z"),
        },
        successor_priv,
        now=NOW,
        resolve_verification_key=resolve_key,
        resolve_revocation=always_active,
    )

    fixture = {
        "_placeholder": False,
        "now": NOW,
        "verification_keys": keys,
        # Maps a stable role name to the delegation_id computed for it, so
        # the runners can key a revocation resolver by role instead of by
        # chain-local index. org_to_employee is the same delegation_id under
        # both the ORG_TO_EMPLOYEE role and everywhere it appears below.
        "roles": {
            "ORG_TO_EMPLOYEE": org_to_employee["delegation_id"],
            "EMPLOYEE_TO_X": employee_to_x["delegation_id"],
            "EMPLOYEE_TO_Y": employee_to_y["delegation_id"],
            "ORG_TO_SUCCESSOR": org_to_successor["delegation_id"],
            "SUCCESSOR_TO_X": successor_to_x["delegation_id"],
        },
        "chains": {
            "OLD": [org_to_employee, employee_to_x],
            "NEW": [org_to_successor, successor_to_x],
            "OTHER": [org_to_employee, employee_to_y],
        },
    }
    (HERE / "chains.json").write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
