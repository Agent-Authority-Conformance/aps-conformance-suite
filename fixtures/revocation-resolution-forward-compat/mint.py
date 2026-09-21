#!/usr/bin/env python3
"""Mint chain.json for the C19 fixture, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. The chain is one root
AuthorityDelegationV1 and one child, both valid at `NOW` when the revocation
resolver answers "active". Delegation nonces are supplied, not generated, which
the Python SDK documents as the path that keeps issuance deterministic.

Run from the suite root with agent-passport-system 4.0.0 or later installed:

    python3 fixtures/revocation-resolution-forward-compat/mint.py

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

PRINCIPAL = "did:aps:example:c19-principal"
AGENT_A = "did:aps:example:c19-agent-a"
AGENT_B = "did:aps:example:c19-agent-b"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:c19:{label}".encode()).hexdigest()


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
    principal_priv = _seed("principal:v1")
    agent_a_priv = _seed("agent-a:v1")
    keys = {
        PRINCIPAL + "#key-1": public_key_from_private(principal_priv),
        AGENT_A + "#key-1": public_key_from_private(agent_a_priv),
    }

    root = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": PRINCIPAL,
            "subject": AGENT_A,
            "verification_method": PRINCIPAL + "#key-1",
            "issued_at": "2026-09-20T10:00:00.000Z",
            "nonce": _seed("root-nonce:v1")[:32],
            "authority": _authority(1, "2026-09-20T10:00:00.000Z"),
        },
        principal_priv,
    )
    child = issue_sub_authority_delegation(
        root,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": root["delegation_id"],
            "issuer": AGENT_A,
            "subject": AGENT_B,
            "verification_method": AGENT_A + "#key-1",
            "issued_at": "2026-09-20T11:00:00.000Z",
            "nonce": _seed("child-nonce:v1")[:32],
            "authority": _authority(0, "2026-09-20T11:00:00.000Z"),
        },
        agent_a_priv,
        now=NOW,
        resolve_verification_key=lambda _issuer, method, _issued_at: keys.get(method),
        resolve_revocation=lambda _delegation: "active",
    )
    fixture = {"_placeholder": False, "now": NOW, "verification_keys": keys, "chain": [root, child]}
    (HERE / "chain.json").write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
