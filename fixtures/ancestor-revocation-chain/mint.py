#!/usr/bin/env python3
"""Mint chain.json for the ancestor-revocation-chain fixture, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. The chain is three
AuthorityDelegationV1 hops, root R to agent A, A to agent B, B to leaf L, all
valid at `NOW` when the revocation resolver answers "active" for every
member. Delegation nonces are supplied, not generated, which the Python SDK
documents as the path that keeps issuance deterministic. This mirrors the
fixtures/revocation-resolution-forward-compat/mint.py pattern extended to a
third hop.

Run from the suite root with agent-passport-system 4.0.0 or later installed:

    python3 fixtures/ancestor-revocation-chain/mint.py

Then `git diff` on chain.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent
NOW = "2026-09-20T13:00:00.000Z"

PRINCIPAL = "did:aps:example:aac-principal"
AGENT_A = "did:aps:example:aac-agent-a"
AGENT_B = "did:aps:example:aac-agent-b"
AGENT_L = "did:aps:example:aac-agent-l"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:aac:{label}".encode()).hexdigest()


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
    agent_b_priv = _seed("agent-b:v1")
    keys = {
        PRINCIPAL + "#key-1": public_key_from_private(principal_priv),
        AGENT_A + "#key-1": public_key_from_private(agent_a_priv),
        AGENT_B + "#key-1": public_key_from_private(agent_b_priv),
    }

    always_active = lambda _delegation: "active"
    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)

    root_to_a = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": PRINCIPAL,
            "subject": AGENT_A,
            "verification_method": PRINCIPAL + "#key-1",
            "issued_at": "2026-09-20T10:00:00.000Z",
            "nonce": _seed("root-nonce:v1")[:32],
            "authority": _authority(2, "2026-09-20T10:00:00.000Z"),
        },
        principal_priv,
    )
    a_to_b = issue_sub_authority_delegation(
        root_to_a,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": root_to_a["delegation_id"],
            "issuer": AGENT_A,
            "subject": AGENT_B,
            "verification_method": AGENT_A + "#key-1",
            "issued_at": "2026-09-20T11:00:00.000Z",
            "nonce": _seed("a-to-b-nonce:v1")[:32],
            "authority": _authority(1, "2026-09-20T11:00:00.000Z"),
        },
        agent_a_priv,
        now=NOW,
        resolve_verification_key=resolve_key,
        resolve_revocation=always_active,
    )
    b_to_l = issue_sub_authority_delegation(
        a_to_b,
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": a_to_b["delegation_id"],
            "issuer": AGENT_B,
            "subject": AGENT_L,
            "verification_method": AGENT_B + "#key-1",
            "issued_at": "2026-09-20T12:00:00.000Z",
            "nonce": _seed("b-to-l-nonce:v1")[:32],
            "authority": _authority(0, "2026-09-20T12:00:00.000Z"),
        },
        agent_b_priv,
        now=NOW,
        resolve_verification_key=resolve_key,
        resolve_revocation=always_active,
    )

    fixture = {
        "_placeholder": False,
        "now": NOW,
        "verification_keys": keys,
        "chain": [root_to_a, a_to_b, b_to_l],
    }
    (HERE / "chain.json").write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
