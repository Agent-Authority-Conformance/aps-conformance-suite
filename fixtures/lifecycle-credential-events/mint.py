#!/usr/bin/env python3
"""Mint chain.json for the lifecycle-credential-events family, byte for byte.

The family's own question is about which checks a boundary requires and what
each one can establish from records, not about chain shape. The chain exists so
the SDK bridges have a real delegation to ask about, and so `credential_ref`
names something an implementation can recompute rather than a made-up string.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. Delegation nonces are
supplied, not generated, which is the path the Python SDK documents for
deterministic issuance.

Run from the suite root with agent-passport-system 4.1.0 or later installed:

    python3 fixtures/lifecycle-credential-events/mint.py

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

SEED_INPUT = "aac-lifecycle-credential-events-v0"
PRINCIPAL = "did:aps:example:lce-principal"
INTEGRATOR = "did:aps:example:lce-integrator"
AGENT = "did:aps:example:lce-agent"


def _seed(label: str) -> str:
    return hashlib.sha256(f"{SEED_INPUT}:{label}".encode()).hexdigest()


def _authority(depth: int, not_before: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["billing:submit"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": depth},
        "time": {"not_before": not_before, "not_after": "2026-09-21T00:00:00.000Z"},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def main() -> None:
    principal_priv = _seed("principal:v1")
    integrator_priv = _seed("integrator:v1")
    keys = {
        PRINCIPAL + "#key-1": public_key_from_private(principal_priv),
        INTEGRATOR + "#key-1": public_key_from_private(integrator_priv),
    }

    root = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": PRINCIPAL,
            "subject": INTEGRATOR,
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
            "issuer": INTEGRATOR,
            "subject": AGENT,
            "verification_method": INTEGRATOR + "#key-1",
            "issued_at": "2026-09-20T11:00:00.000Z",
            "nonce": _seed("child-nonce:v1")[:32],
            "authority": _authority(0, "2026-09-20T11:00:00.000Z"),
        },
        integrator_priv,
        now=NOW,
        resolve_verification_key=lambda _issuer, method, _issued_at: keys.get(method),
        resolve_revocation=lambda _delegation: "active",
    )

    fixture = {
        "seed_input": SEED_INPUT,
        "seed_sha256_hex": hashlib.sha256(SEED_INPUT.encode()).hexdigest(),
        "now": NOW,
        "subjects": {"principal": PRINCIPAL, "integrator": INTEGRATOR, "agent": AGENT},
        "verification_keys": keys,
        "chain": [root, child],
    }
    (HERE / "chain.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
