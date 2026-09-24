#!/usr/bin/env python3
"""Mint chains.json for the chain-selection-no-union fixture, byte for byte.

Three independent single-hop AuthorityDelegationV1 root delegations, all three
naming the same leaf agent L as subject, each issued by a different root
principal:

  chain_read_r1      P1 -> L, scope ["resource1:read"],  spend 5/5
  chain_write_r2     P2 -> L, scope ["resource2:write"], spend 5/5
  chain_read_r1_alt  P3 -> L, scope ["resource1:read"],  spend 5/5

The two spend ceilings are equal and in the same unit so that their sum, 10, is
larger than either one, which is what the budget vectors need: an action of 8
fits inside 5 + 5 and fits inside neither 5.

Every record here is produced by the SDK's ordinary cooperative issuance path,
`issue_authority_delegation`. This fixture never needs a record wider than its
parent, because it decides scope coverage and spend headroom with the SDK's own
scope and budget primitives rather than by appending a synthetic requirement hop
to the chain. Contrast fixtures/single-chain-selection/mint.py, which does need
the lower-level signing primitives for exactly that reason.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. Delegation nonces are
supplied, not generated, which the Python SDK documents as the path that keeps
issuance deterministic. This mirrors the
fixtures/ancestor-revocation-chain/mint.py and
fixtures/single-chain-selection/mint.py pattern.

Run from the suite root with agent-passport-system 4.1.0 or later installed:

    python3 fixtures/chain-selection-no-union/mint.py

Then `git diff` on chains.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation
from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent

SEED_PREFIX = "aps-conformance-suite:csnu:"

NOW = "2026-09-23T13:00:00.000Z"
ISSUED_AT = "2026-09-23T10:00:00.000Z"
NOT_BEFORE = "2026-09-23T10:00:00.000Z"
NOT_AFTER = "2026-09-24T00:00:00.000Z"

PRINCIPAL_1 = "did:aps:example:csnu-principal-1"
PRINCIPAL_2 = "did:aps:example:csnu-principal-2"
PRINCIPAL_3 = "did:aps:example:csnu-principal-3"
AGENT_L = "did:aps:example:csnu-agent-l"

SPEND_UNIT = "iso4217:USD:minor"
# Equal per-chain ceiling. The budget vectors turn on 8 being above this and
# below 2 * this.
CEILING = "5"

KEY_LABELS = {
    PRINCIPAL_1 + "#key-1": "principal-1:v1",
    PRINCIPAL_2 + "#key-1": "principal-2:v1",
    PRINCIPAL_3 + "#key-1": "principal-3:v1",
    AGENT_L + "#key-1": "agent-l:v1",
}

NONCE_LABELS = {
    "chain_read_r1": "p1-to-l-read-r1-nonce:v1",
    "chain_write_r2": "p2-to-l-write-r2-nonce:v1",
    "chain_read_r1_alt": "p3-to-l-read-r1-alt-nonce:v1",
}


def _seed(label: str) -> str:
    return hashlib.sha256((SEED_PREFIX + label).encode()).hexdigest()


def _authority(grants: list[str]) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": grants},
        "spend": {
            "mode": "bounded",
            "unit": SPEND_UNIT,
            "per_action": CEILING,
            "cumulative": CEILING,
        },
        # remaining: 0. Nothing in this family appends a further hop: every
        # decision is taken by the SDK's scope and budget primitives against the
        # one presented root-to-leaf chain, which here is one record long.
        "depth": {"remaining": 0},
        "time": {"not_before": NOT_BEFORE, "not_after": NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def _root(issuer: str, private_key: str, nonce_label: str, grants: list[str]) -> dict:
    return issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": issuer,
            "subject": AGENT_L,
            "verification_method": issuer + "#key-1",
            "issued_at": ISSUED_AT,
            "nonce": _seed(nonce_label)[:32],
            "authority": _authority(grants),
        },
        private_key,
    )


def main() -> None:
    keys = {
        method: public_key_from_private(_seed(label))
        for method, label in KEY_LABELS.items()
    }

    chain_read_r1 = _root(
        PRINCIPAL_1, _seed("principal-1:v1"), NONCE_LABELS["chain_read_r1"], ["resource1:read"]
    )
    chain_write_r2 = _root(
        PRINCIPAL_2, _seed("principal-2:v1"), NONCE_LABELS["chain_write_r2"], ["resource2:write"]
    )
    chain_read_r1_alt = _root(
        PRINCIPAL_3, _seed("principal-3:v1"), NONCE_LABELS["chain_read_r1_alt"], ["resource1:read"]
    )

    fixture = {
        "_placeholder": False,
        "now": NOW,
        # Recorded so a reader can rederive every key and nonce in this file
        # without reading the script: private key = SHA-256(seed_prefix + label),
        # used as the RFC 8032 Ed25519 seed. Nonce = the first 32 hex characters
        # of the same digest for the nonce label.
        "seeds": {
            "seed_prefix": SEED_PREFIX,
            "derivation": "private_key = sha256(seed_prefix + label); nonce = sha256(seed_prefix + label)[:32]",
            "key_labels": KEY_LABELS,
            "nonce_labels": NONCE_LABELS,
        },
        "verification_keys": keys,
        "chains": {
            "chain_read_r1": [chain_read_r1],
            "chain_write_r2": [chain_write_r2],
            "chain_read_r1_alt": [chain_read_r1_alt],
        },
        # sha256 over the RFC 8785 JCS canonical bytes of each signed record,
        # recomputed and checked by both runners. This pins the exact record
        # bytes each verdict below was reached against, independently of how
        # this file happens to be indented.
        "canonical_sha256": {
            name: hashlib.sha256(
                canonicalize_jcs(record).encode("utf-8")
            ).hexdigest()
            for name, record in (
                ("chain_read_r1", chain_read_r1),
                ("chain_write_r2", chain_write_r2),
                ("chain_read_r1_alt", chain_read_r1_alt),
            )
        },
        # Stable name -> delegation id, so a vector can key a revocation answer
        # by name instead of by chain-local index.
        "delegation_ids": {
            "chain_read_r1": chain_read_r1["delegation_id"],
            "chain_write_r2": chain_write_r2["delegation_id"],
            "chain_read_r1_alt": chain_read_r1_alt["delegation_id"],
        },
    }
    (HERE / "chains.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
