#!/usr/bin/env python3
"""Mint fixture.json for the issuance-refusal-expiry fixture, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. This mirrors
fixtures/ancestor-revocation-chain/mint.py's key-derivation pattern.

The fixture holds one parent AuthorityDelegationV1 (principal -> agent A),
a byte-identical copy of it with one hex character of the signature flipped
(parent_signature_tampered), an unsigned child body template naming agent A
as issuer and agent L (leaf) as subject, and the actual signed leaf record
produced by issuing that child body under the parent while the parent is
valid and active (chain[1] below). verify.ts and validate.py call the SDKs'
own issuance functions at run time with different `now` values, revocation
answers, and parent records to exercise draft-03 section 3.6's issuer
refusal; they do not read a pre-baked reject artifact, because none exists to
read: a conforming issuer refuses to produce one.

Run from the suite root with agent-passport-system 4.0.0 or later installed:

    python3 fixtures/issuance-refusal-expiry/mint.py

Then `git diff` on fixture.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent

PRINCIPAL = "did:aps:example:irx-principal"
AGENT_A = "did:aps:example:irx-agent-a"
AGENT_L = "did:aps:example:irx-agent-l"

PARENT_NOT_BEFORE = "2026-09-20T10:00:00.000Z"
PARENT_NOT_AFTER = "2026-09-20T20:00:00.000Z"

NOW_NOT_YET_VALID = "2026-09-20T09:00:00.000Z"
NOW_VALID = "2026-09-20T12:00:00.000Z"
NOW_EXPIRED = "2026-09-20T21:00:00.000Z"

LEAF_NOT_BEFORE = "2026-09-20T12:00:00.000Z"
LEAF_NOT_AFTER = "2026-09-20T14:00:00.000Z"

NOW_LEAF_ACTIVE = "2026-09-20T13:00:00.000Z"
NOW_LEAF_EXPIRED = "2026-09-20T15:00:00.000Z"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:irx:{label}".encode()).hexdigest()


def _tamper_signature(signature: str) -> str:
    first = signature[0]
    replacement = "1" if first == "0" else "0"
    return replacement + signature[1:]


def _authority(remaining: int, not_before: str, not_after: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["calendar:write"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": remaining},
        "time": {"not_before": not_before, "not_after": not_after},
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

    parent = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": PRINCIPAL,
            "subject": AGENT_A,
            "verification_method": PRINCIPAL + "#key-1",
            "issued_at": "2026-09-20T09:00:00.000Z",
            "nonce": _seed("root-nonce:v1")[:32],
            "authority": _authority(2, PARENT_NOT_BEFORE, PARENT_NOT_AFTER),
        },
        principal_priv,
    )

    parent_signature_tampered = {**parent, "signature": _tamper_signature(parent["signature"])}

    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)
    always_active = lambda _delegation: "active"

    child_body = {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "parent_delegation_id": parent["delegation_id"],
        "issuer": AGENT_A,
        "subject": AGENT_L,
        "verification_method": AGENT_A + "#key-1",
        "issued_at": NOW_VALID,
        "nonce": _seed("a-to-leaf-nonce:v1")[:32],
        "authority": _authority(1, LEAF_NOT_BEFORE, LEAF_NOT_AFTER),
    }

    leaf = issue_sub_authority_delegation(
        parent,
        child_body,
        agent_a_priv,
        now=NOW_VALID,
        resolve_verification_key=resolve_key,
        resolve_revocation=always_active,
    )

    fixture = {
        "_placeholder": False,
        "principal_priv": principal_priv,
        "agent_a_priv": agent_a_priv,
        "verification_keys": keys,
        "parent": parent,
        "parent_signature_tampered": parent_signature_tampered,
        "child_body": child_body,
        "chain": [parent, leaf],
        "now": {
            "not_yet_valid": NOW_NOT_YET_VALID,
            "valid": NOW_VALID,
            "expired": NOW_EXPIRED,
            "leaf_active": NOW_LEAF_ACTIVE,
            "leaf_expired": NOW_LEAF_EXPIRED,
        },
    }
    (HERE / "fixture.json").write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
