#!/usr/bin/env python3
"""Mint chains.json for the single-chain-selection fixture, byte for byte.

Two independent single-hop AuthorityDelegationV1 chains, root P1 to leaf L and
root P2 to leaf L. Both hold the same leaf agent, different roots, disjoint
scope grants, and the same spend ceiling in the same unit.

Each numbered case's action requirement is modeled as a second, synthetic
delegation hop appended after the leaf: issuer L, subject a fixed
"scs-action" identity, carrying exactly the scope grants and spend ceiling
the action needs. This lets every vector be decided by the SDKs' one public,
exported entry point for checking a proposed authority vector against a
chain: `verifyAuthorityDelegationChain`'s own seven-facet narrowing check
(compareAuthority, draft-pidlisnyi-aps-03 Section 3.2), run as phase 9 of
chain verification. Neither SDK's published package exports a separate
action-versus-chain evaluation function; see the family README's "SDK
surface" section.

For the reject vectors this script deliberately signs a hop whose authority
is wider than its stated parent permits (extra scope, or a higher spend
ceiling), which is exactly the record shape a verifier must reject. Minting
it therefore bypasses the SDK's cooperative-issuance path
(`issue_sub_authority_delegation`), which itself refuses to sign a widening
child (draft section 3.6): this script instead computes the delegation_id
and signs directly, the same two steps that issuance function performs
internally, using only the public `compute_authority_delegation_id_for_write`
and `sign_authority_delegation` primitives. The resulting record is a
syntactically valid, correctly signed AuthorityDelegationV1 that a verifier
must still catch and reject at the attenuation phase. That is the property
this fixture tests: it does not depend on cooperative issuance ever refusing
to create such a record, only on chain verification refusing to accept one
that is presented.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. Delegation nonces
are supplied, not generated, which the Python SDK documents as the path that
keeps issuance deterministic. This mirrors the
fixtures/ancestor-revocation-chain/mint.py and
fixtures/revocation-resolution-forward-compat/mint.py pattern.

Run from the suite root with agent-passport-system 4.0.0 or later installed:

    python3 fixtures/single-chain-selection/mint.py

Then `git diff` on chains.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation
from agent_passport.crypto import public_key_from_private
from agent_passport.v2.authority_delegation import (
    compute_authority_delegation_id_for_write,
    sign_authority_delegation,
)

HERE = Path(__file__).resolve().parent
NOW = "2026-09-20T13:00:00.000Z"
NOT_BEFORE = "2026-09-20T10:00:00.000Z"
NOT_AFTER = "2026-09-21T00:00:00.000Z"

PRINCIPAL_1 = "did:aps:example:scs-principal-1"
PRINCIPAL_2 = "did:aps:example:scs-principal-2"
AGENT_L = "did:aps:example:scs-agent-l"
ACTION_TARGET = "did:aps:example:scs-action"

SPEND_UNIT = "iso4217:USD:minor"
ROOT_SPEND_CEILING = "60"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:scs:{label}".encode()).hexdigest()


def _root_authority(grants: list[str]) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": grants},
        "spend": {
            "mode": "bounded",
            "unit": SPEND_UNIT,
            "per_action": ROOT_SPEND_CEILING,
            "cumulative": ROOT_SPEND_CEILING,
        },
        # remaining: 1 lets the leaf be extended by exactly one further hop,
        # which is the synthetic per-action record each vector appends.
        "depth": {"remaining": 1},
        "time": {"not_before": NOT_BEFORE, "not_after": NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


ACTION_ISSUED_AT = "2026-09-20T11:00:00.000Z"


def _action_authority(grants: list[str], amount: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": grants},
        "spend": {
            "mode": "bounded",
            "unit": SPEND_UNIT,
            "per_action": amount,
            "cumulative": amount,
        },
        "depth": {"remaining": 0},
        # not_before cannot predate issued_at (closed-schema rule), and must stay
        # contained in the parent's [NOT_BEFORE, NOT_AFTER) window.
        "time": {"not_before": ACTION_ISSUED_AT, "not_after": NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def _sign_record(body: dict, private_key: str) -> dict:
    """Compute delegation_id and sign, without the issuer-side attenuation check
    that issue_sub_authority_delegation performs. See the module docstring."""
    delegation_id = compute_authority_delegation_id_for_write(body)
    unsigned = {**body, "delegation_id": delegation_id}
    signature = sign_authority_delegation(unsigned, private_key)
    return {**unsigned, "signature": signature}


def _action_hop(parent: dict, private_key: str, label: str, grants: list[str], amount: str) -> dict:
    body = {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "parent_delegation_id": parent["delegation_id"],
        "issuer": AGENT_L,
        "subject": ACTION_TARGET,
        "verification_method": AGENT_L + "#key-1",
        "issued_at": ACTION_ISSUED_AT,
        "nonce": _seed(label)[:32],
        "authority": _action_authority(grants, amount),
    }
    return _sign_record(body, private_key)


def main() -> None:
    principal_1_priv = _seed("principal-1:v1")
    principal_2_priv = _seed("principal-2:v1")
    agent_l_priv = _seed("agent-l:v1")
    keys = {
        PRINCIPAL_1 + "#key-1": public_key_from_private(principal_1_priv),
        PRINCIPAL_2 + "#key-1": public_key_from_private(principal_2_priv),
        AGENT_L + "#key-1": public_key_from_private(agent_l_priv),
    }

    chain_1_root = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": PRINCIPAL_1,
            "subject": AGENT_L,
            "verification_method": PRINCIPAL_1 + "#key-1",
            "issued_at": "2026-09-20T10:00:00.000Z",
            "nonce": _seed("p1-to-l-nonce:v1")[:32],
            "authority": _root_authority(["calendar:write"]),
        },
        principal_1_priv,
    )
    chain_2_root = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": PRINCIPAL_2,
            "subject": AGENT_L,
            "verification_method": PRINCIPAL_2 + "#key-1",
            "issued_at": "2026-09-20T10:00:00.000Z",
            "nonce": _seed("p2-to-l-nonce:v1")[:32],
            "authority": _root_authority(["payments:refund"]),
        },
        principal_2_priv,
    )

    hop_scs01 = _action_hop(chain_1_root, agent_l_priv, "hop-scs-01:v1", ["calendar:write"], "50")
    hop_scs02 = _action_hop(chain_2_root, agent_l_priv, "hop-scs-02:v1", ["payments:refund"], "50")
    hop_scs03 = _action_hop(chain_1_root, agent_l_priv, "hop-scs-03:v1", ["calendar:write", "payments:refund"], "50")
    hop_scs04 = _action_hop(chain_2_root, agent_l_priv, "hop-scs-04:v1", ["calendar:write", "payments:refund"], "50")
    hop_scs05 = _action_hop(chain_1_root, agent_l_priv, "hop-scs-05:v1", ["calendar:write"], "100")

    fixture = {
        "_placeholder": False,
        "now": NOW,
        "verification_keys": keys,
        "chain_1": [chain_1_root],
        "chain_2": [chain_2_root],
        "presented": {
            "SCS-01": [chain_1_root, hop_scs01],
            "SCS-02": [chain_2_root, hop_scs02],
            "SCS-03": [chain_1_root, hop_scs03],
            "SCS-04": [chain_2_root, hop_scs04],
            "SCS-05": [chain_1_root, hop_scs05],
            "SCS-06": [chain_1_root, chain_2_root],
        },
    }
    (HERE / "chains.json").write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
