#!/usr/bin/env python3
"""Mint chains.json for the authority-epoch-rollback candidate family, byte for byte.

WHAT THIS GENERATES. One two-member AuthorityDelegationV1 chain, one draft-03
section 3.5.1 revocation of its root, two fixture-local revocation-withdrawal
records (one signed by the revoker, one signed by a party that is not the
revoker), and five named epoch-tagged views of a revocation store. Every record
is minted through the published Python SDK, so no signature or identifier in
chains.json is hand-written.

DETERMINISM. Ed25519 seeds are SHA-256 over the published labels in _seed()
below, so the file carries no secret material and anyone can regenerate it.
Nonces are supplied, never generated. No clock is read: every timestamp is a
constant in this file. The `digests` block records SHA-256 over the RFC 8785 JCS
canonical bytes of each record, computed with the SDK's own canonicalizer, and
both runners recompute those digests before they verify anything.

Run from the suite root with agent-passport-system 4.1.0 or later installed:

    python3 fixtures/authority-epoch-rollback/mint.py

Then `git diff` on chains.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import (
    issue_authority_delegation,
    issue_authority_revocation,
    issue_sub_authority_delegation,
)
from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private, sign

HERE = Path(__file__).resolve().parent

# Every instant in this fixture, fixed here and nowhere else.
ROOT_ISSUED_AT = "2026-09-20T10:00:00.000Z"
CHILD_ISSUED_AT = "2026-09-20T11:00:00.000Z"
REVOKED_AT = "2026-09-20T11:30:00.000Z"
WITHDRAWN_AT = "2026-09-20T12:30:00.000Z"
NOT_AFTER = "2026-09-21T00:00:00.000Z"
NOW = "2026-09-20T13:00:00.000Z"

PRINCIPAL = "did:aps:example:aer-principal"
AGENT_A = "did:aps:example:aer-agent-a"
AGENT_B = "did:aps:example:aer-agent-b"

# Fixture-local record type for a withdrawal of a recorded revocation. This is
# NOT APS vocabulary and is not proposed as any. Neither draft-03 nor the
# agent-authority-lifecycle text at 5c1bf09 defines a record for withdrawing a
# revocation, which is one of this fixture's findings. The shape below exists so
# the case is runnable, and the README says so in two places.
WITHDRAWAL_RECORD_TYPE = "fixture:authority-epoch-rollback:revocation-withdrawal:v0"
WITHDRAWAL_SIGNATURE_DOMAIN = "fixture:authority-epoch-rollback:revocation-withdrawal:v0:sig"

SEED_PREFIX = "aps-conformance-suite:authority-epoch-rollback:"


def _seed(label: str) -> str:
    """Ed25519 private seed as 64 lowercase hex, derived from a published label."""
    return hashlib.sha256((SEED_PREFIX + label).encode()).hexdigest()


def _authority(depth: int, not_before: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["ledger:write"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": depth},
        "time": {"not_before": not_before, "not_after": NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def _withdrawal(revocation: dict, withdrawn_by: str, method: str, private_key: str) -> dict:
    """A fixture-local record stating that a recorded revocation is withdrawn.

    It references the revocation by `revocation_id` and never modifies it. The
    signature covers a domain-tagged JCS preimage of the body, the same
    separation pattern the SDK uses for its own records.
    """
    body = {
        "fixture_record_type": WITHDRAWAL_RECORD_TYPE,
        "version": "0",
        "revocation_id": revocation["revocation_id"],
        "delegation_id": revocation["delegation_id"],
        "withdrawn_by": withdrawn_by,
        "verification_method": method,
        "withdrawn_at": WITHDRAWN_AT,
        "reason_code": "recorded-in-error",
        "detail": "The revocation was recorded against the wrong delegation identifier.",
    }
    preimage = WITHDRAWAL_SIGNATURE_DOMAIN + "\n" + canonicalize_jcs(body)
    return {**body, "signature": sign(preimage, private_key)}


def _jcs_sha256(record: dict) -> str:
    return hashlib.sha256(canonicalize_jcs(record).encode()).hexdigest()


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
            "issued_at": ROOT_ISSUED_AT,
            "nonce": _seed("root-nonce:v1")[:32],
            "authority": _authority(1, ROOT_ISSUED_AT),
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
            "issued_at": CHILD_ISSUED_AT,
            "nonce": _seed("child-nonce:v1")[:32],
            "authority": _authority(0, CHILD_ISSUED_AT),
        },
        agent_a_priv,
        now=CHILD_ISSUED_AT,
        resolve_verification_key=lambda _issuer, method, _issued_at: keys.get(method),
        resolve_revocation=lambda _delegation: "active",
    )

    # draft-03 section 3.5: "Any delegation MAY be revoked by its issuer." The
    # root's issuer is PRINCIPAL, so PRINCIPAL is the only party that can mint
    # this record, and verify_authority_revocation() re-derives that from the
    # target rather than from the record.
    revocation = issue_authority_revocation(
        root,
        now=REVOKED_AT,
        revoker=PRINCIPAL,
        verification_method=PRINCIPAL + "#key-1",
        reason_code="credential-compromise",
        nonce=_seed("revocation-nonce:v1")[:32],
        private_key=principal_priv,
    )

    withdrawal_authorized = _withdrawal(
        revocation, PRINCIPAL, PRINCIPAL + "#key-1", principal_priv
    )
    # Signed by the root's subject, who is not the root's issuer and therefore
    # not the revoker. The signature is genuine and the standing is not there.
    withdrawal_unauthorized = _withdrawal(
        revocation, AGENT_A, AGENT_A + "#key-1", agent_a_priv
    )

    root_id = root["delegation_id"]
    child_id = child["delegation_id"]
    tracked = [root_id, child_id]

    views = {
        "epoch-6": {
            "epoch": 6,
            "description": "State as it stood before the revocation was recorded. Both delegations tracked, no revocation held.",
            "tracked": tracked,
            "revocations": [],
            "withdrawals": [],
        },
        "epoch-7": {
            "epoch": 7,
            "description": "State after the root revocation was recorded.",
            "tracked": tracked,
            "revocations": ["root-revocation"],
            "withdrawals": [],
        },
        "epoch-8": {
            "epoch": 8,
            "description": "One epoch later with no change to the record set. Used to show a forward move is not fenced.",
            "tracked": tracked,
            "revocations": ["root-revocation"],
            "withdrawals": [],
        },
        "epoch-8-corrected": {
            "epoch": 8,
            "description": "The root revocation plus a withdrawal record signed by the revoker.",
            "tracked": tracked,
            "revocations": ["root-revocation"],
            "withdrawals": ["withdrawal-authorized"],
        },
        "epoch-8-unauthorized-correction": {
            "epoch": 8,
            "description": "The root revocation plus a withdrawal record signed by a party that is not the revoker.",
            "tracked": tracked,
            "revocations": ["root-revocation"],
            "withdrawals": ["withdrawal-unauthorized"],
        },
    }

    records = {
        "root-revocation": revocation,
        "withdrawal-authorized": withdrawal_authorized,
        "withdrawal-unauthorized": withdrawal_unauthorized,
    }

    fixture = {
        "profile": "aps-authority-epoch-rollback-v0",
        "generated_by": "fixtures/authority-epoch-rollback/mint.py",
        "seed_prefix": SEED_PREFIX,
        "seed_labels": [
            "principal:v1",
            "agent-a:v1",
            "root-nonce:v1",
            "child-nonce:v1",
            "revocation-nonce:v1",
        ],
        "now": NOW,
        "withdrawal_record_type": WITHDRAWAL_RECORD_TYPE,
        "withdrawal_signature_domain": WITHDRAWAL_SIGNATURE_DOMAIN,
        "verification_keys": keys,
        "roles": {"ROOT": root_id, "CHILD": child_id},
        "chain": [root, child],
        "records": records,
        "views": views,
        "digests": {
            "algorithm": "sha256 over RFC 8785 JCS canonical bytes",
            "chain": [_jcs_sha256(root), _jcs_sha256(child)],
            "records": {name: _jcs_sha256(record) for name, record in records.items()},
        },
    }
    (HERE / "chains.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
