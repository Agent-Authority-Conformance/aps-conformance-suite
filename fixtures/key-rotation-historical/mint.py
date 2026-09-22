#!/usr/bin/env python3
"""Mint delegations.json for the key-rotation-historical fixture, byte for byte.

Keys are Ed25519 seeds derived from the published labels below, so the file
carries no secret material and anyone can regenerate it. Every record here is
an independent root AuthorityDelegationV1 (parent_delegation_id: null) issued
by the same identifier, did:aps:example:krh-principal, under the same
verification_method the whole time. What varies per record is issued_at and
which of the two key epochs, K1 or K2, actually produced the signature.

This models draft-pidlisnyi-aps-03 section 2.2's "one stable agent identifier
across key rotation... resolve the verification method at the artifact's
signing time" together with section 2.4's key rotation and historical
verification rule: the identifier does not change across rotation, and a
resolver must pick the key version authorized at issued_at, not the version
current when verification runs.

K1 is authorized for issued_at < ROTATION_BOUNDARY, but only when evidence
establishes that the claimed issued_at is honest: section 2.4's second
paragraph makes K1's eligibility depend on the artifact's signing time, and
issued_at is only an issuer claim about that time. K2 is authorized for
issued_at >= ROTATION_BOUNDARY unconditionally: K2 is the identifier's
current key going forward, so nothing about its validity window depends on
whether a given issued_at claim can be corroborated. `boundary_evidence`
below models the "timestamp, transparency-log, or equivalent evidence
source" section 2.4 requires a profile to identify; it is this fixture's own
test-only profile, not a proposed addition to the draft. Delegation nonces
are supplied, not generated, which the Python SDK documents as the path that
keeps issuance deterministic. This mirrors
fixtures/ancestor-revocation-chain/mint.py's seed-derivation pattern.

Run from the suite root with agent-passport-system 4.0.0 or later installed:

    python3 fixtures/key-rotation-historical/mint.py

Then `git diff` on delegations.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent

ROTATION_BOUNDARY = "2026-09-20T12:00:00.000Z"
ISSUED_BEFORE = "2026-09-20T11:00:00.000Z"
ISSUED_AFTER = "2026-09-20T13:00:00.000Z"
# KRH-05 needs its own issued_at, distinct from ISSUED_BEFORE: the resolver
# in verify.ts / validate.py is called as (issuer, verification_method,
# issued_at) only, the same three arguments the real SDKs pass it, so two
# records sharing all three could not be told apart by any resolver and
# could not be given different results. Thirty minutes before the boundary,
# as far from it as ISSUED_BEFORE itself, so nothing about this value's
# distance from ROTATION_BOUNDARY is doing any work; only the presence or
# absence of boundary_evidence distinguishes KRH-05 from KRH-01.
ISSUED_BEFORE_NO_EVIDENCE = "2026-09-20T11:30:00.000Z"
VERIFY_NOW = "2026-09-20T14:00:00.000Z"
AUTHORITY_NOT_AFTER = "2026-09-21T00:00:00.000Z"

# This fixture's own test-only evidence profile: section 2.4 (lines 317-321)
# requires a profile to identify an acceptable timestamp, transparency-log,
# or equivalent evidence source when a result depends on whether signing
# fell before a key-retirement boundary. The draft defines no such service
# itself. This is not a proposal for one; it is the minimal, deterministic
# stand-in this fixture needs to make section 2.4's evidence requirement
# executable at all.
BOUNDARY_EVIDENCE_SOURCE = "aps-conformance-suite-test-timestamp-v0"

ISSUER = "did:aps:example:krh-principal"
SUBJECT = "did:aps:example:krh-agent"
VERIFICATION_METHOD = ISSUER + "#key-1"


def _evidence() -> dict:
    return {"source": BOUNDARY_EVIDENCE_SOURCE, "attests_before_boundary": True}


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:krh:{label}".encode()).hexdigest()


def _authority(not_before: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["calendar:write"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": 1},
        "time": {"not_before": not_before, "not_after": AUTHORITY_NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def _record(label: str, issued_at: str, private_key: str) -> dict:
    return issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": ISSUER,
            "subject": SUBJECT,
            "verification_method": VERIFICATION_METHOD,
            "issued_at": issued_at,
            "nonce": _seed(f"{label}:nonce:v1")[:32],
            "authority": _authority(issued_at),
        },
        private_key,
    )


def main() -> None:
    k1_priv = _seed("key-1:v1")
    k2_priv = _seed("key-2:v1")
    k1_pub = public_key_from_private(k1_priv)
    k2_pub = public_key_from_private(k2_priv)

    records = {
        "KRH-01-accept-before-rotation-signed-k1": _record(
            "krh-01", ISSUED_BEFORE, k1_priv
        ),
        "KRH-02-accept-after-rotation-signed-k2": _record(
            "krh-02", ISSUED_AFTER, k2_priv
        ),
        "KRH-03-reject-after-rotation-signed-k1": _record(
            "krh-03", ISSUED_AFTER, k1_priv
        ),
        "KRH-04-reject-before-rotation-signed-k2": _record(
            "krh-04", ISSUED_BEFORE, k2_priv
        ),
        "KRH-05-indeterminate-boundary-no-evidence": _record(
            "krh-05", ISSUED_BEFORE_NO_EVIDENCE, k1_priv
        ),
    }

    fixture = {
        "_placeholder": False,
        "now": VERIFY_NOW,
        "rotation_boundary": ROTATION_BOUNDARY,
        "verification_method": VERIFICATION_METHOD,
        "issuer": ISSUER,
        "keys": {"K1": k1_pub, "K2": k2_pub},
        "records": records,
        # Keyed by issued_at, the only temporal argument the resolver
        # receives. ISSUED_BEFORE carries evidence (KRH-01 and KRH-04 both
        # claim it); ISSUED_BEFORE_NO_EVIDENCE does not (KRH-05). Records
        # claiming issued_at >= rotation_boundary never consult this map:
        # K2's validity window does not close, so no boundary-dependent
        # evidence question arises for them.
        "boundary_evidence": {
            ISSUED_BEFORE: _evidence(),
        },
    }
    (HERE / "delegations.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
