#!/usr/bin/env python3
"""Mint chains.json for the lifecycle-subdelegation-edges candidate family.

Every key is an Ed25519 seed derived from a published label below, so this file
carries no secret material and anyone can regenerate the fixture byte for byte.
Nonces are supplied, not generated, which the Python SDK documents as the path
that keeps issuance deterministic. This mirrors the minting pattern in
fixtures/sponsor-handover/mint.py and fixtures/ancestor-revocation-chain/mint.py.

Three artifact groups, one per CASES.md case:

  G7  LC-H-007  a parent window and three children: one nested, one whose
                not_after equals the parent's exactly, and one whose not_after
                extends past the parent's.
  G8  LC-H-008  a chain at its own declared maximum depth, plus a further
                child minted past that limit.
  G9  LC-H-009  a parent revoked at the source, and a child minted afterwards
                by an issuer whose local view of the parent still said active.

The over-extending child in G7 and the over-depth child in G8 cannot be minted
through issue_sub_authority_delegation: the SDK refuses both at issuance, and
the refusal codes it returns are themselves recorded as issuance-layer vectors.
They are produced here by the write-boundary id and signature primitives the
SDK exposes, which is what a non-conforming issuer would do, and the refusal
the SDK raised for each is recorded in refusals below.

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-subdelegation-edges/mint.py

Then `git diff` on chains.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private
from agent_passport.v2.authority_delegation import AuthorityDelegationError
from agent_passport.v2.authority_delegation.canonical import (
    compute_authority_delegation_id_for_write,
    sign_authority_delegation,
)

HERE = Path(__file__).resolve().parent

# The instant issuance-time parent checks are run against while minting. It is
# not the instant any vector verifies at: every vector carries its own `now`.
MINT_NOW = "2026-09-20T12:00:00.000Z"

ORG = "did:aps:example:sde-org"
MGR7 = "did:aps:example:sde-mgr-7"
AGENT7 = "did:aps:example:sde-agent-7"
MGR8 = "did:aps:example:sde-mgr-8"
AGENT8 = "did:aps:example:sde-agent-8"
DEEP8 = "did:aps:example:sde-deep-8"
MGR9 = "did:aps:example:sde-mgr-9"
AGENT9 = "did:aps:example:sde-agent-9"

PARENT_NOT_AFTER = "2026-09-21T00:00:00.000Z"
CHILD_NESTED_NOT_AFTER = "2026-09-20T23:00:00.000Z"
CHILD_WIDENING_NOT_AFTER = "2026-09-25T00:00:00.000Z"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:sde:{label}".encode()).hexdigest()


def _authority(depth: int, not_before: str, not_after: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["calendar:write"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": depth},
        "time": {"not_before": not_before, "not_after": not_after},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }


def _body(parent_id, issuer, subject, issued_at, nonce_label, authority) -> dict:
    return {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "parent_delegation_id": parent_id,
        "issuer": issuer,
        "subject": subject,
        "verification_method": issuer + "#key-1",
        "issued_at": issued_at,
        "nonce": _seed(nonce_label)[:32],
        "authority": authority,
    }


def _sign_without_parent_checks(body: dict, private_key: str) -> dict:
    """Produce a signed record the SDK's issuer would have refused to mint.

    This is the write path an issuer that skips the section 3.6 parent checks
    would take: content-address the body at the write boundary, then sign the
    record. It mints nothing the SDK would not also verify the signature of.
    """
    record = dict(body)
    record["delegation_id"] = compute_authority_delegation_id_for_write(body)
    record["signature"] = sign_authority_delegation(record, private_key)
    return record


def main() -> None:
    privs = {
        ORG: _seed("org:v1"),
        MGR7: _seed("mgr-7:v1"),
        AGENT7: _seed("agent-7:v1"),
        MGR8: _seed("mgr-8:v1"),
        AGENT8: _seed("agent-8:v1"),
        DEEP8: _seed("deep-8:v1"),
        MGR9: _seed("mgr-9:v1"),
        AGENT9: _seed("agent-9:v1"),
    }
    keys = {did + "#key-1": public_key_from_private(priv) for did, priv in privs.items()}

    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)
    always_active = lambda _delegation: "active"

    refusals: dict[str, dict] = {}

    def record_refusal(label: str, fn) -> None:
        try:
            fn()
        except AuthorityDelegationError as err:
            code = str(err).split(":", 1)[0].strip()
            refusals[label] = {"raised": True, "code": code, "message": str(err)}
            return
        refusals[label] = {"raised": False, "code": None, "message": None}

    # ---- G7. LC-H-007, a child validity period against its parent's --------
    p7 = issue_authority_delegation(
        _body(None, ORG, MGR7, "2026-09-20T09:00:00.000Z", "p7-nonce:v1",
              _authority(1, "2026-09-20T09:00:00.000Z", PARENT_NOT_AFTER)),
        privs[ORG],
    )
    c7_nested = issue_sub_authority_delegation(
        p7,
        _body(p7["delegation_id"], MGR7, AGENT7, "2026-09-20T09:30:00.000Z", "c7-nested-nonce:v1",
              _authority(0, "2026-09-20T09:30:00.000Z", CHILD_NESTED_NOT_AFTER)),
        privs[MGR7], now=MINT_NOW,
        resolve_verification_key=resolve_key, resolve_revocation=always_active,
    )
    # not_after exactly equal to the parent's. Containment is inclusive, so the
    # SDK's issuer mints this one.
    c7_equal = issue_sub_authority_delegation(
        p7,
        _body(p7["delegation_id"], MGR7, AGENT7, "2026-09-20T09:31:00.000Z", "c7-equal-nonce:v1",
              _authority(0, "2026-09-20T09:31:00.000Z", PARENT_NOT_AFTER)),
        privs[MGR7], now=MINT_NOW,
        resolve_verification_key=resolve_key, resolve_revocation=always_active,
    )
    widening_body = _body(
        p7["delegation_id"], MGR7, AGENT7, "2026-09-20T09:32:00.000Z", "c7-widening-nonce:v1",
        _authority(0, "2026-09-20T09:32:00.000Z", CHILD_WIDENING_NOT_AFTER),
    )
    record_refusal(
        "c7_widening",
        lambda: issue_sub_authority_delegation(
            p7, widening_body, privs[MGR7], now=MINT_NOW,
            resolve_verification_key=resolve_key, resolve_revocation=always_active,
        ),
    )
    c7_widening = _sign_without_parent_checks(widening_body, privs[MGR7])

    # ---- G8. LC-H-008, subdelegation past a declared maximum depth --------
    # p8 declares two remaining hops, so org -> mgr8 -> agent8 -> deep8 is the
    # deepest chain the declared limit allows. p8_tight declares one hop, so a
    # third link past it is the over-depth case.
    p8 = issue_authority_delegation(
        _body(None, ORG, MGR8, "2026-09-20T09:00:00.000Z", "p8-nonce:v1",
              _authority(2, "2026-09-20T09:00:00.000Z", PARENT_NOT_AFTER)),
        privs[ORG],
    )
    c8 = issue_sub_authority_delegation(
        p8,
        _body(p8["delegation_id"], MGR8, AGENT8, "2026-09-20T09:30:00.000Z", "c8-nonce:v1",
              _authority(1, "2026-09-20T09:30:00.000Z", PARENT_NOT_AFTER)),
        privs[MGR8], now=MINT_NOW,
        resolve_verification_key=resolve_key, resolve_revocation=always_active,
    )
    g8_within = issue_sub_authority_delegation(
        c8,
        _body(c8["delegation_id"], AGENT8, DEEP8, "2026-09-20T09:40:00.000Z", "g8-within-nonce:v1",
              _authority(0, "2026-09-20T09:40:00.000Z", PARENT_NOT_AFTER)),
        privs[AGENT8], now=MINT_NOW,
        resolve_verification_key=resolve_key, resolve_revocation=always_active,
    )
    p8_tight = issue_authority_delegation(
        _body(None, ORG, MGR8, "2026-09-20T09:01:00.000Z", "p8-tight-nonce:v1",
              _authority(1, "2026-09-20T09:01:00.000Z", PARENT_NOT_AFTER)),
        privs[ORG],
    )
    c8_tight = issue_sub_authority_delegation(
        p8_tight,
        _body(p8_tight["delegation_id"], MGR8, AGENT8, "2026-09-20T09:32:00.000Z", "c8-tight-nonce:v1",
              _authority(0, "2026-09-20T09:32:00.000Z", PARENT_NOT_AFTER)),
        privs[MGR8], now=MINT_NOW,
        resolve_verification_key=resolve_key, resolve_revocation=always_active,
    )
    overdepth_body = _body(
        c8_tight["delegation_id"], AGENT8, DEEP8, "2026-09-20T09:42:00.000Z", "g8-overdepth-nonce:v1",
        _authority(0, "2026-09-20T09:42:00.000Z", PARENT_NOT_AFTER),
    )
    record_refusal(
        "g8_overdepth",
        lambda: issue_sub_authority_delegation(
            c8_tight, overdepth_body, privs[AGENT8], now=MINT_NOW,
            resolve_verification_key=resolve_key, resolve_revocation=always_active,
        ),
    )
    g8_overdepth = _sign_without_parent_checks(overdepth_body, privs[AGENT8])

    # ---- G9. LC-H-009, a child minted inside a revocation propagation window
    # p9 is revoked at the source at 10:00:00Z. c9 is minted at 10:05:00Z by an
    # issuer whose last status answer for p9 was taken at 09:55:00Z and said
    # active. Nothing in c9's own bytes records that gap: the issuer's stale
    # observation is a separate record, pinned below.
    p9 = issue_authority_delegation(
        _body(None, ORG, MGR9, "2026-09-20T09:00:00.000Z", "p9-nonce:v1",
              _authority(1, "2026-09-20T09:00:00.000Z", PARENT_NOT_AFTER)),
        privs[ORG],
    )
    c9 = issue_sub_authority_delegation(
        p9,
        _body(p9["delegation_id"], MGR9, AGENT9, "2026-09-20T10:05:00.000Z", "c9-nonce:v1",
              _authority(0, "2026-09-20T10:05:00.000Z", PARENT_NOT_AFTER)),
        privs[MGR9], now="2026-09-20T10:05:00.000Z",
        # The stale local view. This resolver is what the issuer had, not what
        # was true at the source at that instant.
        resolve_verification_key=resolve_key, resolve_revocation=always_active,
    )

    fixture = {
        "_placeholder": False,
        "mint_now": MINT_NOW,
        "verification_keys": keys,
        # Stable role names, so a runner keys a revocation resolver by role
        # rather than by chain-local index.
        "roles": {
            "P7": p7["delegation_id"],
            "C7_NESTED": c7_nested["delegation_id"],
            "C7_EQUAL": c7_equal["delegation_id"],
            "C7_WIDENING": c7_widening["delegation_id"],
            "P8": p8["delegation_id"],
            "C8": c8["delegation_id"],
            "G8_WITHIN": g8_within["delegation_id"],
            "P8_TIGHT": p8_tight["delegation_id"],
            "C8_TIGHT": c8_tight["delegation_id"],
            "G8_OVERDEPTH": g8_overdepth["delegation_id"],
            "P9": p9["delegation_id"],
            "C9": c9["delegation_id"],
        },
        "chains": {
            "H7_NESTED": [p7, c7_nested],
            "H7_EQUAL": [p7, c7_equal],
            "H7_WIDENING": [p7, c7_widening],
            "H8_WITHIN_DEPTH": [p8, c8, g8_within],
            "H8_OVER_DEPTH": [p8_tight, c8_tight, g8_overdepth],
            "H9_PROPAGATION": [p9, c9],
        },
        # What the SDK's own issuer did when asked to mint the two
        # non-conforming children. Recorded, not asserted: the vectors that
        # reference these read them back.
        "refusals": refusals,
        # The issuer's contemporaneous status observation for P9. It is a
        # separate record. A later finding about P9 never rewrites it.
        "issuer_observation_p9": {
            "record_type": "aac:status-observation:v0",
            "about_delegation_id": p9["delegation_id"],
            "observed_by": MGR9,
            "as_of": "2026-09-20T09:55:00.000Z",
            "answer": "active",
            "used_to_issue": c9["delegation_id"],
        },
        # When the revocation of P9 was recorded at the source, and when it
        # became visible to the issuer. c9 was minted between the two.
        "p9_revocation": {
            "recorded_at_source": "2026-09-20T10:00:00.000Z",
            "visible_to_issuer_at": "2026-09-20T10:30:00.000Z",
        },
    }
    (HERE / "chains.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
