#!/usr/bin/env python3
"""Mint records-single-use.json for the lifecycle-purpose-exhaustion candidate family.

Keys are Ed25519 seeds derived from the published labels below, so this file
carries no secret material and anyone can regenerate it byte for byte. Nonces
are supplied, not generated, which the Python SDK documents as the path that
keeps issuance deterministic. The minting and key-resolution pattern follows
fixtures/sponsor-handover/mint.py.

Four chains, covering the two CASES.md cases in this section:

  SU_GRANT      org -> su_issuer -> G_su
                the single-use artifact of LC-I-013.
  SU_DERIVED    org -> su_issuer -> G_su -> D_su
                an artifact issued out of G_su's first and only use. LC-I-013's
                distinct question is what happens to this one when G_su is
                presented a second time.
  NOTCH_GRANT   org2 -> permit_authority -> G_notch
                the permit of LC-I-014, whose use and whose exhaustion are the
                same recorded event.
  OTHER_DERIVED org3 -> other_issuer -> G_other -> D_other
                an independently rooted derived artifact, used only to show the
                LC-I-013 cascade does not reach past the grant that was reused.

Every not_after here is 2026-09-30T00:00:00.000Z, well past every instant in
the timeline, and each record's not_before is its own issued_at, so no vector in this family can reach its verdict through expiry.
That is deliberate: the whole question is whether exhaustion is a state
separate from expiry and from revocation.

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-purpose-exhaustion/mint_single_use.py

Then `git diff` on records-single-use.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private

HERE = Path(__file__).resolve().parent

MINT_NOW = "2026-09-22T08:00:00.000Z"
NOT_AFTER = "2026-09-30T00:00:00.000Z"

ORG_SU = "did:aps:example:pxs-org-su"
SU_ISSUER = "did:aps:example:pxs-su-issuer"
SU_AGENT = "did:aps:example:pxs-su-agent"
SU_DERIVED_SUBJECT = "did:aps:example:pxs-su-derived"

ORG_NOTCH = "did:aps:example:pxs-org-notch"
PERMIT_AUTHORITY = "did:aps:example:pxs-permit-authority"
NOTCH_AGENT = "did:aps:example:pxs-notch-agent"

ORG_OTHER = "did:aps:example:pxs-org-other"
OTHER_ISSUER = "did:aps:example:pxs-other-issuer"
OTHER_AGENT = "did:aps:example:pxs-other-agent"
OTHER_DERIVED_SUBJECT = "did:aps:example:pxs-other-derived"


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:pxs:{label}".encode()).hexdigest()


def _authority(depth: int, grants: list[str], not_before: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": grants},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": depth},
        "time": {"not_before": not_before, "not_after": NOT_AFTER},
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


def main() -> None:
    dids = [
        ORG_SU, SU_ISSUER, SU_AGENT, SU_DERIVED_SUBJECT,
        ORG_NOTCH, PERMIT_AUTHORITY, NOTCH_AGENT,
        ORG_OTHER, OTHER_ISSUER, OTHER_AGENT, OTHER_DERIVED_SUBJECT,
    ]
    privs = {did: _seed(did.rsplit(":", 1)[-1] + ":v1") for did in dids}
    keys = {did + "#key-1": public_key_from_private(priv) for did, priv in privs.items()}

    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)
    always_active = lambda _delegation: "active"

    def sub(parent, issuer, subject, issued_at, label, authority):
        return issue_sub_authority_delegation(
            parent,
            _body(parent["delegation_id"], issuer, subject, issued_at, label, authority),
            privs[issuer], now=MINT_NOW,
            resolve_verification_key=resolve_key, resolve_revocation=always_active,
        )

    # ---- LC-I-013. The single-use artifact and what was issued out of it ---
    su_root = issue_authority_delegation(
        _body(None, ORG_SU, SU_ISSUER, "2026-09-22T07:10:00.000Z", "su-root-nonce:v1",
              _authority(2, ["exchange:redeem"], "2026-09-22T07:10:00.000Z")),
        privs[ORG_SU],
    )
    g_su = sub(su_root, SU_ISSUER, SU_AGENT, "2026-09-22T07:20:00.000Z", "g-su-nonce:v1",
               _authority(1, ["exchange:redeem"], "2026-09-22T07:20:00.000Z"))
    d_su = sub(g_su, SU_AGENT, SU_DERIVED_SUBJECT, "2026-09-22T07:30:00.000Z", "d-su-nonce:v1",
               _authority(0, ["exchange:redeem"], "2026-09-22T07:30:00.000Z"))

    # ---- LC-I-014. The permit whose use and exhaustion are one event -------
    notch_root = issue_authority_delegation(
        _body(None, ORG_NOTCH, PERMIT_AUTHORITY, "2026-09-22T07:10:00.000Z", "notch-root-nonce:v1",
              _authority(1, ["harvest:record"], "2026-09-22T07:10:00.000Z")),
        privs[ORG_NOTCH],
    )
    g_notch = sub(notch_root, PERMIT_AUTHORITY, NOTCH_AGENT, "2026-09-22T07:20:00.000Z",
                  "g-notch-nonce:v1", _authority(0, ["harvest:record"], "2026-09-22T07:20:00.000Z"))

    # ---- An independently rooted derived artifact, for the blast radius ----
    other_root = issue_authority_delegation(
        _body(None, ORG_OTHER, OTHER_ISSUER, "2026-09-22T07:10:00.000Z", "other-root-nonce:v1",
              _authority(2, ["exchange:redeem"], "2026-09-22T07:10:00.000Z")),
        privs[ORG_OTHER],
    )
    g_other = sub(other_root, OTHER_ISSUER, OTHER_AGENT, "2026-09-22T07:20:00.000Z",
                  "g-other-nonce:v1", _authority(1, ["exchange:redeem"], "2026-09-22T07:20:00.000Z"))
    d_other = sub(g_other, OTHER_AGENT, OTHER_DERIVED_SUBJECT, "2026-09-22T07:30:00.000Z",
                  "d-other-nonce:v1", _authority(0, ["exchange:redeem"], "2026-09-22T07:30:00.000Z"))

    fixture = {
        "_placeholder": False,
        "mint_now": MINT_NOW,
        "verification_keys": keys,
        "roles": {
            "SU_ROOT": su_root["delegation_id"],
            "G_SU": g_su["delegation_id"],
            "D_SU": d_su["delegation_id"],
            "NOTCH_ROOT": notch_root["delegation_id"],
            "G_NOTCH": g_notch["delegation_id"],
            "OTHER_ROOT": other_root["delegation_id"],
            "G_OTHER": g_other["delegation_id"],
            "D_OTHER": d_other["delegation_id"],
        },
        "chains": {
            "SU_GRANT": [su_root, g_su],
            "SU_DERIVED": [su_root, g_su, d_su],
            "NOTCH_GRANT": [notch_root, g_notch],
            "OTHER_DERIVED": [other_root, g_other, d_other],
        },
        # Which grant each presented chain's leaf depends on, and which grant a
        # derived artifact was issued out of. A verifier reads this from the
        # chain itself; it is restated here so a runner does not have to infer
        # the family's own vocabulary from parent_delegation_id.
        "grant_bounds": {
            "G_SU": {"bound": "single_use", "issued_from": None},
            "D_SU": {"bound": "none", "issued_from": "G_SU"},
            "G_NOTCH": {"bound": "notch", "issued_from": None},
            "G_OTHER": {"bound": "single_use", "issued_from": None},
            "D_OTHER": {"bound": "none", "issued_from": "G_OTHER"},
        },
        # Who may sign a record asking to undo an exhaustion. G_NOTCH's issuer
        # holds standing to revoke it; its subject does not. Neither can undo
        # an exhaustion, which is the point LC-I-014-c and LC-I-014-d keep
        # apart from each other.
        "void_standing": {
            "G_NOTCH": {"has_standing": [PERMIT_AUTHORITY], "subject": NOTCH_AGENT},
        },
    }
    (HERE / "records-single-use.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
