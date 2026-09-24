#!/usr/bin/env python3
"""Mint chains.json for the lifecycle-organization-events candidate family.

Keys are Ed25519 seeds derived from the published labels below, so this file
carries no secret material and anyone can regenerate it byte for byte. Nonces
are supplied, not generated, which the Python SDK documents as the path that
keeps issuance deterministic. The minting and key-resolution pattern follows
fixtures/sponsor-handover/mint.py.

Four artifact groups, covering the CASES.md "Organization events" cases that
this family builds vectors for.

  SUCC  LC-B-004  a departed officer's broad root and a narrower interim
                  successor's root, with four leaves under the successor:
                  one inside the successor's own ceiling, one claiming the
                  predecessor's broader scope, and two shapes of the old
                  child re-parented onto the successor.
  MERG  LC-B-012  a chain rooted in the constituent company's officer, a
        LC-B-013  corporate succession attestation that is NOT a delegation
                  record, the same attestation signed by a party with no
                  standing, and a fresh delegation-layer issuance from the
                  surviving company's officer.
  OPS   LC-B-016  one ordinary operating chain, plus the external records the
        LC-B-030  boundary vectors present against it: a dissolution
                  restriction, and three shapes of third-party consent.
  FLOW  LC-B-028  the same operating chain, used by the two in-flight
        LC-B-029  timelines. No extra artifact is needed for those.

External records here (corporate succession attestations, restrictions,
consents) are not delegations. They are small signed objects whose signing
material is the RFC 8785 canonical form of the record without its signature,
so both runners rebuild the identical bytes. They exist so a boundary can be
asked what it does with a record that is authentic and is still not a
delegation-layer event.

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-organization-events/mint.py

Then `git diff` on chains.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation, issue_sub_authority_delegation
from agent_passport.crypto import public_key_from_private, sign
from agent_passport.v2.authority_delegation import AuthorityDelegationError
from agent_passport.v2.authority_delegation.canonical import (
    compute_authority_delegation_id_for_write,
    sign_authority_delegation,
)

HERE = Path(__file__).resolve().parent

MINT_NOW = "2026-09-22T08:00:00.000Z"
NOT_AFTER = "2026-09-30T00:00:00.000Z"

ORG = "did:aps:example:oev-org"
PREDECESSOR = "did:aps:example:oev-predecessor"
INTERIM = "did:aps:example:oev-interim"
AGENT_S = "did:aps:example:oev-agent-s"

COMPANY_A_OFFICER = "did:aps:example:oev-company-a-officer"
COMPANY_B_OFFICER = "did:aps:example:oev-company-b-officer"
A_FORMER_CFO = "did:aps:example:oev-a-former-cfo"
AGENT_M = "did:aps:example:oev-agent-m"

ORG_OPS = "did:aps:example:oev-org-ops"
OPS_MANAGER = "did:aps:example:oev-ops-manager"
AGENT_O = "did:aps:example:oev-agent-o"

COMPANY_A = "did:aps:example:oev-company-a"
COMPANY_B = "did:aps:example:oev-company-b"
REGISTRY_OFFICE = "did:aps:example:oev-registry-office"
VENDOR_C = "did:aps:example:oev-vendor-c"
VENDOR_D = "did:aps:example:oev-vendor-d"

PREDECESSOR_GRANTS = ["contracts:settle", "contracts:sign:new"]
INTERIM_GRANTS = ["contracts:settle", "contracts:sign:renewal"]
OPS_GRANTS = ["contracts:settle", "contracts:sign:new", "orders:place", "payments:submit"]


def _seed(label: str) -> str:
    return hashlib.sha256(f"aps-conformance-suite:oev:{label}".encode()).hexdigest()


def _canonical(value) -> str:
    """RFC 8785 canonical form, for the flat signed objects this file writes."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: [ord(ch) for ch in kv[0]])
        return "{" + ",".join(f"{_canonical(k)}:{_canonical(v)}" for k, v in members) + "}"
    raise TypeError(f"_canonical does not handle {type(value).__name__}")


def _authority(depth: int, grants: list[str], not_before: str) -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": sorted(grants)},
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
        ORG, PREDECESSOR, INTERIM, AGENT_S,
        COMPANY_A_OFFICER, COMPANY_B_OFFICER, A_FORMER_CFO, AGENT_M,
        ORG_OPS, OPS_MANAGER, AGENT_O,
        REGISTRY_OFFICE, VENDOR_C, VENDOR_D,
    ]
    privs = {did: _seed(did.rsplit(":", 1)[-1] + ":v1") for did in dids}
    keys = {did + "#key-1": public_key_from_private(priv) for did, priv in privs.items()}

    resolve_key = lambda _issuer, method, _issued_at: keys.get(method)
    always_active = lambda _delegation: "active"

    refusals: dict[str, dict] = {}

    def record_refusal(label: str, fn) -> None:
        try:
            fn()
        except AuthorityDelegationError as err:
            refusals[label] = {
                "raised": True,
                "code": str(err).split(":", 1)[0].strip(),
                "message": str(err),
            }
            return
        refusals[label] = {"raised": False, "code": None, "message": None}

    def sign_without_parent_checks(body: dict, private_key: str) -> dict:
        record = dict(body)
        record["delegation_id"] = compute_authority_delegation_id_for_write(body)
        record["signature"] = sign_authority_delegation(record, private_key)
        return record

    def sub(parent, issuer, subject, issued_at, label, authority):
        return issue_sub_authority_delegation(
            parent,
            _body(parent["delegation_id"], issuer, subject, issued_at, label, authority),
            privs[issuer], now=MINT_NOW,
            resolve_verification_key=resolve_key, resolve_revocation=always_active,
        )

    def external(body: dict, signer: str) -> dict:
        record = dict(body)
        record["attestor"] = signer
        record["signature"] = sign(_canonical(record), privs[signer])
        return record

    # ---- SUCC. LC-B-004 -------------------------------------------------
    pred_root = issue_authority_delegation(
        _body(None, ORG, PREDECESSOR, "2026-09-22T07:00:00.000Z", "pred-root-nonce:v1",
              _authority(2, PREDECESSOR_GRANTS, "2026-09-22T07:00:00.000Z")),
        privs[ORG],
    )
    pred_to_agent = sub(pred_root, PREDECESSOR, AGENT_S, "2026-09-22T07:10:00.000Z",
                        "pred-to-agent-nonce:v1",
                        _authority(1, PREDECESSOR_GRANTS, "2026-09-22T07:10:00.000Z"))
    succ_root = issue_authority_delegation(
        _body(None, ORG, INTERIM, "2026-09-22T07:20:00.000Z", "succ-root-nonce:v1",
              _authority(2, INTERIM_GRANTS, "2026-09-22T07:20:00.000Z")),
        privs[ORG],
    )
    succ_within = sub(succ_root, INTERIM, AGENT_S, "2026-09-22T07:30:00.000Z",
                      "succ-within-nonce:v1",
                      _authority(1, ["contracts:settle"], "2026-09-22T07:30:00.000Z"))
    # The interim officer signing the predecessor's broader scope. The SDK's
    # issuer refuses this before signing; the refusal code is pinned below.
    succ_wide_body = _body(succ_root["delegation_id"], INTERIM, AGENT_S,
                           "2026-09-22T07:31:00.000Z", "succ-wide-nonce:v1",
                           _authority(1, ["contracts:sign:new"], "2026-09-22T07:31:00.000Z"))
    record_refusal("succ_wide", lambda: issue_sub_authority_delegation(
        succ_root, succ_wide_body, privs[INTERIM], now=MINT_NOW,
        resolve_verification_key=resolve_key, resolve_revocation=always_active))
    succ_wide = sign_without_parent_checks(succ_wide_body, privs[INTERIM])
    # The old child, untouched, presented under the successor's root. Nothing
    # in its bytes changed: it still names the predecessor's root as parent.
    # Second shape: the same child re-pointed at the successor's root and
    # re-signed by the predecessor, who is no longer the parent's subject.
    reparent_resigned = sign_without_parent_checks(
        _body(succ_root["delegation_id"], PREDECESSOR, AGENT_S, "2026-09-22T07:32:00.000Z",
              "reparent-resigned-nonce:v1",
              _authority(1, ["contracts:settle"], "2026-09-22T07:32:00.000Z")),
        privs[PREDECESSOR],
    )

    # ---- MERG. LC-B-012 and LC-B-013 ------------------------------------
    a_root = issue_authority_delegation(
        _body(None, COMPANY_A_OFFICER, AGENT_M, "2026-09-22T07:00:00.000Z", "a-root-nonce:v1",
              _authority(1, ["orders:place"], "2026-09-22T07:00:00.000Z")),
        privs[COMPANY_A_OFFICER],
    )
    b_root = issue_authority_delegation(
        _body(None, COMPANY_B_OFFICER, AGENT_M, "2026-09-22T09:00:00.000Z", "b-root-nonce:v1",
              _authority(1, ["orders:place"], "2026-09-22T09:00:00.000Z")),
        privs[COMPANY_B_OFFICER],
    )
    succession_body = {
        "record_type": "aac:corporate-succession:v0",
        "constituent": COMPANY_A,
        "surviving": COMPANY_B,
        "effective_at": "2026-09-22T08:30:00.000Z",
    }
    succession_with_standing = external(succession_body, REGISTRY_OFFICE)
    succession_without_standing = external(succession_body, A_FORMER_CFO)

    # ---- OPS. LC-B-016 and LC-B-030 -------------------------------------
    ops_root = issue_authority_delegation(
        _body(None, ORG_OPS, OPS_MANAGER, "2026-09-22T07:00:00.000Z", "ops-root-nonce:v1",
              _authority(1, OPS_GRANTS, "2026-09-22T07:00:00.000Z")),
        privs[ORG_OPS],
    )
    ops_leaf = sub(ops_root, OPS_MANAGER, AGENT_O, "2026-09-22T07:10:00.000Z", "ops-leaf-nonce:v1",
                   _authority(0, OPS_GRANTS, "2026-09-22T07:10:00.000Z"))

    dissolution_restriction = external(
        {
            "record_type": "aac:external-restriction:v0",
            "about_principal": ORG_OPS,
            "effective_at": "2026-09-22T08:30:00.000Z",
            "basis": "winding-up",
            # What remains exercisable. Everything outside this list is
            # restricted, and nothing here is revoked.
            "remaining_operations": ["contracts:settle"],
        },
        REGISTRY_OFFICE,
    )
    consent_vendor_c = external(
        {
            "record_type": "aac:third-party-consent:v0",
            "gate_holder": VENDOR_C,
            "target": VENDOR_C,
            "operation": "orders:place",
            "effective_at": "2026-09-22T08:45:00.000Z",
        },
        VENDOR_C,
    )
    consent_vendor_d = external(
        {
            "record_type": "aac:third-party-consent:v0",
            "gate_holder": VENDOR_D,
            "target": VENDOR_D,
            "operation": "orders:place",
            "effective_at": "2026-09-22T08:45:00.000Z",
        },
        VENDOR_D,
    )
    # Authentic, and signed by the acquirer rather than by the party whose own
    # contract holds the gate. Standing, not authenticity, is what fails.
    consent_from_acquirer = external(
        {
            "record_type": "aac:third-party-consent:v0",
            "gate_holder": VENDOR_C,
            "target": VENDOR_C,
            "operation": "orders:place",
            "effective_at": "2026-09-22T08:45:00.000Z",
        },
        COMPANY_B_OFFICER,
    )

    fixture = {
        "_placeholder": False,
        "mint_now": MINT_NOW,
        "verification_keys": keys,
        "roles": {
            "PRED_ROOT": pred_root["delegation_id"],
            "PRED_TO_AGENT": pred_to_agent["delegation_id"],
            "SUCC_ROOT": succ_root["delegation_id"],
            "SUCC_WITHIN": succ_within["delegation_id"],
            "SUCC_WIDE": succ_wide["delegation_id"],
            "REPARENT_RESIGNED": reparent_resigned["delegation_id"],
            "A_ROOT": a_root["delegation_id"],
            "B_ROOT": b_root["delegation_id"],
            "OPS_ROOT": ops_root["delegation_id"],
            "OPS_LEAF": ops_leaf["delegation_id"],
        },
        "chains": {
            "PRED": [pred_root, pred_to_agent],
            "SUCC_WITHIN": [succ_root, succ_within],
            "SUCC_WIDE": [succ_root, succ_wide],
            "REPARENT_STALE": [succ_root, pred_to_agent],
            "REPARENT_RESIGNED": [succ_root, reparent_resigned],
            "A_CHAIN": [a_root],
            "B_CHAIN": [b_root],
            "OPS": [ops_root, ops_leaf],
        },
        # Which principal each chain's root delegation is issued for. A
        # verifier reads the issuer from the root record; this map says which
        # organization that issuer acted for, which the record itself does not.
        "principal_of_root": {
            pred_root["delegation_id"]: ORG,
            succ_root["delegation_id"]: ORG,
            a_root["delegation_id"]: COMPANY_A,
            b_root["delegation_id"]: COMPANY_B,
            ops_root["delegation_id"]: ORG_OPS,
        },
        # Which parties the verifier's trust policy accepts as attestors for
        # each external record type. Standing is a property of the trust
        # policy here, not something a record can claim about itself.
        "attestor_standing": {
            "aac:corporate-succession:v0": [REGISTRY_OFFICE],
            "aac:external-restriction:v0": [REGISTRY_OFFICE],
            # A consent gate is held by the party named in the record, so
            # standing is checked against gate_holder rather than a fixed list.
            "aac:third-party-consent:v0": "gate_holder",
        },
        "external_records": {
            "SUCCESSION_WITH_STANDING": succession_with_standing,
            "SUCCESSION_WITHOUT_STANDING": succession_without_standing,
            "DISSOLUTION_RESTRICTION": dissolution_restriction,
            "CONSENT_VENDOR_C": consent_vendor_c,
            "CONSENT_VENDOR_D": consent_vendor_d,
            "CONSENT_FROM_ACQUIRER": consent_from_acquirer,
        },
        "refusals": refusals,
    }
    (HERE / "chains.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
