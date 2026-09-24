#!/usr/bin/env python3
"""Mint fixture.json for the authority-revocation-record fixture, byte for byte.

The positive case is not authored here. It is the TypeScript SDK's committed
`aps:authority-revocation:v1` vector, re-minted from the published inputs and
then checked against the identifiers and signature that vector carries. The
expected values below are copied from
`fixtures/authority-revocation/authority-revocation-vectors-v1.json` in
aeoess/agent-passport-system (sha256
43dbe7fed137269405be38bf829681bc18525a1eccb8e8236e37f03720147ee2), whose
outcomes were produced by the TypeScript reference at commit
f6792af732f2102b239cca6b18840f6fa7d8fe87. If a re-mint no longer reproduces
them this script raises and writes nothing, so the positive vector cannot
drift away from the SDK vector it claims to be.

The six negatives are each one named defect from that record, minted here.
Every one carries correctly recomputed identifiers and a fresh signature
wherever the defect does not forbid it, so exactly one thing is wrong per
vector.

Keys are the SDK vector's own published Ed25519 seeds,
sha256(utf8("agent-passport-system:authority-revocation-vector:<label>")).
The 32 bytes are the seed. They are test keys in a public repository and
control nothing.

Run from the suite root with agent-passport-system 4.2.0 or later installed:

    python3 fixtures/authority-revocation-record/mint.py

Then `git diff` on fixture.json should be empty.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport import issue_authority_delegation
from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private, sign
from agent_passport.v2.authority_revocation import issue_authority_revocation

HERE = Path(__file__).resolve().parent

# --- provenance of the positive case -------------------------------------------------

SDK_REPOSITORY = "aeoess/agent-passport-system"
SDK_VECTOR_PATH = "fixtures/authority-revocation/authority-revocation-vectors-v1.json"
SDK_VECTOR_SHA256 = "43dbe7fed137269405be38bf829681bc18525a1eccb8e8236e37f03720147ee2"
SDK_IMPLEMENTATION_COMMIT = "f6792af732f2102b239cca6b18840f6fa7d8fe87"

EXPECTED_DELEGATION_ID = "sha256:b7e452c7d640c3aeb1ddd0943d75d8a44dfabac8ad96f85c31428a8aa4e895e6"
EXPECTED_DELEGATION_SIGNATURE = (
    "085c9e08b72517aaa3f724a6c2bfeeb307ad017cf468be75bf5cad1c71b1aebf"
    "66ea6068fc2181230e957cd31f2ba7bab030fabbf565971b77532b17b0474b0d"
)
EXPECTED_CASCADE_TRANSACTION_ID = (
    "sha256:62d509615d78dd1a0f72222b78ea887e51a5ec3fbf94113539828af9e8c93137"
)
EXPECTED_REVOCATION_ID = (
    "sha256:2e4a42ace216ca9041e15a5207804af7ad3e213d44563644ba5db721a34b23dc"
)
EXPECTED_REVOCATION_SIGNATURE = (
    "94e7cd2e8ef0faa8523606380ee12b9dd80c29d9bd08f331960607d76f9719a9"
    "343a616008032a143c57edab8528c73877e65296a98aefbc257aa24ff357ac08"
)

# --- domain tags ---------------------------------------------------------------------
#
# The three this record uses, and one tag from a different APS construction. The
# fourth is what the wrong-domain negatives mint against: domain separation exists
# so that bytes minted for one construction can never read as bytes minted for
# another, and a fixture that used an invented tag would not exercise that.

ID_DOMAIN = "APS-AUTHORITY-REVOCATION-ID-V1\x00"
SIGNATURE_DOMAIN = "APS-AUTHORITY-REVOCATION-SIGNATURE-V1\x00"
CASCADE_DOMAIN = "APS-AUTHORITY-REVOCATION-CASCADE-TRANSACTION-ID-V1\x00"
DELEGATION_ID_DOMAIN = "APS-AUTHORITY-DELEGATION-ID-V1\x00"

# --- published inputs ----------------------------------------------------------------

ROOT_AUTHORITY = "did:example:aps-root-authority"
AGENT_ALPHA = "did:example:aps-agent-alpha"
IMPOSTOR = "did:example:aps-impostor"

DELEGATION_ISSUED_AT = "2026-03-01T00:00:00.000Z"
DELEGATION_NONCE = "0f0e0d0c0b0a09080706050403020100"
NOT_BEFORE = "2026-03-01T00:00:00.000Z"
NOT_AFTER = "2026-04-01T00:00:00.000Z"

REVOKED_AT = "2026-03-15T12:00:00.000Z"
REVOCATION_NONCE = "3c3d3e3f404142434445464748494a4b"
REASON_CODE = "issuer-key-compromise"
DETAIL = "Issuer signing key retired after a hardware replacement."

# A second, equally well-formed origin. Its cascade transaction identity is what
# ARR-06 carries: a shape-valid identity that is bound to different content.
FOREIGN_NONCE = "4c4d4e4f505152535455565758595a5b"

UNKNOWN_RECORD_TYPE = "aps:authority-revocation-record:v1"


def seed(label: str) -> str:
    return hashlib.sha256(
        f"agent-passport-system:authority-revocation-vector:{label}".encode()
    ).hexdigest()


def content_address(domain: str, value: dict) -> str:
    return "sha256:" + hashlib.sha256((domain + canonicalize_jcs(value)).encode("utf-8")).hexdigest()


def mint(
    content: dict,
    private_key: str,
    *,
    id_domain: str = ID_DOMAIN,
    signature_domain: str = SIGNATURE_DOMAIN,
    cascade_domain: str = CASCADE_DOMAIN,
    cascade_transaction_id: str | None = None,
) -> dict:
    """Build a record from `content`, the members minus the two identifiers and the
    signature, following the shipped construction unless a caller overrides a domain.

    `cascade_transaction_id`, when given, is written instead of the one this content
    derives, which is the only way to mint a record whose cascade identity is not
    bound to its own originating content.
    """
    body = dict(content)
    body["cascade_transaction_id"] = (
        cascade_transaction_id
        if cascade_transaction_id is not None
        else content_address(cascade_domain, content)
    )
    unsigned = dict(body)
    unsigned["revocation_id"] = content_address(id_domain, body)
    record = dict(unsigned)
    record["signature"] = sign(signature_domain + canonicalize_jcs(unsigned), private_key)
    return record


def authority() -> dict:
    return {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["commerce:checkout"]},
        "spend": {
            "mode": "bounded",
            "unit": "iso4217:USD:minor",
            "per_action": "2500",
            "cumulative": "50000",
        },
        "depth": {"remaining": 2},
        "time": {"not_before": NOT_BEFORE, "not_after": NOT_AFTER},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 75},
        "values": {"profile": "aps-values-identifiers-v1", "required": ["F-001", "F-003"]},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "compensable"},
    }


def main() -> None:
    issuer_priv = seed("issuer-key")
    rotated_priv = seed("issuer-rotated-key")
    impostor_priv = seed("impostor-key")

    delegation = issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": ROOT_AUTHORITY,
            "subject": AGENT_ALPHA,
            "verification_method": ROOT_AUTHORITY + "#key-1",
            "issued_at": DELEGATION_ISSUED_AT,
            "nonce": DELEGATION_NONCE,
            "authority": authority(),
        },
        issuer_priv,
    )
    if delegation["delegation_id"] != EXPECTED_DELEGATION_ID:
        raise SystemExit(
            "target delegation drifted from the SDK vector: "
            f"{delegation['delegation_id']} != {EXPECTED_DELEGATION_ID}"
        )
    if delegation["signature"] != EXPECTED_DELEGATION_SIGNATURE:
        raise SystemExit("target delegation signature drifted from the SDK vector")

    control = issue_authority_revocation(
        delegation,
        now=REVOKED_AT,
        revoker=ROOT_AUTHORITY,
        verification_method=ROOT_AUTHORITY + "#key-1",
        reason_code=REASON_CODE,
        nonce=REVOCATION_NONCE,
        detail=DETAIL,
        private_key=issuer_priv,
    )
    for field, expected in (
        ("cascade_transaction_id", EXPECTED_CASCADE_TRANSACTION_ID),
        ("revocation_id", EXPECTED_REVOCATION_ID),
        ("signature", EXPECTED_REVOCATION_SIGNATURE),
    ):
        if control[field] != expected:
            raise SystemExit(
                f"control revocation drifted from the SDK vector on {field}: "
                f"{control[field]} != {expected}"
            )

    # The members the shipped construction signs, minus the two identifiers and the
    # signature. Every negative below starts from exactly this content.
    content = {
        "record_type": "aps:authority-revocation:v1",
        "version": "1.0",
        "delegation_id": delegation["delegation_id"],
        "revoker": ROOT_AUTHORITY,
        "verification_method": ROOT_AUTHORITY + "#key-1",
        "revoked_at": REVOKED_AT,
        "reason_code": REASON_CODE,
        "detail": DETAIL,
        "nonce": REVOCATION_NONCE,
    }
    if mint(content, issuer_priv) != control:
        raise SystemExit("mint() does not reproduce the SDK's own construction")

    # ARR-02. revocation_id hashed under the AuthorityDelegationV1 identifier tag.
    # Every other byte of the construction is the shipped one, and the signature is
    # minted over the record as it stands, so the tag is the only defect.
    wrong_id_domain = mint(content, issuer_priv, id_domain=DELEGATION_ID_DOMAIN)

    # ARR-03. Signature over the identifier tag instead of the signature tag. Both
    # identifiers recompute.
    wrong_signature_domain = mint(content, issuer_priv, signature_domain=ID_DOMAIN)

    # ARR-04. The revocation time is not a member, so it is not inside any of the
    # three preimages. The schema is closed, so there is no other member it could
    # ride in: a record under this format either signs its revocation time or does
    # not carry one. Both identifiers and the signature are minted over the
    # truncated content.
    without_time = {k: v for k, v in content.items() if k != "revoked_at"}
    revocation_time_unsigned = mint(without_time, issuer_priv)

    # ARR-05. A record_type this version does not define. Identifiers and signature
    # are minted over the changed content, so nothing but the type is wrong.
    unknown_type_content = dict(content)
    unknown_type_content["record_type"] = UNKNOWN_RECORD_TYPE
    unknown_record_type = mint(unknown_type_content, issuer_priv)

    # ARR-06. A cascade transaction identity of the right shape, derived from a
    # different origin: the same revocation with a different nonce. revocation_id is
    # recomputed over the body carrying it and the record is re-signed, so the
    # cascade binding is the only thing that does not hold.
    foreign_origin = dict(content)
    foreign_origin["nonce"] = FOREIGN_NONCE
    foreign_cascade_transaction_id = content_address(CASCADE_DOMAIN, foreign_origin)
    cascade_not_bound = mint(
        content, issuer_priv, cascade_transaction_id=foreign_cascade_transaction_id
    )

    fixture = {
        "_placeholder": False,
        "provenance": {
            "positive_case": {
                "repository": SDK_REPOSITORY,
                "vector_file": SDK_VECTOR_PATH,
                "vector_file_sha256": SDK_VECTOR_SHA256,
                "implementation_commit": SDK_IMPLEMENTATION_COMMIT,
                "vector_name": "valid-direct-revocation",
                "note": (
                    "ARR-01 is that vector's valid_case record. mint.py re-mints it from "
                    "the published seeds and inputs and refuses to write this file unless "
                    "it reproduces the vector's delegation_id, cascade_transaction_id, "
                    "revocation_id and both signatures byte for byte."
                ),
            },
            "negatives": "Minted by this script from the same content, one defect each.",
        },
        "domain_tags": {
            "revocation_id": ID_DOMAIN,
            "signature": SIGNATURE_DOMAIN,
            "cascade_transaction_id": CASCADE_DOMAIN,
            "foreign_delegation_id": DELEGATION_ID_DOMAIN,
        },
        "keys": {
            "issuer_priv": issuer_priv,
            "issuer_rotated_priv": rotated_priv,
            "impostor_priv": impostor_priv,
        },
        "key_resolver": {
            "description": (
                "Look up the (controller, verification_method) pair. When no entry "
                "matches, or when the record's revoked_at is earlier than the entry's "
                "key_valid_from, answer not_found. Otherwise answer public_key_hex. The "
                "verifier hands the resolver the TARGET delegation's issuer as the "
                "controller, never the revocation's own revoker."
            ),
            "entries": [
                {
                    "controller": ROOT_AUTHORITY,
                    "verification_method": ROOT_AUTHORITY + "#key-1",
                    "key_valid_from": "2026-03-01T00:00:00.000Z",
                    "public_key_hex": public_key_from_private(issuer_priv),
                    "key_label": "issuer-key",
                },
                {
                    "controller": ROOT_AUTHORITY,
                    "verification_method": ROOT_AUTHORITY + "#key-2",
                    "key_valid_from": "2026-03-10T00:00:00.000Z",
                    "public_key_hex": public_key_from_private(rotated_priv),
                    "key_label": "issuer-rotated-key",
                },
                {
                    "controller": IMPOSTOR,
                    "verification_method": IMPOSTOR + "#key-1",
                    "key_valid_from": "2026-03-01T00:00:00.000Z",
                    "public_key_hex": public_key_from_private(impostor_priv),
                    "key_label": "impostor-key",
                },
            ],
        },
        "target_delegation": delegation,
        "records": {
            "control": control,
            "revocation_id_wrong_domain": wrong_id_domain,
            "signature_wrong_domain": wrong_signature_domain,
            "revocation_time_outside_signed_content": revocation_time_unsigned,
            "unknown_record_type": unknown_record_type,
            "cascade_transaction_id_not_bound": cascade_not_bound,
        },
        "out_of_band": {
            "revoked_at": REVOKED_AT,
            "note": (
                "The revocation time ARR-04's record does not carry. Kept here rather "
                "than in the record because the closed schema has no member that could "
                "hold it outside the signed content."
            ),
        },
        "foreign_cascade_origin": {
            "nonce": FOREIGN_NONCE,
            "cascade_transaction_id": foreign_cascade_transaction_id,
            "note": (
                "The origin ARR-06's cascade_transaction_id is bound to: this record's "
                "content with a different nonce."
            ),
        },
    }
    (HERE / "fixture.json").write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
