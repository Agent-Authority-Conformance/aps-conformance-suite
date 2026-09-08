"""CTEF v0.3.1 admissibility — structural claim-model checks + validity (expiry).

Applied to the object decoded from a signed fixture's JWS payload. Derived from
the CTEF v0.3.1 claim_model. Order: structural (fail-closed) before validity.

  - `claim_type` is REQUIRED and drawn from the closed set
    {identity, transport, authority, continuity}. Missing or unknown ->
    INVALID_CLAIM_SCOPE (a claim with no declared type cannot have its fields
    be in-category).
  - Authority-layer delegation fields (delegation_chain_root / delegation_depth
    / chains) under a non-authority claim_type -> INVALID_CLAIM_SCOPE.
  - An authority claim composing multiple chains with disjoint scopes ->
    INVALID_COMPOSITION (monotonic narrowing yields an empty intersection).
  - Validity: an object whose `expires_at` is at or before the run's
    `verification_time` -> EXPIRED. This is a freshness check, distinct from the
    structural INVALID_CLAIM_SCOPE / INVALID_COMPOSITION codes, and is applied
    only after structural admission passes.

These are CTEF codes, presented as an ingestion; this module mints no suite
vocabulary.
"""
from __future__ import annotations

from datetime import datetime, timezone

CLOSED_CLAIM_TYPES = frozenset({"identity", "transport", "authority", "continuity"})
_AUTHORITY_LAYER_FIELDS = ("delegation_chain_root", "delegation_depth", "chains")


def _parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def admit(envelope: dict, verification_time: str) -> tuple[str, str | None]:
    """Return ("pass", None) or ("fail-closed", <CODE>)."""
    claim_type = envelope.get("claim_type")

    # Structural: claim_type is required and closed.
    if claim_type is None or claim_type not in CLOSED_CLAIM_TYPES:
        return ("fail-closed", "INVALID_CLAIM_SCOPE")

    delegation = envelope.get("delegation") or {}
    carries_authority = any(f in delegation for f in _AUTHORITY_LAYER_FIELDS)

    # Structural: authority-layer fields under a non-authority claim.
    if carries_authority and claim_type != "authority":
        return ("fail-closed", "INVALID_CLAIM_SCOPE")

    # Structural: monotonic narrowing over multiple authority chains.
    if claim_type == "authority" and "chains" in delegation:
        scopes = []
        for chain in delegation["chains"]:
            scope = chain.get("scope")
            scopes.append({scope} if isinstance(scope, str) else set(scope or []))
        effective = set.intersection(*scopes) if scopes else set()
        if not effective:
            return ("fail-closed", "INVALID_COMPOSITION")

    # Validity (post-structural): expiry against the run's verification time.
    expires_at = envelope.get("expires_at")
    if expires_at is not None and _parse_iso(expires_at) <= _parse_iso(verification_time):
        return ("fail-closed", "EXPIRED")

    return ("pass", None)
