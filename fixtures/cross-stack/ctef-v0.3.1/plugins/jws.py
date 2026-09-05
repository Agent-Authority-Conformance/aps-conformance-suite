"""Compact JWS (RFC 7515) decode + header policy + Ed25519 verify — stdlib only.

Enforces the header policy a CTEF verifier must apply (per #43 review): the
protected header MUST declare `alg: EdDSA`, the resolved key MUST be
`kty: OKP` / `crv: Ed25519`, and the `kid` MUST resolve to exactly one key in
the JWKS. Signature verification uses the Wycheproof-hardened pure-Python
verifier in `ed25519_pure`.
"""
from __future__ import annotations

import base64
import json

from . import ed25519_pure


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class JwsError(Exception):
    pass


def decode_and_verify(jws: str, jwks: dict) -> bytes:
    """Assert header policy, verify the Ed25519 signature, and return the raw
    (still-encoded-decoded) payload bytes. Raises JwsError on any failure."""
    parts = jws.split(".")
    if len(parts) != 3:
        raise JwsError("compact JWS must have three parts")
    h_b64, p_b64, s_b64 = parts

    header = json.loads(_b64url(h_b64))
    if header.get("alg") != "EdDSA":
        raise JwsError(f"header alg must be EdDSA, got {header.get('alg')!r}")
    kid = header.get("kid")
    if kid is None:
        raise JwsError("header must carry a kid")

    matches = [k for k in jwks.get("keys", []) if k.get("kid") == kid]
    if len(matches) != 1:
        raise JwsError(f"kid {kid!r} must resolve to exactly one JWKS key, found {len(matches)}")
    key = matches[0]
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        raise JwsError("resolved key must be kty=OKP, crv=Ed25519")

    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    if not ed25519_pure.verify(_b64url(key["x"]), signing_input, _b64url(s_b64)):
        raise JwsError("Ed25519 signature does not verify")

    return _b64url(p_b64)
