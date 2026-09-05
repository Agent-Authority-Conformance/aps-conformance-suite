"""Vendored, stdlib-only reference implementation for the CTEF v0.3.1 ingestion.

Nothing here reaches the network or depends on a third-party package, so the
whole family recomputes with `python3` alone from the signed fixtures under
`../fixtures/` and the vendored `../jwks.json`.

- `jws.decode_and_verify` — compact-JWS decode + header policy (alg/kty/crv/kid)
  + Ed25519 verification.
- `ed25519_pure.verify` — verification-only Ed25519, hardened to pass the full
  Wycheproof Ed25519 set (canonical encoding, S<L, x=0 sign-bit). Public-domain
  base from ed25519.cr.yp.to.
- `jcs.canonicalize_jcs_strict` — RFC 8785 (JCS) canonicalizer, copied verbatim
  from the CTEF reference implementation.
- `admissibility.admit` — the structural claim-model checker plus the expiry
  validity check.
"""
