# ctef-v0.3.1 — CTEF signed fixtures (external-system ingestion)

Signed **CTEF (Composable Trust Evidence Format) v0.3.1** fixtures from
**AgentAvow**, ingested per [a2aproject/A2A#1628](https://github.com/a2aproject/A2A/issues/1628)
and reshaped per the [#43](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/43)
review into a real end-to-end record.

Each fixture is a signed CTEF attestation whose **signed JWS payload is the
RFC 8785 (JCS) canonicalization of the object**. A verifier decodes the payload,
re-canonicalizes it, checks it reproduces the signed bytes, verifies the Ed25519
signature under a header policy, then applies the claim model and expiry.

## Reproduce (no network, no dependencies)

```console
$ python3 validate.py
```

Stdlib-only, Python 3.9+. Exit 0 iff all 32 checks pass. `--json` for machine
output (mirrored in `results.json`).

## What it proves

| check | claim |
|-------|-------|
| **wycheproof** | the vendored Ed25519 verifier accepts every `valid` and rejects every `invalid` in the known-answer set (malleability + non-canonical encoding) |
| **jws-verify** | each fixture's signature verifies against the vendored JWKS under `alg=EdDSA`, `kty=OKP`, `crv=Ed25519`, unique `kid` |
| **recompute** | JCS of the decoded payload reproduces the signed bytes + `canonical_sha256` |
| **admissibility** | `positive-authority` passes; the four negatives fail closed with `INVALID_CLAIM_SCOPE` / `INVALID_COMPOSITION` / `EXPIRED` |
| **tamper** | a flipped signing input is rejected |

The signed payload being the admitted object is the point: a fixture can be
authentic and canonical yet still inadmissible (the negatives).

## Layout

```
ctef-v0.3.1/
├── validate.py              end-to-end adapter (stdlib-only, no network)
├── results.json             author-produced run (32/32)
├── jwks.json                public half of the throwaway fixture key
├── fixtures/
│   ├── positive-authority.json + four signed negatives
│   └── wycheproof-kat.json  Ed25519 known-answer subset
├── plugins/                 jcs, ed25519_pure (Wycheproof-hardened), jws, admissibility
├── SOURCE.md                provenance, keys, attribution, boundaries
└── NOTICE                   MIT (AgentAvow-derived JCS) + ed25519.cr.yp.to
```

Full detail in `SOURCE.md`. A merge is not an APS/lab endorsement — see this
repo's CONTRIBUTING.
