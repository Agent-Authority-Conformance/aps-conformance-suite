# Provenance: ctef-v0.3.1

External-system vector family: **CTEF (Composable Trust Evidence Format) v0.3.1**,
ingested as a set of **signed, self-owned CTEF fixtures**. Nothing here reaches
the network; every check recomputes from the bytes in this directory with
`python3` alone. Reshaped per the #43 review so the record is a real end-to-end
"re-canonicalize, verify, admit, compare" rather than a canonicalize-then-verify-
a-different-artifact.

## What a fixture is
Each file in `fixtures/` (except the KAT) is a signed CTEF `TrustAttestation`
whose **signed JWS payload IS the RFC 8785 (JCS) canonicalization of
`input_object`**. The adapter decodes the payload, re-canonicalizes it, asserts
it reproduces the signed bytes (`canonical_bytes_utf8` / `canonical_sha256`),
verifies the Ed25519 signature under a header policy, then applies the claim
model + expiry and compares to `expected_result` / `expected_error_code`.

| fixture | expected |
|---|---|
| `positive-authority` | pass |
| `negative-scope-violation` | fail-closed · `INVALID_CLAIM_SCOPE` (identity claim carrying authority delegation) |
| `negative-composition-failure` | fail-closed · `INVALID_COMPOSITION` (disjoint authority scopes) |
| `negative-missing-claim-type` | fail-closed · `INVALID_CLAIM_SCOPE` (`claim_type` is required) |
| `negative-expired` | fail-closed · `EXPIRED` (a validity check vs `verification_time`, distinct from the structural codes) |

Each fixture carries a fixed `verification_time` (`2026-09-03T00:00:00Z`) that the
expiry check runs against, so expiry is deterministic.

## Keys and self-ownership
The fixtures are signed with a **dedicated, throwaway fixture key** generated for
this family; its public half is in `jwks.json` (`kid: ctef-fixture-v1`, OKP /
Ed25519). The private key is not published and secures nothing — it exists only
to author these fixtures. The subject is a **self-owned synthetic**
(`agentgraph-co/ctef-conformance-fixture`); the family contains **no verdict about
any third party** (the previous run's `mcp-playwright.jws` — a live security
verdict about `executeautomation/mcp-playwright` — is removed, per review). Nothing
here depends on AgentAvow's production signing key or on any live endpoint.

## Vendored reference implementation (`plugins/`)
- **`jcs.py`** — `canonicalize_jcs_strict`, copied verbatim from `src/signing.py`
  in the AgentAvow repo (the CTEF reference implementation). **Label caveat:** it
  is byte-identical to RFC 8785 JCS **on the subset these fixtures exercise**; it
  sorts keys by Unicode code point and formats numbers Python-style, which is not
  the full RFC 8785 number grammar. It does not diverge on these inputs: they are
  strings, ints, bools, and null, plus one float (`attestation.confidence` = 0.9),
  which serializes identically (`0.9`) under both this canonicalizer and RFC 8785,
  so the number-grammar difference does not bite here. MIT notice for the
  AgentAvow-derived code is in `NOTICE`.
- **`ed25519_pure.py`** — verification-only Ed25519, public-domain base from
  **ed25519.cr.yp.to** (not RFC 8032 Appendix A), **hardened to pass the full
  Wycheproof Ed25519 set**: canonical-encoding check (rejects `y >= p` and the
  `x = 0` set-sign-bit encoding), `S < L` scalar-range check (rejects the
  `S, S+L … S+8L` malleability family and `S` above the group order). A
  known-answer subset is vendored at `fixtures/wycheproof-kat.json` and run by the
  adapter.
- **`jws.py`** — compact-JWS decode + **header policy** (`alg == EdDSA`,
  resolved key `kty == OKP` / `crv == Ed25519`, `kid` resolves to exactly one
  JWKS key) + Ed25519 verify.
- **`admissibility.py`** — structural claim-model checker (`claim_type` required
  and closed; authority-field scope; multi-chain composition) plus the expiry
  validity check.

## Reproduce
`python3 validate.py` — 25 checks: 9 Wycheproof known-answers (3 valid + the 6
deciding invalids), then per fixture across the 5 fixtures (jws-verify +
recompute + admissibility = 15), plus a tamper control. Stdlib-only, no network,
runs on Python 3.9+. Author-produced results in `results.json` (**25/25**, this
build). `.gitattributes` marks the fixtures `-text` so no EOL/encoding
normalization perturbs the signed bytes on any checkout.

## Trigger
- [a2aproject/A2A#1628](https://github.com/a2aproject/A2A/issues/1628) — aeoess
  invited the CTEF vectors into the lab.
- Reshaped per the [#43](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/43)
  review (2026-08-29): real end-to-end signed fixtures, a Wycheproof-conformant
  verifier, header policy, `claim_type`/expiry admissibility, corrected
  attribution and canonicalizer labeling, and no third-party verdict.

## Verification split
One entry per verification claim, attributed to its runner (required by CONTRIBUTING).

- Canonical bytes + `canonical_sha256` reproduce; runner `validate.py`; Mode A; **author-produced** locally (fixtures and `jcs.py` are AgentAvow's); implementation: vendored `plugins/jcs.py`. **Independent** recompute (rfc8785 0.1.4, runner aeoess) merged at #71 under `interop/`.
- JWS signature validity (the Ed25519 signature over the signing input verifies); runner `validate.py`; Mode A; **independent** for this layer — the recomputation is supplied by an independent implementation (cryptography 49.0.0, runner aeoess) merged at #71; author-produced locally via `plugins/ed25519_pure.py`.
- Ed25519 verifier is Wycheproof-conformant; runner `validate.py` (KAT); Mode A; **author-produced** (the verifier supplying the recomputation is AgentAvow's, though the Wycheproof vectors are independent); implementation: `plugins/ed25519_pure.py` against C2SP/wycheproof vectors. **Independent** full-corpus run through this verifier (runner aeoess) merged at #71.
- JWS header-policy enforcement (`alg=EdDSA`, key `kty=OKP`/`crv=Ed25519`, unique `kid`); runner `validate.py`; Mode A; **author-produced** (the policy check is AgentAvow's `plugins/jws.py`); implementation: `plugins/jws.py`. Listed in `docs/OPEN-RUNS.md` for an independent run.
- Admissibility outcomes (claim model + expiry); runner `validate.py`; Mode A; **author-produced** locally (the family exercises only AgentAvow's `admissibility.py`); implementation: `plugins/admissibility.py`. **Independent** record: an independent claim-model checker (giskard09, built from the published vectors only, pinned at `fd256bc4`) run by aeoess — 5/5 verdicts + error codes match — merged at `interop/ctef-v0.3.1-admissibility-checker-fd256bc4-run-aeoess/` (#79), with giskard09's own author-produced run beside it at `interop/ctef-v0.3.1-admissibility-giskard09-a642c17/`.
- Tamper rejection (a mutated signing input is refused at the signature check); runner `validate.py`; Mode A; **author-produced** (AgentAvow's `plugins/jws.py` + `plugins/ed25519_pure.py`). Listed in `docs/OPEN-RUNS.md` for an independent run.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Boundaries
- CTEF ingestion. `INVALID_CLAIM_SCOPE`, `INVALID_COMPOSITION`, and the `EXPIRED`
  validity code are CTEF's, presented as an external system's vocabulary — not a
  proposal to add names to this suite's taxonomy. This PR touches no suite verifier
  or schema; it does modify the root README inventory table and
  `fixtures/cross-stack/index.json`, as family registration requires.
- Per CONTRIBUTING, a merge means the fixtures verified as deterministic, in
  scope, and correctly labeled — **not** an endorsement, adoption, or partnership
  by APS or the lab.
