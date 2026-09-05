# Lab recompute of the crypto-layer claims of the ctef-v0.3.1 family at PR #43 head a642c17f

Family under review: `fixtures/cross-stack/ctef-v0.3.1/` as proposed in
[PR #43](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/43) at head
`a642c17f2b5b003d403d7d0faec4b72910afb787` (family tree `db0467d0e96df365350f92723cf9b16a5fb6bb63`).
The family is not on `main` at the time of this run. This record is pinned to those bytes; a later
head with different fixture bytes gets a new record, this one is not edited.

This record supersedes `interop/crypto-recompute-ctef-v0.3.1-a71b7329`, which speaks about head
`a71b7329ff34e92523281a1cf98a00a80c0237ef`. Between the two heads the fixture signing key was
rotated (`jwks.json` `x` moves to `KE3Lgb85eyrk3AWSgJwqI-3sJOiehqTPFuvmrUogK2Q`, `kid` unchanged)
and all five fixtures were re-signed, so seven of the eight input pins moved;
`plugins/ed25519_pure.py` is byte-identical at both heads. The vendored known-answer subset went
from 16 entries to 9.

## Provenance of this run, stated exactly

- Executed 2026-09-05 by aeoess (lab maintainer) on macOS arm64, Python 3.14.6, against the eight
  family inputs and the corpus file whose SHA-256 digests are pinned in `recompute.py`. The
  script refuses (exit 2) if any input differs from its pin, so the record speaks only about
  these bytes.
- Corpus: C2SP/wycheproof `testvectors_v1/ed25519_test.json` at commit
  `5722833ca004983abd1a91bcb6c24596d50ac0f9` (2026-08-11), 151 tests,
  sha256 `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536`.
- Implementations that supply the recomputation: `rfc8785==0.1.4` (Trail of Bits) for the
  canonical bytes and digests; `cryptography==49.0.0` for the Ed25519 JWS signatures; the
  contributor's `plugins/ed25519_pure.py` (implementation under test) run against the corpus's
  published expected results. `recompute.py` transports the pinned inputs and compares outputs;
  it does not implement or evaluate the family's CTEF admissibility semantics.

## What was run

`pip install -r requirements.txt`, then
`python3 recompute.py <family dir at a642c17f> <ed25519_test.json at 5722833c>`.

## Result (`results-recompute.txt`, verbatim)

19/19: the nine input digests match their pins; for each of the five signed fixtures, the
RFC 8785 canonicalization of `input_object` under rfc8785 equals the signed JWS payload bytes
and `canonical_bytes_utf8`, its SHA-256 equals `canonical_sha256`, and the JWS signature
verifies under cryptography against the `kid` in the vendored JWKS; the contributor's verifier
accepts 88/88 valid and rejects 63/63 invalid corpus cases with no mismatches; the vendored
known-answer subset (9 entries) is byte-identical to the corpus entries it names.

## Not covered, deliberately

The admissibility outcomes (`INVALID_CLAIM_SCOPE`, `INVALID_COMPOSITION`, `EXPIRED`) are not
covered here: this family exercises only the contributor's implementation of the claim semantics,
and a lab-written implementation would be author-produced. Also not covered are the family's
header-policy and tamper-control claims, or canonicalizer-equivalence claims beyond these five
inputs. The review of PR #43 records what the vendored known-answer subset does and does not pin.

## Verification split

- JCS canonical bytes and SHA-256 of `input_object`, 5 fixtures; runner aeoess; Mode B;
  independent; rfc8785 0.1.4 (the runner authored neither the fixtures nor rfc8785).
- Ed25519 JWS signature over the signing input, 5 fixtures; runner aeoess; Mode B; independent;
  cryptography 49.0.0 (the runner authored neither the fixtures nor cryptography).
- Verifier behaviour against the full Wycheproof Ed25519 set, 151 cases; runner aeoess; Mode A;
  independent; implementation under test `plugins/ed25519_pure.py` at a642c17f, expected results
  from C2SP/wycheproof at 5722833c (the runner authored neither the verifier nor the corpus).

These records are attributed per layer. Merge of this family is not an end-to-end verification
or a family-level verdict.
