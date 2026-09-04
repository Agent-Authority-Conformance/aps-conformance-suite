# Open independent runs

One line per layer of a merged external-system family that policy permits to land with
author-produced evidence and that does not yet have an independent run record.
`Independent` has the meaning defined in `CONTRIBUTING.md`. A qualifying independent run
of a listed layer merges as a new record under `interop/` or in the family's `SOURCE.md`
and removes the line here in the same commit; earlier records stay as they were.

This file is a work queue, not a status board. It tracks optional independent follow-up
for layers that policy permits to land with author-produced evidence. It is not a complete
inventory of claims awaiting admission, and it is not a deferral mechanism for
independently recomputable claims whose independent record is required before merge.


| family | layer / claim | what an independent run recomputes | command |
|---|---|---|---|
| `fixtures/cross-stack/nobulex-bilateral-v0` | two-profile comparison: nobulex integer-epoch digests against the APS string-timestamp profile via `computeExternalActionRefV1` | render each vector's instant in the string profile and recompute the digest under an implementation other than the APS SDK; report per-vector match or diverge | `node fixtures/cross-stack/nobulex-bilateral-v0/run.mjs` |
| `fixtures/cross-stack/action-ref-v1-negatives` | every layer: the vectors were authored by this lab's maintainer (upstreamed as argentum-core PR #12), so no run by the vector author or by the Argentum implementation author is independent | recompute the five positive `action_ref` digests and the nine drifted `claimed_action_ref` digests from the stated byte forms under any third implementation; confirm each negative fails at its declared stage | `node fixtures/cross-stack/action-ref-v1-negatives/run.mjs` |
| `fixtures/cross-stack/aat-amdal` | window bounds evaluated against each vector's `verification_time`; the comparison is hand written in `runners/aat_runner.py`, so the layer is author-produced | evaluate each vector's window against its `verification_time` under an implementation the runner did not write; report per-vector match or diverge | `python3 runners/aat_runner.py fixtures/cross-stack/aat-amdal/aat-amdal-2026-08-26.json` |
| `fixtures/cross-stack/nobulex-bilateral-v0` | the canonical preimage of each vector under the integer-epoch profile, produced by the hand-written `jcsFlat` in `run.mjs`, so the layer is author-produced | recompute each vector's canonical preimage under an RFC 8785 implementation the runner did not write and compare it byte for byte | `node fixtures/cross-stack/nobulex-bilateral-v0/run.mjs` |
| `fixtures/cross-stack/receipts-amdal` | did:key resolution of the receipt signer, decided by the hand-written base58 and multicodec decoder in `runners/receipt_runner.py`, so the layer is author-produced | resolve each signer's did:key under a third-party resolver and compare the recovered public key | `python3 runners/receipt_runner.py fixtures/cross-stack/receipts-amdal/receipts-amdal-2026-07-29.json` |

Layers with an independent record and therefore not listed: `aat-amdal` (issuer signature,
runner aeoess, `cryptography` library, vectors and implementation by AgentLair);
`receipts-amdal` (JCS bytes, Ed25519 signature, `receipt_id` recomputation, runner aeoess,
Python stdlib for canonicalization and hashing and `cryptography` for Ed25519, vectors and
implementation by AgentLair); `nobulex-bilateral-v0` SHA-256 over each vector's own
`expected_canonical_preimage` (runner aeoess, node:crypto, vectors and implementation by
Nobulex).

Families under review carry their verification split at admission and are not listed here.
Interop records under `interop/` are runs of other projects' vectors and carry mode and
attribution per run; they are not families and are not listed.
| `interop/attenu-guard-0.8.0` | package canonicalization over the corpus canonical-bytes cases at 0.8.0 | the ten canonical byte outputs under attenu-guard 0.8.0, compared byte for byte with fixtures/canonical-bytes | `v/bin/python interop/attenu-guard-0.6.1/jcs-byte-diff.py` with attenu-guard==0.8.0 installed |
| `interop/attenu-guard-0.8.0` | draft-semantics recomputation over the 19 package vectors at 0.8.0 | the nineteen accept and reject verdicts under an independently authored verifier of the draft rules | `v/bin/python interop/attenu-guard-0.6.1/cleanroom/verify_asor00.py` with attenu-guard==0.8.0 installed |
| `interop/attenu-guard-0.11.0-bundles` | bundle verification by the author's runner over the eight bundle vectors at 0.11.0 | the eight accept and reject verdicts and their failure sets under attenu-guard 0.11.0's own `verify_bundle` | `v/bin/python` with attenu-guard==0.11.0 installed, per SOURCE.md direction 1 |
| `interop/attenu-guard-0.11.0-bundles` | bundle verification by a README-derived verifier over the same eight vectors | the eight accept and reject verdicts and their failure sets under an independently authored verifier of the published rules | `cr/bin/python interop/attenu-guard-0.11.0-bundles/cleanroom/verify_bundle_v1.py <bundle_vectors_v1.json>` with rfc8785==0.1.4 |
| `interop/attenu-guard-0.13.0-envelopes` | observer-envelope verification by the author's Python runner over the 18 envelope vectors at revision envelope_vectors_v1.1 | the 18 accept and reject verdicts, their failure sets and every entry's witness-signed or process-asserted state under attenu-guard 0.13.0's own `verify_bundle` | `pkg/bin/python` with attenu-guard==0.13.0 installed, per SOURCE.md direction 1 |
| `interop/attenu-guard-0.13.0-envelopes` | observer-envelope verification by the author's TypeScript runner over the same 18 vectors | the same 18 verdicts, failure sets and states under the npm package's `verifyBundle` | `node run.js <envelope_vectors_v1.json>` with attenu-guard@0.8.0 installed, per SOURCE.md direction 1 |
| `interop/attenu-guard-0.13.0-envelopes` | observer-envelope verification by a README-derived verifier over the same 18 vectors | the same 18 verdicts, failure sets and states under an independently authored verifier of the published rules | `cr/bin/python interop/attenu-guard-0.13.0-envelopes/cleanroom/verify_envelope_v1.py <envelope_vectors_v1.json>` with rfc8785==0.1.4 and cryptography==50.0.1 |
| `interop/ethers-oracle-safety-check-6e8b05b2` | EIP-712 digest and secp256k1 signer recovery over the 13 oracle-safety-check vectors at the merged corpus | the 13 digest and signer comparisons under ethers 6.17.0, with the two declared negatives diverging | `npm ci && node eip712-recompute.mjs <corpus dir>` in that directory, per its SOURCE.md |
| `interop/cleanroom-oracle-safety-check-6e8b05b2` | JCS bytes, SHA-256 and Ed25519 outer witness over the same 13 vectors | the 13 outer-primitive reproductions under rfc8785 and cryptography, no suite or SDK code | `python cleanroom_osc.py <corpus dir>` in that directory, per its SOURCE.md |
