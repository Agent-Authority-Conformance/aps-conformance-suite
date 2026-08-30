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

