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

Layers with an independent record and therefore not listed: `aat-amdal` (issuer signature
and window bounds, runner aeoess, `cryptography` library, vectors and implementation by
AgentLair); `receipts-amdal` (did:key resolution, JCS bytes, Ed25519 signature, `receipt_id`
recomputation, runner aeoess, stdlib, vectors and implementation by AgentLair);
`nobulex-bilateral-v0` stdlib recompute of each vector's own preimage (runner aeoess,
node:crypto, vectors and implementation by Nobulex).

Families under review carry their verification split at admission and are not listed here.
Interop records under `interop/` are runs of other projects' vectors and carry mode and
attribution per run; they are not families and are not listed.

