# Open independent runs

One line per layer of a merged external-system family that has no independent run record
yet. Independent means the runner authored neither the family's vectors nor the
implementation that layer exercises (`docs/RUN-REPORT.md`). An independent run of a listed
layer merges as a new record under `interop/` or in the family's `SOURCE.md` and removes
the line here in the same commit; earlier records stay as they were.

This file is a work queue, not a status board. It lists what nobody outside the authors
has recomputed yet, so that a reader can see the corpus's unverified surface in one place.

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

Families under review carry their split at admission; for `oracle-safety-check` (PR #32) the
EIP-712 layer already has an independent record at
`interop/ethers-oracle-safety-check-9b4ffee/` and its APS receipt and delegation layer will
be listed here on merge. Interop records under `interop/` are runs of other projects'
vectors and carry mode and attribution per run; they are not families and are not listed.
