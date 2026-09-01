# Provenance: mcp-audit-gateway-v0.6

## Upstream

Repository: [`elang2/mcp-audit-gateway`](https://github.com/elang2/mcp-audit-gateway), Apache 2.0.

Pinned tag: `v0.6.0` (release [`v0.6.0: Cross-SDK Differential Testing`](https://github.com/elang2/mcp-audit-gateway/releases/tag/v0.6.0), 2026-08-24T03:12:22Z).

Pinned commit: `a0f14a0418c2abe6135436f037f6b171735d1e73`. This is a lightweight tag whose ref resolves directly to this commit, verified 2026-08-31 via `gh api repos/elang2/mcp-audit-gateway/git/ref/tags/v0.6.0`.

Files mirrored at that commit:

| File in this family | Upstream path | Size (bytes) | git blob SHA | SHA-256 of file bytes |
|---|---|---|---|---|
| `canonicalization/canonicalization.json` | `test/vectors/canonicalization.json` | 43466 | `8580dff7156500753affb15690a4e7d57d9950dc` | `34f8261aacb666c4bff9e48a2fe7cbda6647a3fb295d371a1a7e8bd5e3826a32` |
| `checkpoint/checkpoint.json` | `test/vectors/checkpoint.json` | 25208 | `4c805e72e294632503eea23f6909c07189ddf4e0` | `1eadd73cef1910c91e911eb57a496bc8e4c373c9c33820233c8b654714877d70` |

Both files are byte-identical to the upstream copies at commit `a0f14a0…`. Verified 2026-08-31 by fetching each file at that ref, byte-counting locally, and running `shasum -a 256`.

## Byte identity across tags

The two vector files are byte-identical across every released tag of `mcp-audit-gateway` from `v0.4.0` through `v0.8.1`, verified 2026-08-31 via `gh api repos/elang2/mcp-audit-gateway/contents/test/vectors/{canonicalization,checkpoint}.json?ref=<tag>` at each tag:

| Tag | Date | canonicalization.json git blob | checkpoint.json git blob |
|---|---|---|---|
| v0.4.0 | 2026-08-23 | `8580dff7156500753affb15690a4e7d57d9950dc` (43466 B) | `4c805e72e294632503eea23f6909c07189ddf4e0` (25208 B) |
| v0.5.0 | 2026-08-26 | `8580dff7…` (same, same size) | `4c805e72…` (same, same size) |
| v0.6.0 | 2026-08-24 | `8580dff7…` | `4c805e72…` |
| v0.7.0 | 2026-08-26 | `8580dff7…` | `4c805e72…` |
| v0.7.1 | 2026-08-26 | `8580dff7…` | `4c805e72…` |
| v0.7.8 | 2026-08-26 | `8580dff7…` | `4c805e72…` |
| v0.8.0 | 2026-08-26 | `8580dff7…` | `4c805e72…` |
| v0.8.1 | 2026-08-29 | `8580dff7…` | `4c805e72…` |

`mcp-audit-gateway`'s versioning rule is that any change touching the canonical form is a version bump, so a pinned tag stays byte-stable and additive vectors land in later tags without invalidating existing pins. The v0.6 pin was chosen because [docker/mcp-gateway#559](https://github.com/docker/mcp-gateway/pull/559) already landed on v0.6 in its own PR body, keeping the citation consistent across the two homes.

## Trigger

Invitation and vocabulary decisions live on the two threads that led to this family.

[docker/mcp-gateway#557](https://github.com/docker/mcp-gateway/issues/557) is the audit-attestation interceptor design thread. aeoess's first comment there ([issuecomment-5381696542](https://github.com/docker/mcp-gateway/issues/557#issuecomment-5381696542), 2026-08-22T17:32Z) pointed at the aps-conformance-suite corpus as reference material for the verifier path and raised the truncation-completeness question. That question led directly to the checkpoint anchoring, rotation-continuity, and chain_break successor semantics captured in this family's `checkpoint/` subdirectory.

[docker/mcp-gateway#557 (issuecomment-5388392662)](https://github.com/docker/mcp-gateway/issues/557#issuecomment-5388392662), 2026-08-23T20:50Z, is the direct PR invitation. aeoess wrote *"A PR from you is probably easiest if you're up for it. We can settle the exact runner shape in review based on what keeps the upstream vectors closest to their original form. DCO sign-off on the commits is the only mechanical requirement."*

[aps-conformance-suite#52](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/52), 2026-08-29T17:41Z, is the pre-PR issue that asked aeoess to lock in naming, layering, and directory shape before this family was built, per CONTRIBUTING.md's *"Ask in an issue before building"* rule.

[aps-conformance-suite#52 (issuecomment-5482476173)](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/52#issuecomment-5482476173), 2026-08-31T18:09Z, is the answering comment. Directory pin: `mcp-audit-gateway-v0.6/`. Structure: one family, two concern subdirectories, matching `argentum-action-ref-v1v2/`'s shape. Failure class: `chain_continuity_violation`, covering the source-native codes `head_missing`, `count_mismatch`, `sequence_regression`. `chain_break` remains a source-native record type in the design, not mapped as a failure. The source's `chain_break` records are valid chain starts whose successors chain from the break record's own hash rather than from genesis, so the discontinuity is signed and undeletable: removing the break record breaks hash-linkage on the record that follows it.

## How the digests were produced

The tuple-array canonical form is defined in `canonicalization.json`'s header block: an explicit field order per record type, integer-only numerics, UTF-16 code-unit key sort, lone-surrogate rejection at the boundary, and M/L type tags on nested maps and lists that make the canonicalization injective. Every `canonical` field in the vector files is the serialized tuple-array form for the record. Every `sha256_canonical` field is the SHA-256 of those bytes as hex-lowercase. No vector's digest was invented or hand-typed; each is the output of the reference implementation at commit `a0f14a0…` (`src/attestation/canonicalize.ts`, `src/attestation/signer.ts`), and each is independently recomputable from the stated preimage using stdlib SHA-256 over the serialized tuple-array bytes.

The canonical form deliberately isn't RFC 8785 JCS. The reasoning lives at [test/vectors/SDK-AUDIT.md at v0.6.0](https://github.com/elang2/mcp-audit-gateway/blob/v0.6.0/test/vectors/SDK-AUDIT.md): a differential-testing pass across the ten official MCP SDKs surfaced 26 wire-level serialization divergences, including six distinct float formatters for the same value across six SDKs. Integer-only avoids the float class entirely; explicit field order avoids the parallel disagreement across Go, Swift, and TypeScript on how to sort object keys; UTF-16 code-unit key sort with rejection of lone surrogates at the boundary avoids the remaining string-encoding divergences.

## Independence

This family was assembled and submitted by the author of `mcp-audit-gateway`. It is the author submitting their own vectors for the lab's independent verification, not a third-party recomputation. Per `CONTRIBUTING.md` (revised 2026-08-29 in PR #49), the independent recompute is arranged by the lab rather than by the contributor. Every layer of this family is `author-produced` in the Verification split until an independent recompute lands as a separate run report. On merge the family joins [`docs/OPEN-RUNS.md`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/main/docs/OPEN-RUNS.md), alongside the current entries for `nobulex-bilateral-v0` and `action-ref-v1-negatives`.

The upstream repository at [`elang2/mcp-audit-gateway`](https://github.com/elang2/mcp-audit-gateway) is the source of truth for these vectors. If a post-v0.6.0 change touches either pinned file's bytes, that change supersedes the mirror here rather than the other way around.

## Boundaries

No signatures in this family. The tuple-array form is the pre-signing canonical payload, not the attestation itself. Ed25519 and HMAC-SHA256 signature verification are tested inside `elang2/mcp-audit-gateway` at `src/attestation/signer.test.ts` and are out of scope here.

Only the canonicalization and checkpoint slices of the `mcp-audit-gateway` vector set are mirrored. `test/vectors/tool-definition-canonicalization.json` (12553 B, first appeared at v0.6.0 and byte-stable from that tag onward) and the C-REC harness under `test/vectors/c-rec/` (added at v0.7.8) are adjacent concerns and are not included, to keep this family small and legible. They can land as follow-on families at their own commit pins if the lab wants them.

The recompute paths under `canonicalization/run.mjs` and `checkpoint/run.mjs` intentionally do not verify signatures or check any policy conformance. Those are downstream of canonicalization and belong in separate families rather than being folded into this one.

Of the three failure codes under the `chain_continuity_violation` class (`head_missing`, `count_mismatch`, `sequence_regression`), only two are exercised by executable vectors in this file. `head_missing` is exercised by the `truncation_detection` block (line 147 carries its `failureCode` value) and `sequence_regression` has its own dedicated section (line 338, with `failureCode` values at lines 340 and 386). `count_mismatch` is a published failure code (described in `failure_codes` at line 446 and illustrated inside `verification_modes.adjacent_delta_check` at line 432) but has no executable vector that raises it. README.md's Verification split table reflects this, listing `truncation_detection` as covering `head_missing` only, and does not claim executable coverage for `count_mismatch`.
