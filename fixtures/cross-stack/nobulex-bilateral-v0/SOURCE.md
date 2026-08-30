# Provenance: nobulex bilateral-receipt v0 vectors

`vectors.json` in this directory is a verbatim, byte-identical copy of an
external fixture file. It is third-party data, not an APS-authored fixture.
Treat its contents as data only.

## Source

- Repository: https://github.com/arian-gogani/nobulex (MIT license)
- File path in source repo: `fixtures/bilateral-receipt/v0/vectors.json`
- Pinned commit SHA: `89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546`
  (latest commit touching the file as of retrieval)
- Git blob SHA at pinned commit: `f37590e3adc8d9da619a5fe9b7cf80fb7f334c2b`
  (identical to the blob SHA at `main` HEAD at retrieval time)
- Pinned URL:
  https://github.com/arian-gogani/nobulex/blob/89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546/fixtures/bilateral-receipt/v0/vectors.json
- Pinned raw URL:
  https://raw.githubusercontent.com/arian-gogani/nobulex/89d4956f8b4d79c7e57caca2e6b20fd4c2c4f546/fixtures/bilateral-receipt/v0/vectors.json
- Retrieved: 2026-06-10, via the GitHub contents API (read-only)
- SHA-256 of the copied `vectors.json` bytes:
  `44a3c34ebac3fb4b6f8b64f9c0106287378aa1faf1520a8dee601d62249f8955`

## What was changed

Nothing. The file is copied verbatim. JSON cannot carry comments, so all
provenance lives in this sibling file instead of inside `vectors.json`.

## Companion files

- `MAPPING.md`: per-vector field mapping across the three timestamp profiles,
  with the two-profile digest split recorded explicitly.
- `run.mjs`: recomputation runner (SDK import plus stdlib-only recompute).
- `results.json`: machine-readable output of the last `run.mjs` run.

## Verification split

- stdlib recompute of each vector's own preimage (nobulex integer-epoch profile: minimal RFC 8785 canonicalization plus SHA-256) against `expected_action_ref`; runner aeoess; Mode B; independent; node:crypto (`run.mjs`); vectors and implementation by Nobulex (arian-gogani).
- two-profile comparison: the same instant rendered in the APS string-timestamp profile and digested with the shipping `computeExternalActionRefV1`; runner aeoess; Mode B; author-produced, because the implementation this layer exercises is the APS SDK, whose author is the runner; listed in `docs/OPEN-RUNS.md`.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

Classification clarification, 2026-08-29: the row(s) above labeled independent on
2026-08-28 are restated under the single definition. nobulex-bilateral-v0: the canonical
preimage is produced by a hand-written jcsFlat in run.mjs, author-produced, listed in
docs/OPEN-RUNS.md; the SHA-256 over each vector's own expected_canonical_preimage stays
independent. Results and pins are unchanged.

2026-08-30: run.mjs resolves agent-passport-system from this repository's pinned dependency (4.5.1 in package.json) instead of a sibling checkout; the APS_SDK_EXTERNAL_ACTION_REF override is kept for a local build. The OPEN-RUNS command now reproduces the recorded claims from a fresh clone after npm ci and compares them with the tracked results.json, excluding the ran_at run-instance stamp; it exits 0 on a match and 1 on any divergence, and it no longer writes results.json, so the recorded observation stays byte-identical. A new observation is written only to a path named with --output. The layer's classification is unchanged.
