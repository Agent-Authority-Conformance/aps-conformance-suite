# Provenance

## Corpus source

| item | value |
|---|---|
| repository | Agent-Authority-Conformance/aps-conformance-suite |
| pull request | #191, "lease-revocation-axes: revision 3 adds refusal_reason and grant_ref to decision records" |
| merge commit | `7774daee77a7766f737c6da71265c9e214b47ff5` (merged 2026-10-25) |
| PR head | `9a28261967bf0d2f9d08ed48f06026871818e816` |
| fetch / re-verification date | 2026-10-26 |

The frozen inputs were re-verified byte-identical at the merged head on 2026-10-26:
`revision-3/vectors.json` served at the merged mainline hashes to
`3b7b3fb97682fb967801641b8ed680a9cae608ff57738a594fc6f0314aac1bb6`, identical to the
pinned manifest entry below. The revision-2 inputs vendored in `vendor/` are the same
bytes recorded in `interop/rttp-iqa-lra-runner-lease-revocation-axes-8cb2e24/`.

## Manifest pins, and their verification

The lab pins the revision-3 inputs by digest in
`fixtures/lease-revocation-axes/revision-3/SHA256SUMS.txt`:

| pinned item | pinned sha256 |
|---|---|
| vectors.json | `3b7b3fb97682fb967801641b8ed680a9cae608ff57738a594fc6f0314aac1bb6` |
| oracle-checkpoints.json | `08293dbd991fe3f76534e176800e15365545a43a6d94e4d89f79d6d58ec7e830` |

The data files under `vendor-r3/` are byte-identical to the pinned head; the vendored
`SHA256SUMS.txt` is the pinned manifest trimmed to the two vendored files. The runner
enforces the pinned vectors digest as a hard gate at load time — it refuses to score
any vectors whose sha256 is not in the manifest — and the gate was verified negatively:
a tampered copy is rejected before any scoring occurs.

The revision-3 manifest also pins `model.json`
(`b71f02f570237a354cf23abd515c1bd1138461016f7eaaed7e83e16d61bc8237`), which this runner
deliberately does not vendor and does not read: the runner's independence rests on
deriving every verdict from the family specification plus the frozen vectors, so every
scored comparison is made against the per-call expected blocks, the pinned mutant
failure sets and the hand-reasoned oracle checkpoints — never against lab model output.

## Run mode and authorship

Run mode: **B** (alternate recomputation), per `docs/RUN-REPORT.md`. Record label:
**author-produced**, with the following authorship relationship.

- The filer authored the alternate implementation (`lra_runner.py`) whose behavior
  supplies the recomputation, so under the definition in `CONTRIBUTING.md` the record
  is not independent.
- The filer authored neither the vectors nor any claim inputs being checked (pack
  author: aeoess). Every scored comparison in this run is made against the per-call
  expected blocks, the pinned mutant failure sets and the hand-reasoned oracle
  checkpoints contained in the lab's vectors file — never against lab model output.
- The implementation is independent of the lab's code: it was written from the family
  specification (`README.md`, `CLARIFICATIONS.md`) and the frozen vectors, is
  stdlib-only Python, shares no code or library with the lab's TypeScript model
  (`verify.ts` / `harness.ts`), and the lab model was reviewed as the interface
  contract only.

Third-party reproductions of this runner (or independent implementations of the
family) are the independent records for this layer.

## Artifact of record

The sealed artifact of this run is
[`lra-runner-20261026a.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261026a.tar.gz)
(sha256 `0bd67a7a89c1a0ff46f72c119ca847868d04b5ca333d5eb35701ff88e7e0d152`), carrying
two addresses derived from its own digest — one per sister scheme, nothing invented,
nothing registered, both resolve live:
[`rttp://0bd67a7a.conformance.iqa`](https://rttp.com/open/?uri=rttp://0bd67a7a.conformance.iqa)
(the question side, WHERE + WHEN) and
[`iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa`](https://iqa.org/open/?uri=iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa)
(the answer side, WHETHER; subject = first 32 hex of the same digest).
