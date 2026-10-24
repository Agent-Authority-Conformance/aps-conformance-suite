# Provenance

## Corpus source

| item | value |
|---|---|
| repository | Agent-Authority-Conformance/aps-conformance-suite |
| pull request | #180, "Add candidate lease-revocation-axes family for the W3C revocation timeline" |
| commit read | `b745d252191e89fe123e33411f124a1b67542c2a` |
| fetch date | 2026-10-22 |
| PR head at filing | `86e5e7a` (2026-10-24) |

Commits on the PR branch after the run revision (`bccef3e`, `86e5e7a`) and commits on
`main` after the fetch date touch the family README, repository CI, dependency pins and
other families only. The frozen inputs were re-verified on 2026-10-24: the
`revision-2/vectors.json` served at the PR head hashes to
`a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8`, identical to the
pinned manifest entry below.

## Manifest pin, and its verification

The lab pins the revision-2 inputs by digest in
`fixtures/lease-revocation-axes/revision-2/SHA256SUMS.txt`:

| pinned item | pinned sha256 |
|---|---|
| vectors.json | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` |
| oracle-checkpoints.json | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` |

The data files under `vendor/` are byte-identical to the pinned commit; the vendored
`SHA256SUMS.txt` is the pinned manifest trimmed to the two vendored files. This runner enforces
the pinned vectors digest as a hard gate at load time — it refuses to score any vectors
whose sha256 is not in the manifest — and the gate was verified negatively: a tampered
copy is rejected before any scoring occurs.

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
[`lra-runner-20261023c.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261023c.tar.gz)
(sha256 `94bbaf3c292abf69595bf5782d1db8cbb4178536d53182578b46cff94a5c4b15`), carrying
two addresses derived from its own digest — one per sister scheme, nothing invented,
nothing registered, both resolve live:
[`rttp://94bbaf3c.conformance.iqa`](https://rttp.com/open/?uri=rttp://94bbaf3c.conformance.iqa)
(the question side, WHERE + WHEN) and
[`iqa://94bbaf3c292abf69595bf5782d1db8cb.forge.iqa`](https://iqa.org/open/?uri=iqa://94bbaf3c292abf69595bf5782d1db8cb.forge.iqa)
(the answer side, WHETHER; subject = first 32 hex of the same digest).
