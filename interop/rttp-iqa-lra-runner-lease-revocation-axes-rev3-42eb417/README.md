# RTTP & IQA Python runner over lease-revocation-axes, revision 3 — Mode B, author-produced

This directory records a Mode B alternate recomputation of the `lease-revocation-axes`
family **revision 3** (merged upstream in PR #191) using the same independently written,
stdlib-only Python runner (`lra_runner.py`, 741 lines) that produced the revision-2
record in `interop/rttp-iqa-lra-runner-lease-revocation-axes-8cb2e24/`. One runner,
two revisions, two recorded outputs.

**Result:** all 48 baseline runs (4 profiles × 12 cases) matched with zero failures —
176 calls, 528 axis comparisons, 176 composite comparisons — and all 12 defective
mutants failed on exactly their pinned case sets (identical to revision 2's sets).
Revision 3 adds refusal semantics: every answer carries `refusal_reason` (five values
under a fixed precedence) and `grant_ref`; 117 of the 176 records deny, and all five
refusal values are exercised. A full run costs ~0.2 s wall-clock.

## Re-run

No build step and no network access are needed: the frozen inputs of both revisions
are vendored, and the runner refuses to score any vectors whose sha256 is not pinned
in the corresponding `SHA256SUMS.txt` (hard digest gate).

```
python lra_runner.py                       # human summary, revision 2 (exit 0 = matched)
python lra_runner.py --json                # full machine-readable report, revision 2
python lra_runner.py --revision 3          # human summary, revision 3
python lra_runner.py --revision 3 --json   # full machine-readable report, revision 3
```

The revision-2 replay over the vendored `vendor/` inputs is byte-identical (modulo
line-ending normalization) to the recorded output of the revision-2 record.

## Files

- `run-report.md` — the run report (required fields per `docs/RUN-REPORT.md`)
- `PROVENANCE.md` — corpus source, manifest pin, run mode and authorship
- `RESULTS.md` — tally, refusal vocabulary, mutation observation, determinism, environment
- `VECTOR-INVENTORY.md` — sha256 of every vendored frozen input, against the lab's pinned manifests
- `SHA256SUMS.txt` — digests of the files in this directory
- `lra_runner.py` — the runner (dual-revision; the script needed to recompute the result)
- `vendor/…` — frozen revision-2 inputs; `vendor-r3/…` — frozen revision-3 inputs
  (each: `vectors.json`, `oracle-checkpoints.json`, trimmed pinned `SHA256SUMS.txt`)
- `run-output.json` — recorded revision-2 output; `run-output-rev3.json` — recorded
  revision-3 output

## Archive of record

The complete artifact (code, frozen inputs of both revisions, run reports, recorded
outputs) is pinned and sealed on the archive of record:
[`lra-runner-20261026a.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261026a.tar.gz),
sha256 `0bd67a7a89c1a0ff46f72c119ca847868d04b5ca333d5eb35701ff88e7e0d152`, at
[iqa.org/conformance/lra-runner-rev3/](https://iqa.org/conformance/lra-runner-rev3/).
The artifact carries two addresses derived from its own digest — one per sister
scheme, nothing invented, nothing registered, both resolve live:

- [`rttp://0bd67a7a.conformance.iqa`](https://rttp.com/open/?uri=rttp://0bd67a7a.conformance.iqa) —
  the question side (WHERE + WHEN); intent = first 8 hex of the artifact digest
- [`iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa`](https://iqa.org/open/?uri=iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa) —
  the answer side (WHETHER); subject = first 32 hex of the same digest, answering at the
  [organ endpoint](https://iqa.org/organ-api/v1/production?subject=0bd67a7a89c1a0ff46f72c119ca84786)
