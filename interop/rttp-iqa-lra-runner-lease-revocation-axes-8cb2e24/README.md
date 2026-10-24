# RTTP & IQA Python runner over lease-revocation-axes — Mode B, author-produced

This directory records a Mode B alternate recomputation of the `lease-revocation-axes`
family (revision 2, candidate, PR #180) using an independently written, stdlib-only
Python runner (`lra_runner.py`, ~650 lines).

**Result:** all 48 baseline runs (4 profiles × 12 cases) matched with zero failures —
176 calls, 528 axis comparisons, 176 composite comparisons — and all 12 defective
mutants failed on exactly their pinned case sets. Three consecutive full runs produce
byte-identical JSON reports; a full run costs ~0.2 s wall-clock.

## Re-run

No build step and no network access are needed: the frozen inputs are vendored and the
runner refuses to score any vectors whose sha256 is not pinned in `SHA256SUMS.txt`
(hard digest gate).

```
python lra_runner.py            # human summary (exit 0 = matched, 1 otherwise)
python lra_runner.py --json     # full machine-readable report
```

Run against the family at PR #180 commit `b745d252191e89fe123e33411f124a1b67542c2a`
(vectors sha256 `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8`,
re-verified against the PR head on 2026-10-24).

## Files

- `run-report.md` — the run report (required fields per `docs/RUN-REPORT.md`)
- `PROVENANCE.md` — corpus source, manifest pin, run mode and authorship
- `RESULTS.md` — tally, mutation observation, determinism, environment
- `VECTOR-INVENTORY.md` — sha256 of every file in this directory
- `SHA256SUMS.txt` — digests of the files in this directory
- `lra_runner.py` — the runner (the script needed to recompute the result)
- `vendor/vectors.json`, `vendor/oracle-checkpoints.json`, `vendor/SHA256SUMS.txt` —
  frozen family inputs, verbatim from the pinned PR #180 revision
- `run-output.json` — machine-readable result of the recorded run
