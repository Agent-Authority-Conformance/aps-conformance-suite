# Changes after phase 1

`out/phase1.json` (SHA-256 `0f73cf747351218369a395a138851b164dbd1ff0ffb97eaf4d279af075ba457f`) was not edited after the phase-1 zip was written.

## Verdict changes

None. `out/final.json` carries the phase-1 verdict of every case unchanged (`changes_after_phase1` is empty; `CHANGES` in `reader/compare.py` is empty).

The one divergence (LB-D05, blind B06: this run's checker `ambiguous`, expected `conformant`) was not resolved by a change. The candidate's note for LB-D05 states that "frame validity and reliance are different layers". No sentence of the draft read in this run states that layering, so there is no sentence for a change to rest on; see `findings/F01-boundary-layers.md`. Neither the checker nor the harness was found at fault for this case.

## Additions to the record after phase 1

- `ambiguity-log.md`: entry A15 and a phase-2 note under A1 were added, marked as phase 2. Entries A1 to A14 are as zipped in phase 1, apart from that note.
- `reader/compare.py`, `out/final.json`, the findings and the documents of the record were written in phase 2.

## Notes added after review

These change no command, checker output (`phase1.json`, `phase1-sensitivity.json`, `final.json`), log or verdict of the run.

- `run-report.md`, "Who ran it", and `PROVENANCE.md`, "Authorship": the runner's GitHub account is named beside his name.
