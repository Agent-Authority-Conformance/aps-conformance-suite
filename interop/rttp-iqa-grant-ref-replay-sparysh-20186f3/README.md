# RTTP & IQA pipeline replay of sparysh-reading-aicent-grant-ref-20186f3

This directory records our pipeline replay of the merged reading record `sparysh-reading-aicent-grant-ref-20186f3` (merged upstream in PR #234, merge commit `dbf9c245ecca1636344dc7f2e23af7dd8844f58d`, 2026-11-17T20:40:28Z): Andrii Sparysh's blind Mode B recomputation of all 25 expectations of the `aicent-grant-ref` candidate (revision 1, corpus pinned at `20186f3ebc78de2f34e79a0b4bfe5f828599653b`) from sections 8.1-8.2 of `draft-li-rttp-iqa-addressing-02`. The lab's classification, adopted verbatim: the replayed run was blind to the candidate's expected results; its semantic verdicts are labeled author-produced Mode B because Andrii wrote the checker - a reading record, not a certification, not an independent run. The operator of this replay is ShaoBao Li (Lee) / @Aicent-com - the author of the pinned draft and of the replayed family's vectors and checkers, who wrote none of the reading record's checker, comparison script, ambiguity log, or findings.

A replay is a verification of bytes, not a second opinion: this directory adds no verdict logic and re-judges nothing. The generic thin wrapper `replay_runner.py` (code as run, driven by `profile.json`) executes the record's own checker exactly as the record specifies and compares every produced output against the record's recorded bytes; nothing in the wrapper knows the family, the candidate, or the external operator.

## Result

Exit 0, status `replay_matched`: 7 vendor pins and 3 recorded pins verified byte-exact before anything executes (the wrapper fails closed on any mismatch); both commands exit 0 with stdout exactly as the record's run report transcribed (`{"ambiguous": 2, "conformant": 11, "nonconformant": 12}`); all three produced outputs are byte-identical to the recorded artifacts after line-ending normalization (the record's Linux host wrote LF, the replay host on Windows wrote CRLF) and canonically equal as JSON; the recorded comparison reproduces verdict agreement 25/25 with zero named-part divergences. No suspected defective vector was observed.

## Re-run

The wrapper is self-contained in this directory: `replay_runner.py` reads `profile.json`, verifies the vendor and recorded pins, executes the record's two commands over the vendored frozen bytes, and compares the outputs against `recorded/`:

```
python3 -I replay_runner.py . rerun-output.json
cmp rerun-output.json run-output.json
```

Expected output begins with `VENDOR PIN OK 7/7 (profile.json vendor_pins)` and ends with `REPLAY ok: sparysh-reading-aicent-grant-ref-20186f3 reproduced (pins 7, commands 2, outputs 3)`, exit status 0. The replay is deterministic - the machine-readable output carries no timestamps and no paths - and a rerun must reproduce the committed `run-output.json` byte for byte; write your rerun to a different file, as in the command above, so the committed record is preserved untouched, then compare explicitly and treat the run as reproduced only if the comparison reports no difference. The full console output of the recorded replay is preserved verbatim in `run-output.txt`.

## Relationship to the replayed record

The wrapper does not implement any verdict rule; the checker that supplies the verdicts is the record's own `reader/check_reader.py`, executed as code-as-run. The record's material is vendored frozen solely so the digest gate can pin what was on disk and third parties can audit it. The record's ambiguity log and findings are its own analysis, published unchanged in the merged entry and not re-performed here.

## Files

- `profile.json` - the replay profile: pins, commands, expected summary (machine-readable)
- `run-report.md` - the replay report (scope, method, results, limitations)
- `PROVENANCE.md` - operator, mode, authorship relationships, environment
- `RESULTS.md` - per-case results, transcribed from the record's own comparison output
- `replay_runner.py` - the generic thin wrapper, code as run
- `vendor/` - the record's frozen material as run: the checker and comparison script, the pinned draft, the blind copy, the candidate's sealed vectors, description and id-map
- `recorded/` - the record's own recorded outputs (the comparison targets)
- `run-output.json` - the machine-readable record of the replay
- `run-output.txt` - the complete console output of the recorded replay, uncut
- `ENVIRONMENT.txt` - the replay environment
- `SHA256SUMS.txt` - digests of the accompanying files

The canonical sealed copy of this record (sealed artifact, per-cut table, complete 18-block report page) lives at <https://iqa.org/conformance/grant-ref-replay-sparysh/>; the repository copy is `replay/grant-ref-replay-sparysh` in <https://github.com/Aicent-Stack/conformance>.
