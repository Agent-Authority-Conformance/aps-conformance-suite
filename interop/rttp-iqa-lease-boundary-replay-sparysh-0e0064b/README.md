# Pipeline replay — lease-boundary-replay-sparysh (external reading 1 on aicent-lease-boundary)

This directory records **our pipeline replay** of a merged lab record: `sparysh-reading-aicent-lease-boundary-0e0064b` in [Agent-Authority-Conformance/aps-conformance-suite](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/main/interop/sparysh-reading-aicent-lease-boundary-0e0064b) (merged via [PR #238](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/238), 2026-11-23T15:42:40Z, merge commit `87256d7911e70c9c676dcab1dd3bef5855ef0866`). That record is an outside reading of our vector family `aicent-lease-boundary` (revision 1) carried out by **Andrii Sparysh** (GitHub `andreysparish`) from sections 6.1–6.3 and 7.2 of `draft-li-rttp-iqa-addressing-02`: a phase-1 checker written from the draft text, run blind over a shuffled copy of the 15 cases, then compared against the family's expected verdicts. The lab's classification, which we adopt verbatim: the run was **blind to the candidate's expected results**, and its semantic verdicts are labeled **author-produced Mode B because Andrii wrote the checker** (`reader/checker.py`) — a reading record, not a certification, not an independent run. The merged lab entry is the source of record; this directory is a replay of it, not a second opinion.

The replay is our hub-card commitment fulfilled: once the record merged, we ran it through our own pipeline and published the complete report page at [iqa.org/conformance/lease-boundary-replay-sparysh/](https://iqa.org/conformance/lease-boundary-replay-sparysh/). The operator of this replay is ShaoBao Li (Lee) / Aicent Stack — the family's author and the author of the pinned draft, who wrote none of the reading record's checker, comparison script, ambiguity log, or findings.

## What the replay does

The generic thin wrapper [`replay_runner.py`](replay_runner.py), present in this directory, reads `profile.json` here and:

1. verifies the seven vendor pins (the record's checker and comparison script as run, the pinned draft, the frozen blind copy, and the candidate's sealed vectors, description and id-map) — byte-exact against the digests the record itself publishes; any mismatch aborts before anything executes;
2. executes the record's two commands exactly as the record's run report specifies (`checker.py` over the draft and blind copy, then `compare.py` over the produced phase-1 output, the sealed vectors and the id-map);
3. compares every produced output against the record's recorded bytes — byte-identical modulo line endings plus canonical JSON equality, all three recorded artifacts (`phase1.json`, `phase1-sensitivity.json`, `final.json`);
4. asserts the recorded summary (14 of 15 verdicts matching, one documented divergence, tally 8 conformant / 5 nonconformant / 2 ambiguous) and fails closed on any deviation.

The wrapper adds no verdict logic of its own — the checker that supplies the verdicts is the record's own `reader/checker.py`, executed as code-as-run. This record knows nothing that the merged lab record does not publish.

## Result

Exit 0, `status: replay_matched`. All 7 vendor pins and all 3 recorded pins verified; both commands exit 0 with stdout exactly as the record's run report transcribed (`citations verified: 27` and the 15-case tally for phase 1, `match 14, diverge 1` for the comparison); all three produced outputs are byte-identical to the recorded artifacts after line-ending normalization (the record's Linux host wrote LF, the replay host on Windows wrote CRLF) and canonically equal as JSON; the recorded comparison itself reproduces: 14 of 15 verdicts match, the single divergence (LB-D05) is the record's own documented two-reading of section 7.2 (its finding F01), and the tally is 8 conformant / 5 nonconformant / 2 ambiguous. The replay reproduces the record; it does not re-judge it — the value of the match is that the record's bytes are what the record says they are, executable by anyone offline.

## Re-run

From this directory:

```
python3 -I replay_runner.py . rerun-output.json
cmp rerun-output.json run-output.json
```

Expected output begins with `VENDOR PIN OK 7/7 (profile.json vendor_pins)` and ends with `REPLAY ok: sparysh-reading-aicent-lease-boundary-0e0064b reproduced (pins 7, commands 2, outputs 3)`, exit status 0. The replay is deterministic: the machine-readable output carries no timestamps and no paths, and a rerun must reproduce the committed `run-output.json` byte for byte. The full console output of the recorded replay is preserved verbatim in `run-output.txt`.

## Files

- `replay_runner.py` — the generic thin wrapper, code as run
- `profile.json` — the replay profile: pins, commands, expected summary (machine-readable)
- `run-report.md` — the replay report (scope, method, results, limitations)
- `PROVENANCE.md` — operator, mode, authorship relationships, vendor acquisition, environment
- `RESULTS.md` — per-case results, transcribed from the record's own comparison output
- `run-output.json` — the machine-readable record of the replay
- `run-output.txt` — the complete console output of the recorded replay, uncut
- `ENVIRONMENT.txt` — the replay environment
- `vendor/` — the frozen external material as run: the record's checker and comparison script, the pinned draft, the blind copy, the candidate's sealed vectors, description and id-map
- `recorded/` — the record's own recorded outputs (the comparison targets)
- `SHA256SUMS.txt` — digests of the accompanying files
