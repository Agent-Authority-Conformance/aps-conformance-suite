# Reading of aicent-lease-boundary (aps-conformance-suite 0e0064b) from draft-li-rttp-iqa-addressing-02

*Carried out and checked by Andrii Sparysh, using an AI assistant.*

## What was run

- **Phase 1, blind.** A checker written from sections 6.1, 6.2, 6.3 and 7.2 of draft-li-rttp-iqa-addressing-02 (with 2, 6.4, 8.1 and 9.2 where they are referred to) decided each of the 15 cases of the blind copy (`basis`, `input`, `outcome` only) as conformant, nonconformant or ambiguous, ran 20 sensitivity variants, verified 27 citations of the draft at start-up, and was run twice with byte-identical output. Its output was zipped before the expected verdicts were opened.
- **Phase 2, compare.** The blind identifiers were mapped to the candidate's, each phase-1 verdict was compared with `expect`, and the parts of the ambiguous cases with `expect_parts`. No verdict was changed.

## Result

Of 15 cases, 14 verdicts match the candidate's expectation and 1 diverges: LB-D05, which this run's checker returns as `ambiguous` and the candidate expects as `conformant`. LB-D04 matches as `ambiguous`, but this run's checker places the open part in the `reason` member, while the candidate scores `answer_within_a_convention` as conformant and `declaration` as ambiguous.

What the match shows, and what it does not: a match shows that this run's checker, written from the draft's text and the blind cases, reached the same verdict as the candidate for that case under the representation rules and the field mappings chosen in this run (`ambiguity-log.md`). It does not show that either reading is the right reading of the text, that the candidate's own checker is correct (it was not read), or anything about any implementation, none of which was run. Several matches rest on choices of this run that the text leaves open (LB-M04 on A3, LB-W01 and LB-W02 on A6). The divergence records that two parties computed different values from the same inputs; either can be wrong.

## Re-running

Run from this directory. The first command calls the fetch script, which downloads the inputs into `rerun/inputs/` and checks their digests.

```
mkdir -p rerun && (cd rerun && bash ../inputs/aicent-lease-boundary-reading-1-fetch-inputs.sh)
python3 -B reader/checker.py --draft rerun/inputs/draft/draft-li-rttp-iqa-addressing-02.txt --cases rerun/inputs/blind/cases.json --out rerun/phase1.json --sensitivity rerun/phase1-sensitivity.json
python3 -B reader/compare.py --phase1 rerun/phase1.json --vectors rerun/inputs/sealed/vectors.json --idmap rerun/inputs/sealed/id-map.json --out rerun/final.json
cmp rerun/phase1.json out/phase1.json
cmp rerun/phase1-sensitivity.json out/phase1-sensitivity.json
cmp rerun/final.json out/final.json
```

The fetch step of these commands was not attempted in this run; the remaining commands were run from copies of the fetched inputs and `cmp` reported no difference (`PROVENANCE.md`, event 8).

## Verification split

- R-DECLARED (LB-D01 to LB-D05); Andrii Sparysh; Mode B; author-produced; `reader/checker.py`
- R-NOEXTEND (LB-E01 to LB-E03); Andrii Sparysh; Mode B; author-produced; `reader/checker.py`
- R-MODE (LB-M01 to LB-M05); Andrii Sparysh; Mode B; author-produced; `reader/checker.py`
- R-WINDOW (LB-W01, LB-W02); Andrii Sparysh; Mode B; author-produced; `reader/checker.py`
- LB-D04 ambiguous, parts `answer_within_a_convention` and `declaration`; Andrii Sparysh; Mode B; author-produced; `reader/checker.py`, `reader/compare.py`

Authorship relationship: the runner wrote the checker that supplies the recomputation.

What the label does not change: Andrii Sparysh authored none of the candidate, its vectors, its checker or the draft. The checker was written from the draft's text and a blind copy of the cases. Its phase-1 output was frozen and zipped before the expected verdicts were opened. The candidate's `check.py` and `mutate.py` were not downloaded or read.

The lab certifies nothing. This directory is a record of one run. It is not a verdict on the candidate, the draft or any implementation.

## Layout

| path | content |
|---|---|
| `README.md` | this file |
| `run-report.md` | the lab's run fields, labels per claim, per-vector table, commands with output |
| `PROVENANCE.md` | sources, files read with digests, sections read, the boundary of this run as kept, events, authorship |
| `RESULTS.md` | tallies, per-case table, sensitivity table, byte-identity check, limits of the checker, environment |
| `ambiguity-log.md` | every place the text admits more than one reading, and the mappings chosen |
| `VECTOR-INVENTORY.md` | digests of the corpus inputs |
| `findings/` | F01 to F05, draft notes to the author, not filed |
| `reader/checker.py` | the phase-1 checker as it ran |
| `reader/compare.py` | the phase-2 comparison as it ran |
| `out/phase1.json`, `out/phase1-sensitivity.json` | phase-1 output, frozen |
| `out/final.json`, `out/changes.md` | phase-2 output and the changes after phase 1 (none to verdicts) |
| `logs/fetch.log` | output of the fetch script |
| `logs/transcript.log` | every recorded command with its output and exit code |
| `logs/sparysh-reading-aicent-lease-boundary-0e0064b-phase1.zip`, `logs/phase1-zip.sha256` | the phase-1 zip as frozen, and its digest |
| `inputs/SHA256SUMS`, `inputs/aicent-lease-boundary-reading-1-fetch-inputs.sh` | input digests and the fetch script |
| `SHA256SUMS.txt` | digests of every other file of this directory |
