# Outside reading — aicent-grant-ref, revision 1, from draft-li-rttp-iqa-addressing-02 §8.1–8.2

*Carried out and checked by Andrii Sparysh, using an AI assistant.*

## What was run

This is a Mode B (alternate recomputation) run of the candidate `aicent-grant-ref` in `aps-conformance-suite` at commit `20186f3ebc78de2f34e79a0b4bfe5f828599653b`.

- **Phase 1 (blind).** A checker (`reader/check_reader.py`) was written from sections 8.1 and 8.2 of draft-li-rttp-iqa-addressing-02. It was run on a blind copy of the 25 cases, which contained only input and outcome, under identifiers B01–B25. Its output was frozen as `out/phase1.json` and zipped before the candidate's expected verdicts were opened.
- **Phase 2 (compare).** The phase-1 verdicts were compared with the candidate's `expect` and `expect_parts` (`reader/compare.py` → `out/final.json`).

## Result

The phase-1 checker gave 11 conformant, 12 nonconformant and 2 ambiguous. All 25 verdicts and all four named parts of the two ambiguous cases equal the candidate's expected values. The run also records 18 ambiguity-log entries, 7 draft findings, and 4 of the checker's 12 rules on which no case depends alone.

What the match shows, and what it does not: the checker judges each case's facts as the candidate encodes them, and how each input field maps to a condition of the text was this run's choice, recorded in `ambiguity-log.md`. A full match shows that the expected verdicts follow from the text under that mapping. It tests no implementation, and not how an implementation would establish those facts.

## Re-running

From this directory, with bash, curl and Python 3 (standard library only):

```
bash inputs/aicent-grant-ref-reading-1-fetch-inputs.sh      # fetches pinned files, checks SHA-256, writes inputs/blind and inputs/sealed
python3 -I reader/check_reader.py inputs/draft/draft-li-rttp-iqa-addressing-02.txt inputs/blind/cases.json rerun-phase1.json --sensitivity rerun-sens.json
cmp rerun-phase1.json out/phase1.json && cmp rerun-sens.json out/phase1-sensitivity.json
python3 -I reader/compare.py out/phase1.json inputs/sealed/vectors.json inputs/sealed/id-map.json rerun-final.json
cmp rerun-final.json out/final.json
```

The fetch script takes the draft from `./draft-li-rttp-iqa-addressing-02.txt` if present, otherwise from the IETF archive. The SHA-256 decides which copy is accepted.

## Independence

This run was produced independently. Andrii Sparysh authored none of the candidate, its vectors, its checker or the draft. The checker was written from the draft's text before the expected verdicts were opened. The candidate's `check.py` and `mutate.py` were not downloaded or read.

The lab certifies nothing. This directory is a record of one run. It is not a verdict on the candidate, the draft or any implementation.

## Layout

`run-report.md` (lab fields), `RESULTS.md` (tallies, per-case and sensitivity tables), `PROVENANCE.md`, `ambiguity-log.md`, `findings/` (drafts addressed to the author, not filed), `reader/` (checker and comparison script as run), `out/` (`phase1.json`, `phase1-sensitivity.json`, `final.json`, `changes.md`), `logs/` (fetch, transcript, phase-1 zip digest), `inputs/` (`SHA256SUMS` and the fetch script only), `VECTOR-INVENTORY.md`, `SHA256SUMS.txt`.
