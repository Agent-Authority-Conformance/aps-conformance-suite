# Reading of cirisai-ceg-rows (aps-conformance-suite 7a8b392) from draft-moore-scitt-ciris-ceg-03

*Carried out and checked by Andrii Sparysh, using an AI assistant.*

## What was run

- **Pass 2, blind.** A reader written from draft-moore-scitt-ciris-ceg-03 decided 107 of the 154 cases: the `statement`, `payload`, `value` and `object` levels. It used Sections 2, 4, 5, 6, 7.1 and 8 and Appendices A and B. It saw only `inputs/`. Its answers were frozen, and their digests recorded, before `expected.json` was opened. Pass 1 was an earlier blind run of the same reader; the three changes from pass 1 to pass 2 were made before `expected.json` was opened (`out/changes.md`).
- **Comparison.** Each blind answer was compared with `expected.json`. No blind answer was changed.
- **Pass 3, after the comparison.** Three omissions of this reader were fixed: it did not read the disclosures in `sd_claims`, it did not check `attestation_evidence`, and it did not use the case level to require an object typ. Pass 3 is reported apart from pass 2 and changes no reading of the text.
- **Not run.** The 47 `family` cases. They need the family registry of the cited Constitution, which the draft does not restate, as the candidate itself says.

## Result

Of 107 cases read blind, 68 answers match `expected.json` exactly: statement 43 of 73, payload 12 of 17, value 8 of 11, object 5 of 6. Pass 3 adds one (object 6 of 6).

- **All signature answers agree.** The two `bad_signature` cases are refused, and the composite signature verifies on every statement both sides find valid.
- **All values of valid answers agree.** Where both sides answer Valid, the row id, statement id, kid, iss and object id that `expected.json` gives are the ones this run computed.
- **The draft's own known answer reproduces.** The row id of Appendix B.1 is recomputed from the draft's bytes alone (`reader/b1_check.py`).
- **The keys reproduce.** The six public keys of `inputs/keys.json` are the keys their seeds give under the rule `inputs/keys.json` states, and the kids are their RFC 9679 thumbprints.

The 39 blind differences, by cause (`out/classification.json`):

| cause | statement | payload | value | object | total |
|---|---|---|---|---|---|
| The rule is not in the draft (registry, liveness, rotation, end-rule bound) | 12 | 2 | | | 14 |
| The text admits this run's reading as well as the expected one | 10 | | | | 10 |
| Same outcome, reason spelled otherwise | 7 | 1 | | | 8 |
| What "form" means for a value | | | 3 | | 3 |
| This run's omission (fixed in pass 3) | 1 | 2 | | 1 | 4 |

What a match shows and what it does not: a match shows that this reader, written from the draft and the blind inputs, reached the answer `expected.json` gives, under the readings listed in `ambiguity-log.md`. It does not show that either reading is the right reading of the text. It says nothing of CIRISVerify, whose code was not read or run. A difference records that two parties computed different answers from the same inputs; either can be wrong.

## Re-running

Run from this directory:

```
bash inputs/fetch-inputs.sh
bash rerun.sh
```

`fetch-inputs.sh` downloads the candidate's inputs and `expected.json` at 7a8b392 and the draft's TXT, and checks them against `inputs/SHA256SUMS`. `rerun.sh` runs the three passes, the comparison and the B.1 check, and compares every output with `out/` by `cmp`. `logs/transcript.log` is its output on 2026-11-25: every step exited 0.

## Layout

| path | content |
|---|---|
| `README.md` | this file |
| `run-report.md` | the lab's run fields, labels per claim, per-case table |
| `PROVENANCE.md` | sources with digests, sections read, events, authorship |
| `ambiguity-log.md` | every reading this run chose where the text leaves a choice |
| `findings/` | F01 to F09, draft notes to the author of the draft, not filed |
| `reader/cbor_strict.py` | strict CBOR decoding and deterministic re-encoding |
| `reader/ceg_reader_pass1.py`, `reader/ceg_reader_pass2.py` | the blind reader, as it ran in pass 1 and pass 2 |
| `reader/ceg_reader_pass3.py` | the reader after the comparison |
| `reader/compare.py`, `reader/b1_check.py` | the comparison and the B.1 known-answer check |
| `out/answers-pass{1,2,3}.json` | the answers of each pass |
| `out/comparison-pass{2,3}.json`, `out/classification.json`, `out/changes.md` | the comparison, the cause of each difference, and the changes between passes |
| `logs/frozen.sha256`, `logs/frozen-at.txt` | digests of the reader and the blind answers, recorded before `expected.json` was opened |
| `logs/transcript.log` | output of `rerun.sh` |
| `logs/split-check.log` | the candidate's `split.py --check` against the pinned CIRISVerify files |
| `inputs/fetch-inputs.sh`, `inputs/SHA256SUMS` | the fetch script and the input digests |
| `rerun.sh` | the re-run script |
| `SHA256SUMS.txt` | digests of every other file of this directory |

The lab certifies nothing. This directory is a record of one run. It is not a verdict on the candidate, the draft or any implementation.
