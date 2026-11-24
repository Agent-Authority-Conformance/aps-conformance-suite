# Results — replay of sparysh-reading-aicent-lease-boundary-0e0064b

The replay executed the record's own checker (`reader/checker.py`) over the frozen blind copy and compared every produced output against the record's recorded bytes; the per-case rows below are transcribed from the record's own comparison output (`recorded/final.json`, sha256 `eba83874c48b5be358f7a42ed4d06239d5b8ea965ccdcaa0d2652903855ca77b`). Fourteen of the fifteen verdicts match the family's expected values; the single divergence (LB-D05, blind id B06) is the record's own documented two-reading of section 7.2, not a silent resolution.

Tally (reader): 8 conformant, 5 nonconformant, 2 ambiguous. Expected tally (family): 9 conformant, 5 nonconformant, 1 ambiguous. The record's phase 1 and final comparison agree case for case (`changes_after_phase1` is empty), so the reader verdict column equals the phase-1 verdict throughout.

| original | blind | rule | reader verdict | expected | result |
|---|---|---|---|---|---|
| LB-D01 | B11 | R-DECLARED | conformant | conformant | match |
| LB-D02 | B15 | R-DECLARED | conformant | conformant | match |
| LB-D03 | B03 | R-DECLARED | nonconformant | nonconformant | match |
| LB-D04 | B04 | R-DECLARED | ambiguous | ambiguous | match |
| LB-D05 | B06 | R-DECLARED | ambiguous | conformant | diverge |
| LB-E01 | B01 | R-NOEXTEND | conformant | conformant | match |
| LB-E02 | B09 | R-NOEXTEND | nonconformant | nonconformant | match |
| LB-E03 | B10 | R-NOEXTEND | nonconformant | nonconformant | match |
| LB-M01 | B08 | R-MODE | conformant | conformant | match |
| LB-M02 | B02 | R-MODE | nonconformant | nonconformant | match |
| LB-M03 | B13 | R-MODE | conformant | conformant | match |
| LB-M04 | B12 | R-MODE | conformant | conformant | match |
| LB-M05 | B07 | R-MODE | conformant | conformant | match |
| LB-W01 | B14 | R-WINDOW | conformant | conformant | match |
| LB-W02 | B05 | R-WINDOW | nonconformant | nonconformant | match |

## The divergence: LB-D05 (blind id B06)

The record logs two readings of the draft text and reports both rather than picking one:

| reading | verdict | agrees with expected |
|---|---|---|
| 6.1 declared convention governs: expired | conformant | yes |
| 7.2 step (2) acceptance at equality governs: fresh | nonconformant | no |

The record's own verdict is `ambiguous`; the family's expected value is `conformant`. The record carries this as its finding F01 (a text two-reading), and this replay reproduces it byte for byte without judging it.

## Part structures carried by the record

The comparison output carries part structures for two cases. Their part names do not overlap with the expected parts (`same_part_names` is empty in both); the record documents this itself and this replay transcribes it verbatim.

| case | expected parts | parts of this run | verdict result |
|---|---|---|---|
| LB-D04 (B04) | answer_within_a_convention: conformant · declaration: ambiguous | grant_ref member present: held · reason: ambiguous · reason is null or in the closed set: held · reason member present: held | match |
| LB-D05 (B06) | none recorded | grant_ref member present: held · reason: ambiguous · reason is null or in the closed set: held · reason member present: held | diverge |

## Sensitivity variants (the record's own battery, reproduced in our outputs)

The record's sensitivity file is one of the three byte-matched artifacts (`recorded/phase1-sensitivity.json`, sha256 `bcbc23295b3a3231488aea217df698dde86fe3f679c50095b4cd98d2d7c542c6`). It carries twenty rule variants (removed or inverted); the per-variant change counts are transcribed below. Five variants change no verdict (R03 inverted, R11 removed, R13 removed, R14 removed, R15 removed), which the record itself records as `rules_no_case_depends_on`: R03-strict-compare, R13-reason-present, R14-closed-set, R15-grant-ref-present.

| rule | variant | verdicts changed |
|---|---|---|
| R01-expired-refused | removed | 7 |
| R02-stated-expiry | inverted | 2 |
| R03-strict-compare | inverted | 0 |
| R04-no-extend | removed | 1 |
| R05-declared-boundary | removed | 3 |
| R05-declared-boundary | inverted | 4 |
| R06-boundary-vs-7.2 | removed | 1 |
| R06-boundary-vs-7.2 | inverted | 1 |
| R07-undeclared-boundary | removed | 1 |
| R07-undeclared-boundary | inverted | 1 |
| R08-live-fail-closed | removed | 2 |
| R09-cached-policy | removed | 1 |
| R09-cached-policy | inverted | 1 |
| R10-cached-admit-specific | inverted | 1 |
| R11-priority | removed | 0 |
| R11-priority | inverted | 1 |
| R12-condition-holds | removed | 3 |
| R13-reason-present | removed | 0 |
| R14-closed-set | removed | 0 |
| R15-grant-ref-present | removed | 0 |
