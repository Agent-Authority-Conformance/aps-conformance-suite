# Results

## Tallies

| | conformant | nonconformant | ambiguous |
|---|---|---|---|
| phase 1 (blind, `out/phase1.json`) | 11 | 12 | 2 |
| final (`out/final.json`) | 11 | 12 | 2 |
| candidate `expect` | 11 | 12 | 2 |

- Verdicts equal to `expect`: 25 of 25.
- Named parts equal to `expect_parts`: 4 of 4 (GR-A01: 2, GR-A02: 2).
- Verdict changes from phase 1 to final: none (`out/changes.md`).

## Per-case table

"required reason" is computed from the input by the 8.1 priority order. It is computed only when the input carries the four 8.1 facts. "Checks not held" lists every check that did not hold. All other checks applied to the case held. The per-check detail, with the cited sentence for each, is in `out/phase1.json`.

| original | blind | basis | required reason (8.1) | outcome reason | checks not held | reader | expected | result |
|---|---|---|---|---|---|---|---|---|
| GR-A01 | B13 | sect-8.1 | `authority_not_determined` | `authority_not_determined` | R7-computed-over-facts: ambiguous | ambiguous | ambiguous | match |
| GR-A02 | B19 | sect-8.1, sect-8.2 | `authority_revoked` | `authority_revoked` | R12-race-observation-vs-revocation: ambiguous | ambiguous | ambiguous | match |
| GR-C01 | B20 | sect-8.1 | `operation_not_permitted` | `granted` | R2-closed-set: not held, R3-no-granted: not held, R4-priority: not held | nonconformant | nonconformant | match |
| GR-C02 | B16 | sect-8.1 | `evidence_expired` | (absent) | R1-reason-present: not held | nonconformant | nonconformant | match |
| GR-C03 | B25 | sect-8.1 | `authority_not_determined` | `authority_suspended` | R2-closed-set: not held, R4-priority: not held | nonconformant | nonconformant | match |
| GR-C04 | B17 | sect-8.1 | null | null | — | conformant | conformant | match |
| GR-G01 | B23 | sect-8.2 | not computed (no 8.1 facts in input) | null | — | conformant | conformant | match |
| GR-G02 | B24 | sect-8.2 | not computed (no 8.1 facts in input) | null | R8-members-present: not held | nonconformant | nonconformant | match |
| GR-G03 | B14 | sect-8.2 | not computed (no 8.1 facts in input) | `evidence_expired` | R8-members-present: not held | nonconformant | nonconformant | match |
| GR-G04 | B12 | sect-8.2 | not computed (no 8.1 facts in input) | null | R8-members-present: not held | nonconformant | nonconformant | match |
| GR-N01 | B22 | sect-8.2 | not computed (no 8.1 facts in input) | null | — | conformant | conformant | match |
| GR-N02 | B21 | sect-8.2 | not computed (no 8.1 facts in input) | null | — | conformant | conformant | match |
| GR-N03 | B09 | sect-8.2 | not computed (no 8.1 facts in input) | `authority_not_determined` | R9-obs-null-when-absent-or-stale: not held | nonconformant | nonconformant | match |
| GR-N04 | B18 | sect-8.1, sect-8.2 | `authority_not_determined` | null | R6-refuse-when-condition: not held, R9-obs-null-when-absent-or-stale: not held | nonconformant | nonconformant | match |
| GR-N05 | B11 | sect-8.2 | not computed (no 8.1 facts in input) | `authority_not_determined` | — | conformant | conformant | match |
| GR-N06 | B08 | sect-8.2 | not computed (no 8.1 facts in input) | `authority_not_determined` | R11-expires-equals-grant: not held | nonconformant | nonconformant | match |
| GR-P01 | B15 | sect-8.1 | `evidence_binding_mismatch` | `evidence_binding_mismatch` | — | conformant | conformant | match |
| GR-P02 | B01 | sect-8.1 | `evidence_binding_mismatch` | `evidence_expired` | R4-priority: not held | nonconformant | nonconformant | match |
| GR-P03 | B05 | sect-8.1 | `evidence_expired` | `evidence_expired` | — | conformant | conformant | match |
| GR-P04 | B03 | sect-8.1 | `evidence_expired` | `authority_revoked` | R4-priority: not held | nonconformant | nonconformant | match |
| GR-P05 | B10 | sect-8.1 | `evidence_binding_mismatch` | `evidence_binding_mismatch` | — | conformant | conformant | match |
| GR-P06 | B02 | sect-8.1 | `evidence_binding_mismatch` | `evidence_binding_mismatch` | — | conformant | conformant | match |
| GR-P07 | B04 | sect-8.1 | `authority_not_determined` | `authority_not_determined` | — | conformant | conformant | match |
| GR-P08 | B07 | sect-8.1 | `operation_not_permitted` | `operation_not_permitted` | — | conformant | conformant | match |
| GR-P09 | B06 | sect-8.1 | null | `operation_not_permitted` | R5-null-when-no-condition: not held | nonconformant | nonconformant | match |

## Sensitivity table

Each of the reader's 12 rules was removed alone. Rules where an inversion means something were also inverted: R1 (absent reason read as null), R4 (reverse priority: the last applicable value), R5 (refuse when no condition applies), R9 (report the freshest observation seen, i.e. backfill), R11 (require an expiry other than the grant's). For R7 and R12, "invert" resolves the ambiguity to reading A (nonconformant), and "remove" is equivalent to not scoring that part. Inversion was not run for R2, R3, R6, R8 and R10, where it means nothing ("require a value outside the closed set", and so on). Output: `out/phase1-sensitivity.json`, produced in phase 1.

| rule | variant | cases changing verdict (original/blind: from → to) |
|---|---|---|
| R1-reason-present | remove | GR-C02/B16: nonconformant → conformant |
| R1-reason-present | invert | none |
| R2-closed-set | remove | none |
| R3-no-granted | remove | none |
| R4-priority | remove | GR-P02/B01: nonconformant → conformant; GR-P04/B03: nonconformant → conformant |
| R4-priority | invert | GR-P02/B01: nonconformant → conformant; GR-P06/B02: conformant → nonconformant; GR-P04/B03: nonconformant → conformant; GR-P03/B05: conformant → nonconformant; GR-P05/B10: conformant → nonconformant; GR-P01/B15: conformant → nonconformant |
| R5-null-when-no-condition | remove | GR-P09/B06: nonconformant → conformant |
| R5-null-when-no-condition | invert | GR-P09/B06: nonconformant → conformant; GR-C04/B17: conformant → nonconformant |
| R6-refuse-when-condition | remove | none |
| R7-computed-over-facts | remove | GR-A01/B13: ambiguous → conformant |
| R7-computed-over-facts | invert | GR-A01/B13: ambiguous → nonconformant |
| R8-members-present | remove | GR-G04/B12: nonconformant → conformant; GR-G03/B14: nonconformant → conformant; GR-G02/B24: nonconformant → conformant |
| R9-obs-null-when-absent-or-stale | remove | GR-N03/B09: nonconformant → conformant |
| R9-obs-null-when-absent-or-stale | invert | GR-N03/B09: nonconformant → conformant; GR-N05/B11: conformant → nonconformant |
| R10-obs-equals-relied-on | remove | none |
| R11-expires-equals-grant | remove | GR-N06/B08: nonconformant → conformant |
| R11-expires-equals-grant | invert | GR-N06/B08: nonconformant → conformant; GR-N05/B11: conformant → nonconformant; GR-N02/B21: conformant → nonconformant; GR-N01/B22: conformant → nonconformant |
| R12-race-observation-vs-revocation | remove | GR-A02/B19: ambiguous → conformant |
| R12-race-observation-vs-revocation | invert | GR-A02/B19: ambiguous → nonconformant |

Rules on which no case depends alone (finding F03):
- **R2 closed set**: GR-C01 and GR-C03 are also rejected by R4 (priority) and, for C01, by R3.
- **R3 no "granted"**: GR-C01 is also rejected by R2 and R4.
- **R6 refuse when a condition applies**: GR-N04 is also rejected by R9 (its `observation_as_of_ms` is the diagnostic instant 1150).
- **R10 observation equals relied-on as-of when fresh**: no case has a fresh relied-on observation with a different member value.
- **R1 inverted**: no change, because GR-C02 with the absent reason read as null fails R6 instead.

Pairwise removals were not attempted.

## Limits of the checker

Found when the record was reviewed after phase 2. The checker was frozen at phase 1 and is not changed; neither point alters a result.

- R7 treats a refusal as computed over a label when the input's `computed_over` is `label`, `opinion` or `unrecorded_context` (the three words of the 8.1 sentence), or when the outcome's `computed_over` text contains "not re-derivable". The second test matches the wording of one case, GR-A01 (B13), whose input value `label` already decides it.
- In `out/phase1.json`, the text of reading B for R12 names the instants of GR-A02 (B19), 1100 and 1101, rather than the values of the case at hand. Only that description is affected: the check itself compares the case's own `observation_as_of_ms` and `revoked_at_ms`, and B19 is the only case it applies to.

## Two-run byte identity

| Output | run 1 sha256 | run 2 sha256 | `cmp` |
|---|---|---|---|
| phase-1 verdicts | `4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a` | `4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a` | identical (exit 0) |
| sensitivity | `688a6822a609d3e9a7e1a1d3426cc97c2bfec0f170622a14dcd36a38820beb50` | `688a6822a609d3e9a7e1a1d3426cc97c2bfec0f170622a14dcd36a38820beb50` | identical (exit 0) |
| final | `e61ca93a1f01447a7234475e939b5cf5fd9edf0cab2f85f6b75b6e29b1149cc3` | `e61ca93a1f01447a7234475e939b5cf5fd9edf0cab2f85f6b75b6e29b1149cc3` | identical (exit 0) |

The phase-1 pair was produced before the zip. A later re-run of the frozen checker (transcript in run-report.md) also equals `out/phase1.json` byte for byte.

## Environment

- Language: Python, standard library only. `python3 -I` for every run.
- Runtime: Python 3.13.18.
- Operating system: Ubuntu 24.04.5 LTS, Linux 6.18.44-fc-v470 x86_64.

## Wall-clock time

- From the first fetch to the end of result tabulation: 15:24:50 to 15:32:22 UTC on 2026-11-16, 446 s, measured with `date -u +%s`. This covers fetching, reading, writing the checker, both phases and the tables, but not writing the prose documents and the final packaging.
- Checker run time: two phase-1 runs, each with 24 sensitivity variants, took 0.097 s together. This is a timing of the pre-freeze version, measured with `date +%s.%N`; the frozen version runs 19 variants. The frozen version was not timed separately.
