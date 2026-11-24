# Results

## Tallies

| | conformant | nonconformant | ambiguous |
|---|---|---|---|
| phase 1 (`out/phase1.json`) | 8 | 5 | 2 |
| final (`out/final.json`) | 8 | 5 | 2 |
| expected by the candidate | 9 | 5 | 1 |

Comparison of final verdicts with `expect`: 14 match, 1 diverges (LB-D05). No verdict was changed after phase 1.

## Per-case table

| original id | blind id | candidate rule | phase 1 | final | expected | result |
|---|---|---|---|---|---|---|
| LB-D01 | B11 | R-DECLARED | conformant | conformant | conformant | match |
| LB-D02 | B15 | R-DECLARED | conformant | conformant | conformant | match |
| LB-D03 | B03 | R-DECLARED | nonconformant | nonconformant | nonconformant | match |
| LB-D04 | B04 | R-DECLARED | ambiguous | ambiguous | ambiguous | match (parts differ, see below) |
| LB-D05 | B06 | R-DECLARED | ambiguous | ambiguous | conformant | diverge |
| LB-E01 | B01 | R-NOEXTEND | conformant | conformant | conformant | match |
| LB-E02 | B09 | R-NOEXTEND | nonconformant | nonconformant | nonconformant | match |
| LB-E03 | B10 | R-NOEXTEND | nonconformant | nonconformant | nonconformant | match |
| LB-M01 | B08 | R-MODE | conformant | conformant | conformant | match |
| LB-M02 | B02 | R-MODE | nonconformant | nonconformant | nonconformant | match |
| LB-M03 | B13 | R-MODE | conformant | conformant | conformant | match |
| LB-M04 | B12 | R-MODE | conformant | conformant | conformant | match |
| LB-M05 | B07 | R-MODE | conformant | conformant | conformant | match |
| LB-W01 | B14 | R-WINDOW | conformant | conformant | conformant | match |
| LB-W02 | B05 | R-WINDOW | nonconformant | nonconformant | nonconformant | match |

**Ambiguous cases, parts.**

- LB-D04 (B04). Expected parts: `answer_within_a_convention: conformant`, `declaration: ambiguous`. This run's parts: `reason member present: held`, `reason is null or in the closed set: held`, `reason: ambiguous`, `grant_ref member present: held`. Readings: "7.2 step (2) as the default: fresh" → conformant; "undeclared convention may be expired_at_instant: expired" → nonconformant. No part name is shared. Finding F02.
- LB-D05 (B06). No expected parts (expected `conformant`). This run's parts: `reason: ambiguous`, the other three held. Readings: "6.1 declared convention governs: expired" → conformant (agrees with `expect`); "7.2 step (2) acceptance at equality governs: fresh" → nonconformant. First differing condition: whether acceptance of the frame at equality under 7.2 step (2) makes the lease fresh for the answer. Finding F01.

## Sensitivity table

From `out/phase1-sensitivity.json`. Each variant removes or inverts one rule of this run's checker; all other rules as in phase 1.

| rule | variant | cases that change verdict (phase-1 verdict → variant verdict) |
|---|---|---|
| R01-expired-refused | removed | B01 (LB-E01) C→N; B04 (LB-D04) A→C; B06 (LB-D05) A→N; B07 (LB-M05) C→N; B09 (LB-E02) N→C; B10 (LB-E03) N→C; B15 (LB-D02) C→N |
| R02-stated-expiry | inverted (issuance + 120 s from 6.1) | B05 (LB-W02) N→C; B14 (LB-W01) C→N |
| R03-strict-compare | inverted (expired at equality) | none |
| R04-no-extend | removed | B10 (LB-E03) N→C |
| R05-declared-boundary | removed (7.2 step (2) only) | B04 (LB-D04) A→C; B06 (LB-D05) A→N; B15 (LB-D02) C→N |
| R05-declared-boundary | inverted (conventions swapped) | B03 (LB-D03) N→C; B06 (LB-D05) A→N; B11 (LB-D01) C→N; B15 (LB-D02) C→N |
| R06-boundary-vs-7.2 | removed (6.1 governs) | B06 (LB-D05) A→C |
| R06-boundary-vs-7.2 | inverted (7.2 governs) | B06 (LB-D05) A→N |
| R07-undeclared-boundary | removed (7.2 default: fresh) | B04 (LB-D04) A→C |
| R07-undeclared-boundary | inverted (undeclared = expired) | B04 (LB-D04) A→N |
| R08-live-fail-closed | removed | B02 (LB-M02) N→C; B08 (LB-M01) C→N |
| R09-cached-policy | removed | B13 (LB-M03) C→N |
| R09-cached-policy | inverted (policies swapped) | B12 (LB-M04) C→N |
| R10-cached-admit-specific | inverted (general unreachable rules govern) | B12 (LB-M04) C→N |
| R11-priority | removed (any applicable refusal) | none |
| R11-priority | inverted (reverse order) | B07 (LB-M05) C→N |
| R12-condition-holds | removed | B03 (LB-D03) N→C; B05 (LB-W02) N→C; B06 (LB-D05) A→C |
| R13-reason-present | removed | none |
| R14-closed-set | removed | none |
| R15-grant-ref-present | removed | none |

C = conformant, N = nonconformant, A = ambiguous. Original identifiers were added to this table in phase 2; the phase-1 file uses blind identifiers only.

Rules no case depends on: R03-strict-compare, R13-reason-present, R14-closed-set, R15-grant-ref-present; R11-priority in its removed variant. Finding F04.

## Two-run byte-identity check

The checker was run twice on the same inputs in phase 1, the second time into a temporary directory. `cmp` found `phase1.json` and `phase1-sensitivity.json` byte-identical (SHA-256 `0f73cf747351218369a395a138851b164dbd1ff0ffb97eaf4d279af075ba457f` and `bcbc23295b3a3231488aea217df698dde86fe3f679c50095b4cd98d2d7c542c6` for both runs). In phase 2 the checker and the comparison were run a third time into `rerun/` from copies of the fetched inputs, and `cmp` found `phase1.json`, `phase1-sensitivity.json` and `final.json` byte-identical to `out/`. The fetch step of the re-run commands was not attempted in this run (no network requests after setup).

The citation check was tested once: with the sentence "Current deployments use 120 seconds." altered in a copy of the draft, the checker printed `citation not found verbatim in the draft: C61-120` and exited with code 3. The copy was deleted.

## Limits of the checker

Places where a decision rests on a fixed value, a string test or a mapping chosen in this run rather than a derivation from the text:

1. **Input field names.** Every input field (`now_ms`, `lease_expiry_ms`, `issued_at_ms`, `grace_added`, `declared_boundary`, `at_boundary`, `frame_accepted_at_equality`, `mode`, `organ_unreachable`, `cache_fresh`, `policy`) is mapped to a condition of the text by a choice of this run (ambiguity log A9).
2. **String values of input fields.** The checker tests the strings `fresh_at_instant`, `expired_at_instant`, `live`, `cached`, `current`, `lease_fresh` by equality. Any other value falls through to the undeclared or not-stated branch.
3. **Units.** Clock and expiry are compared as the integers given (milliseconds); 7.2 states Unix seconds (A14).
4. **Unstated facts.** A fact the input does not state is treated as not in play: no binding mismatch, no revocation, no mode rule (A8).
5. **The boundary.** At the lease instant the checker takes `at_boundary` as given and does not derive equality from clock and expiry. The conflict of 6.1 and 7.2 is applied only where `frame_accepted_at_equality` is stated (A1).
6. **Cached-lease mode.** The precedence of the may-admit sentence of 6.2 over the general unreachable rules is a choice (A3); a refusal under a lease-fresh policy is allowed by choice and untested (A4).
7. **Members.** Only the presence of `reason` and of `grant_ref` is scored. The members of `grant_ref` (section 8.2, not read) and `observation_as_of_ms` are not scored (A10). `lease_note` is not scored; the extension in LB-E03 is scored from the input fact `grace_added` (A11).
8. **Derived from the text.** The closed refusal set and its priority order are extracted by a regular expression from the lines of section 8.1 that begin with `*name* —`; the 120-second window is extracted by a regular expression from 6.1. If the draft's layout differed, the extraction would differ; the checker exits if either extraction is empty.
9. **Citations.** The check is a substring test after whitespace normalisation; it confirms that each cited sentence occurs in the draft, not that it occurs in the section the checker attributes it to.
10. **Verdict rule.** A reading is conformant when every applied check holds; a case is ambiguous when its readings give different verdicts. This aggregation is this run's, not a rule of the text.

## Environment and wall-clock time

- Python 3.13.18 (CPython), standard library only, run with `-B`.
- Ubuntu 24.04.5 LTS, Linux 6.18.44.
- Fetch log written 2026-11-18T08:22:18Z; `out/phase1.json` written 08:26:33Z; phase-1 zip written 08:27:57Z; `out/final.json` written 08:29:01Z. Setup to final comparison: 6 minutes 43 seconds of wall-clock time. The time spent writing the documents of the record afterwards was not measured.
