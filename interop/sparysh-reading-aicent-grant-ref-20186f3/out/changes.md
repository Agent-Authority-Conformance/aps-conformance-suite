# Changes after phase 1

`out/phase1.json` (sha256 4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a) was not edited after the phase-1 zip was saved. A re-run of the same checker reproduces it byte for byte (see run-report.md).

## Verdict changes

None. No case changed verdict between phase 1 and the final record. `out/final.json` carries the phase-1 verdicts unchanged and adds the original identifiers, the expected verdicts, and the part comparison.

## Code added in phase 2

- `reader/compare.py` (new, sha256 1394a8ce0240aabc092e96f427c88cf4c09ab1b2d805f249a3aa75047d97e136). It reads `out/phase1.json`, the sealed `vectors.json` and `id-map.json`, and writes `out/final.json`.
- Its `PART_MAP` assigns phase-1 rules to the candidate's named parts (`value_and_assent`, `computation_source` for GR-A01; `value`, `boundary_call` for GR-A02). This assignment was made after reading the sealed `expect_parts`. It is the only judgement made in phase 2. It changes no phase-1 check result; it only groups them.

## Checker or harness faults found

None found. `reader/check_reader.py` was not modified after phase 1 (sha256 5eeb294a5e3cd039ff40e94581afc097ac9d1f1e290795a387af7eba405a02f2 in both the phase-1 zip and this directory).

## Notes added after review

- `RESULTS.md`, section "Limits of the checker": two places where the frozen checker is fitted to the wording or values of one case. No result changes.
- `README.md`: a paragraph on what the full match shows and what it does not.
- `findings/F03-cases-not-isolating-rules.md`: the suggestion for isolating the closed-set rule is stated more precisely.

## Notes added to the ambiguity log in phase 2

- A17 records that the two ambiguous cases match by part verdict, but the alternative reading the reader gave for GR-A02 (B19) is not the alternative the candidate's note gives. The text basis is 8.2: "A revocation arriving just before or just after an invocation ends is a boundary no protocol erases".
