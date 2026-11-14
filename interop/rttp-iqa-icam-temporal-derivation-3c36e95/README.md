# RTTP & IQA author-produced Mode B run over icam-temporal-derivation

This directory records an author-produced Mode B run over ICAM's vectors of the `icam-temporal-derivation` candidate (merged upstream in PR #218): temporal-state derivation vectors submitted by Nika Novak (ICAM / aiclavis) — the first third-party candidate anchored to `draft-li-rttp-iqa-addressing-02`. The operator is ShaoBao Li (Lee) / @Aicent-com. The operator is the author of the pinned draft but wrote none of the candidate's vectors, checkers, oracles, or expected values, and is not affiliated with ICAM / aiclavis; the implementation here is a distinct runner, not the candidate's shipped pipeline — the same complement structure as the lab's other RTTP & IQA records (`interop/rttp-iqa-lra-runner-*`, `interop/rttp-iqa-aae-moltycel-vectors-*`).

The candidate's evidence row already lists a first run of this runner against the PR head (`72a0f72`, 2026-11-07, 24/24 + 6/6, recorded before merge). This record supersedes nothing: it is the complete recorded rerun against the merged mainline bytes (`3c36e95`), so the pin is the merged corpus itself rather than a PR head. The merged corpus changed metadata only (candidate package labels, four `case_status` annotations moved to `convention_specific`, refreshed CHECKSUMS); every executable input and expectation is unchanged, and the verdicts of the two runs are identical case by case.

## Scope

The run covers the full published vector set at source `3c36e95` (merged 2026-11-08): 24 cases — 20 `DERIVE` (section 6.1 lease reliance, including two nondefault-window boundary cases) and 4 `WIRE_TIME_GATE` (section 7.2 verification step (2) only). Case statuses as declared by the candidate: 16 `normative`, 4 `convention_specific`, 3 `local_precondition`, 1 `interpretive`. The runner's two layers are kept separate, as the candidate's "bounded question" asks: the reliance layer answers with the declared boundary convention, the wire gate answers section 7.2 step (2) strictly (earlier rejects, equality passes the isolated gate).

## Result

All green, exit 0: the runner's vendor-pin gate verifies the six frozen corpus files byte-identical against the candidate's own `CHECKSUMS.sha256` before anything is scored; 24/24 cases agree with the candidate's declared expectations; the runner's own mutation battery (six mutants, distinct from the candidate's shipped battery) is 6/6 killed, including both global directions and the two adversarial directions the candidate's negative controls target (trusting the advisory `supplied_boundary_classification` flag, and hardcoding a 120-second window). No suspected defective vector was observed.

## Re-run

The runner is self-contained in this directory: `icam_runner.py` reads `vendor/vectors.json`, re-derives every verdict from the published draft text (section 6.1, 7.2 step (2)), embeds the sha256 of every frozen vendor file into the payload, and runs its own six-mutant battery:

```
python3 -I icam_runner.py vendor/vectors.json run-output.json
```

Expected output begins with `VENDOR PIN OK 6/6 (CHECKSUMS.sha256)` — the runner fails closed if any vendored file does not match its recorded digest — and ends with `SUMMARY 24/24 agree (author-produced Mode B runner)` and `MUTATION SUMMARY 6/6 killed (the runner's own battery)`, exit status 0. A rerun must reproduce the recorded `run-output.json` byte for byte; the full console output of the recorded run is preserved verbatim in `run-output.txt`.

## Relationship to the candidate's oracle

The runner does not read the candidate's reference oracle (`check.py`); the oracle is vendored frozen solely so the digest gate can pin the corpus and third parties can audit what was on disk. Rules are derived from the published draft text; the candidate's input and result vocabulary is adopted only as the interface contract. The advisory input `supplied_boundary_classification` is never consulted — the candidate's negative controls exist to punish any oracle that trusts it.

## Files

- `run-report.md` — the run report (scope, method, results, limitations)
- `PROVENANCE.md` — operator, mode, derivation statement, environment
- `RESULTS.md` — per-vector results and the mutation battery, transcribed from the recording
- `VECTOR-INVENTORY.md` — what the vector set contains
- `icam_runner.py` — the Mode B runner, code as run
- `vendor/` — the frozen merged corpus (7 files), digest-gated
- `run-output.json` — the machine-readable record of the run
- `run-output.txt` — the complete console output of the recorded run, uncut
- `ENVIRONMENT.txt` — the run environment
- `SHA256SUMS.txt` — digests of the accompanying files
