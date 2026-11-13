# Run report — RTTP & IQA icam-runner over icam-temporal-derivation @ 3c36e95

## Scope and method

Author-produced Mode B run over ICAM's vectors of the full `icam-temporal-derivation` vector set at lab main `3c36e95` (candidate merged via PR #218, 2026-11-08T17:06:55Z). The runner is `icam_runner.py` in this directory — a distinct implementation written by the operator (ShaoBao Li / Aicent Stack), who authored the pinned draft but none of the candidate's materials. The six frozen corpus files are byte-verified against the candidate's own `CHECKSUMS.sha256` before anything runs; any difference aborts before scoring. Rules are re-derived from the published draft text (`draft-li-rttp-iqa-addressing-02`, TXT sha256 `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044`, sections 6.1 and 7.2 step (2)); the candidate's reference oracle is not executed.

Two layers, kept separate per the candidate's "bounded question": `DERIVE` (section 6.1 reliance: the verifier checks the stated expiry against its own clock; a declared boundary convention decides the instant of equality; with nothing declared the honest result is `boundary_undetermined`) and `WIRE_TIME_GATE` (section 7.2 step (2) only: reject iff `lease_expiry` is strictly earlier than now). The advisory input `supplied_boundary_classification` is never consulted.

## Results

Exit 0. 24/24 cases agree with the declared expectations: 18 standard `DERIVE` cases (including equality and the `invalid_convention` / `insufficient_input` local preconditions), 2 nondefault-window `DERIVE` boundary cases (TD-B07, TD-B08), 1 interpretive case (TD-X03, `boundary_undetermined`), and 4 `WIRE_TIME_GATE` cases (TD-W01–TD-W04: equality passes the isolated gate, earlier rejects). The independent mutation battery is 6/6 killed: `always-fresh`, `always-expired`, `trusts-advisory-flag`, `wire-gate-rejects-equality`, `undeclared-boundary-inclusive`, `hardcoded-120s-window` — each killed by at least one frozen case, in both global directions and both adversarial directions.

## Relation to the earlier head-run

The candidate's evidence row records a first run of this runner against the PR head `72a0f72` (2026-11-07, 24/24 + 6/6). The merged corpus changed metadata only (package labels; TD-B02, TD-B05, TD-N03, TD-N04 `case_status` re-annotated to `convention_specific`; refreshed CHECKSUMS). The verdicts of the two runs are identical case by case; the machine-readable records differ only in the vendored digest set and the reflected annotations.

## Limitations

This is a Mode B run record by an operator distinct from the candidate's author, not a merge vote and not a runtime certification: it scores declared expectations over frozen bytes, oracle-level only. The candidate's author-produced pipeline (checksums, fixtures, mutants, metamorphic invariances) was reproduced separately and is recorded in the candidate's own evidence; that reproduction is author-material executed as-is, not this record. A later revision of the candidate or the draft supersedes the readings here.

## Verbatim recording

The whole-session console output of the recorded run is embedded uncut in `run-output.txt`; the machine-readable record is `run-output.json` (sha256 `46758452bcf58972371017a746d14bb3274feba0ed5c7a1ff3080c7f1b15b75d`, regenerated 2026-11-14 after the mutation-scoring fix — each mutant is now scored only against cases of the rule it changes, per lab review).
