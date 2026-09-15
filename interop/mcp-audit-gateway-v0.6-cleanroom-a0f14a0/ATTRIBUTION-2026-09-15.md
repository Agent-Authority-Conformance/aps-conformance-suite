# Attribution clarification, 2026-09-15: the two exercised semantic outcomes

This is an append-only record. It revises no claim in the `SOURCE.md` beside it and re-runs
nothing. It assigns two layers to checks the independent run already executed and that the
`SOURCE.md` Verification split did not list. A dated clarification pointer is appended to that
file so a reader of the original reaches this one.

## What happened

The clean-room verifier `recompute.py` at `8b5b0f398dc813a2c4192a437270299d544b16f8`
performs 112 checks. Four of them concern the two completeness outcomes the mcp-audit-gateway
v0.6 vectors exercise. Issue #68 asked for a run of that verifier in full, by someone who
wrote neither the vectors nor the verifier, as the independent record PR #63 needs.
Silentpartnercoding's run of 2026-09-05 was that run, and all four checks are PASS in his
preserved verbatim stdout.

The `SOURCE.md` Verification split recorded independent coverage for the byte, digest and
chain layers only. That was a narrower scope than the run it records, not a limit of the
evidence. This record assigns the two semantic layers to the checks that run already made.

## The independent evidence

`results-silentpartnercoding-2026-09-05.txt`, his verbatim stdout as filed on #68, is the
independent provenance for everything claimed here. Lines 112, 113, 115 and 116:

    PASS  truncation_detection :: truncation derived
          (checkpoint present=False, later checkpoints=0, delivered=1)
    PASS  truncation_detection :: stated failure code agrees with derivation
    PASS  sequence_regression :: derived  (checkpoint sequences [3, 2])
    PASS  sequence_regression :: stated failure code agrees with derivation

`results.json` in this directory is the lab's own run of the same verifier and is
author-produced. It carries the same 112 check names and statuses, and it is cited below only
to explain the recorder's behavior. It is not Silentpartnercoding's run and supplies no
independent provenance.

## What the verifier derives, and in what order

For both outcomes the verifier derives the result from the record data first and compares it
to the file's published claim afterwards. It does not read the published `failureCode` to
decide what the outcome is.

`head_missing` is derived from checkpoint absence together with the absence of a later
checkpoint. `sequence_regression` is derived from the checkpoint sequence list, `[3, 2]` in
this vector. Each derived code is then compared to the value the file publishes, which is
`head_missing` at `/truncation_detection/truncated_chain/failureCode` and
`sequence_regression` at `/sequence_regression/detection_result/failureCode`.

One recorder note, read from the lab's `results.json`. On the PASS branch of the second
`sequence_regression` check, `record()` is called without its `derived` and `published`
arguments, so both are stored as `null`. Those nulls are the function's defaults and not the
values compared. The comparison at `recompute.py:575` is between the derived code and the
published one, and it reached PASS with `regressed` true, which means the published value
equalled `sequence_regression`. The vector confirms it does.

## Verification split, added layers

- `head_missing`, the completeness outcome exercised by the `truncation_detection` block,
  derived from the record data and compared to the published failure code; runner:
  Silentpartnercoding; Mode B; independent; implementation: `recompute.py` (lab-authored,
  runner-independent), pinned at `8b5b0f39`.
- `sequence_regression`, the completeness outcome exercised by the `sequence_regression`
  block, derived from the checkpoint sequences and compared to the published failure code;
  runner: Silentpartnercoding; Mode B; independent; implementation: `recompute.py`
  (lab-authored, runner-independent), pinned at `8b5b0f39`.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## What this record does not establish

It does not establish independent coverage of the `chain_continuity_violation` class.
`count_mismatch` is the third code in that class, no vector in these files raises it, and the
verifier reports it as NOT CHECKED. Two of three outcomes carry an independent record and the
third carries none.

It adds no run, no verifier and no vector.
