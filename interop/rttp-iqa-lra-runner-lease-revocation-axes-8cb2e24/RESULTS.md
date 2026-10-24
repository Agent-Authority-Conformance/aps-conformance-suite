# Results

## Tally — 4 profiles × 12 cases = 48 runs (dual-mode, separately scored)

| Profile | Runs | Calls | Axis comparisons | Composite comparisons | Failures |
|---|---|---|---|---|---|
| `cached_lease` × exclusive | 12 | 44 | 132 | 44 | 0 — matched |
| `cached_lease` × inclusive | 12 | 44 | 132 | 44 | 0 — matched |
| `live_standing_read` × exclusive | 12 | 44 | 132 | 44 | 0 — matched |
| `live_standing_read` × inclusive | 12 | 44 | 132 | 44 | 0 — matched |
| **Total** | **48** | **176** | **528** | **176** | **0** |

All three declared axes (`evidence_freshness`, `authority_validity`,
`action_authorization`) were scored on every supported comparison; per-axis separation
is preserved end-to-end (a case may pass one axis while failing composite acceptance —
grading stays distinct per the family spec).

## Mutation observation — 12 defective variants, pinned failure sets, 12/12 match

| mutant | failed cases (pinned = observed) |
|---|---|
| `lease-ignores-expiry` | LRA-04, LRA-05, LRA-07, LRA-08, LRA-10 |
| `sliding-lease` | LRA-04, LRA-05, LRA-07, LRA-08, LRA-10 |
| `live-fail-open` | LRA-03, LRA-07, LRA-11 |
| `sticky-unavailable` | LRA-03, LRA-07, LRA-11 |
| `retrieval-renews-evidence` | LRA-04, LRA-05, LRA-08, LRA-10 |
| `deny-but-dispatch` | LRA-02, LRA-03, LRA-04, LRA-05, LRA-06, LRA-07, LRA-08, LRA-09, LRA-10, LRA-11, LRA-12 |
| `deny-everything` | LRA-01, LRA-02, LRA-03, LRA-05, LRA-06, LRA-07, LRA-08, LRA-10, LRA-11, LRA-12 |
| `live-first-read-only` | LRA-01, LRA-02, LRA-03, LRA-06, LRA-07, LRA-08, LRA-09, LRA-10, LRA-11 |
| `second-worker-stale` | LRA-08 (w2-only failure verified) |
| `fabricated-live-read` | LRA-01, LRA-02, LRA-03, LRA-05, LRA-06, LRA-07, LRA-08, LRA-09, LRA-10, LRA-11, LRA-12 (read-provenance-only verification) |
| `selective-not-supported` | LRA-02, LRA-03, LRA-04, LRA-05, LRA-06, LRA-07, LRA-08, LRA-09, LRA-10, LRA-11, LRA-12 |
| `ignore-evidence-binding` | LRA-12 |

## Post-expiry diagnostics — 20/20 clean

5 diagnostic cases × 4 profiles; every emitted diagnostic is backed by an actual
recorded read; no speculative diagnostics.

## Oracle checkpoints — 12/12

Hand-reasoned checkpoint table (frozen alongside the vectors) replayed against runner
output: all field values and `downstream_reached` match; zero failures.

## Reporting semantics — 5/5

`no_scored_coverage` · `statement_only_matched` · `policy_mismatch_partial` ·
`unsupported_only_no_coverage` · `oracle_inputs_not_read` — all true, and executed, not
asserted: during all scoring phases the runner wraps `open()` and records any attempt
to read a file whose name contains `oracle`; the check is the measured result of that
guard.

## Determinism

Three consecutive full runs on 2026-10-24 produce byte-identical JSON reports
(identical sha256), including all axis verdicts, mutant failure sets and composite
comparisons. Full run cost ~0.17–0.2 s wall-clock including interpreter startup
(measured 2026-10-24; pure in-memory timeline replay — no network, no RPC, no
real-time waiting).

## Negative-path self-check

A tampered copy of the vectors file (one case id altered) is rejected by the digest
gate before any scoring: `DIGEST GATE FAILED ... refusing to score`.

## Environment

| item | value |
|---|---|
| language | Python 3.14.2 (stdlib only, no third-party packages) |
| operating system | Windows 11 (10.0.26300) |
| run date | 2026-10-24 |
| implementation commit | `8cb2e241419cd03d9be40c5977e0e9caa1d723a4` |
