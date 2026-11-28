# Results — revision 3

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
is preserved end-to-end. The decisions themselves are identical to revision 2 —
revision 3 refines the *reasons* attached to each decision.

## Refusal vocabulary — 117 of 176 records deny, all five values exercised

Every answer carries `refusal_reason` (closed five-value set, fixed precedence:
`evidence_binding_mismatch` → `evidence_expired` → `authority_not_determined` →
`authority_revoked` → `operation_not_permitted`; null whenever the decision is not
deny) and `grant_ref` (the grant as issued, with `observation_as_of_ms`; null when the
evidence was expired or the binding mismatched — a diagnostic read never renews
evidence). Observed distribution over the 176 call records:

| refusal_reason | records |
|---|---|
| `authority_not_determined` | 67 |
| `evidence_expired` | 26 |
| `authority_revoked` | 14 |
| `operation_not_permitted` | 6 |
| `evidence_binding_mismatch` | 4 |
| **denying (total)** | **117** |
| (matched — `refusal_reason` null) | 59 |

All 176/176 records carry `grant_ref`.

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

The observed failure sets are identical to revision 2's pinned sets: the revision-3
fields refine the reasons attached to decisions, not the decisions themselves.

## Post-expiry diagnostics — 20/20 clean

5 diagnostic cases × 4 profiles. Every emitted diagnostic is backed by an actual
recorded read; no speculative diagnostics; post-expiry diagnostic reads are recorded
and reported but never fed back into `grant_ref.observation_as_of_ms`.

## Oracle checkpoints — 12/12

Hand-reasoned checkpoint table (frozen alongside the revision-3 vectors, digest
`08293dbd991fe3f76534e176800e15365545a43a6d94e4d89f79d6d58ec7e830`) replayed against
runner output: all field values — including the revision-3 fields — and
`downstream_reached` match; zero failures.

## Reporting semantics — 5/5

`no_scored_coverage` · `statement_only_matched` · `policy_mismatch_partial` ·
`unsupported_only_no_coverage` · `oracle_inputs_not_read` — all true, and executed, not
asserted: during all scoring phases the runner wraps `builtins.open` — its only
instrumented path — and records any attempt to read a file whose name contains
`oracle`; the check is the measured result of that guard.

## Determinism

Full runs on 2026-10-26 produce byte-identical JSON reports (identical sha256),
including all axis verdicts, refusal reasons, grant references, mutant failure sets
and composite comparisons. A fresh clone of the canonical repository at the filed
commit rerun in an isolated directory reproduced the recorded
`run-output-rev3.json` byte-for-byte (modulo line-ending normalization; canonical
sha256 `78824b82a07eccdb…` on both sides). The frozen revision-2 replay over the
vendored `vendor/` inputs remains byte-identical to the recorded revision-2 output.
Full run cost ~0.17–0.2 s wall-clock including interpreter startup (pure in-memory
timeline replay — no network, no RPC, no real-time waiting).

## Negative-path self-check

A tampered copy of the vectors file (one case id altered) is rejected by the digest
gate before any scoring: `DIGEST GATE FAILED ... refusing to score`.

## Environment

| item | value |
|---|---|
| language | Python 3.14.2 (stdlib only, no third-party packages) |
| operating system | Windows 11 (10.0.26300) |
| run date | 2026-10-26 |
| implementation commit | `42eb4172bd7063e8aae4732dc6a720138db5263b` |

## Artifact of record

The sealed artifact of this run is
[`lra-runner-20261026a.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261026a.tar.gz)
(sha256 `0bd67a7a89c1a0ff46f72c119ca847868d04b5ca333d5eb35701ff88e7e0d152`), carrying
two addresses derived from its own digest — one per sister scheme, nothing invented,
nothing registered, both resolve live:
[`rttp://0bd67a7a.conformance.iqa`](https://rttp.com/open/?uri=rttp://0bd67a7a.conformance.iqa)
(the question side, WHERE + WHEN) and
[`iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa`](https://iqa.org/open/?uri=iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa)
(the answer side, WHETHER; subject = first 32 hex of the same digest).
