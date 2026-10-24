# Run report: lease-revocation-axes via independent Python runner, Mode B (author-produced)

| field | value |
|---|---|
| who ran it | ShaoBao Li (Lee) (@Aicent-com); the runner is maintained under the @Aicent-Stack organization |
| date | 2026-10-24 |
| run mode | B, alternate recomputation |
| implementation name | `lra_runner.py` — independent stdlib-only Python runner for the lease-revocation-axes family |
| implementation repo and commit | https://github.com/Aicent-Stack/conformance — `lra-runner/` @ `8cb2e241419cd03d9be40c5977e0e9caa1d723a4` (code as run; a verbatim copy is included in this directory) |
| corpus reference | aps-conformance-suite PR #180, commit `b745d252191e89fe123e33411f124a1b67542c2a`; vectors sha256 `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` re-verified against the PR head `86e5e7a` on 2026-10-24 (commits after the run revision touch the family README and repository CI/docs only — the frozen inputs are unchanged) |
| per-vector result | 48/48 matched (full per-vector list below) |
| verbatim command and output | below, uncut |
| environment | Python 3.14.2, Windows 11 (10.0.26300) |
| author-produced or independent | **author-produced** — authorship relationship: the filer authored the alternate implementation (`lra_runner.py`) whose behavior supplies the recomputation, so the record cannot be labeled independent under the definition in `CONTRIBUTING.md`. The filer authored neither the vectors nor any claim inputs checked (pack author aeoess); every scored comparison is made against the per-call expected blocks, the pinned mutant failure sets and the hand-reasoned oracle checkpoints in the vectors file, never against lab model output. The implementation itself is independent of the lab's code: it was written from the family README and the frozen vectors, shares no code or library with the lab's TypeScript model, and the lab model was reviewed as the interface contract only. |
| suspected defective vectors | none observed |

## What was run

The runner replays the revision-2 vectors in memory under both lease modes
(`cached_lease`, `live_standing_read`) and both boundary policies (`exclusive`,
`inclusive`), scoring three declared axes (`evidence_freshness`, `authority_validity`,
`action_authorization`) under the `P1-current-observation` policy. Action-time
authorization is not claimed (by design); the declaration mapping is frozen before any
verifier is constructed. The vectors digest is a hard gate: the runner refuses to score
any vectors whose sha256 is not pinned in the family's `SHA256SUMS.txt`, and the gate
was verified negatively (a tampered copy is rejected before any scoring occurs).

## Per-vector result

All 48 baseline runs are `matched`; per-axis separation is preserved end-to-end.

| Case | Mode | Boundary | Status |
|---|---|---|---|
| LRA-01 | `cached_lease` | `exclusive` | matched |
| LRA-02 | `cached_lease` | `exclusive` | matched |
| LRA-03 | `cached_lease` | `exclusive` | matched |
| LRA-04 | `cached_lease` | `exclusive` | matched |
| LRA-05 | `cached_lease` | `exclusive` | matched |
| LRA-06 | `cached_lease` | `exclusive` | matched |
| LRA-07 | `cached_lease` | `exclusive` | matched |
| LRA-08 | `cached_lease` | `exclusive` | matched |
| LRA-09 | `cached_lease` | `exclusive` | matched |
| LRA-10 | `cached_lease` | `exclusive` | matched |
| LRA-11 | `cached_lease` | `exclusive` | matched |
| LRA-12 | `cached_lease` | `exclusive` | matched |
| LRA-01 | `cached_lease` | `inclusive` | matched |
| LRA-02 | `cached_lease` | `inclusive` | matched |
| LRA-03 | `cached_lease` | `inclusive` | matched |
| LRA-04 | `cached_lease` | `inclusive` | matched |
| LRA-05 | `cached_lease` | `inclusive` | matched |
| LRA-06 | `cached_lease` | `inclusive` | matched |
| LRA-07 | `cached_lease` | `inclusive` | matched |
| LRA-08 | `cached_lease` | `inclusive` | matched |
| LRA-09 | `cached_lease` | `inclusive` | matched |
| LRA-10 | `cached_lease` | `inclusive` | matched |
| LRA-11 | `cached_lease` | `inclusive` | matched |
| LRA-12 | `cached_lease` | `inclusive` | matched |
| LRA-01 | `live_standing_read` | `exclusive` | matched |
| LRA-02 | `live_standing_read` | `exclusive` | matched |
| LRA-03 | `live_standing_read` | `exclusive` | matched |
| LRA-04 | `live_standing_read` | `exclusive` | matched |
| LRA-05 | `live_standing_read` | `exclusive` | matched |
| LRA-06 | `live_standing_read` | `exclusive` | matched |
| LRA-07 | `live_standing_read` | `exclusive` | matched |
| LRA-08 | `live_standing_read` | `exclusive` | matched |
| LRA-09 | `live_standing_read` | `exclusive` | matched |
| LRA-10 | `live_standing_read` | `exclusive` | matched |
| LRA-11 | `live_standing_read` | `exclusive` | matched |
| LRA-12 | `live_standing_read` | `exclusive` | matched |
| LRA-01 | `live_standing_read` | `inclusive` | matched |
| LRA-02 | `live_standing_read` | `inclusive` | matched |
| LRA-03 | `live_standing_read` | `inclusive` | matched |
| LRA-04 | `live_standing_read` | `inclusive` | matched |
| LRA-05 | `live_standing_read` | `inclusive` | matched |
| LRA-06 | `live_standing_read` | `inclusive` | matched |
| LRA-07 | `live_standing_read` | `inclusive` | matched |
| LRA-08 | `live_standing_read` | `inclusive` | matched |
| LRA-09 | `live_standing_read` | `inclusive` | matched |
| LRA-10 | `live_standing_read` | `inclusive` | matched |
| LRA-11 | `live_standing_read` | `inclusive` | matched |
| LRA-12 | `live_standing_read` | `inclusive` | matched |

## Verbatim command and output

```
$ python lra_runner.py

candidate lease-revocation-axes revision 2, vectors sha256 a0a07ea58bcacfd0
digest gate vs pinned manifest: OK
48 independent baseline runs, 176 calls, 528 axis comparisons; 176 composite comparisons
baseline failures: 0 | statuses: ['matched']
  mutant lease-ignores-expiry         MATCH  failed=LRA-04,LRA-05,LRA-07,LRA-08,LRA-10
  mutant sliding-lease                MATCH  failed=LRA-04,LRA-05,LRA-07,LRA-08,LRA-10
  mutant live-fail-open               MATCH  failed=LRA-03,LRA-07,LRA-11
  mutant sticky-unavailable           MATCH  failed=LRA-03,LRA-07,LRA-11
  mutant retrieval-renews-evidence    MATCH  failed=LRA-04,LRA-05,LRA-08,LRA-10
  mutant deny-but-dispatch            MATCH  failed=LRA-02,LRA-03,LRA-04,LRA-05,LRA-06,LRA-07,LRA-08,LRA-09,LRA-10,LRA-11,LRA-12
  mutant deny-everything              MATCH  failed=LRA-01,LRA-02,LRA-03,LRA-05,LRA-06,LRA-07,LRA-08,LRA-10,LRA-11,LRA-12
  mutant live-first-read-only         MATCH  failed=LRA-01,LRA-02,LRA-03,LRA-06,LRA-07,LRA-08,LRA-09,LRA-10,LRA-11
  mutant second-worker-stale          MATCH  failed=LRA-08
  mutant fabricated-live-read         MATCH  failed=LRA-01,LRA-02,LRA-03,LRA-05,LRA-06,LRA-07,LRA-08,LRA-09,LRA-10,LRA-11,LRA-12
  mutant selective-not-supported      MATCH  failed=LRA-02,LRA-03,LRA-04,LRA-05,LRA-06,LRA-07,LRA-08,LRA-09,LRA-10,LRA-11,LRA-12
  mutant ignore-evidence-binding      MATCH  failed=LRA-12
diagnostic runs: 20 (failures: 0)
oracle checkpoints: 12 (failures: none)
reporting checks: {'no_scored_coverage': True, 'statement_only_matched': True, 'policy_mismatch_partial': True, 'unsupported_only_no_coverage': True, 'oracle_inputs_not_read': True}
RESULT: independent_run_matched
```

(`python lra_runner.py --json` writes the equivalent machine-readable report;
`run-output.json` in this directory is the recorded one.)

## Source-read contract (instrumented, not asserted)

- `cached_lease`: 0 authority reads per call (the lease decides from carried evidence)
- `live_standing_read`: exactly 1 instrumented read per unexpired + bound call
- Outage calls: the getter returns null, the attempt is recorded, and diagnostics must
  be backed by actual reads
- Hostile-call boundary: the runner raises if any implementation path touches
  expected/truth inputs mid-call

## Artifact of record

The complete artifact (code, frozen inputs, run report, recorded output) is pinned and
sealed on the archive of record:
[`lra-runner-20261023c.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261023c.tar.gz),
sha256 `94bbaf3c292abf69595bf5782d1db8cbb4178536d53182578b46cff94a5c4b15`, at
[iqa.org/conformance/lra-runner/](https://iqa.org/conformance/lra-runner/). The two
derived addresses it carries (`rttp://94bbaf3c.conformance.iqa`,
`iqa://94bbaf3c292abf69595bf5782d1db8cb.forge.iqa`) are derived from the artifact's own
digest; nothing is invented or registered.
