# Third-party implementation run record by @astrogilda

A separate record for this directory. It records a run published by @astrogilda (ProbityAI) of his own checker over the pinned pair. `run-report.md`, `results/` and `independent-entry1-imokokok.md` are unchanged by this file.

| field | value |
|---|---|
| who ran it | @astrogilda |
| run mode | Mode B, alternate recomputation |
| implementation | `e2check.py` at `probityai/agent-evidence-vectors` `00f5acab880bffc5ee8fe124f3a015d3ed970514`, `interop/aps-priorseal-e2-2026-09-30/`, SHA-256 `40d816bff91123f59ad719e126d6921f99fd662d2b70a31f6bf7badcb62a05e5`. It imports no APS or PriorSeal code. RFC 8785 and Ed25519 come from `agent-evidence-vectors` 0.15.0, Keccak-256 from `pycryptodome` 3.23.0 |
| author-produced or independent | author-produced. The runner authored `e2check.py`, the implementation that decides each claimed result, so under `CONTRIBUTING.md` this record is not independent |
| relationship to the producers | third party. The runner authored neither the APS fixtures nor the PriorSeal pair, and neither producer wrote the checker |
| what the checker was written from | draft-pidlisnyi-aps-03 (Sections 3.1, 4.1, 5.1 to 5.6), the APS fixture README, the PriorSeal example README and PriorSeal's `docs/architecture/aps-priorseal-claim-boundary.md`, per its README |
| inputs | APS `948f99b8` `fixtures/priorseal-decision-binding/` and PriorSeal `d749d269` `examples/aps-priorseal-decision-binding-v1/`, 31 files fetched by `fetch_inputs.sh` with a SHA-256 check on each. Reference time `2026-09-19T10:05:00.000Z` |
| published outputs | `RESULTS.json` SHA-256 `80e1adbb4c0e97fd2a9a7a8d2c290e9f225fd37793324f72b49198861861a8cd` (96 rows: 86 pass, 4 fail, 6 not-exercised). `NEGATIVES.json` SHA-256 `cb43bd4409e30dad465ea0e445668e9b8282914a62beecaecf88099fd1141829` |
| what it is not | an independent record for any entry, and not a replacement for one. Entries 3, 5 and 6 still have no independent record |

## Results per claim entry, as the runner reports them

| entry | claim | within limit | over limit |
|---|---|---|---|
| 1 | APS evidence under pinned keys at the reference time | pass, 12 of 12 entry-1 rows | same |
| 2 | PriorSeal signatures | not-exercised, cause `out_of_scope` | same |
| 3 | `decision_ref` correlation | pass | pass |
| 4 | exact call against observation | pass | fail, signed 1e15 and observed 6e15 |
| 5 | APS cap compliance | pass | fail, 6e15 over the 5e15 `per_action` cap |
| 6 | the report | 22 recomputed values agree, 3 quoted values agree, 3 rows not-exercised (PriorSeal receipt validity and the scope flags) | same |

The two `fail` rows on the over-limit payment are the expected outcome, the same one the producers state. The runner's `DISAGREEMENTS.md` records no disagreement with either producer on any exercised claim. The checker also recomputes all four APS cases beyond the rows carrying lab-entry labels: permit and narrow recompute on every row, `expired` fails only the reference-time check, and `deny` does not admit dispatch.

## Negatives, as the runner reports them

Signature-invalid, wrong-key, altered-authorization and `decision_ref`-unbound inputs are each rejected at a named row. The rehashed altered authorization survives at its target, the principal signature, which this checker does not exercise, and is refused by the cross-check against the APS requested call. The positive control is caught and the inert control moves no state.

## Limits the runner states

At the run's `00f5acab` pin, the checker records that the PriorSeal signing inputs were not available to it as a text specification, so entry 2 is not exercised. A PriorSeal signing-byte profile was published later and is not part of this recorded run. Two PriorSeal hashes and the APS payload object were recovered by trial and are labeled where used. The mapping between the APS spend unit and the PriorSeal asset in entry 5 is the checker's own reading. The run is against draft-03.

## Reproduction of the published outputs

A rerun by @aeoess on 2026-09-30 (macOS arm64, Python 3.13 through `uv`, the same pinned packages) reproduced `RESULTS.json` and `NEGATIVES.json` byte for byte: `fetch_inputs.sh` exit 0, `e2check.py` exit 0, `build_and_run.py` exit 0. This is a reproduction of the runner's record, not a second implementation and not a review of the checker's logic. @aeoess authored the APS fixtures, so this rerun is not independent for any claim that reads them.

The offline synthetic claim ceiling in `run-report.md` is unchanged.
