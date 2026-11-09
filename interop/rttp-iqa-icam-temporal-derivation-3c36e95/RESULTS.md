# Results

All 24 cases agree with the candidate's declared expectations (exit status 0); the runner's independent six-mutant battery killed all six mutants. No suspected defective vector was observed. The tables below are transcribed from the recorded run: `run-output.json` (sha256 `505810f9360ae9818f9bd056a53f17547c8516afddde8a5be8718f60849824d0`) and the uncut console recording `run-output.txt`.

## Per-vector results

| # | Case | Rule / layer | Case status | Basis | Expected | Observed | Agree |
|---|------|--------------|-------------|-------|----------|----------|-------|
| 1 | TD-B01 | DERIVE / reliance | normative | 6.1 | fresh | fresh | yes |
| 2 | TD-B02 | DERIVE / reliance | convention_specific | 6.1 | fresh | fresh | yes |
| 3 | TD-B03 | DERIVE / reliance | normative | 6.1 | expired | expired | yes |
| 4 | TD-B04 | DERIVE / reliance | normative | 6.1 | fresh | fresh | yes |
| 5 | TD-B05 | DERIVE / reliance | convention_specific | 6.1 | expired | expired | yes |
| 6 | TD-B06 | DERIVE / reliance | normative | 6.1 | expired | expired | yes |
| 7 | TD-N01 | DERIVE / reliance | normative | 6.1 | expired | expired | yes |
| 8 | TD-N02 | DERIVE / reliance | normative | 6.1 | fresh | fresh | yes |
| 9 | TD-N03 | DERIVE / reliance | convention_specific | 6.1 | expired | expired | yes |
| 10 | TD-N04 | DERIVE / reliance | convention_specific | 6.1 | fresh | fresh | yes |
| 11 | TD-N05 | DERIVE / reliance | normative | 6.1 | expired | expired | yes |
| 12 | TD-N06 | DERIVE / reliance | normative | 6.1 | fresh | fresh | yes |
| 13 | TD-X01 | DERIVE / reliance | normative | 6.1 | fresh | fresh | yes |
| 14 | TD-X02 | DERIVE / reliance | normative | 6.1 | expired | expired | yes |
| 15 | TD-X03 | DERIVE / reliance | interpretive | 6.1 (SHOULD declaration, interpretive only) | boundary_undetermined | boundary_undetermined | yes |
| 16 | TD-X04 | DERIVE / reliance | local_precondition | ICAM-local | insufficient_input | insufficient_input | yes |
| 17 | TD-X05 | DERIVE / reliance | local_precondition | ICAM-local | insufficient_input | insufficient_input | yes |
| 18 | TD-X06 | DERIVE / reliance | local_precondition | ICAM-local | invalid_convention | invalid_convention | yes |
| 19 | TD-W01 | WIRE_TIME_GATE / wire_time_gate_only | normative | 7.2 step 2 | time_gate_pass | time_gate_pass | yes |
| 20 | TD-W02 | WIRE_TIME_GATE / wire_time_gate_only | normative | 7.2 step 2 | time_gate_pass | time_gate_pass | yes |
| 21 | TD-W03 | WIRE_TIME_GATE / wire_time_gate_only | normative | 7.2 step 2 | time_gate_reject | time_gate_reject | yes |
| 22 | TD-W04 | WIRE_TIME_GATE / wire_time_gate_only | normative | 7.2 step 2 | time_gate_pass | time_gate_pass | yes |
| 23 | TD-B07 | DERIVE / reliance | normative | 6.1 | fresh | fresh | yes |
| 24 | TD-B08 | DERIVE / reliance | normative | 6.1 | expired | expired | yes |

Rows appear in the order the runner emitted them (`run-output.txt` lines 1-24); every row ends with `PASS` in the console recording.

## Mutation battery (independent, six mutants)

The battery is the runner's own, distinct from the candidate's shipped battery; order below follows the console recording. `killed by` lists the cases whose verdict changed under each mutant.

| Mutant | Killed by | Killed-by count |
|--------|-----------|-----------------|
| trusts-advisory-flag | TD-N01, TD-N02, TD-N03, TD-N04, TD-X04, TD-X06, TD-B08 | 7 |
| always-fresh | TD-B03, TD-B05, TD-B06, TD-N01, TD-N03, TD-N05, TD-X02, TD-X03, TD-X04, TD-X05, TD-X06, TD-B08 | 12 |
| always-expired | TD-B01, TD-B02, TD-B04, TD-N02, TD-N04, TD-N06, TD-X01, TD-X03, TD-X04, TD-X05, TD-X06, TD-B07 | 12 |
| wire-gate-rejects-equality | TD-B01, TD-B02, TD-B03, TD-B04, TD-B05, TD-B06, TD-B07, TD-B08, TD-N01, TD-N02, TD-N03, TD-N04, TD-N05, TD-N06, TD-X01, TD-X02, TD-X03, TD-X06, TD-W02, TD-W04 | 20 |
| undeclared-boundary-inclusive | TD-X03 | 1 |
| hardcoded-120s-window | TD-B03, TD-B05, TD-B06, TD-N01, TD-N03, TD-N05, TD-X02, TD-X03, TD-X06, TD-B07, TD-B08 | 11 |

## Summary

24/24 cases agree · 6/6 mutants killed · exit status 0 · CHECKSUMS gate 6/6 before anything ran.
