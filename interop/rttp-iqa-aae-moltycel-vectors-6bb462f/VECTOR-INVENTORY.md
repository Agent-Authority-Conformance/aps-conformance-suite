# Vector inventory

Candidate: `candidates/moltycel-aae-vectors` (PR #190). Counts as declared in its CANDIDATE.md and confirmed by this run.

| Set | Path in candidate | Count | Normative target |
|---|---|---|---|
| native | `vectors/` | 15 | draft-kroehl-agentic-trust-aae-00 |
| composition | `interop/psea/vectors/` | 6 | draft-kroehl-agentic-trust-aae-00 with draft-yossif-psea-02 |
| enforce | `vectors/enforce/` | 26 | draft-kroehl-agentic-trust-aae-02 (enforce kernel 3.0) |
| negative controls | `interop/psea/negative-controls.json` | 11 | mutated composition inputs with pinned expected rows |

Total vectors scored: 47 (15 + 6 + 26), plus 11 negative controls and 14 verifier unit tests. Each vector carries its expected verdict inside the frozen file; the verifiers compare row-by-row and the byte gate plus regeneration gate pin the bytes end to end. The candidate ships no mutation battery (see run-report.md).
