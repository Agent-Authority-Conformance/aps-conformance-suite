# CoSAI WS4 #189, evidence sufficiency: candidate cases against the freeze candidate

Three candidate cases for the verdict rule being frozen in
cosai-oasis/ws4-secure-design-agentic-systems#189. The rule is a **freeze
candidate in an open RFC**, not an approved CoSAI position and not a
normative requirement. Every case here is `candidate_against_proposed` and
carries `expected_if_adopted`, not `expected`. Nothing in this directory is
a conformance case.

The rule under test, as stated on the issue on 2026-09-11: where declared
capability and gating establish that the producer would have emitted the
field, an absent field is evidence of absence and can support the narrow
property. Where that production coverage was never established, the same
missing field is absence of evidence, verdict `not_established`, unmet
obligation `producer_capability_coverage`.

| id | origin | context | expected if adopted |
|---|---|---|---|
| `CAND-COSAI-189-SINK-01` | Levaj2000, observed behavior of praxis-proxy/policy PR #84 at `5b76fa6f` | capabilities declared empty | `not_established` / `producer_capability_coverage` |
| `CAND-COSAI-189-SINK-02-COUNTERFACTUAL` | Levaj2000, stated counterfactual in the same comment (hypothetical) | `read_delegation` declared | `pass` |
| `CAND-COSAI-189-SINK-03-UNKNOWN` | lab-authored variant | capabilities unknown (not declared at all) | `not_established` / `producer_capability_coverage` |

All three reproduce under the checker in `adapter/py/checker.py`, which
implements only the stated rule for the single property
`no_delegation_occurred`. The checker never sees `expected_if_adopted`; the
runner compares afterwards. That separation is the point darklordVirtual
made on the issue and the fixture shape keeps it.

What the source comment did not determine: the concrete OCSF field values
(the case records field presence and gating, not payloads), and whether an
unknown declaration should be treated the same as an explicit empty one.
SINK-03 fixes the lab's reading of the second point and is labelled as
lab-authored so it cannot be mistaken for the author's.

Field names follow the freeze-candidate shape on the issue. When the corpus
schema settles they should be renamed to match it.

## Re-run

    cd interop/cosai-ws4-189-evidence-sufficiency
    python3 adapter/py/run.py

## Lab operating constraints

The lab certifies nothing and issues no conformance verdicts. Each case
records its origin, the revision it was observed at where one exists, and
the proposed rule it is written against.
