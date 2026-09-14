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

**Revised 2026-09-14 after review by imran-siddique and Levaj2000 on the
issue.** Imran reran the three committed cases at `6d5d942a`, confirmed all
three and all nine checksums, and reported four defects. Levaj2000 reproduced
all four and confirmed each. All four are repaired here and each
carries a regression in `adapter/py/test_checker.py`.

The verdict vocabulary stays exactly `pass | fail | not_established`, as the
freeze candidate states. The same comment says malformed input, an unsupported
verification path, parser failure and an internal error are not
`not_established`, because otherwise a broken verifier becomes conformant by
returning the third value. Those four are therefore not verdicts here at all.
They raise.

1. **A missing `gated_on` descriptor was read as explicitly ungated.**
   Deleting `evidence.delegation.gated_on` moved the verdict from
   `not_established` to `pass`, a fail-open. Structural validation of the
   candidate input now runs once, before any inference, so no inference branch
   decides what an absent key means. A descriptor requires `present` and
   `gated_on`; `gated_on` accepts a capability string or an explicit `null` for
   ungated. A missing or malformed descriptor raises `CandidateInputError`.
2. **An unsupported property returned a verdict.** It now raises
   `UnsupportedVerification`, distinct from `CandidateInputError` so a caller
   can tell "I cannot evaluate this property" from "this input is malformed".
   Neither is a verdict.
3. **Field visibility was treated as interval completeness.** These are two
   premises and the checker had collapsed them. Both are now required for a
   negative quantified over a session, and they are checked in order so neither
   obligation masks the other.
4. **The harness could silently repair the artifact it graded.** See Re-run
   below.

**On finding 3, what the source shows.** Tracing the case through the modelled
implementation at `praxis-proxy/policy` `5b76fa6` rather than treating the
mutation as the whole proof:

- `read_delegation` does establish visibility. `filter_extensions` clones the
  delegation slot into the sink's view only when the capability is held, and
  the capability comes from that sink's operator-controlled `plugins:` entry
  and is fixed before the sink sees the extensions. So an absent delegation
  block does mean no delegation was visible on a processed invocation, and this
  is not a post-hoc producer declaration.
- The capability set is carried in no emitted record, so a verifier holding only
  the bytes cannot recover it. That is why it belongs in `context` rather than
  `evidence`, which is what the freeze candidate already has.
- It establishes nothing about whether every relevant invocation in the session
  is represented. A failing audit sink is logged and skipped rather than failing
  the request, so a record can be lost. Completeness has separate machinery in
  `epoch`, `stream_id` and dense `stream_seq`, and dense sequence detects an
  internal gap without establishing the boundaries of the evaluated interval.

So `producer_capability_coverage` is field visibility and `observation_coverage`
is interval completeness. SINK-02 now carries the second premise in `context`,
labelled `assumed by this counterfactual` and not observed in the incident. In a
real evaluation that premise would have to be established by a separate verifier
surface; in this fixture it is an authored assumption, and the `basis` field says
so rather than presenting it as a verifier output. Per the freeze candidate no
recursion is needed either way: this checker reads and requires the premise and
never verifies completeness itself. Removing the premise returns
`not_established` / `observation_coverage`.

**A second adversarial pass, after the first repair.** Imran's exact mutation
was fixed, but the invariant behind finding 3 was still reachable two other ways,
so both are closed here.

- **Every path to a negative `pass` now requires interval completeness.** The
  coverage check previously sat only on the absent-field branch, so a delegation
  block that was present with zero events returned `pass` before completeness was
  considered. Zero events in one record establishes a session-wide negative no
  better than an absent block does. Outcomes are asymmetric: one observed event
  is a witness and settles `fail` with no completeness premise, while every
  no-event path now converges on the same requirement.
- **The completeness premise is now bound to the evaluated interval.** The check
  previously accepted any descriptor whose `status` was `established`, with no
  `scope` and no relation to the property's interval, so coverage established for
  one invocation satisfied a session-wide claim. `evaluation_scope` is now
  required, the coverage descriptor is validated in `_validate` like every other
  inference input, and `established` counts only when
  `observation_coverage.scope` equals `evaluation_scope`. A mismatch is
  `not_established`; a malformed descriptor raises.

`evaluation_scope` was decorative while capability was the only premise. It is
load-bearing now, because a completeness premise has to be about something.

Field names here are this candidate's vocabulary. WS4 has frozen none of them,
and like the rest of the shape they follow whatever the corpus settles on.

| id | origin | context | expected if adopted |
|---|---|---|---|
| `CAND-COSAI-189-SINK-01` | Levaj2000, observed behavior of praxis-proxy/policy PR #84 at `5b76fa6f` | capabilities declared empty | `not_established` / `producer_capability_coverage` |
| `CAND-COSAI-189-SINK-02-COUNTERFACTUAL` | Levaj2000, stated counterfactual in the same comment (hypothetical) | `read_delegation` declared, plus session observation coverage assumed by the counterfactual | `pass` |
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

Generation and verification are separate modes, and **verification never
writes to the committed tree**.

    cd interop/cosai-ws4-189-evidence-sufficiency
    python3 adapter/py/run.py              # VERIFY, read-only, nonzero exit on any mismatch
    python3 adapter/py/test_checker.py     # checker regressions
    python3 adapter/py/test_harness.py     # harness regressions, run.py as an artifact
    python3 adapter/py/run.py --generate   # rewrite the fixtures and results.json

Verify first requires the candidate set to be exactly the three declared cases,
so a missing case fails and an unverified extra file dropped into
`candidates-proposed/` cannot go unexamined. That invariant comes from the
proposed `check.py` imran-siddique posted on #91. It then performs three
independent checks: it regenerates each case into a
scratch directory and diffs against the committed bytes, it runs the checker
over the committed fixtures and compares against their committed
expectations, and it compares `results.json` against what the committed
fixtures produce.

Previously `run.py` regenerated the fixtures before evaluating them, so
altering a committed expectation was silently overwritten and the run still
exited 0. Imran demonstrated this by changing a committed expectation to
`fail`. Under the current harness that same edit fails three ways and the
altered file is left on disk rather than repaired.

`adapter/py/test_harness.py` pins that property rather than leaving it to a
manual check. It copies the record to a scratch directory, mutates it, and
asserts that verification exits nonzero AND that the mutated bytes are
unchanged afterwards, across a mutated expectation, a mutated checker input, an
extra candidate file and a missing one.

## Lab operating constraints

The lab certifies nothing and issues no conformance verdicts. Each case
records its origin, the revision it was observed at where one exists, and
the proposed rule it is written against.
