# CoSAI WS4 #149, decision-to-effect: candidate cases against the agreed scope

Eleven candidate cases for the decision-to-effect seam named on
cosai-oasis/ws4-secure-design-agentic-systems#149, using the verdict
vocabulary of the candidate rule agreed on cosai-oasis/ws4-secure-design-agentic-systems#189,
which the workstream has not adopted.
Both are **open RFCs**, not approved CoSAI positions and not normative
requirements. Every case here is `candidate_against_proposed` and carries
`expected_if_adopted`, not `expected`. **Nothing in this directory is a
conformance case, and adoption is a decision for the workstream, not for this
repository.**

## The seam

imran-siddique named the non-transitive chain on #149 (2026-09-09T04:01:23Z):

> a valid manifest does not imply an authorized action
> an authorized action does not imply the exact authorized call ran
> an exact authorized call does not imply execution was non-bypassable
> execution does not imply the intended effect occurred

This corpus isolates the last three arrows as three separate properties,
each checked by exactly one case-isolated evaluation:

- `exact_call`: the dispatched call carries exactly the authorized arguments
- `non_bypassability`: the protected effect was not reached by a path that
  bypasses the authorization boundary
- `effect_verified`: the tool's self-report agrees with an independent
  read-back of the effect

## Evidence shape

Fixture-local, no OCSF or other external schema dependency, per
Levaj2000's confirmation on #149 (2026-09-09T21:13:45Z) that the
admission/closure pairing is "a structural pattern, not a schema."

- `evidence.admission`: authorized intent: `action_id`, `tool`,
  `args_digest`, `decision`. Nullable: a bypass case has no admission
  covering the credential use, and that absence is the evidence.
- `evidence.closure`: observed outcome, joined to the admission by a
  stable `ref`. Carries a `dispatch` record (a dispatched args digest, or a
  refusal with a `reason` and an `attributed_cause`), a `tool_self_report`,
  an independent `read_back` result (`agrees` / `disagrees` with an
  `observed_digest`, or `unavailable` with a `reason`), and, only for
  `non_bypassability`, a `credential_use` record (`credential`, `path`
  of `governed` or `alternate`, `admission_ref`).
- `context.evaluation_scope`: the interval or unit the property is
  evaluated over, required always.
- `context.observation_coverage`: an established-coverage premise,
  supplied by a separate verifier surface and never verified recursively
  here, per the no-recursion rule on #189. When supplied it must carry
  `status`, `scope` and `claim_ref`, and `context.claim_ref` must then also
  be present: coverage is bound to both the evaluated scope and the
  evaluated claim instance (see PROVENANCE.md on the #98 addition to this
  suite's #189 candidate), and a mismatch on either leaves the verdict
  `not_established`, never `pass`.
- `runtime_outcome` (optional): carried strictly as evidence. Never read
  to decide a verdict. See `D2E-EFFECT-03` below.

Checker input is `{property, evidence, context, runtime_outcome?}`. The
checker never sees `expected_if_adopted`. `adapter/py/run.py` compares them
afterwards, matching the split darklordVirtual required on #189
(2026-09-11T06:29:26Z): "I would not make `expected_property_verdict` or
`unmet_proof_obligation` inputs to the inference itself."

## Verdict vocabulary

Exactly three: `pass | fail | not_established`, reused from the #189
candidate rule. `unmet_obligation` is populated only when the verdict is
`not_established`. An unsupported property name raises
`UnsupportedVerification`. Malformed or structurally invalid input raises
`CandidateInputError`. Neither is a verdict. See `adapter/py/checker.py`'s
module docstring for why folding either into `not_established` would make a
broken checker conformant by construction.

## Cases

| id | property | scenario | expected if adopted | obligation | provenance |
|---|---|---|---|---|---|
| `CAND-COSAI-149-D2E-POS-01-EXACT-CALL` | exact_call | authorized `C(args)`, dispatched `C(args)` | pass | none | lab-authored |
| `CAND-COSAI-149-D2E-POS-01-EFFECT-VERIFIED` | effect_verified | same scenario, read-back agrees | pass | none | lab-authored |
| `CAND-COSAI-149-D2E-POS-01-NON-BYPASSABILITY-COVERED` | non_bypassability | same scenario, observation coverage established for the scope and claim | pass | none | lab-authored |
| `CAND-COSAI-149-D2E-POS-01-NON-BYPASSABILITY-UNCOVERED` | non_bypassability | same scenario, no coverage premise supplied | not_established | `observation_coverage` | lab-authored |
| `CAND-COSAI-149-D2E-EXACT-01` | exact_call | args mutated after authorization, dispatched anyway | fail | none | REMORA V-02 |
| `CAND-COSAI-149-D2E-EXACT-02` | exact_call | args mutated after authorization, dispatch refused citing the mismatch | pass | none | REMORA V-02 |
| `CAND-COSAI-149-D2E-BYPASS-01` | non_bypassability | protected credential used via an alternate path, no covering admission | fail | none | new, no REMORA vector |
| `CAND-COSAI-149-D2E-BYPASS-02` | non_bypassability | no bypass observed, coverage of alternate paths not established | not_established | `observation_coverage` | new, no REMORA vector |
| `CAND-COSAI-149-D2E-EFFECT-01` | effect_verified | tool self-report success, independent read-back disagrees | fail | none | REMORA V-13 |
| `CAND-COSAI-149-D2E-EFFECT-02` | effect_verified | independent read-back could not be performed | not_established | `read_back` | new, no REMORA vector |
| `CAND-COSAI-149-D2E-EFFECT-03` | effect_verified | `runtime_outcome = EFFECT_INDETERMINATE` carried as evidence, read-back unavailable | not_established | `read_back` | REMORA V-14 |

**On splitting `D2E-POS-01`.** The spec for this corpus describes one positive
control scenario tested against all three properties, with `non_bypassability`
conditional on the coverage premise. That is split into four case files here,
one property (or one property/premise combination) per file, so that every
case in the directory isolates exactly one property, matching the rest of the
corpus and the convention in `interop/cosai-ws4-189-evidence-sufficiency/`.
All four files carry the identical admission/dispatch/read-back facts and
differ only in which property is under evaluation and, for the two
non-bypassability files, whether the coverage premise is supplied.

Full REMORA pins (repository, tag/ref, commit, vector-to-case mapping) and
the CoSAI comment URLs for #149 and #189 are in `PROVENANCE.md`. What a
passing run does not establish is in `NON-COVERAGE.md`.

## Labels

Every case carries `"status": "candidate_against_proposed"`. **These are
candidate cases, not conformance cases.** Adoption of the exact_call /
non_bypassability / effect_verified properties, the verdict vocabulary, or
this evidence shape is a decision for the CoSAI WS4 workstream, not something
this repository asserts or certifies.

## Re-run

Generation and verification are separate modes, and **verification never
writes to the committed tree**.

    cd interop/cosai-ws4-149-decision-to-effect
    python3 adapter/py/test_checker.py     # checker regressions, including the adversarial pass
    python3 adapter/py/run.py              # VERIFY, read-only, nonzero exit on any mismatch
    python3 adapter/py/test_harness.py     # harness regressions, run.py as an artifact
    python3 adapter/py/run.py --generate   # rewrite the fixtures and results.json
    shasum -a 256 -c SHA256SUMS.txt        # check the published digests

Verify requires the candidate set to be exactly the eleven declared cases, so
a missing case fails and an unverified extra file dropped into
`candidates-proposed/` cannot go unexamined. It then performs three
independent checks: it regenerates each case into a scratch directory and
diffs against the committed bytes, it runs the checker over the committed
fixtures and compares against their committed expectations, and it compares
`results.json` against what the committed fixtures produce.

`adapter/py/test_harness.py` pins the read-only property itself. It copies
the record to a scratch directory, mutates it, and asserts that verification
exits nonzero AND that the mutated bytes are unchanged afterwards, across a
mutated expectation, a mutated checker input, an extra candidate file and a
missing one.

## Adversarial pass

Before committing, every negative and `not_established` case in this corpus
was attacked by deleting or mutating exactly one field, attempting to reach
`pass`. Every attempt ended in `fail`, `not_established`, or a structural
error. Each attempt is a permanent regression in `adapter/py/test_checker.py`
under the header `ADVERSARIAL PASS`, including relabeling an unresolved
alternate-path credential use as `governed`, injecting a `refusal` object
alongside a `dispatched` status, supplying observation coverage for a
different scope or a different claim than the one evaluated, blanking or
deleting a read-back-unavailable reason, sneaking an `observed_digest` into
an `unavailable` read-back, and supplying `runtime_outcome` as a bare string
or a falsely-successful status while `read_back` stays unavailable. None of
them reached `pass`.

## Lab operating constraints

The lab certifies nothing and issues no conformance verdicts. Each case
records its origin, the REMORA pin it was observed against where one exists,
and the proposed rule it is written against. Field names in this candidate's
evidence shape are this corpus's own vocabulary. WS4 has settled none of them,
and, like the rest of the shape, they follow whatever the workstream settles
on if and when this is adopted.
