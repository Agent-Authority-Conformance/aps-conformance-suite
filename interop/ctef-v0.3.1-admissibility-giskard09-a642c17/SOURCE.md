# ctef-v0.3.1 at PR #43 head a642c17f: a second implementation of the admissibility outcomes, run by its author (giskard09)

Family under review: `fixtures/cross-stack/ctef-v0.3.1/` as proposed in
[PR #43](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/43) at head
`a642c17f2b5b003d403d7d0faec4b72910afb787`. The family is not on `main` at the time of this
run. This record is pinned to those bytes; a later head with different fixture bytes gets a
new record, this one is not edited.

This record covers one layer only: the admissibility outcomes (claim model and expiry) that the
family's own `plugins/admissibility.py` produces for the five signed fixtures. The byte,
signature and Wycheproof layers have their own lab record beside this one,
`interop/crypto-recompute-ctef-v0.3.1-a642c17/`. The two are different layers, different
implementations and different runners, and are not folded together.

## Why this run was asked for, and what it is

At a642c17 the family's SOURCE.md labels the admissibility outcomes author-produced: the only
implementation of the CTEF claim semantics exercised by `validate.py` is the family author's.
CONTRIBUTING admits an external family's independently recomputable semantic verdicts only with
an independent record. The ask went out as issue #72 on 2026-09-03; the family author pointed
an outside implementer at it on 2026-09-05.

The issue text asked for a run "using an implementation ... that you authored or that is
independent of both". That wording was the lab's error: CONTRIBUTING's independence test follows
the implementation that supplies the recomputation, and in Mode B that is the alternate
checker. giskard09 wrote that checker and ran it, so this record is Mode B, author-produced,
with the authorship relationship stated below. It is a second implementation of the claim
model reaching the same five verdicts, which is real evidence and is recorded as such; it is
not yet the independent record the family's admissibility layer needs. What would make the
layer independent: his checker published at a pin, run by someone who authored neither the
fixtures nor that checker (the lab qualifies, so does any third party), recorded as a further
record beside this one.

## The run

Runner: giskard09 (Pablo Etcheverry, argentum-core), on his own machine, with his own
implementation, reported on issue #72 on 2026-09-05 (comments 5551733751 and 5551782874).
His stated terms, in his words: built from the published vectors and fixture shapes only,
SOURCE.md plus `fixtures/*.json` and `jwks.json`, without reading `plugins/admissibility.py` or
the rest of `plugins/`. His checker is not published; this record carries his method statement
and his results, not his code.

Method, as reported: the five fixtures at a642c17 verified byte-exact against the tree first
(git blob SHA match via `git hash-object`); JCS canonical bytes and SHA-256 re-derived against
each fixture's declared values; then the claim model applied: the closed `claim_type` set, the
scope rule, the composition rule, expiry.

Results, verbatim from the report (5 of 5 match the family's declared outcomes):

    positive-authority:            pass
    negative-scope-violation:      fail-closed / INVALID_CLAIM_SCOPE
    negative-composition-failure:  fail-closed / INVALID_COMPOSITION
    negative-missing-claim-type:   fail-closed / INVALID_CLAIM_SCOPE
    negative-expired:              fail-closed / EXPIRED

He also reports four cases beyond the five, run to check that his checker is not fitted to the
given vectors: tampered signature, out-of-set `claim_type`, valid multi-chain composition, and
the boundary `expires_at == verification_time`; all behaved as he expected. Those four inputs
are not published and are not part of this record's claim; they are noted because he reported
them.

## The bytes he ran against

Fixture blobs at a642c17, recorded by the lab from the PR head so the pin outlives the branch:

    positive-authority.json            bca2ce37265c
    negative-scope-violation.json      3369a64eeafc
    negative-composition-failure.json  9ce243733794
    negative-missing-claim-type.json   70a22b30a4d7
    negative-expired.json              b110f9407feb

`jwks.json` at this head carries `x = KE3Lgb85eyrk3AWSgJwqI-3sJOiehqTPFuvmrUogK2Q`, `kid`
`ctef-fixture-v1`; the key was rotated between a71b7329 and a642c17 and all five fixtures were
re-signed, which is why this record exists at a642c17 and not at the earlier head.

## Where the runs differ, recorded and not adjudicated

They do not differ. The family's `validate.py` at a642c17 reports the five admissibility checks
passing (results.json, `admissibility:*`, 5 of 5) and his checker reaches the same five verdicts
with the same error codes.

## Verification split

- Admissibility outcomes (claim model and expiry), five fixtures; runner: giskard09; Mode B;
  author-produced; implementation: his own checker, unpublished, written from SOURCE.md and
  the fixture shapes. He authored neither the vectors nor the family's `admissibility.py`, but
  he authored the implementation whose output supplies this recomputation, which is the
  relationship that keeps the record author-produced under CONTRIBUTING. The layer is
  independently recomputable, so its independent record is a condition of the family's merge,
  not an `OPEN-RUNS` entry: a non-author's run of a pinned copy of that checker.
- Byte identity of the five fixtures at a642c17; runner: aeoess (blob SHAs above); Mode A;
  author-produced as a lab pin, not a verification claim.

These records are attributed per layer. Merge of this family is not an end-to-end verification
or a family-level verdict.

## What this record does not establish

It is not an independent record for the admissibility layer; see the Verification split. It
does not establish that the CTEF claim model is correct, only that two implementations written
from the same published description reach the same five verdicts on these five fixtures, each
run by its own author. It does not cover the four extra cases he ran, whose inputs are his. It is not an
adoption or endorsement claim by or about argentum-core, AgentAvow or APS, and it says nothing
about any other head of the family.
