# conflicting-status-sources

Candidate cases for status observation and coverage at one authorization
boundary. Two status sources a verifier trusts disagree about the same
delegation. A source answers past the freshness bound the verifier declared for
it. A verifier that declared itself offline admits on a snapshot inside a bound
it declared in advance, and records what it admitted on.

Nothing here is merged specification text and nothing here is a conformance
claim about APS or any other protocol. The harness is protocol neutral: a
synthetic verifier in front of a set of synthetic status sources, with no APS
type, no APS receipt, no network call and no wall-clock read anywhere in it.

## Status

**candidate_against_proposed.** Every case carries that label in `vectors.json`
and every case names the proposed text it tests. The text under test is the
Authority Lifecycle document, cited by section name and commit so a reader can
pin exactly what this fixture was written against.

| field | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| commit | `5c1bf09` |
| version at that commit | 0.1.2-draft |
| status of the text itself | proposed, and the document says no public case tests these concepts yet |

That repository is the text under test, not an external source for any factual
claim in this README. Where this README makes a claim about a standard, the
source is fetched and quoted below.

### The proposed text each case tests

| section in the document at 5c1bf09 | quoted |
|---|---|
| Lifecycle concepts are separate > Verification and evidence > **Status observation** | "What authority state a verifier could establish, from which source, at what time and with what freshness. Current authority and observed authority can differ." |
| Lifecycle concepts are separate > Verification and evidence > **Verifier trust policy** | "Which issuers, roots, status sources and rules a verifier accepts." |
| Lifecycle concepts are separate > Verification and evidence > **Coverage and completeness** | "What set or interval the available evidence covers." |
| Lifecycle concepts are separate > Verification and evidence > **Evidence** | "Ending authority does not by itself erase or invalidate evidence of earlier events." |
| Invariants > **L7. Unknown revocation state is not active** | "A revocation answer that is unavailable or stale is indeterminate. It does not become active, and the evidence does not claim a revocation that never happened." |

Per-case section lists are in `vectors.json` under `cases[].proposed_text`.

### What draft-03 does and does not state

`draft-pidlisnyi-aps-03`, fetched from
`https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt` on 2026-09-23.

What it does state, and this fixture relies on:

- Section 3.3: "An unavailable or stale revocation result is indeterminate."
- Section 3.3: "A caller MUST NOT collapse indeterminate or unsupported into
  valid."
- Section 3.5: "Revocation is irreversible."

What it does not state, which is why every case here is labelled
candidate_against_proposed and none is labelled a draft-03 conformance case:

- Nothing about more than one status source answering about the same chain
  member. Section 3.3 rules one revocation result per member.
- No per-source freshness bound. "Stale" is used without a rule for measuring
  it against a declared bound.
- No rule for what a boundary returns when one source is fresh and another is
  stale, or when a required source is silent.
- No coverage requirement over a declared set of status sources.
- No offline admission on a snapshot inside a declared bound.

Section 5.4 does require that "authority_state MUST include the selected
authority chain, authority-basis resolution, revocation observations, and the
spend state used by the decision", which is the closest published text to this
family's record. It does not say what fields one revocation observation
carries, so it does not decide any case here. See **Where the proposed text was
too vague to test** below.

## Sources

Every claim below about deployed practice was fetched in the session that wrote
this fixture and is quoted verbatim.

**A status answer already carries a freshness bound in deployed practice.**
RFC 6960 (OCSP), Section 2.4, fetched from
`https://www.rfc-editor.org/rfc/rfc6960.txt`: "thisUpdate The most recent time
at which the status being indicated is known by the responder to have been
correct." Section 3.2, on accepting a signed response: "The time at which the
status being indicated is known to be correct (thisUpdate) is sufficiently
recent".

This is why each source in the model carries its own `as_of` and its own
`freshness_bound_s`, rather than one global staleness setting.

**A verifier holding a cached status list with a declared time to live is
deployed practice.** W3C Bitstring Status List, W3C Recommendation 15 May 2025,
fetched from `https://www.w3.org/TR/vc-bitstring-status-list/`: "The ttl is an
OPTIONAL property that indicates the \"time to live\" in milliseconds before a
refresh SHOULD be attempted." And: "Verifiers SHOULD cache the retrieved status
list".

This is why the offline variant is modelled as a snapshot with a bound the
verifier declared, not as a verifier guessing.

**No fetched source states a rule for two trusted status sources disagreeing.**
Neither RFC 6960 nor the Bitstring Status List Recommendation defines what a
verifier does when two sources it trusts give different determinate answers
about the same subject. Neither does draft-03. That gap is what CSS-04 and
CSS-05 are for, and this README does not claim otherwise.

None of these sources says anything about AI agents. The translation into
agent-authority terms is this lab's, and the sources are a source of model
shape, not a claim that they apply.

## The model

`harness.ts` is a synthetic verifier. For one delegation, at one authorization
boundary, it holds:

- a **trust policy**: the sources it requires an answer from, each with its own
  freshness bound in seconds, plus, in offline mode, a snapshot source and the
  maximum snapshot age it declared in advance that it would admit on,
- a set of **observations**: one per source that answered, each carrying the
  answer (`active`, `revoked` or `unavailable`) and `as_of`, the instant that
  source says the answer was known correct,
- a synthetic clock: `evaluated_at` comes from the vector, and nothing reads
  wall time.

It produces one **status-observation record** per boundary, which is the
artifact this family pins. The record carries the decision, the reason, every
source line with its age and whether it was within its bound and whether it was
used, the coverage count, the conflict when there is one, the snapshot when an
offline admission used one, and a reference to the record written at the
previous boundary.

### The decision procedure

1. Age every answer against the boundary instant. An answer is **within bound**
   when its age is at most the bound declared for its source. The bound is
   inclusive, and CSS-13 and CSS-14 pin which side each verdict sits on.
2. Decide which answers are **used**. An `unavailable` answer is never used. An
   answer within its bound is used. A `revoked` answer past its bound is still
   used, because a revocation that was observed does not become unobserved with
   age, and draft-03 Section 3.5 says revocation is irreversible. An `active`
   answer past its bound is not used.
3. If the used answers carry more than one determinate state, that is a
   **conflict**: deny, reason `status_sources_conflict`, and the record names
   both states and both sources. A conflict never admits, whatever coverage
   says.
4. If the used answers are all `revoked`: deny, reason `status_revoked`.
5. If nothing usable and determinate remains: `not_established`.
6. Otherwise the used answers are all `active`. An offline verifier with a
   snapshot inside its declared bound admits on that snapshot and records it.
   An online verifier admits only when every source the trust policy requires
   produced a usable determinate answer. Short of that it returns
   `not_established` with a reason that distinguishes a stale answer from a
   silent source.

There are three verdicts: `admit`, `deny`, `not_established`. A conflict and an
unestablished status are different findings and never collapse into each other,
and neither is ever `admit`. Nothing in this family says an answer is false: a
stale `active` answer is an answer the verifier could not use, not a lie.

### Reasons

| reason | verdict | meaning |
|---|---|---|
| `status_active_all_sources_agree` | admit | every required source answered inside its bound and every answer was active |
| `admitted_on_snapshot_within_declared_bound` | admit | an offline verifier used a snapshot inside the bound it declared, and recorded which snapshot and what age |
| `status_revoked` | deny | a trusted source answered revoked and no usable answer disagreed |
| `status_sources_conflict` | deny | two trusted sources gave different determinate answers about the same delegation |
| `status_stale_beyond_bound` | not_established | an answer the verdict needed was older than the bound declared for its source |
| `status_coverage_incomplete` | not_established | a source the trust policy requires produced no answer at all |
| `status_no_usable_observation` | not_established | no source produced a usable determinate answer |

## Cases

Fourteen cases, fifteen boundaries, in `vectors.json`.

| case | verdict | reason | what it covers |
|---|---|---|---|
| `CSS-01-single-source-active-admits` | admit | `status_active_all_sources_agree` | positive control, one source, one fresh active answer |
| `CSS-02-two-sources-agree-active-admits` | admit | `status_active_all_sources_agree` | positive control, both required sources fresh and agreeing |
| `CSS-03-two-sources-agree-revoked-denies` | deny | `status_revoked` | agreement on revoked is not a conflict |
| `CSS-04-fresh-conflict-denies-with-conflict-reason` | deny | `status_sources_conflict` | the family core: two fresh trusted sources, one active and one revoked |
| `CSS-05-stale-revoked-against-fresh-active-denies` | deny | `status_sources_conflict` | the negative control a naive implementation passes wrongly |
| `CSS-06-one-source-stale-past-bound-not-established` | not_established | `status_stale_beyond_bound` | one required source past its bound |
| `CSS-07-required-source-silent-not-established` | not_established | `status_coverage_incomplete` | one required source answered nothing at all |
| `CSS-08-no-usable-answer-not-established` | not_established | `status_no_usable_observation` | one stale, one unavailable, nothing usable left |
| `CSS-09-offline-snapshot-within-declared-bound-admits` | admit | `admitted_on_snapshot_within_declared_bound` | offline admission, and the record has to name the snapshot and its age |
| `CSS-10-offline-snapshot-past-declared-bound-not-established` | not_established | `status_stale_beyond_bound` | snapshot older than the declared bound |
| `CSS-11-offline-snapshot-revoked-denies` | deny | `status_revoked` | being offline does not soften an observed revocation |
| `CSS-12-later-conflict-does-not-rewrite-the-earlier-record` | admit, then deny | then `status_sources_conflict` | two boundaries: the later record references the earlier one and does not change it |
| `CSS-13-answer-exactly-at-the-bound-admits` | admit | `status_active_all_sources_agree` | the bound is inclusive |
| `CSS-14-answer-one-second-past-the-bound-not-established` | not_established | `status_no_usable_observation` | one second past the bound |

### The negative control a naive implementation passes wrongly

`CSS-05`. One source answers `active` inside its bound. The other answers
`revoked`, and that answer is past its own bound. An implementation that
discards every stale answer before deciding is left with one fresh `active`
answer, admits, and looks correct doing it: it applied a freshness rule, it
found agreement, it wrote a clean record. It has admitted on a delegation a
source it trusts told it was revoked.

The `drop-stale-then-decide` control below is exactly that implementation, and
it fails exactly this case and two others for the same reason.

## Negative controls

Three controls, each changing one axis of the reference verifier and running
against a declared scope of cases, not only the ones predicted to fail, so a
declared failure that quietly stops failing is visible.

| control | axis changed | scope | must fail |
|---|---|---|---|
| `latest-answer-wins` | disagreement resolution: the newest `as_of` decides alone | CSS-01, 02, 03, 04, 05, 12 | CSS-04, CSS-05, CSS-12 |
| `drop-stale-then-decide` | what survives the freshness bound, and what coverage is measured over | CSS-02, 05, 06, 07, 08, 13, 14 | CSS-05, CSS-06, CSS-07 |
| `offline-admit-without-recording` | whether an offline admission records the snapshot and the age it used | CSS-09, 10, 11 | CSS-09 |

`offline-admit-without-recording` reaches the same verdict as the reference on
every case in its scope. It fails CSS-09 only because the record it writes is
not the record the vector pins: it admits without saying what it admitted on.
That is the whole point of the case.

## Results

Both runners produced the same table.

| runner | cases | boundaries | reference verifier | controls |
|---|---|---|---|---|
| `verify.ts` (TypeScript) | 14 | 15 | matched every pinned record | each failed exactly its declared set |
| `verify.py` (Python) | 14 | 15 | matched every pinned record | each failed exactly its declared set |

The two runners agree on every decision, every reason and every RFC 8785
canonical digest.

SDK results are in `SDK-RUNS.md`, with the exact commands, exit codes and
verbatim output.

| claim | `agent-passport-system` 7.1.0 (npm) | `agent-passport-system` 4.1.0 (PyPI) |
|---|---|---|
| chain verdict under the projected single revocation answer | supported, 15/15 boundaries | supported, 15/15 boundaries |
| per-source freshness bound, inside or past | supported, 22/22 source lines | not_supported |
| two sources compared for conflict | not_supported | not_supported |
| coverage over a declared required-source set | not_supported | not_supported |
| `not_established` at the observation layer | not_supported | not_supported |
| an offline admission records the snapshot and the age it used | partial | not_supported |

A `not_supported` row means the SDK has no API for the behaviour and nothing
was simulated in its place. The bridges assert the absence against the
installed package, so a later release that adds the surface turns the run into
a failure rather than leaving a stale note.

## Determinism

- Seed input `aac-conflicting-status-sources-v0`, recorded in `vectors.json`
  with its SHA-256. Every key in `chain.json` is an Ed25519 seed derived from
  that string, so the file carries no secret material.
- Every instant is a constant in `generate.ts`. No wall clock, no random
  source, no network.
- Records are canonicalized under RFC 8785 JCS and pinned by SHA-256 over those
  bytes, plus the byte length. `verify.ts` uses the suite's vendored
  canonicalizer, and `verify.py` uses its own, written against RFC 8785 rather than
  ported, and covering the object, array, string, boolean, null and integer
  shapes this record domain holds. A float raises rather than being serialized,
  because guessing at ECMAScript number formatting would be a silent source of
  byte divergence and the record domain has none.
- `CHECKSUMS.sha256` pins `vectors.json` and `chain.json`. The suite's
  `npm run test:digest-integrity` recomputes it.

Regenerate:

    python3 fixtures/conflicting-status-sources/mint.py
    npm run generate:conflicting-status-sources

After both, `git diff` on `chain.json` and `vectors.json` should be empty. The
generator declares each case's expected decision and reason by hand and refuses
to write a vectors file when the reference verifier disagrees with a
declaration, so the expectation is the fixture's claim rather than a transcript
of whatever the code did.

## Running

From the repository root, TypeScript:

    npm ci --include=dev
    npm run verify:conflicting-status-sources
    npm run verify:conflicting-status-sources:sdk-ts

Both also run in `npm test`. Expected final line of the first:

    PASSED: conflicting-status-sources TypeScript, 14 cases, 15 boundaries, reference verifier matched every pinned record, each control failed exactly its declared set

Python, independently written from this README and `vectors.json`, not by
porting `harness.ts`, with no third-party dependency:

    python3 fixtures/conflicting-status-sources/verify.py

This is a manual run, not part of `npm test`. The rest of this suite's
`npm test` stays Node only and runs on the Windows job, and this fixture
follows that existing convention rather than adding a Python dependency to the
hermetic gate. It prints the same case list with `(python)` appended.

The Python SDK bridge needs the PyPI SDK and is also manual:

    python3 -m venv /tmp/css-venv
    /tmp/css-venv/bin/pip install "agent-passport-system==4.1.0"
    /tmp/css-venv/bin/python fixtures/conflicting-status-sources/sdk_bridge.py

## Verification split

One entry per distinct verification claim, using the definitions in
`CONTRIBUTING.md`.

- **Vectors and reference records / the reference verifier reproduces every
  pinned decision, reason and RFC 8785 digest; `verify.ts`; Mode A;
  author-produced; `harness.ts` in this directory.** Authorship relationship:
  the runner, the vectors and the implementation being exercised were all
  written in this lab, in the same change.
- **Vectors and reference records / the same decisions, reasons and digests
  recomputed by a second implementation; `verify.py`; Mode B; author-produced;
  an independent Python reimplementation of the decision procedure and of RFC
  8785, in this directory.** Authorship relationship: written from this README
  and `vectors.json` rather than ported, but by the same author as the
  TypeScript side, so agreement is agreement between two implementations from
  one author, not independent corroboration.
- **Negative controls / each control fails exactly its declared set;
  `verify.ts` and `verify.py`; Mode A; author-produced; the control policies in
  `harness.ts` and `verify.py`.** Authorship relationship: the declared fail
  sets and the control policies were written together in this lab.
- **SDK claim 1, chain verdict under the projected single revocation answer /
  the SDK never answers valid for a boundary this family denies or leaves
  unestablished; `sdk-bridge.ts`; Mode B; author-produced; `agent-passport-system`
  7.1.0 (npm).** Authorship relationship: the bridge and the vectors are this
  lab's, and this lab also maintains the SDK being exercised.
- **SDK claim 1, chain verdict under the projected single revocation answer /
  the same, recomputed by the second reference SDK; `sdk_bridge.py`; Mode B;
  author-produced; `agent-passport-system` 4.1.0 (PyPI).** Authorship
  relationship: as above.
- **SDK claim 2, per-source freshness boundary / the SDK freshness primitives
  place every source line on the same side of its bound as the harness;
  `sdk-bridge.ts`; Mode B; author-produced; `agent-passport-system` 7.1.0
  (npm).** Authorship relationship: as above.
- **SDK claims 3 to 6 / recorded not_supported with the missing API named, and
  the absence asserted against the installed package; `sdk-bridge.ts` and
  `sdk_bridge.py`; Mode A; author-produced; both reference SDKs.** Authorship
  relationship: as above. A not_supported entry records an absence, not a
  verification.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## What a pass establishes

For this reference model, at this revision, a pass establishes that:

- two trusted sources disagreeing about one delegation produce a deny carrying
  a conflict reason and naming both states and both sources, and never an
  admit, whether both answers are inside their bounds (CSS-04) or the revoked
  one is past its bound (CSS-05),
- an answer past the freshness bound declared for its source yields
  `not_established` rather than an admit or a deny, and the reason distinguishes
  a stale answer from a silent source and from an empty answer set,
- an offline verifier with a snapshot inside a bound it declared in advance may
  admit, and a policy that reaches the same admission without recording the
  snapshot and the age it used produces a different record and is caught,
- a later boundary that finds a revocation writes a new record referencing the
  earlier one, and the earlier record's bytes are unchanged,
- both reference SDKs, given the single revocation answer their API accepts,
  never answer `valid` for a boundary this family denies or leaves
  unestablished.

## What a pass does not establish

- **It does not establish a rule.** Every case is a candidate against proposed
  text. A pass says the reference model behaves as the fixture declares. It
  does not say any specification requires that behaviour, and the proposed text
  may change or never be adopted.
- **It does not resolve which verdict a conflict should carry.** The proposed
  text does not choose between denying on a conflict and returning
  `not_established`. This fixture denies, and says so as a modelling choice
  rather than a finding. See the next section.
- **It does not establish that the two sources are independent.** The model
  treats `registry-a` and `registry-b` as two sources a verifier trusts. It has
  no way to tell two genuinely independent sources from two replicas of one,
  which is a different failure shape with a different answer.
- **It does not test replication lag, partition, ordering or rollback.** Every
  observation in this family is supplied by the vector. Nothing here models how
  the disagreement arose.
- **It does not establish that a snapshot inside a declared bound is safe.** It
  establishes that this model admits on one and records what it admitted on. A
  revocation that happened after the snapshot is invisible to it by
  construction, and the record is what makes that visible afterwards.
- **It is author-produced, on one machine.** The vectors, both runners and both
  SDK bridges were written in this lab, which also maintains both SDKs. No
  independent party has run any of it.

## Where the proposed text was too vague to test

This is a finding of the fixture, not a caveat on it. Four places where the
text at 5c1bf09 does not decide an outcome, so the fixture had to choose and
label the choice:

1. **A conflict has no declared verdict.** The Status observation concept says
   current authority and observed authority can differ. L7 rules unavailable
   and stale answers. Neither says what a verifier returns when two sources it
   trusts both answer determinately and disagree. `deny` with a conflict reason
   and `not_established` are both defensible, and they differ in what a caller
   may do next. This fixture denies. The text should say which, because an
   implementation that returns `not_established` here and one that denies are
   both conformant to the text as written and are not interchangeable.

2. **Whether an observed revocation stays usable past its bound is not
   stated.** The fixture's step 2 treats a stale `revoked` answer as still
   counting, reasoning from draft-03 Section 3.5, "Revocation is irreversible."
   The proposed text does not say this. Read the other way, L7's "unavailable
   or stale is indeterminate" would drop that answer, and CSS-05 would admit.
   The two readings give opposite verdicts on the one case most likely to
   matter in deployment, and the text does not choose.

3. **Coverage has no declared unit.** The Coverage and completeness concept
   asks what set or interval the available evidence covers, and says a
   completeness claim needs a defined basis. It does not say whether a
   verifier's status coverage is measured over a declared source set, over the
   sources that answered, or over something else, nor whether an incomplete set
   of agreeing answers blocks an admit. This fixture measures against the
   declared set and blocks. `drop-stale-then-decide` is the other reading, and
   it is a coherent implementation, not a bug, under the text as written.

4. **What an offline admission has to record is not stated anywhere.** The
   proposed text names the snapshot and its freshness as things a status
   observation is about. It does not require a verifier that admitted on a
   snapshot to record which snapshot or how old it was. draft-03 Section 5.4
   requires a decision's `authority_state` to include "revocation observations"
   without saying what one carries. The SDK run makes the cost concrete: the
   npm SDK's signed observation record carries the source identity and the
   tolerated staleness, but neither the snapshot's `as_of` nor the age the
   decision used, so a reader of the signed record alone cannot recompute what
   age it admitted on. CSS-09 and `offline-admit-without-recording` exist to
   make that requirement testable if the text adopts it.

A fifth, smaller one: the text says a verifier trust policy names which status
sources it accepts, but says nothing about a source it accepts going silent.
CSS-07 treats silence as a coverage failure rather than as an unavailable
answer, which is a choice this fixture made and labelled.

## Boundary

A run of this family does not establish:

- anything about a real revocation service, a real status list, a real
  registry, a real gateway or any protocol. No protocol is spoken and no
  network call is made.
- that the record shape here, `aac.status-observation-record.v0`, is the shape
  a specification will adopt. It is this fixture's working definition, named so
  it cannot be mistaken for APS vocabulary.
- that `registry-a`, `registry-b` and `snapshot-c` are representative of how
  status sources are deployed. They are the smallest set that exercises
  disagreement, a bound and an offline snapshot.
- that the projection from this family's verdicts onto the SDKs' single
  revocation answer is the projection a deployment should use. It is the only
  one the SDK vocabulary allows, which is itself the finding recorded in
  `SDK-RUNS.md`.
