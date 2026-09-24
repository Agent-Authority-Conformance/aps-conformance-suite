# lifecycle-infrastructure-failure

Candidate cases for the **Infrastructure failure** section of `CASES.md` in the
agent-authority-lifecycle work. Six questions, each about a boundary evaluation
whose answer depends on something underneath the authority layer: a status
artifact past its own declared refresh time, a publisher un-saying its own bad
publication, an issuer timestamp with nothing behind it, a merge of two
divergent write histories, a read that has to follow a specific prior write, and
the coverage of an evidence interval that is still inside a declared delivery
lag.

**Status: candidate against proposed text. This is not a draft-03 conformance
family.** Every vector in `vectors.json` carries
`label: "candidate_against_proposed"` and names the proposed text it tests.
`verify.ts` and `verify.py` both fail if any vector loses that label, names no
proposed text, or returns a verdict outside the settled vocabulary.

The harness is protocol neutral. It has no APS type, no APS receipt, no network
call, no randomness, and no wall-clock read anywhere in it. Every instant is a
literal in `vectors.json`.

## What is being tested, and where it lives

| field | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| commit | `2bf5c7e` (CASES.md v0.2, descends from `7796e22`) |
| documents | `CASES.md` section "Infrastructure failure", `AUTHORITY-LIFECYCLE.md` 0.1.2-draft, `OPEN-QUESTIONS.md` |
| status of the text | proposed and open. `AUTHORITY-LIFECYCLE.md` states that no public case tests these concepts yet, and every case in the section carries `Status: proposed` |

That repository is the thing under test. It is not cited anywhere in this file
as a source for a claim about a law, a standard or an incident. A vector that
stops matching it after an edit there is a stale vector, not a finding.

Per-case section lists are in `vectors.json` under `cases[].proposed_text`.
The concepts and invariants each group exercises:

| group | CASES.md cases | proposed text |
|---|---|---|
| `status_artifact` | LC-F-006, variant LC-F-015 | Status observation, Coverage and completeness, Verifier trust policy, L7, L3 |
| `status_correction` | LC-F-009 | Lifecycle standing, Issuer standing, Evidence, L3 |
| `issuer_time_evidence` | LC-F-014 | Evidence attestor, Status observation, L9, L1 |
| `history_reconciliation` | LC-F-016, LC-F-022, LC-F-026 | L1, L11, L12, `OPEN-QUESTIONS.md` "Authority rollback", "Teardown completeness" |
| `causal_read` | LC-F-017 | Status observation, Notice, L7, L1 |
| `evidence_coverage` | LC-F-027, variant LC-F-029 | Coverage and completeness, Notice, L12 |

### What draft-03 does and does not state

[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/),
Section 3.3, fetched this session, is the nearest published text:

> Verification returns one of valid, invalid, indeterminate, or unsupported with a
> stable failure code. An unavailable or stale revocation result is indeterminate. A
> caller MUST NOT collapse indeterminate or unsupported into valid.

That covers one corner of one group: a stale or unavailable revocation answer is
indeterminate. It does not define a status artifact's own declared refresh
window, a publication-error retraction, evidence about an issuer's timestamp, a
merge of two histories, a required-observation token, or coverage of an evidence
interval. The same fetch confirmed the draft contains none of the strings
"accountable", "shared identity", "reconciliation" or "consistency token". So no
vector here is a draft-03 conformance case, and none is labelled as one.

## Sources

Every claim below about a standard or a documented incident was fetched this
session, with the verbatim quote it supports. Each is cited for the mechanism a
group models, never as evidence that the mechanism applies to AI agents.

| group | source | verbatim quote |
|---|---|---|
| `status_artifact` | [RFC 5280 §5.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.txt) | "The next update field specifies the date by which the next CRL will be issued." |
| `history_reconciliation` (LC-F-016) | [GitHub October 2018 post-incident analysis](https://github.blog/news-insights/company-news/oct21-post-incident-analysis/) | "Because the database clusters in both data centers now contained writes that were not present in the other data center, we were unable to fail the primary back over to the US East Coast data center safely." |
| `history_reconciliation` (LC-F-022) | [AWS DynamoDB global tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables_HowItWorks.html) | "Conflicts can arise if applications update the same item in different Regions at about the same time." and "DynamoDB global tables use a *last writer wins* reconciliation between concurrent updates, in which DynamoDB makes a best effort to determine the last writer." |
| `history_reconciliation` (LC-F-026) | [Redis Sentinel documentation](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/) | "clients, like C1, that are in the same partition as the old master, may continue to write data to the old master. This data will be lost forever" |
| `causal_read` | [AuthZed, "New Enemies"](https://authzed.com/blog/new-enemies) | "a token which represents the exact permissions used to protect a specific version of the content, and the content itself" |
| `evidence_coverage` | [AWS CloudTrail FAQs](https://aws.amazon.com/cloudtrail/faqs/) | "Typically, CloudTrail delivers an event within 5 minutes of the API call." |

Two groups have no external source, and `CASES.md` says so itself.
`status_correction` (LC-F-009) and `issuer_time_evidence` (LC-F-014) are both
labelled "None cited" there: a status-list build-pipeline bug and adversarial
control of an issuer's time reference are named risk classes, not documented
incidents anyone reported in these terms. This README makes no factual claim
about either, and the vectors for both groups test a rule, not a history.

## The model

`harness.ts` holds six independent pure evaluators, one per group, each mapping
one vector's `input` object to one `{verdict, reason}` pair. They are separate
because the six groups read genuinely different record sets. Folding them into
one evaluator would mean inventing a union record shape none of the cases
describes, which would put the model under test instead of the text.

### Verdict vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended`,
`restricted`. `not_established` says the record set does not establish the fact.
It never says the fact is false. This family returns four of the six. The other
two are listed so a reader can see what was available and not used.

The distinction carries weight in three places. `LC-F-006-b` is
`not_established`, not `invalid`: an overdue list is not a revocation.
`LC-F-014-b` is `not_established`, not `invalid`: an unattested issuer timestamp
does not make the grant bad, it leaves the ordering undecided. `LC-F-026-a` is
`not_established`, not `invalid`: a grant on a discarded history is authentic
and correctly signed, and nobody with standing ended it, so calling it invalid
would assert something no record says.

### What each group's reference evaluator does

**`status_artifact`.** Two windows, checked independently: the artifact's own
`next_update`, and the verifier's own freshness bound. An answer dated ahead of
the evaluation instant is `not_established` before anything else, because a
negative age is not a small age. A recorded revocation is `invalid` regardless
of either window, since an overdue list does not un-say what it records.

**`status_correction`.** A publisher may retract its own erroneous publication,
over the versions it names, and only where no signed revocation from a party
with lifecycle standing underlies the entry. A correction from a non-publisher
is not a correction. A correction over a version range the consumer does not
hold does not reach it.

**`issuer_time_evidence`.** A declared time-source-disagreement window covering
the claimed `issued_at` is checked first. Where the verdict turns on whether the
artifact predates a revocation, the issuer's own claim is not enough and
independent time evidence has to cover it. Where nothing turns on the ordering,
the issuer's claim is enough.

**`history_reconciliation`.** No reconciliation record means `not_established`:
something merged and nothing says what it covered. With a record, a revocation
anywhere in the kept set decides, whatever a non-revocation write's timestamp
says. A grant only on the discarded side is `not_established`.

**`causal_read`.** A required-observation token naming a write is checked before
lag. A replica that has not applied that write has not answered the question,
however recent it is. Lag is checked separately, against the bound the
deployment declared.

**`evidence_coverage`.** An interval whose end is inside the declared delivery
lag has an unsettled tail, so a result over it is `not_established` whatever it
contains. A declared consumer whose delivery record stops short of the
interval's end is a gap that only a later delivery record closes.

## Vectors

30 cases in `vectors.json`. Every negative differs from its nearest control by
exactly one stated change.

| id | case | role | expected | what it pins |
|---|---|---|---|---|
| `LC-F-006-a` | LC-F-006 | control | valid | inside both windows |
| `LC-F-006-b` | LC-F-006 | negative | not_established | past the artifact's own `next_update`, inside the verifier's bound |
| `LC-F-006-c` | LC-F-006 | negative | invalid | a recorded revocation on an overdue list still denies |
| `LC-F-006-d-inverse-check` | LC-F-006 | negative | not_established | inside `next_update`, past the verifier's bound: the windows are independent |
| `LC-F-015-a` | LC-F-015 | negative | not_established | an answer dated ahead of the evaluation instant |
| `LC-F-015-b` | LC-F-015 | control | valid | an answer dated exactly at the instant is not future dated |
| `LC-F-009-a` | LC-F-009 | control | invalid | a consumer holding the erroneous version denies on what it holds |
| `LC-F-009-b` | LC-F-009 | positive | valid | the publisher retracting its own bad entry |
| `LC-F-009-c` | LC-F-009 | negative | invalid | a correction signed by a non-publisher |
| `LC-F-009-d` | LC-F-009 | negative | invalid | a publisher cannot correct away a revocation it did not make |
| `LC-F-009-e` | LC-F-009 | negative | invalid | a correction reaches only the versions it names |
| `LC-F-014-a` | LC-F-014 | control | valid | independent time evidence establishes the ordering |
| `LC-F-014-b` | LC-F-014 | negative | not_established | the issuer's own claim does not |
| `LC-F-014-c` | LC-F-014 | negative | not_established | signed inside a declared disagreement window |
| `LC-F-014-d` | LC-F-014 | negative | invalid | independent evidence can establish the ordering against the issuer too |
| `LC-F-014-e` | LC-F-014 | control | valid | the requirement is scoped to the ordering question |
| `LC-F-016-a` | LC-F-016 | negative | invalid | a revocation only on the losing side survives the merge |
| `LC-F-016-b` | LC-F-016 | negative | not_established | a merge with no record of what it kept |
| `LC-F-022-a` | LC-F-022 | negative | invalid | a revocation must not lose a race to an unrelated write |
| `LC-F-022-b` | LC-F-022 | control | invalid | with no divergence, last-writer-wins is right |
| `LC-F-026-a` | LC-F-026 | negative | not_established | a grant only on a discarded history |
| `LC-F-026-b` | LC-F-026 | control | valid | the same grant on the kept history |
| `LC-F-017-a` | LC-F-017 | control | invalid | the replica applied the required write and answers revoked |
| `LC-F-017-b` | LC-F-017 | negative | not_established | the replica has not applied the write the read must follow |
| `LC-F-017-c` | LC-F-017 | control | valid | no required observation, inside the declared bound |
| `LC-F-017-d` | LC-F-017 | negative | not_established | no required observation, past the declared bound |
| `LC-F-027-a` | LC-F-027 | control | valid | a fully settled interval with every consumer delivered |
| `LC-F-027-b` | LC-F-027 | negative | not_established | an empty window inside the delivery lag |
| `LC-F-029-a` | LC-F-029 | negative | not_established | a consumer that never received part of the interval |
| `LC-F-029-b` | LC-F-029 | control | valid | the gap closes by a delivery record, not by time |

### Negative controls

Six, one per group, each with exactly one defect and a declared fail set. Each
control runs against **every** case in its group, not only the ones predicted to
fail, so an undeclared failure and a declared failure that quietly starts
passing are both errors. A control with an empty declared fail set fails the
runners on that ground alone.

| control | defect | declared fail set | observed |
|---|---|---|---|
| `N1-verifier-bound-only` | reads only the verifier's bound, ignores `next_update`, and floors a negative age at zero | `LC-F-006-b`, `LC-F-015-a` | same |
| `N2-correction-accepts-any-signer` | takes any signed correction at face value | `LC-F-009-c`, `LC-F-009-d`, `LC-F-009-e` | same |
| `N3-trusts-issuer-clock` | treats the issuer's `issued_at` as established fact | `LC-F-014-b`, `LC-F-014-c` | same |
| `N4-last-writer-wins` | highest-timestamp write per delegation decides, with no revocation priority, no discarded-history handling and no coverage requirement | `LC-F-016-a`, `LC-F-016-b`, `LC-F-022-a`, `LC-F-026-a` | same |
| `N5-ignores-required-observation` | checks lag, not the required observation | `LC-F-017-b` | same |
| `N6-empty-means-absent` | an empty result means nothing happened | `LC-F-027-b`, `LC-F-029-a` | same |

`N1` and `N4` are the two that matter most. `N1` is a verifier that reads only
its own freshness tolerance, which is a normal and widely shipped design, and it
admits a list its publisher stopped standing behind. `N4` is generic
last-writer-wins, which is the documented conflict resolution of a production
database (see the DynamoDB quote above), and it silently un-revokes.

## Determinism

No randomness, no wall clock, no network, no seed. Nothing here is generated:
every field of every input is a literal in `vectors.json` and both runners are
pure functions over those literals. The seed record other families keep exists
so a minted artifact can be regenerated, and there is no minted artifact here.

`input-digests.json` pins, per case, the SHA-256 of the RFC 8785 (JCS)
canonicalization of that case's `input` object. Regenerate with:

    node fixtures/lifecycle-infrastructure-failure/gen-digests.mjs

`verify.ts` recomputes every pin through npm `canonicalizeJCS` and `verify.py`
recomputes the same pins through PyPI `canonicalize_jcs`, so the two
implementations' canonicalizations are compared against one set of bytes and an
edited input that was not regenerated is a test failure rather than silent drift.

`CHECKSUMS.sha256` pins every file in this directory.

## Running

TypeScript, from the repository root:

    npm ci --include=dev
    npm run verify:lifecycle-infrastructure-failure

It also runs in `npm test`. Expected final line:

    lifecycle-infrastructure-failure TypeScript: 30/30 passed

Python, independently written from this README and `vectors.json` rather than
ported from `harness.ts`, with the published PyPI package as its only
third-party import:

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
    /path/to/venv/bin/python fixtures/lifecycle-infrastructure-failure/verify.py

Expected final line:

    lifecycle-infrastructure-failure Python: 30/30 passed

This is a manual run, not part of `npm test`. The rest of this suite's `npm test`
stays Node only so it runs on the Windows job, and this fixture follows that
existing convention rather than adding a Python dependency to the hermetic gate.

Both runners were run for this fixture and matched on every vector, every
reference verdict and reason, and every control's declared fail set.

## SDK results

Per-vector and per-group SDK results are in [`SDK-RUNS.md`](SDK-RUNS.md), as the
verbatim stdout of two probe scripts anyone can rerun. In short: all 30 vectors
have a real result from both SDKs for canonicalization, one of the six groups
(`status_artifact`) has a behavioural surface in npm 7.1.0 and was run through
it, and the other five are `not_supported` in both packages with a named reason
each. The npm run shows a published implementation reading a future-dated status
answer as fresh, which is what `LC-F-015-a` is about.

## Verification split

One entry per distinct verification claim.

`reference model and negative controls / every case's verdict and reason under
its group's reference evaluator, and each control's observed fail set equalling
its declared fail set; runner fixtures/lifecycle-infrastructure-failure/verify.ts;
Mode A; author-produced; implementation fixtures/lifecycle-infrastructure-failure/harness.ts.`
Author-produced because the same author wrote the vectors, the harness and the
runner.

`reference model and negative controls / the same claim, recomputed by an
independently written implementation; runner
fixtures/lifecycle-infrastructure-failure/verify.py; Mode B; author-produced;
implementation fixtures/lifecycle-infrastructure-failure/verify.py's own
evaluators.` Author-produced because the same author wrote the vectors and both
implementations, even though neither was ported from the other.

`canonical input bytes / each case's input canonicalizes under RFC 8785 to the
pinned SHA-256; runner fixtures/lifecycle-infrastructure-failure/verify.ts;
Mode B; author-produced; implementation npm agent-passport-system 7.1.0
canonicalizeJCS.` The recomputation is supplied by a published package this
author did not write, but the pins and the runner are author-written, so the
record is not independent.

`canonical input bytes / the same pins, recomputed through a second
implementation; runner fixtures/lifecycle-infrastructure-failure/verify.py;
Mode B; author-produced; implementation PyPI agent-passport-system 4.1.0
canonicalize_jcs.` Same relationship as above.

`SDK behaviour, status_artifact group / what npm agent-passport-system 7.1.0
returns for each status_artifact vector under fail_closed and
bounded_staleness; runner fixtures/lifecycle-infrastructure-failure/sdk-probe.mjs;
Mode B; author-produced; implementation npm agent-passport-system 7.1.0
enforceFreshnessPolicy and isEvidenceFresh.` The probe transports inputs and
prints outputs; the SDK decides. Author-produced because the vectors and the
probe are author-written.

`SDK surface absence, five groups / no named surface exists in either package
for the five groups recorded not_supported; runners
fixtures/lifecycle-infrastructure-failure/sdk-probe.mjs and sdk_probe.py;
Mode B; author-produced; implementations npm agent-passport-system 7.1.0 and
PyPI agent-passport-system 4.1.0 export tables.` The probes read each package's
own export surface; the patterns they search for are author-chosen, which is
what keeps this from being independent.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

Six places. Each names what a vector would have needed and what was written
instead, so the gap is reviewable rather than inferred from a missing vector.

1. **"Stale" is never given a source.** L7 says an unavailable or stale
   revocation answer is indeterminate, and draft-03 Section 3.3 says the same.
   Neither says who declares staleness: the publisher, on the artifact, or the
   relying party, in its trust policy. This family had to decide, and it decided
   that both declare one and either lapsing is enough. That is a choice
   `LC-F-006-d-inverse-check` exists to make visible, not something the text
   settles. The npm SDK's `bounded_staleness` mode reads it the other way, and
   nothing in the proposed text says which reading is right.

2. **Nothing says what an overdue answer that reports `revoked` does.**
   `LC-F-006-c` returns `invalid` on the reasoning that L3 makes revocation
   terminal, so an expired refresh commitment cannot un-say a recorded
   revocation. The text does not state this. A reading in which a stale artifact
   establishes nothing at all, including its own revocations, is also available
   and would flip that vector.

3. **Correcting an erroneous publication has no vocabulary.** L3 covers a
   revocation being reversed and forbids it. `LC-F-009` is the case where no
   valid revocation ever existed, and the model has no name for the operation
   or for who may perform it. `status_correction` invents
   `publication_error_correction`, gives standing to the list publisher, and
   scopes it to a version range. All three are this fixture's inventions. The
   boundary vector `LC-F-009-d` exists because that invention would otherwise
   read as a general reversal mechanism.

4. **"Acceptable timestamp or log evidence" is not defined.** L9 says that where
   a result depends on whether an artifact was signed before a key was retired,
   it needs acceptable timestamp or log evidence, and without it the result is
   indeterminate. It does not say what makes evidence acceptable, who may
   attest, or whether the attestor's own key lifecycle matters. `LC-F-014-a`
   models acceptable evidence as an interval from a named attestor, with no
   check on the attestor at all, which is the weakest thing that still makes the
   vector run. `LC-F-014-c`'s declared time-source-disagreement window has no
   counterpart in the text whatsoever.

5. **The threshold between "not established" and "invalid" is never stated.**
   Four vectors here turn on it (`LC-F-006-b`, `LC-F-014-b`, `LC-F-026-a`,
   `LC-F-017-b`), and in each case the reasoning is this fixture's, drawn from
   `REVIEW-DECISIONS.md`'s wording rule that missing evidence gives not
   established. That rule is an editorial instruction in a private review
   document, not a statement in `AUTHORITY-LIFECYCLE.md`. Anyone implementing
   from the published text alone has nothing to go on.

6. **`OPEN-QUESTIONS.md`'s "Authority rollback" names two mechanisms and
   specifies neither.** It says an authority epoch, or an append-only record a
   restore must replay, would stop a restore reviving revoked authority, then
   says neither is specified. `history_reconciliation` needed a third thing
   entirely, a record of what a merge kept and discarded, because a merge of two
   live histories is not a restore and neither named mechanism addresses it.
   `LC-F-016-b`'s `reconciliation_record_absent` verdict is the fixture's own.

A seventh gap is a boundary rather than a vagueness, and it is recorded in
"Does not claim" below: the text says nothing about what a relying party that
already acted on a bad answer is entitled to, which is half of what `LC-F-009`
is about.

## What a pass establishes

For this reference model, at this revision, a pass establishes that:

- honouring a status artifact's own declared refresh window and the verifier's
  own bound as two independent checks is sufficient to make the
  `status_artifact` group's six verdicts hold, and that a policy reading only
  the verifier's bound predictably admits exactly the overdue and future-dated
  cases
- retracting an erroneous publication can be made a bounded operation, gated on
  publisher standing, on the absence of an underlying signed revocation, and on
  the version range the correction names, without becoming a way to reverse a
  revocation
- requiring independent time evidence only where a verdict turns on ordering
  separates the unattested case (`not_established`) from the adverse case
  (`invalid`) and from the case where nothing turns on the timestamp (`valid`)
- a merge rule that preserves revocations and requires a record of what it kept
  reaches the right answer on all six reconciliation vectors, and generic
  last-writer-wins predictably fails four of them
- a required-observation token is what separates `LC-F-017-b` from `LC-F-017-c`,
  and replica lag alone does not
- treating an interval's tail inside a declared delivery lag as unsettled, and a
  short consumer delivery record as a gap, produces `not_established` on exactly
  the two vectors where an empty result would otherwise read as absence
- both runners, independently written, agree on every vector, every reference
  verdict and reason, and every control's fail set
- the published npm and PyPI packages canonicalize all 30 inputs to the same
  pinned RFC 8785 digests

## What this does not claim

- **Nothing here is a draft-03 conformance result.** Every vector is a candidate
  against proposed text. Merging the family would not change that.
- **Nothing here says a legal doctrine applies to AI agents.** No group in this
  family has a legal source at all. The six sources are two RFCs, three vendor
  documentation pages and one post-incident analysis, each cited for a mechanism.
- **The six evaluators are one modelling choice each.** A different record shape
  would produce different verdicts on the same underlying facts, and the model
  is not offered as the only way to represent any of these six questions.
- **`not_supported` in `SDK-RUNS.md` is not a defect report.** Nothing in
  draft-03 asks either SDK for these behaviours. The npm `bounded_staleness`
  result on `LC-F-006-b` is that mode working as its own documentation says,
  under a configuration this fixture chose, not a bug found in a published
  package.
- **This family says nothing about remediation.** `LC-F-009` in `CASES.md` is
  partly about agents wrongly denied during a bad-version window needing
  remediation rather than only future consumers being spared. That is a claim
  about what a relying party is owed, which `OPEN-QUESTIONS.md` lists under
  "Notice and relying parties" as undefined. No vector here touches it, and
  `LC-F-009-a` deliberately returns `invalid` without saying the consumer that
  denied did anything wrong.
- **It does not establish a propagation bound.** `LC-F-018` in `CASES.md` asks
  for a declared, tested maximum propagation bound across enforcement points.
  This family evaluates one boundary at a time and never runs two enforcement
  points against each other, so it establishes nothing about a fleet-wide bound.
  See the coverage note below.

## Cases in this section that are not built here

Two of the section's ten cases are covered by existing fixtures rather than
rebuilt.

- **LC-F-018** (regional enforcement points briefly disagree) is covered by
  `conflicting-status-sources` vectors `CSS-06`, `CSS-13` and `CSS-14`. The
  verdict rule at a single boundary is identical: an answer past its declared
  freshness bound is `not_established`, with the boundary inclusive. What
  LC-F-018 adds beyond that, attributing the lag to a named enforcement point in
  the decision record, is a record-content question rather than a different
  verdict, so no vector here would differ from `CSS-06` except in a label.
- **LC-F-024** (a stale lock holder's write after a lease expires) is covered by
  `authority-epoch-rollback` vectors `AER-07` through `AER-10`, which are exactly
  fencing-token acceptance, refusal of a superseded token, acceptance of a higher
  token, and an equal-token retry.

`LC-F-017` is built here rather than treated as covered by
`authority-epoch-rollback`. `AER-04` fences a lagging replica against an epoch
the **verifier** has already observed, and `AER-06` admits when the verifier has
observed nothing. `LC-F-017-b` is the case neither reaches: the requirement
travels with the **request**, naming a write this read must follow, and the
verifier has no prior observation of its own to compare against. Compare
`LC-F-017-b` with `LC-F-017-c`, which differ only in whether that token is
present.
