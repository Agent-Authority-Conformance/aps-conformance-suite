# lifecycle-evidence-and-record

Candidate cases for the **Evidence and record** section of `CASES.md` in the
agent-authority-lifecycle work. Two questions. Does a duty to keep evidence of
an authority relationship run on its own clock after that relationship ends? And
can what a boundary decided at one instant be rewritten by what is learned
afterwards?

**Status: candidate against proposed text. This is not a draft-03 conformance
family.** Every vector in `vectors.json` carries
`label: "candidate_against_proposed"` and names the proposed text it tests.
`verify.ts` and `verify.py` both fail if any vector loses that label, names no
proposed text, or returns a verdict outside the settled vocabulary.

The harness is protocol neutral: no APS type, no network call, no randomness, no
wall-clock read. Every instant is a literal in `vectors.json`.

## What is being tested, and where it lives

| field | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| commit | `2bf5c7e` (CASES.md v0.2, descends from `7796e22`) |
| documents | `CASES.md` section "Evidence and record", `AUTHORITY-LIFECYCLE.md` 0.1.2-draft, `OPEN-QUESTIONS.md` |
| status of the text | proposed. Both cases in the section carry `Status: proposed`, and `AUTHORITY-LIFECYCLE.md` states that no public case tests these concepts yet |

That repository is the thing under test, not a source for any factual claim in
this file.

| group | CASES.md case | proposed text |
|---|---|---|
| `retention_restriction` | LC-G-005 | External restriction, Evidence, Coverage and completeness, `OPEN-QUESTIONS.md` "Release from suspension" |
| `receipt_immutability` | LC-G-006 | Evidence, Authorization decision, Policy version, Issuer standing |

### What draft-03 does and does not state

A fetch of
[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/)
this session found the word "retention" once, in Section 10, Privacy
Considerations, where a deployment "SHOULD define access and retention
policies". That is a deployment instruction, not a rule about whether a
retention duty survives the relationship it documents or composes with an
independent hold. The draft states nothing about evaluating a receipt against
the record available at its decision instant. No vector here is a draft-03
conformance case.

## Sources

Both claims about an external instrument were fetched this session.

| group | source | verbatim quote |
|---|---|---|
| `retention_restriction` | [17 CFR § 240.17a-4(c), Cornell LII](https://www.law.cornell.edu/cfr/text/17/240.17a-4) | "preserve for a period of not less than six years after the closing of any customer's account any account cards or records which relate to the terms and conditions with respect to the opening and maintenance of the account." |
| `receipt_immutability` | [Citizens to Preserve Overton Park v. Volpe, 401 U.S. 402 (1971), via Findlaw](https://caselaw.findlaw.com/us-supreme-court/401/402.html) | "That review is to be based on the full administrative record that was before the Secretary at the time he made his decision." |

Each is cited for the mechanism a group models and for nothing else. The first
is a recordkeeping rule for broker-dealers. It says nothing about AI agents, and
this family does not claim it applies to them. The second is about the scope of
judicial review of agency action, and it says nothing about AI agents either. What
both supply is the shape of a rule that can be written as a verdict: a duty
running from a defined trigger for a defined period, and a decision judged on
the record available when it was made.

The specific numbers in the vectors come from the first source's own terms, six
years running from closing of the account, so a reader can check the arithmetic
against the quoted text rather than against a number this fixture picked.

## The model

`harness.ts` holds two pure evaluators. Every evaluation returns **two**
verdicts and a reason.

- `chain_verdict` is the state of the authority the requester holds.
- `verdict` is the state of the effect being requested under it.

Keeping them apart is the point of the retention group. A valid chain whose
particular effect is blocked from outside the grant chain is `restricted`, which
`AUTHORITY-LIFECYCLE.md` describes under External restriction: it "can stop some
effects while the grant itself stays valid". Collapsing the two would force the
model to say either that the requester's authority is bad, which it is not, or
that the deletion may proceed, which it may not.

### Verdict vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended`,
`restricted`. This family uses four. `not_established` says the record set does
not establish the fact and never says the fact is false: `LC-G-006-f` returns it
because a receipt whose bytes no longer match its digest answers nothing, not
because the decision was wrong.

### retention_restriction

A record's duty is set by the record's own type and runs from the record's own
trigger. It is not scoped to the life of the relationship the record documents.
Restrictions from different sources compose and each releases separately. The
duty restricts destruction, not reading, so `LC-G-005-f`'s read of retained
evidence is permitted: ending authority does not by itself erase or invalidate
evidence of earlier events.

A duty stated in years advances the calendar year on the trigger's own UTC date
rather than adding a fixed span, so it does not drift by a day per leap year.
Both implementations do this the same way and both say so in a comment. No date
in this family is 29 February, so there is no end-of-February case, and the
model does not pretend to have a rule for one.

### receipt_immutability

Two different questions over one unchanged record. `verdict_at_decision_time`
always returns what the boundary recorded, with reason
`decided_on_the_record_then_available`. `verdict_now` is answered against what
is known now, and the record that says so is a new record referencing the prior
receipt rather than an edit of it. A receipt whose bytes do not match its
recorded digest answers neither question.

The two kinds of later evidence give different present-tense reasons on purpose.
`new_information` means the decision was validly made and something has since
come to light. `void_from_inception` means an ancestor was never validly issued,
so the chain was defective from the start. Both leave
`verdict_at_decision_time` untouched, because the boundary could not see the
defect either way. Keeping the reasons apart is what lets a reader of the record
set tell a chain that went bad from a chain that was never good, and it is what
separates LC-G-006 from LC-C-006.

## Vectors

12 cases. Every negative differs from its nearest control by exactly one stated
change.

| id | case | role | chain / effect | what it pins |
|---|---|---|---|---|
| `LC-G-005-a` | LC-G-005 | control | valid / restricted | a clock that has not started cannot have run out |
| `LC-G-005-b` | LC-G-005 | negative | valid / restricted | the relationship ending does not end the duty |
| `LC-G-005-c` | LC-G-005 | control | valid / valid | the duty running out lifts the restriction |
| `LC-G-005-d` | LC-G-005 | negative | valid / restricted | a second restriction is not released by the first expiring |
| `LC-G-005-e` | LC-G-005 | control | valid / valid | releasing the second, with the first expired, permits the effect |
| `LC-G-005-f` | LC-G-005 | positive | valid / valid | retention restricts destruction, not reading |
| `LC-G-006-a` | LC-G-006 | control | valid / valid | with no later evidence, the recorded verdict stands |
| `LC-G-006-b` | LC-G-006 | negative | valid / valid | new information does not change what was decided then |
| `LC-G-006-c` | LC-G-006 | positive | invalid / invalid | the present-tense question has a different answer |
| `LC-G-006-d` | LC-G-006 | negative | valid / valid | void-from-inception does not rewrite the receipt either |
| `LC-G-006-e` | LC-G-006 | positive | invalid / invalid | the two later-evidence kinds give different present reasons |
| `LC-G-006-f` | LC-G-006 | negative | not_established / not_established | a receipt whose bytes do not match its digest |

### Negative controls

| control | defect | declared fail set | observed |
|---|---|---|---|
| `N1-relationship-scoped-retention` | scopes the duty to the life of the relationship, with no record-type clock and no composition | `LC-G-005-b`, `LC-G-005-d` | same |
| `N2-retroactive-correction` | answers every question against what is known now, and never checks the receipt's bytes | `LC-G-006-b`, `LC-G-006-d`, `LC-G-006-f` | same |

Each control runs against every case in its group, not only the ones predicted
to fail, so an undeclared failure and a declared failure that quietly starts
passing are both errors. A control with an empty declared fail set fails the
runners on that ground alone.

`N1` is the implementation the case is about: purging once the relationship ends
is a reasonable-sounding retention policy that destroys exactly the evidence a
later dispute about the ended relationship would need.

### The immutability check

`LC-G-006-f` pins that a rewritten receipt is detectable from its own digest.
Both runners go one step further and recompute every case's JCS input digest
**after** all evaluators have run, so a harness that produced its answer by
editing the receipt in place would pass the reference check and fail the
immutability check. Without that, the group would only be testing that the
reference implementation happens not to mutate its input.

## Determinism

No randomness, no wall clock, no network, no seed. Nothing is generated: every
field of every input is a literal in `vectors.json`.

`input-digests.json` pins, per case, the SHA-256 of the RFC 8785 (JCS)
canonicalization of that case's `input`. Regenerate with:

    node fixtures/lifecycle-evidence-and-record/gen-digests.mjs

`verify.ts` recomputes every pin through npm `canonicalizeJCS` and `verify.py`
through PyPI `canonicalize_jcs`. `CHECKSUMS.sha256` pins every file here.

## Running

    npm ci --include=dev
    npm run verify:lifecycle-evidence-and-record

It also runs in `npm test`. Expected final line:

    lifecycle-evidence-and-record TypeScript: 12/12 passed

Python, independently written from this README and `vectors.json` rather than
ported from `harness.ts`:

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
    /path/to/venv/bin/python fixtures/lifecycle-evidence-and-record/verify.py

Expected final line:

    lifecycle-evidence-and-record Python: 12/12 passed

This is a manual run, not part of `npm test`, following the same Node-only
convention the rest of the suite's gate uses.

Both runners were run and matched on every vector, both verdict fields, every
reason, and both controls' declared fail sets.

## SDK results

In [`SDK-RUNS.md`](SDK-RUNS.md), as verbatim probe output. All 12 vectors have a
real canonicalization result from both SDKs. Both groups are `not_supported`
behaviourally in both packages. The retention block is worth reading: npm's
`isRetentionExpired` runs, and it answers the opposite question, a maximum
retention ceiling where LC-G-005 needs a preservation floor.

## Verification split

`reference model and negative controls / every case's chain_verdict, verdict and
reason, and each control's observed fail set equalling its declared fail set;
runner fixtures/lifecycle-evidence-and-record/verify.ts; Mode A; author-produced;
implementation fixtures/lifecycle-evidence-and-record/harness.ts.`
Author-produced because the same author wrote the vectors, the harness and the
runner.

`reference model and negative controls / the same claim, recomputed by an
independently written implementation; runner
fixtures/lifecycle-evidence-and-record/verify.py; Mode B; author-produced;
implementation fixtures/lifecycle-evidence-and-record/verify.py's own
evaluators.` Author-produced because the same author wrote the vectors and both
implementations, even though neither was ported from the other.

`input immutability / no evaluator mutated the input it was handed, checked by
recomputing every input digest after all evaluators ran; runners
fixtures/lifecycle-evidence-and-record/verify.ts and verify.py; Mode B;
author-produced; implementations npm agent-passport-system 7.1.0 canonicalizeJCS
and PyPI agent-passport-system 4.1.0 canonicalize_jcs.` The digests are supplied
by published packages this author did not write; the runners and pins are
author-written.

`canonical input bytes / each case's input canonicalizes under RFC 8785 to the
pinned SHA-256; runners fixtures/lifecycle-evidence-and-record/verify.ts and
verify.py; Mode B; author-produced; implementations npm agent-passport-system
7.1.0 canonicalizeJCS and PyPI agent-passport-system 4.1.0 canonicalize_jcs.`
Same relationship as above.

`SDK surface absence / no named surface exists in either package for either
group; runners fixtures/lifecycle-evidence-and-record/sdk-probe.mjs and
sdk_probe.py; Mode B; author-produced; implementations npm agent-passport-system
7.1.0 and PyPI agent-passport-system 4.1.0 export tables.` The probes read each
package's own export surface; the patterns they search for are author-chosen.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

Five places.

1. **`restricted` has no definition beyond one sentence.**
   `AUTHORITY-LIFECYCLE.md`'s External restriction entry says a block from
   outside the grant chain "can stop some effects while the grant itself stays
   valid", and L8 adds that "a restricted state is different again and does not
   have to pause descendants". Nothing says which effects, who may impose one,
   how one is released, or whether a restricted effect is recorded differently
   from a denied one. Every `restricted` verdict in this family is the fixture's
   reading of those two sentences.

2. **Nothing in the model says a retention duty exists at all.** The Evidence
   concept says ending authority does not by itself erase or invalidate evidence
   of earlier events. That is a statement about what a verifier may conclude, not
   a duty on anyone to keep anything, and it says nothing about a trigger, a
   period, or who sets either. The entire `retention_restriction` group rests on
   reading a duty into a sentence about evidence remaining valid, with the
   trigger-and-period shape borrowed from the external source quoted above.

3. **Composition of restrictions is explicitly open.**
   `OPEN-QUESTIONS.md`'s "Release from suspension" says multiple suspension
   causes "probably need to compose, with each one released separately. Not yet
   specified." `LC-G-005-d` is that probably, made executable for restriction
   rather than suspension, which is a further step the text does not take.
   Nothing says the two behave alike.

4. **"Later findings never rewrite earlier receipts" is a review rule, not
   published text.** It appears in `REVIEW-DECISIONS.md`, a private editorial
   document. `AUTHORITY-LIFECYCLE.md` itself says only that ending authority
   does not erase evidence of earlier events, which is a weaker and different
   statement. The whole `receipt_immutability` group is built on the stronger
   rule, and anyone implementing from the published text alone would not find
   it.

5. **Neither `new_information` nor `void_from_inception` is named anywhere.**
   The model has no vocabulary for the reason a later record carries, and no
   statement that the two should be distinguishable. `LC-G-006-c` and
   `LC-G-006-e` differ only in that reason string, and both strings are this
   fixture's. A reader who thinks one reason is enough would collapse those two
   vectors into one and nothing in the proposed text would contradict them.

## What a pass establishes

For this reference model, at this revision, a pass establishes that:

- a retention duty running from the record type's own trigger, for the record
  type's own period, reaches the right answer on all six retention vectors, and
  a duty scoped to the life of the relationship predictably purges on
  `LC-G-005-b`
- two restrictions from different sources compose and release independently, so
  the retention duty expiring does not lift an unrelated hold
- the same record set answers "what was decided then" and "what is true now"
  differently, without the first answer changing, across both kinds of later
  evidence
- a receipt whose bytes no longer match its recorded digest is `not_established`
  rather than readable, and no evaluator in either runner mutates the input it
  is given
- both runners, independently written, agree on every vector, both verdict
  fields, every reason, and both controls' fail sets

## What this does not claim

- **Nothing here is a draft-03 conformance result.**
- **Nothing here says a legal doctrine applies to AI agents.** Neither source is
  about AI agents and neither is offered as reaching them. What is borrowed is
  the shape of a rule, and `CASES.md` says the same about its own use of them.
- **It says nothing about which records a system should keep.** The retention
  group takes the record type, trigger and period as given inputs. Deciding
  those is a policy question this family does not touch, and `LC-G-005-c`
  permitting a deletion is not advice to delete anything.
- **It says nothing about liability.** `AUTHORITY-LIFECYCLE.md` says an
  accountability record "does not by itself establish legal liability", and
  neither does anything here. A `restricted` verdict is a statement about a
  record set, not about what anyone owes anyone.
- **The immutability check is about this fixture's own evaluators.** It shows no
  evaluator here mutated an input. It establishes nothing about whether a real
  system's receipts are immutable in storage.
