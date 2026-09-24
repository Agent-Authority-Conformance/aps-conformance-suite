# lifecycle-shared-identity-with-no-accountable-principal

Candidate cases for the **Shared identity with no accountable principal**
section of `CASES.md` in the agent-authority-lifecycle work. One question in
three shapes: when an action arrives under a valid, currently authorized
identity that more than one person can drive, what does the record set establish
about who is accountable for it?

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
| documents | `CASES.md` section "Shared identity with no accountable principal", `AUTHORITY-LIFECYCLE.md` 0.1.2-draft |
| status of the text | proposed. All three cases carry `Status: proposed`, and each says that none of L1 to L12 names shared identity as a distinct authority-lifecycle problem |

The proposed text this family is built on is one entry, quoted whole:

> **Accountability record.** Who a system identifies as responsible for an agent
> or action. It does not by itself establish legal liability.

`AUTHORITY-LIFECYCLE.md` states the status of that entry itself: "The grouping
and every other entry are **proposed**, added in 0.1.1-draft or 0.1.2-draft. No
public case tests them yet." This family is a candidate against that entry and
nothing more. The repository is the thing under test, not a source for any
factual claim in this file.

### What draft-03 does and does not state

A fetch of
[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/)
this session confirmed it contains neither the word "accountable" nor the phrase
"shared identity" anywhere. There is no draft-03 text to be a conformance case
against, and no vector here is labelled as one.

## Sources

All three claims about an external standard, guidance document or incident were
fetched this session.

| case | source | verbatim quote |
|---|---|---|
| LC-I-010 | PCI DSS requirement 8.2.2, as reproduced on [Microsoft Learn](https://learn.microsoft.com/en-us/entra/standards/pci-requirement-8) | "Group, shared, or generic accounts, or other shared authentication credentials are only used when necessary on an exception basis" and, among its sub-requirements, "Individual user identity is confirmed before access to an account is granted. Every action taken is attributable to an individual user." |
| LC-I-011 | [NBC News](https://www.nbcnews.com/id/wbna42132041), datelined March 17, 2011, on the Chrysler branded-account incident | the contractor blamed "a mix-up using a program that aims to help users juggle multiple Twitter accounts" |
| LC-I-012 | [AWS IAM documentation, AWS account root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html) | "We strongly recommend that you don't use the root user for your everyday tasks." |

Three notes on those sources, because each needed a correction against what
`CASES.md` records.

1. **The PCI quote is not the one `CASES.md` uses.** `CASES.md` cites PCI SSC
   FAQ 1080. That page could not be fetched this session: the request returned a
   domain-verification failure rather than content. Rather than reuse a quote
   from an unfetched page, this README cites requirement 8.2.2 itself as
   reproduced on a page that was fetched. The reproduced text is stronger for
   this family's purpose anyway, because its own sub-requirements state the
   individual-attribution rule directly.

2. **The incident year.** `CASES.md` says 2013. The fetched NBC article is
   datelined "March 17, 2011, 12:22 PM EDT" and describes the message as having
   gone out "last week", so the incident is March 2011. This README uses the
   date the source supports. Nothing in the family turns on it, but a corpus
   that cites a source should not disagree with it.

3. **The individual is not named here.** The fetched article names the
   contractor. `LC-I-011` is about a record that could not say who acted, and
   naming a private individual adds nothing to a fixture about that. The vectors
   use an opaque identifier and this README describes the role.

Each source is cited for the mechanism a case models and for nothing else. None
of them says anything about AI agents, and this family does not claim any of
them reaches them. A compliance requirement and a vendor recommendation are not
authority-lifecycle rules. What they supply is a documented shape, which is that
"which credential authenticated this" and "who is accountable for this" are
treated as two facts by parties who had to operate at scale.

## The model

`harness.ts` holds one pure evaluator over one record shape. Every evaluation
returns **two verdicts and a flag**.

- `authority_verdict` is the state of the authority the acting identity holds.
- `accountability_verdict` is whether the record set establishes which
  individual is accountable for this action.
- `anomaly` is not a verdict. It records whether an unscoped all-powerful
  identity was used for a task on its own enumerated required-list or off it,
  and is `not_applicable` for any other identity kind.

The two verdicts are computed from disjoint inputs on purpose. **Every case in
this family has a valid chain**, and both runners fail the family if that stops
being true or if no case pairs a valid chain with accountability
`not_established`. A family in which the two axes never diverge would not be
testing what the section is about, so it is a checked property rather than a
convention.

### Verdict vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended`,
`restricted`. This family uses two. On the accountability axis, `valid` reads as
"the record set establishes who is accountable" and `not_established` as "it
does not". `not_established` is not a claim that nobody is accountable, and not
a claim that the action was unauthorized. Both of those would be different, and
stronger, statements than the records support.

### The rule

1. An identity bound to one individual answers both questions at once.
2. Otherwise, look for a checkout record from a party with standing whose
   interval covers the action. Exactly one is an answer. More than one is not:
   the broker was supposed to make the identity exclusive and did not, and
   resolving to the earlier, later or longer one would name a person the records
   do not place at the keyboard. Checkouts existing but none covering the action
   is its own reason, distinct from no checkout at all.
3. With no checkout, a later attribution record can still close the gap, if it
   comes from a party with standing **and** references this boundary's record.
   A later record closes a gap in the record it names and no other, which is
   what keeps a finding attached to a specific earlier receipt instead of
   floating over everything the identity ever did.
4. The anomaly flag is computed from the acting identity's kind and the task,
   independently of everything above.

## Vectors

12 cases. Every negative differs from its nearest control by exactly one stated
change.

| id | case | role | authority / accountability | anomaly | what it pins |
|---|---|---|---|---|---|
| `LC-I-010-a` | LC-I-010 | control | valid / valid | not_applicable | an individually bound identity answers both at once |
| `LC-I-010-b` | LC-I-010 | negative | valid / not_established | not_applicable | a valid shared credential is uninformative about who acted |
| `LC-I-010-c` | LC-I-010 | positive | valid / valid | not_applicable | a checkout with standing reconstitutes individual accountability |
| `LC-I-010-d` | LC-I-010 | negative | valid / not_established | not_applicable | a checkout that does not cover the action does not attribute it |
| `LC-I-010-e` | LC-I-010 | negative | valid / not_established | not_applicable | two overlapping checkouts resolve to neither |
| `LC-I-011-a` | LC-I-011 | negative | valid / not_established | not_applicable | at the first boundary, attribution is pending or external |
| `LC-I-011-b` | LC-I-011 | positive | valid / valid | not_applicable | a later investigation closes the gap as a new record |
| `LC-I-011-c` | LC-I-011 | negative | valid / not_established | not_applicable | an attribution without standing establishes nothing |
| `LC-I-011-d` | LC-I-011 | negative | valid / not_established | not_applicable | an attribution referencing a different record does not attach |
| `LC-I-012-a` | LC-I-012 | control | valid / not_established | on_enumerated_list | the privileged identity used as intended still has no accountable individual |
| `LC-I-012-b` | LC-I-012 | negative | valid / not_established | off_enumerated_list | the same identity off-list gets its own flag |
| `LC-I-012-c` | LC-I-012 | control | valid / valid | not_applicable | a scoped identity doing the same task is neither flagged nor unattributed |

The `LC-I-012` triple is the clearest piece of the family. `-a` and `-b` have
identical verdicts and differ only in the anomaly flag, so the flag is visibly
the thing LC-I-012 asks for and not a restatement of the accountability verdict.
`-b` and `-c` have an identical task and differ only in who acted, so the flag
is visibly about the acting identity and not about the task.

### Negative controls

| control | defect | declared fail set | observed |
|---|---|---|---|
| `N1-authenticated-is-accountable` | treats a valid authenticated identity as the answer to who is accountable | 10 of 12: everything except `LC-I-010-a` and `LC-I-012-c` | same |
| `N2-shared-flag-only` | notices the shared flag and looks for a checkout, but reads any checkout as an answer: no interval check, no multiplicity check | `LC-I-010-d`, `LC-I-010-e` | same |

Both controls run against **every** case, not only the ones predicted to fail.
A control with an empty declared fail set fails the runners on that ground
alone, and so does a control that fails every case, since that one would have no
passing baseline and would isolate nothing.

`N1` is the naive implementation the whole section is about, and its fail set is
deliberately broad because its single defect is broad: it never separates which
credential authenticated an action from who is accountable for it. It is right
in exactly the two cases where the acting identity really is bound to one
individual, and wrong everywhere else, including the two cases (`LC-I-010-c`,
`LC-I-011-b`) where its verdict coincides with the reference but its recorded
reason names the credential instead of the checkout or the later attribution
that actually answered the question. A verdict that is right for the wrong
recorded reason is still a record a reader cannot rely on, so the runners count
it as a failure.

`N2` is the narrower control, and it is the one that shows `LC-I-010-d` and
`LC-I-010-e` are not redundant with `LC-I-010-b`: an implementation can know the
identity is shared, look for the compensating record, and still get both of them
wrong.

## Determinism

No randomness, no wall clock, no network, no seed. Nothing is generated: every
field of every input is a literal in `vectors.json`.

`input-digests.json` pins, per case, the SHA-256 of the RFC 8785 (JCS)
canonicalization of that case's `input`. Regenerate with:

    node fixtures/lifecycle-shared-identity-with-no-accountable-principal/gen-digests.mjs

`verify.ts` recomputes every pin through npm `canonicalizeJCS` and `verify.py`
through PyPI `canonicalize_jcs`. `CHECKSUMS.sha256` pins every file here.

## Running

    npm ci --include=dev
    npm run verify:lifecycle-shared-identity

It also runs in `npm test`. Expected final line:

    lifecycle-shared-identity TypeScript: 12/12 passed

Python, independently written from this README and `vectors.json` rather than
ported from `harness.ts`:

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
    /path/to/venv/bin/python fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.py

Expected final line:

    lifecycle-shared-identity Python: 12/12 passed

This is a manual run, not part of `npm test`, following the same Node-only
convention the rest of the suite's gate uses.

Both runners were run and matched on every vector, both verdict fields, every
reason, every anomaly flag, and both controls' declared fail sets.

## SDK results

In [`SDK-RUNS.md`](SDK-RUNS.md), as verbatim probe output. All 12 vectors have a
real canonicalization result from both SDKs. All four surfaces this family needs
are `not_supported` in both packages.

Worth reading there: both packages have a large attribution surface and it is a
different sense of the word. `ATTRIBUTION_ROLES` is `["primary_source",
"supporting_evidence","context_only","background_retrieval"]`, which is
attribution of contribution between systems. The npm probe also constructs one
of the package's own accountability records and prints it, so a reader can see
that a well-built record with `capture_mode` and `completeness` fields still has
nowhere to say which individual acted, and nowhere to say the acting identity
was one several people can drive.

## Verification split

`reference model and negative controls / every case's authority verdict,
accountability verdict, reason and anomaly, and each control's observed fail set
equalling its declared fail set; runner
fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.ts;
Mode A; author-produced; implementation
fixtures/lifecycle-shared-identity-with-no-accountable-principal/harness.ts.`
Author-produced because the same author wrote the vectors, the harness and the
runner.

`reference model and negative controls / the same claim, recomputed by an
independently written implementation; runner
fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.py;
Mode B; author-produced; implementation that file's own evaluators.`
Author-produced because the same author wrote the vectors and both
implementations, even though neither was ported from the other.

`axis separation / every case has a valid chain and at least one pairs it with
accountability not_established; runners
fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.ts and
verify.py; Mode A; author-produced; implementation the runners' own check.`
A structural property of the vector set, checked rather than asserted.

`canonical input bytes / each case's input canonicalizes under RFC 8785 to the
pinned SHA-256; runners
fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.ts and
verify.py; Mode B; author-produced; implementations npm agent-passport-system
7.1.0 canonicalizeJCS and PyPI agent-passport-system 4.1.0 canonicalize_jcs.`
The recomputation is supplied by published packages this author did not write;
the pins and runners are author-written.

`SDK surface absence / no named surface exists in either package for the four
surfaces this family needs, and the package's own accountability record carries
no accountable-individual field; runners
fixtures/lifecycle-shared-identity-with-no-accountable-principal/sdk-probe.mjs
and sdk_probe.py; Mode B; author-produced; implementations npm
agent-passport-system 7.1.0 and PyPI agent-passport-system 4.1.0.` The probes
read each package's own export surface and construct one of its own records; the
patterns they search for are author-chosen.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

Six places. The proposed text for this family is a single two-sentence entry, so
almost everything the vectors needed had to be invented, and naming what was
invented is most of what this section is for.

1. **The accountability record has no fields.** The entry says what the concept
   is for, "Who a system identifies as responsible for an agent or action", and
   what it does not do, establish legal liability. It does not say what the
   record carries, who signs it, when it is produced, or whether it is separate
   from an authorization decision record. Every field in this family's input
   shape is the fixture's.

2. **There is no vocabulary for accountability being unknown.** The entry
   presumes the system identifies someone. `LC-I-010-b`'s whole content is the
   case where it cannot, and `not_established` on an accountability axis is a
   verdict this fixture introduced by borrowing the authority-axis vocabulary.
   Nothing says the two axes should share a vocabulary, and a reader who thinks
   accountability needs its own words would be arguing with the fixture and not
   with the text.

3. **Shared identity is not a concept in the model at all.** `CASES.md` says so
   itself for all three cases: none of L1 to L12 names it. The `identity.kind`
   field, with its three values, is entirely this fixture's, and the boundary
   between `shared` and `privileged_unscoped` is a distinction LC-I-012 gestures
   at without defining.

4. **Standing to issue a checkout or an attribution is undefined.**
   `AUTHORITY-LIFECYCLE.md` has a Lifecycle standing entry, about who may
   suspend, revoke, replace or reaffirm an authority artifact. Neither a
   credential checkout nor an after-the-fact attribution is any of those things,
   so `signer_has_standing` in this family is a flag the vectors set rather than
   something the model could decide. `LC-I-011-c` turns entirely on it.

5. **Nothing says an attribution must reference the record it corrects.**
   `LC-I-011-d` is built on the corpus rule that later findings are new records
   referencing earlier ones, which lives in `REVIEW-DECISIONS.md`, a private
   editorial document, rather than in `AUTHORITY-LIFECYCLE.md`. The published
   Evidence entry says only that ending authority does not erase evidence of
   earlier events, which does not reach this.

6. **The anomaly flag is not a verdict and the model has no room for one.**
   LC-I-012 asks for use of an unscoped all-powerful identity off its enumerated
   list to carry "its own evidence trail". This family models that as a third
   field alongside two verdicts, because making it a verdict would have meant
   saying the action was invalid or restricted, which it is not. Whether a
   non-verdict flag belongs in an authority-lifecycle record at all is a
   question the proposed text does not raise and this fixture had to answer.

## What a pass establishes

For this reference model, at this revision, a pass establishes that:

- separating the accountability axis from the authority axis is sufficient to
  make all 12 verdicts hold, and that an implementation treating a valid
  authenticated identity as the accountable party gets 10 of 12 wrong while
  looking correct on the two that do not exercise the distinction
- a checkout record from a party with standing, covering the action's instant, is
  enough to reconstitute individual accountability under a shared identity, and
  that neither a checkout outside the interval nor two overlapping checkouts is
  enough
- an accountability gap can be closed later by a record from a party with
  standing that references the earlier record, and is not closed by an
  attribution without standing or one that references something else
- the anomaly flag tracks the acting identity's kind and the task's list
  membership independently of both verdicts, which the `LC-I-012` triple
  demonstrates in both directions
- both runners, independently written, agree on every vector, both verdict
  fields, every reason, every anomaly flag, and both controls' fail sets

## What this does not claim

- **Nothing here is a draft-03 conformance result.** The draft has no text on
  this at all.
- **Nothing here says a legal doctrine, a compliance standard or a vendor
  recommendation applies to AI agents.** PCI DSS 8.2.2 is a requirement for
  cardholder-data environments. The AWS root-user guidance is advice about an
  AWS account. The March 2011 incident is about people operating a brand's
  social account. None of them is about AI agents, none is offered as reaching them,
  and the family claims only that they document the same shape of problem.
- **It does not establish liability, and says so in the model.** The proposed
  text's own second sentence is that an accountability record does not by itself
  establish legal liability. A `valid` accountability verdict here says the
  record set establishes who a system identifies as responsible. It says nothing
  about what follows from that.
- **`not_established` is not an accusation.** It does not say the action was
  unauthorized, that anyone did anything wrong, or that nobody is accountable.
  It says this record set does not answer the question, which is why
  `LC-I-010-e` resolves to neither individual rather than picking one.
- **The three identity kinds are a modelling choice.** A real system may have
  more, fewer, or a spectrum. Nothing here establishes that three is the right
  number or that the boundary between `shared` and `privileged_unscoped` is
  drawn in the right place.
- **`not_supported` in `SDK-RUNS.md` is not a defect report.** Neither package
  claims to carry an accountable-individual field and nothing in draft-03 asks
  either to.
