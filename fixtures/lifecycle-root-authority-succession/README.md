# lifecycle-root-authority-succession: office bound or identity bound, and what a verifier returns when the delegation never says

One delegation shape written three ways. Bound to an office, so turnover moves
it. Bound to a person, so turnover does not. And silent, which is the case the
proposed text has not answered and the one this family exists for.

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`.
The proposed text is `aeoess/agent-authority-lifecycle`,
`AUTHORITY-LIFECYCLE.md` at commit `7796e22` (version 0.1.2-draft in the
document), and the case is `LC-C-007` in that repository's `CASES.md` at version
0.2-draft.

| proposed text | vectors |
|---|---|
| Parties and standing > Principal binding | every vector |
| Authority and dependencies > Target binding ("Continuity of a name does not by itself establish continuity of the thing named") | `LRAS-C-007-b`, `LRAS-C-007-c`, `LRAS-C-007-g` |
| What changes when a person leaves | all |
| L2, L3, L4 | `LRAS-C-007-b` is the case those three invariants do not cover: the same delegation verifying for a new occupant with nothing reissued |
| OPEN-QUESTIONS.md > Office vacancy and succession | `LRAS-C-007-j` |

The proposed text states the open question directly. `OPEN-QUESTIONS.md` says
that whether office-based grants continue, suspend or need reaffirmation during
a vacancy "is not defined". `LRAS-C-007-j` returns `not_established`, which
states the gap rather than filling it.

### This is not a draft-03 conformance case

draft-pidlisnyi-aps-03 states no subject-binding-mode rule and defines no
office-holder registry. Its `AuthorityDelegationV1` subject is one identifier
and the draft says nothing about what kind of thing that identifier names. The
one draft-03 surface every vector touches is Section 3.3 chain verification,
quoted in full in the sibling `lifecycle-principal-events` README. Two
chain-stage controls pin that a revoked answer and an unknown answer are
reported at the chain stage, and that unknown surfaces as `not_established`.

### The verdict names are not suite vocabulary

`CONTRIBUTING.md` reserves failure-class names and verifier semantics to the
maintainer. `not_yet_effective`, `suspended` and `restricted` are declared in
the vocabulary and no vector here uses them.

## Source

Fetched while this fixture was authored. The quote is verbatim and under forty
words. This source says nothing about AI agents and nothing here claims a legal
doctrine applies to AI agents.

United States Department of Justice, Office of Legal Counsel, opinion 79-72,
"Attorney General, Delegation of Authority, 18 U.S.C. § 2516", September 27,
1979, <https://www.justice.gov/file/149056/dl>. The opinion asked whether a
delegation survived the resignation of the officer who signed it:

> "in the absence of a limiting provision of law or a limiting provision within
> the delegation itself, a valid delegation of authority or other rule or
> regulation continues in force until revoked by someone with authority to
> revoke it"

and the same sentence continues that it "accordingly continues without regard to
the departures from office of its originator and intervening successors".

Two things in that sentence matter for the fixture. The delegation continues
through turnover, which is `LRAS-C-007-b`. And the continuation is conditioned
on the absence of a limiting provision within the delegation itself, which is
why this fixture reads the binding mode off the delegation's own terms rather
than assuming one.

## What the SDKs supply, and what this fixture supplies

| layer | supplied by |
|---|---|
| chain structure, signatures, key resolution, attenuation, validity window, revocation state | the real SDK chain verifier |
| RFC 8785 canonical bytes and Ed25519 verification for every fixture-local record | the real SDK |
| minting of the four delegations | `issueAuthorityDelegation`, the real SDK |
| the subject-binding mode, the office-holder registry, office vacancy, an actor distinct from the record's subject, the six verdict names | `harness.ts` and `validate.py`, this fixture |

`--sdk-support` on either runner prints the per-vector record. **A pass is a
result about this gate, not a conformance result about either SDK.**

## Records

`chain.json` is minted by `mint.ts` from published seed labels and regenerates
byte for byte. Four chains:

- `G_ROLE_BOUND`, subject is the treasurer office identifier, terms declare
  `subject_binding_mode: role_bound`.
- `G_IDENTITY_BOUND`, subject is a person identifier, terms declare
  `identity_bound`.
- `G_SILENT`, subject is the same office identifier as `G_ROLE_BOUND`, terms
  name the office and declare no binding mode at all.
- `G_ROLE_BOUND_VACANT`, over a second office that goes vacant.

Five `fixture:office-event:v0` records: two office-holder records for the
treasurer office with non-overlapping windows, one from a party without
standing, one office-holder record and one vacancy record for the auditor
office.

## The gate

`harness.ts` and `validate.py` are two independent implementations. Evaluation
order:

1. **Chain**, then **terms**, then **classification** of each presented record
   against the attestor-role registry and the event-standing table.
2. **Binding mode.** If the terms declare none and the actor is the very subject
   the delegation names, the answer is `valid` with code
   `actor_is_the_named_subject`, because the missing term does not have to be
   resolved. If the terms declare none and the actor is somebody else, the
   answer is `not_established` with code `subject_binding_mode_not_declared`.
3. **Identity bound.** The named subject is exercisable and nobody else is.
4. **Role bound.** A vacancy covering the action instant gives
   `not_established`. Otherwise an office-holder record from a party with
   standing, whose window covers the instant, has to name this actor. No
   covering record gives `not_established`. A covering record naming somebody
   else gives `invalid`, which is a positive finding and not a missing one.

## Vectors

Thirteen. Five for the role-bound mode, two for the identity-bound mode, two for
the silent mode, two for the vacant office, and two chain-stage controls.

### Invariant attribution

`vectors.json` names L2, L3 and L4 at the family header. Four vectors now also
name an invariant in their own record, under `proposed_text.sections`, in the
long form the rest of the suite uses:

| vector | invariant | what it returns and why that is the invariant |
|---|---|---|
| `LRAS-C-007-b-role-bound-new-occupant-needs-no-reissuance` | L2 | `valid`. The occupant changed and the unchanged delegation still verifies, so the authority did not travel with the identity |
| `LRAS-C-007-c-role-bound-former-occupant` | L2 | `invalid`. The same identity continues and its authority does not, which is L2 stated directly |
| `LRAS-C-007-g-identity-bound-turnover-does-not-transfer` | L4 | `invalid`. The new occupant inherits nothing from an identity-bound grant and needs a fresh chain |
| `LRAS-C-007-i-silent-binding-with-a-new-occupant` | L4 | `not_established`. The delegation does not say which mode applies, so whether the new occupant inherits is not established here. Not established is not a finding that the successor does inherit, and it is not a finding that they do not |

The other nine vectors name no invariant, which is the accurate record: they turn
on the binding mode, on record standing or on the chain stage, and no invariant
in `AUTHORITY-LIFECYCLE.md` states a rule for any of those. L3 stays a
family-header reference with no vector behind it.

## Negative controls

Six defective configurations. `declared_fail_sets` names exactly which vectors
each one gets wrong.

| configuration | what it does | vectors it gets wrong |
|---|---|---|
| `defective-silent-binding-defaults-to-role` | supplies the missing term in one direction | 1 |
| `defective-silent-binding-defaults-to-identity` | supplies it in the other direction | 1 |
| `defective-role-bound-needs-reissuance` | treats every delegation as identity bound | 7 |
| `defective-identity-bound-follows-the-office` | treats every delegation as role bound | 2 |
| `defective-vacancy-defaults-to-last-known-holder` | keeps the last occupant current through a vacancy | 2 |
| `defective-trusts-self-declared-role` | reads an attestor's role off the record body | 1 |

The first two are the point of the family. Both pick a default for the silent
case, in opposite directions, and both fail `LRAS-C-007-i`. An implementation
cannot get that vector right by choosing better. It gets it right only by not
choosing.

## Running

    npm ci --include=dev
    npm run verify:lifecycle-root-authority-succession
    python3 fixtures/lifecycle-root-authority-succession/validate.py

Expected final lines:

    lifecycle-root-authority-succession TypeScript: 13/13 vectors, 6/6 negative controls
    lifecycle-root-authority-succession Python: 13/13 vectors, 6/6 negative controls

SDK support records:

    npx tsx fixtures/lifecycle-root-authority-succession/verify.ts --sdk-support
    python3 fixtures/lifecycle-root-authority-succession/validate.py --sdk-support

Regenerating:

    npx tsx fixtures/lifecycle-root-authority-succession/mint.ts

`git diff` on `chain.json` must then be empty.

## Results

Both runners were executed locally on one machine, on 2026-09-23, against npm
`agent-passport-system` 7.1.0 and PyPI `agent-passport-system` 4.1.0. Both
report 13/13 vectors and 6/6 negative controls. `CHECKSUMS.sha256` pins the
bytes of every file in this directory.

## Verification split

- chain verification of the four delegation chains at each vector's action
  instant / draft-03 Section 3.3 state and failure code; `verify.ts`; Mode A;
  author-produced; npm `agent-passport-system` 7.1.0. Author-produced because
  the person who wrote these vectors also ran this runner.
- the same chain claim / recomputed by a second implementation; `validate.py`;
  Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- RFC 8785 canonical bytes and Ed25519 verification of the four grant-terms and
  five office-event records / each signature verifies under the key its
  verification method names; `verify.ts`; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.
- the same signature claim / recomputed by the second implementation;
  `validate.py`; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- the binding verdict for each of the 13 vectors / the gate returns the declared
  verdict, stage and code; `verify.ts`; Mode A; author-produced;
  `fixtures/lifecycle-root-authority-succession/harness.ts`. The harness decides
  the claimed semantic result, so under `CONTRIBUTING.md` it is part of the
  recomputation implementation and the record cannot be independent.
- the same binding verdict / recomputed by an independent reimplementation of
  the gate; `validate.py`; Mode B; author-produced;
  `fixtures/lifecycle-root-authority-succession/validate.py`.
- the six defective configurations / each gets wrong exactly the declared set of
  vectors; both runners; Mode A and Mode B; author-produced; the same two gate
  implementations.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

1. **What a verifier should assume when the binding mode is silent.** This is
   the case itself, and `AUTHORITY-LIFECYCLE.md` states no default.
   `LRAS-C-007-i` encodes the one answer that does not invent the missing term.
   It does not establish that `not_established` is the right answer, only that
   both available defaults are choices the text has not made.
2. **Who may act for an office during a vacancy.** `OPEN-QUESTIONS.md` names
   this and answers nothing. `LRAS-C-007-j` returns `not_established` for the
   departed occupant. No vector presents an interim holder, a devolution rule or
   a reaffirmation, because the text names no mechanism for any of them.
3. **Whether a vacancy suspends or ends office-bound grants.** The open question
   lists continuation, suspension and reaffirmation as three possibilities.
   This family returns `not_established`, which is a statement about the
   verifier's knowledge and not a choice among those three. A design that
   returned `suspended` here would be answering the open question.
4. **Where the office-holder registry comes from.** The proposed text has no
   concept for it. This fixture supplies one, and a different design with the
   same source material would produce different codes.
5. **Whether a role-bound grant can outlive the office.** Nothing here tests an
   office that is abolished rather than vacated.
6. **Grants signed just before departure.** `OPEN-QUESTIONS.md` names this and
   states no answer. Nothing here bounds a grant's lifetime by the issuer's
   remaining time in a role.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that two
independently written gate implementations agree, on all 13 vectors and all 6
defective configurations, that:

- a delegation whose terms declare it role bound verifies for the office's
  current occupant at that instant, unchanged and unreissued, after turnover
- the same delegation returns `invalid` for the former occupant once a record
  covering that instant names somebody else
- a delegation whose terms declare it identity bound returns `invalid` for a new
  occupant of the same office, whatever the office-holder registry says
- a delegation that declares no binding mode returns `valid` when its own named
  subject acts and `not_established` when anybody else does
- a role-bound delegation over an office with a vacancy covering the action
  instant returns `not_established`, and the same two records at an instant the
  vacancy does not cover return `valid`
- an office-holder record from a party the registry does not place in the
  registrar role establishes nothing, in either direction
- a revoked or unknown revocation answer is reported at the chain stage and
  never collapses into valid

## Does not claim

- anything about either SDK's handling of subject binding, offices or vacancy.
  No SDK has an API for any of it, which `--sdk-support` records per vector
- that any legal doctrine applies to AI agents. The 1979 opinion quoted above is
  about a delegation between human officers of one department
- that these verdict names, stage names or codes are suite vocabulary
- that `not_established` is the right answer for a silent binding. It is the
  answer that does not invent a term, which is a narrower claim
- that role-bound delegation is safe, or advisable, for any particular grant.
  The fixture reads the mode off the delegation and takes no position on which
  one a deployment should use
- completeness. `chain.json` is the complete universe of records this family
  defines
