# lifecycle-fiduciary-succession: quorum over one instrument, a mandate narrower than the grant, and what a later ratification does not reach

Three questions a single-principal authority model has no slot for. Several
co-equal holders share one instrument and disagree, or one of them drops out.
A caretaker holds authority that is deliberately narrower than ordinary
successor authority and ends on an external event rather than on a clock. An
agent acted outside its declared scope and the principal approves it
afterwards, which is neither reauthorization nor revocation.

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`.
The proposed text is `aeoess/agent-authority-lifecycle`,
`AUTHORITY-LIFECYCLE.md` at commit `7796e22` (version 0.1.2-draft in the
document), and the cases are `LC-A-019`, `LC-A-022` and `LC-A-023` in that
repository's `CASES.md` at version 0.2-draft.

| proposed text | vectors |
|---|---|
| Parties and standing > Lifecycle standing | `LFS-A-019-*`, `LFS-A-022-c` |
| Authority lifecycle state > Expiry or exhaustion | `LFS-A-022-c`: a mandate reaching its declared end with no revocation record |
| Authority lifecycle state > External restriction | `LFS-A-023-g`: the one vector that returns `restricted` |
| Decisions and effects > Approval | `LFS-A-019-*`: approvals with their own scope and their own holder set |
| Verification and evidence > Evidence | `LFS-A-023-b`, `LFS-A-023-c`: a record the verifier does not hold yet decides nothing |
| L3 (reauthorization creates new authority) | `LFS-A-023-*`: ratification is a third mechanism L3 does not name |
| L8 (suspension is not revocation) | the `restricted` verdict is a fourth state, distinct from both |
| L10 (expiry is not revocation) | `LFS-A-022-c` |

### This is not a draft-03 conformance case

draft-pidlisnyi-aps-03 states no rule for co-holders of one instrument, for a
quorum over current holders, for a mandate class, or for ratification. The one
draft-03 surface every vector touches is Section 3.3 chain verification, quoted
in full in the sibling `lifecycle-principal-events` README. Two chain-stage
controls (`LFS-CTRL-a`, `LFS-CTRL-b`) pin that a revoked answer and an unknown
answer are reported at the chain stage, and that unknown surfaces as
`not_established` rather than collapsing into `valid`.

### The verdict names are not suite vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended` and
`restricted` are this family's local labels. `CONTRIBUTING.md` reserves
failure-class names and verifier semantics to the maintainer. `not_yet_effective`
and `suspended` are declared in the vocabulary and no vector here uses them.

## Sources

Fetched while this fixture was authored. Every quote is verbatim and under forty
words. None of these sources says anything about AI agents, and nothing here
claims a legal doctrine applies to AI agents.

**LC-A-019, quorum and vacancy.** Uniform Trust Code §703 as enacted at Maine
Title 18-B §703,
<https://legislature.maine.gov/statutes/18-B/title18-Bsec703.html>:

> "Cotrustees who are unable to reach a unanimous decision may act by majority
> decision."

and:

> "If a vacancy occurs in a cotrusteeship, the remaining cotrustees may act for
> the trust."

Two rules, not one. Disagreement resolves by majority, and a vacancy does not
have to be filled before the remainder can act. `LFS-A-019-c` and `LFS-A-019-f`
are the two negative controls those sentences produce.

**LC-A-022, a mandate scoped to preservation that ends on an external event.**
Cornell LII Wex, "administrator pendente lite",
<https://www.law.cornell.edu/wex/administrator_pendente_lite>. The role exists
to

> "manage an estate and probate a will during the pendency of the dispute, or
> until a more permanent administrator or executor of the estate in question is
> installed."

and:

> "The resolution of the legal dispute terminates the administration."

**LC-A-023, ratification and its three bounds.** Restatement (Third) of Agency,
reproduced text at <https://staff.washington.edu/djdrake/RESt-Agency.doc>.
§4.02(1):

> "Subject to the exceptions stated in subsection (2), ratification retroactively
> creates the effects of actual authority."

§4.02(2)(c), one of those exceptions, that ratification is not effective

> "to diminish the rights or other interests of persons, not parties to the
> transaction, that were acquired in the subject matter prior to the
> ratification."

§4.07:

> "A ratification is not effective unless it encompasses the entirety of an act,
> contract, or other single transaction."

§4.04(1)(b), a person may ratify only if

> "the person had capacity as defined in"

§3.04 at the time of ratifying the act.

## What the SDKs supply, and what this fixture supplies

| layer | supplied by |
|---|---|
| chain structure, signatures, key resolution, attenuation, validity window, revocation state | `verifyAuthorityDelegationChain` / `verify_authority_delegation_chain`, the real SDK |
| RFC 8785 canonical bytes and Ed25519 verification for every fixture-local record | `canonicalizeJCS` and `verify` / `canonicalize_jcs` and `verify`, the real SDK |
| minting of the five delegations | `issueAuthorityDelegation`, the real SDK |
| the co-holder instrument, the quorum rule, the temporary mandate, ratification and its three bounds, the evaluation instant, the six verdict names | `harness.ts` and `validate.py`, this fixture |

`--sdk-support` on either runner prints the per-vector record of what each SDK
decided and what it was asked about and has no API for. **A pass is a result
about this gate, not a conformance result about either SDK.**

## Two clock positions, not one

Every vector carries `action_at`, the instant the action is presented, and
`evaluated_at`, the instant this decision is made. A record is usable only if
its `recorded_at` is at or before `evaluated_at`, and what it establishes is
compared against `action_at`.

That split is load bearing. It is how this family shows that a ratification
recorded later reaches an earlier act **without** rewriting the receipt the
boundary produced at that earlier act. Those are two decisions from two evidence
sets, not one record edited twice. `LFS-A-023-b` carries a `prior_receipt`: the
same act at the same instant, evaluated before the ratification was written. Its
canonical bytes are hashed under RFC 8785 and pinned in `vectors.json`, and both
runners fail the vector if it changed. `LFS-A-023-c` is the verdict-level
statement of the same property: presented to a verifier evaluating before the
ratification exists, the act is still outside scope.

## Records

`chain.json` is minted by `mint.ts` from published seed labels and regenerates
byte for byte. Two fixture-local record types, neither of them an APS record
type:

- `fixture:grant-terms:v0`, signed by the delegation's issuer and bound to a
  `delegation_id`. Carries the co-holder list and decision rule, or a `mandate`
  with its narrower permitted action classes and its `ends_on_event`, or the
  permitted action classes and the components of the one integrated act.
- `fixture:succession-event:v0`, signed by an attestor. Seventeen of them:
  approvals, dissents, vacancies, a dispute resolution, three ratifications,
  two capacity findings and two third-party interest records.

`event_standing` maps an event type to the role with standing for it. Two roles
bypass the `attestor_role_registry` on purpose. `grant-principal` is read off
the chain's root issuer and `named-co-holder` off the instrument's own
co-holder list, because neither is a fact about the wider registry.

Five chains, each valid at every action instant in `vectors.json`. Two of them
present the same three-holder instrument for two different acting holders.

## The gate

`harness.ts` and `validate.py` are two independent implementations of the same
gate. Evaluation order:

1. **Chain**, at `action_at`. A non-valid state returns at the chain stage.
2. **Terms.** Signature, and the named delegation has to be a chain member whose
   issuer signed the terms.
3. **Classification** per record: signature, attestor binding, `recorded_at` at
   or before `evaluated_at`, and the standing check for the event type.
4. **Quorum**, when the instrument names co-holders. The acting holder's own
   vacancy ends it. Otherwise current holders are the named holders minus those
   with a vacancy reaching `action_at`, approvals are counted among current
   holders only, and a strict majority is required.
5. **Mandate**, when the terms carry one. The declared ending event, matched on
   its dispute reference, then the narrower permitted action classes.
6. **Scope and ratification.** An action class the terms permit needs nothing.
   Otherwise a ratification from the grant's own principal, naming this act and
   recorded at or before `evaluated_at`, is required, then capacity at the
   ratifying instant, then atomicity over the act's components, then the
   intervening-interest bound.

## Vectors

Twenty-five. Eight for `LC-A-019`, five for `LC-A-022`, ten for `LC-A-023`, and
two chain-stage controls.

## Negative controls

Nine defective configurations. `declared_fail_sets` in `vectors.json` names
exactly which vectors each one gets wrong, and both runners fail if a
configuration gets more or fewer wrong than declared.

| configuration | what it does | vectors it gets wrong |
|---|---|---|
| `defective-counts-approval-from-vacated-holder` | counts every authentic approval it can find | 1 |
| `defective-requires-unanimity-of-named-holders` | requires every named holder to approve | 4 |
| `defective-requires-backfill-before-acting` | blocks the remainder until a vacancy is filled | 2 |
| `defective-temporary-admin-has-full-successor-powers` | gives the caretaker ordinary successor authority | 1 |
| `defective-revoke-only` | ends authority only on an explicit revocation answer | 1 |
| `defective-ratification-reaches-intervening-interest` | treats ratification as a clean rewrite of history | 1 |
| `defective-accepts-partial-ratification` | lets the principal keep the favourable half | 1 |
| `defective-ignores-capacity-at-ratification` | accepts a ratification signal on its signature alone | 1 |
| `defective-trusts-self-declared-role` | reads an attestor's role off the record body | 1 |

## Running

    npm ci --include=dev
    npm run verify:lifecycle-fiduciary-succession
    python3 fixtures/lifecycle-fiduciary-succession/validate.py

Expected final lines:

    lifecycle-fiduciary-succession TypeScript: 25/25 vectors, 9/9 negative controls
    lifecycle-fiduciary-succession Python: 25/25 vectors, 9/9 negative controls

SDK support records:

    npx tsx fixtures/lifecycle-fiduciary-succession/verify.ts --sdk-support
    python3 fixtures/lifecycle-fiduciary-succession/validate.py --sdk-support

Regenerating:

    npx tsx fixtures/lifecycle-fiduciary-succession/mint.ts

`git diff` on `chain.json` must then be empty.

## Results

Both runners were executed locally on one machine, on 2026-09-23, against npm
`agent-passport-system` 7.1.0 and PyPI `agent-passport-system` 4.1.0. Both
report 25/25 vectors and 9/9 negative controls. `CHECKSUMS.sha256` pins the
bytes of every file in this directory.

## Verification split

- chain verification of the five delegation chains at each vector's action
  instant / draft-03 Section 3.3 state and failure code; `verify.ts`; Mode A;
  author-produced; npm `agent-passport-system` 7.1.0. Author-produced because
  the person who wrote these vectors also ran this runner.
- the same chain claim / recomputed by a second implementation; `validate.py`;
  Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- RFC 8785 canonical bytes and Ed25519 verification of the five grant-terms and
  seventeen succession-event records / each signature verifies under the key its
  verification method names; `verify.ts`; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.
- the same signature claim / recomputed by the second implementation;
  `validate.py`; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- the lifecycle verdict for each of the 25 vectors / the gate returns the
  declared verdict, stage and code; `verify.ts`; Mode A; author-produced;
  `fixtures/lifecycle-fiduciary-succession/harness.ts`. The harness decides the
  claimed semantic result, so under `CONTRIBUTING.md` it is part of the
  recomputation implementation and the record cannot be independent.
- the same lifecycle verdict / recomputed by an independent reimplementation of
  the gate; `validate.py`; Mode B; author-produced;
  `fixtures/lifecycle-fiduciary-succession/validate.py`.
- the pinned prior receipt for `LFS-A-023-b` / the earlier receipt's canonical
  bytes are unchanged; both runners; Mode A and Mode B; author-produced; the
  same two gate implementations.
- the nine defective configurations / each gets wrong exactly the declared set
  of vectors; both runners; Mode A and Mode B; author-produced; the same two
  gate implementations.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

1. **How wide the intervening-interest bound is.** §4.02(2)(c) protects
   interests acquired "prior to the ratification", which on its face includes
   interests acquired before the act as well as between the act and the
   ratification. This fixture encodes the narrower reading, interests acquired
   strictly between the two, because that is the situation `CASES.md` describes.
   `LFS-A-023-h` presents an interest acquired before the act and returns
   `valid`, which is the narrow reading and not a finding about the broad one.
   Nothing in `AUTHORITY-LIFECYCLE.md` picks between them.
2. **What `restricted` does to descendants.** Invariant L8 says a restricted
   state "does not have to pause descendants" and says nothing more. This family
   returns `restricted` for one target under one act. No vector presents a
   descendant, and nothing here establishes what a restricted state does to one.
3. **Who counts as a current holder when the vacancy record is contested.** The
   proposed text has no concept for two disagreeing vacancy records, and this
   fixture presents at most one per vector. The wave 2 `conflicting-status-sources`
   family covers disagreeing status sources for revocation, not for holder sets.
4. **Whether a quorum rule can itself be amended.** The instrument's decision
   rule is a term of the instrument here and nothing can change it. The proposed
   text does not say whether lifecycle standing over an instrument includes
   standing over its decision rule.
5. **When a mandate's ending event is itself disputed.** `LFS-A-022-c` takes one
   resolution record from a party with standing. The proposed text says nothing
   about a mandate whose ending condition is contested, which is the situation a
   caretaker mandate exists for in the first place.
6. **What a ratification does to effects already produced.** `OPEN-QUESTIONS.md`
   under "Work in flight" leaves this open and this family presents no effects.
   Every vector answers a question about authority, never about an outcome.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that two
independently written gate implementations agree, on all 25 vectors and all 9
defective configurations, that:

- a majority of the holders current at the action instant authorizes the action,
  a recorded dissent does not block it, and a vacancy does not have to be filled
  first
- an authentic approval from a holder who has since vacated is not counted, and
  the record is neither forged nor withdrawn
- a holder with its own recorded vacancy cannot act on a quorum of the others
- an approval from a party the instrument's own co-holder list does not name is
  not counted
- a mandate narrower than the grant it sits on rejects an action class outside
  it, and ends on its declared external event with no revocation record anywhere
- an act outside a grant's declared scope is invalid, and a ratification from
  the grant's own principal covering every component of the integrated act makes
  it valid as of the act instant
- the receipt produced at that act instant before the ratification existed is
  byte-identical afterwards, and the same ratification presented to a verifier
  evaluating before it was recorded changes nothing
- a partial ratification, a ratification while a capacity finding covers the
  ratifying instant, and a ratification from a party that is not the principal
  each leave the act invalid, with a code naming which one it was
- a third-party interest recorded between the act and the ratification produces
  `restricted` rather than `valid` for that target
- a revoked or unknown revocation answer is reported at the chain stage and
  never collapses into valid

## Does not claim

- anything about either SDK's handling of quorum, mandates or ratification. No
  SDK has an API for any of them, which `--sdk-support` records per vector
- that any legal doctrine applies to AI agents
- that these verdict names, stage names or codes are suite vocabulary
- that a strict majority is the right quorum rule in general. It is the rule the
  instrument in this fixture declares, and the gate reads it off the instrument
- anything about effects, compensation or work in flight
- completeness. `chain.json` is the complete universe of records this family
  defines
- that the nine defective configurations are the only ways to get these cases
  wrong
