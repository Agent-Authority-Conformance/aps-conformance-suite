# lifecycle-agent-renunciation: the agent ends its own role, and the principal's silence is not a veto

Almost everything in this corpus is about authority ending from the principal's
side. This family is the other direction. The agent gives up the role, and the
questions are when that takes effect, whether the principal has any say in it,
what a stated later date or a stated triggering event does, and whether a
renunciation that breaches some other obligation takes effect any differently
from a clean one.

It also draws a line this family keeps: whether the renunciation was wrongful is
a liability question, and the gate never answers it. There is no liability field
in the result, and two vectors assert that at run time.

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`.
The proposed text is `aeoess/agent-authority-lifecycle`,
`AUTHORITY-LIFECYCLE.md` at commit `7796e22` (version 0.1.2-draft in the
document), and the cases are `LC-H-010` and `LC-H-011` in that repository's
`CASES.md` at version 0.2-draft.

| proposed text | vectors |
|---|---|
| Parties and standing > Sponsor or responsible owner | the family as a whole: who is responsible for an agent's continued operation, from the agent's side |
| Authority lifecycle state > Revocation | `LAR-H-010-b`: authority ends without anyone revoking anything |
| Verification and evidence > Notice ("Recording a transition and observing it are different events") | `LAR-H-010-b`, `LAR-H-010-c` |
| Verification and evidence > Accountability record ("It does not by itself establish legal liability") | `LAR-H-011-a`, `LAR-H-011-b` |
| What changes when a person leaves | all |
| L3, L4 | both invariants are about what replaces departed authority. This family is about the timing of the departure itself, which neither names |

### This is not a draft-03 conformance case

draft-pidlisnyi-aps-03 states no rule for an agent ending its own role. Section
3.5 gives the issuer a revocation power and says nothing about the subject. The
one draft-03 surface every vector touches is Section 3.3 chain verification,
quoted in full in the sibling `lifecycle-principal-events` README. Two
chain-stage controls pin that a revoked answer and an unknown answer are
reported at the chain stage, and that unknown surfaces as `not_established`.

### The verdict names are not suite vocabulary

`CONTRIBUTING.md` reserves failure-class names and verifier semantics to the
maintainer. `not_established`, `not_yet_effective` and `restricted` are declared
in the vocabulary and no vector here uses them. `suspended` appears only inside
one defective configuration, as the wrong answer it produces.

## Sources

Fetched while this fixture was authored. Every quote is verbatim and under forty
words. Neither source says anything about AI agents, and nothing here claims a
legal doctrine applies to AI agents.

**LC-H-010, effective on delivery.** Delaware Code, Title 8 §141(b),
<https://delcode.delaware.gov/title8/c001/sc04/index.html>:

> "A resignation is effective when the resignation is delivered unless the
> resignation specifies a later effective date or an effective date determined
> upon the happening of an event or events."

One sentence, three rules. Delivery controls by default, a stated date displaces
it, and a stated event displaces it too. `LAR-H-010-b`, `LAR-H-010-d` with
`LAR-H-010-e`, and `LAR-H-010-f` with `LAR-H-010-g` are those three.

What the sentence does not contain is any role for the principal's acceptance.
That absence is `LAR-H-010-b`'s negative control: an implementation that waits
for an acceptance record builds in a veto the source does not give.

**LC-H-011, wrongful and rightful are equally effective.** Delaware Code, Title
6 §15-602(a), <https://delcode.delaware.gov/title6/c015/sc06/index.html>:

> "A partner has the power to dissociate at any time, rightfully or wrongfully,
> by express will"

and §15-602(c):

> "A partner who wrongfully dissociates is liable to the partnership and to the
> other partners for damages"

Two separate questions in two separate subsections. Whether the standing ended,
and whether ending it that way was a breach. This family answers the first and
records that it is not answering the second.

## What the SDKs supply, and what this fixture supplies

| layer | supplied by |
|---|---|
| chain structure, signatures, key resolution, attenuation, validity window, revocation state | the real SDK chain verifier |
| RFC 8785 canonical bytes and Ed25519 verification for every fixture-local record | the real SDK |
| minting of the delegation | `issueAuthorityDelegation`, the real SDK |
| renunciation, its delivery instant, its stated effective date or triggering event, the principal's acceptance, the six verdict names | `harness.ts` and `validate.py`, this fixture |

`--sdk-support` on either runner prints the per-vector record. **A pass is a
result about this gate, not a conformance result about either SDK.**

## Records

`chain.json` is minted by `mint.ts` from published seed labels and regenerates
byte for byte. One chain, principal to agent, valid at every action instant. Ten
`fixture:renunciation-event:v0` records: four renunciations from the agent
itself (plain, with a stated later date, with a stated triggering event, and one
naming an agreement it breaches), one renunciation from another party, one
acceptance from the principal, two records of the triggering event with and
without standing, one no-exit agreement and one liability determination.

The last two exist only so a defective configuration has something to wait for.
The reference gate never reads them.

`agent_renunciation` and `principal_acceptance` bypass the attestor-role
registry. Who the agent is and who the principal is are read off the chain,
because neither is a fact about the wider registry.

## The gate

`harness.ts` and `validate.py` are two independent implementations. Evaluation
order:

1. **Chain**, then **classification** of each presented record.
2. A renunciation naming this delegation, from this grant's own subject, whose
   `delivered_at` is at or before the action instant. Without one, the grant is
   exercisable and the code says no renunciation was presented.
3. A stated `effective_date`. Later than the action instant gives `valid` with
   code `renunciation_not_yet_effective`, which is a wait and not a missing
   record. At or before gives `invalid`.
4. A stated `effective_on_event`. A record of that event type from a party with
   standing, matching the renunciation's own event reference and reaching the
   action instant, gives `invalid`. Without one the grant stays exercisable and
   the code says the trigger is not recorded.
5. Otherwise delivery controls and the answer is `invalid`.

The principal's acceptance is never consulted. Neither is the no-exit agreement
or the liability determination.

## Vectors

Thirteen. Nine for `LC-H-010`, two for `LC-H-011`, and two chain-stage controls.

`LAR-H-011-a` and `LAR-H-011-b` carry two extra assertions the runners check
beyond the verdict. `assert_no_liability_field` fails if the gate result grows a
field whose name matches liability, fault, wrongfulness or breach.
`assert_same_code_as` fails unless the wrongful renunciation reaches the exact
verdict and code the clean one reaches. Together they hold the separation as a
run-time property rather than a claim in prose.

### Invariant attribution

`vectors.json` names L3 and L4 at the family header and no vector names either
in its own record. That is deliberate and it is now stated in the data as well,
under `proposed_text.invariants_note`. L3 is about whether a revocation can be
reversed, and no vector here presents a withdrawn renunciation. L4 is about what
a successor inherits, and this family establishes nothing about who covers the
work after the agent leaves, which the vagueness section below says in full. The
two header names are context for the departure scenario, not coverage. A reader
building an L4 coverage map should read it off
`fixtures/lifecycle-root-authority-succession`, where `LRAS-C-007-g` and
`LRAS-C-007-i` name L4 at vector level.

## Negative controls

Four defective configurations. `declared_fail_sets` names exactly which vectors
each one gets wrong.

| configuration | what it does | vectors it gets wrong |
|---|---|---|
| `defective-requires-principal-acceptance` | waits for an acceptance record from the principal | 8 |
| `defective-wrongful-renunciation-pends-liability` | holds a breaching renunciation until a determination lands | 1 |
| `defective-ignores-stated-effective-date` | treats delivery as always controlling | 2 |
| `defective-trusts-self-declared-role` | reads an attestor's role off the record body | 1 |

## Running

    npm ci --include=dev
    npm run verify:lifecycle-agent-renunciation
    python3 fixtures/lifecycle-agent-renunciation/validate.py

Expected final lines:

    lifecycle-agent-renunciation TypeScript: 13/13 vectors, 4/4 negative controls
    lifecycle-agent-renunciation Python: 13/13 vectors, 4/4 negative controls

SDK support records:

    npx tsx fixtures/lifecycle-agent-renunciation/verify.ts --sdk-support
    python3 fixtures/lifecycle-agent-renunciation/validate.py --sdk-support

Regenerating:

    npx tsx fixtures/lifecycle-agent-renunciation/mint.ts

`git diff` on `chain.json` must then be empty.

## Results

Both runners were executed locally on one machine, on 2026-09-23, against npm
`agent-passport-system` 7.1.0 and PyPI `agent-passport-system` 4.1.0. Both
report 13/13 vectors and 4/4 negative controls. `CHECKSUMS.sha256` pins the
bytes of every file in this directory.

## Verification split

- chain verification of the delegation chain at each vector's action instant /
  draft-03 Section 3.3 state and failure code; `verify.ts`; Mode A;
  author-produced; npm `agent-passport-system` 7.1.0. Author-produced because
  the person who wrote these vectors also ran this runner.
- the same chain claim / recomputed by a second implementation; `validate.py`;
  Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- RFC 8785 canonical bytes and Ed25519 verification of the ten
  renunciation-event records / each signature verifies under the key its
  verification method names; `verify.ts`; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.
- the same signature claim / recomputed by the second implementation;
  `validate.py`; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- the renunciation verdict for each of the 13 vectors / the gate returns the
  declared verdict, stage and code; `verify.ts`; Mode A; author-produced;
  `fixtures/lifecycle-agent-renunciation/harness.ts`. The harness decides the
  claimed semantic result, so under `CONTRIBUTING.md` it is part of the
  recomputation implementation and the record cannot be independent.
- the same renunciation verdict / recomputed by an independent reimplementation
  of the gate; `validate.py`; Mode B; author-produced;
  `fixtures/lifecycle-agent-renunciation/validate.py`.
- the absence of a liability field, and the identity of the wrongful and clean
  results / two run-time assertions on `LAR-H-011-a` and `LAR-H-011-b`; both
  runners; Mode A and Mode B; author-produced; the same two gate
  implementations.
- the four defective configurations / each gets wrong exactly the declared set
  of vectors; both runners; Mode A and Mode B; author-produced; the same two
  gate implementations.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

1. **How delivery is established.** §141(b) makes delivery the default trigger
   and says nothing about proving it. This fixture takes the agent's own record
   of `delivered_at` as the fact, which means the agent decides when its own
   renunciation landed. `AUTHORITY-LIFECYCLE.md` lists Notice as a concept and
   says recording a transition and observing it are different events. It does
   not say who attests delivery. No vector tests a disputed delivery instant.
2. **Whether the two domains quoted here agree.** Delaware's corporate rule is
   effective on delivery. `CASES.md` notes that the Restatement of Agency has a
   different default for renunciation by notice to the principal, and this
   fixture does not resolve which applies to an agent. It encodes the delivery
   rule because that is the rule the source it fetched states.
3. **What happens to the role afterwards.** Nothing here establishes who covers
   the work, whether a successor exists, or whether the principal is entitled to
   notice before the gap opens. The sibling `lifecycle-principal-events` family
   covers pre-committed succession, and nothing connects the two.
4. **Whether a renunciation can be withdrawn.** Invariant L3 says revocation is
   not reversible and says nothing about renunciation. No vector presents a
   withdrawal.
5. **Whether a stated triggering event can be one the agent controls.**
   `LAR-H-010-g` requires the event from a party with standing. The proposed
   text does not say whether an agent may name its own record as its own
   trigger, and nothing here tests that.
6. **Liability, at all.** By design. The `restricted` and `suspended` verdicts
   exist in the vocabulary and neither is the right home for a liability
   question. `CASES.md` treats the wrongfulness half as a separate, later
   question, and so does this family.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that two
independently written gate implementations agree, on all 13 vectors and all 4
defective configurations, that:

- a renunciation from the grant's own subject, naming no later date and no
  triggering event, ends the grant at delivery with the principal having
  recorded nothing
- presenting an acceptance record from the principal alongside it changes
  neither the verdict nor the code
- a renunciation naming a later effective date leaves the grant exercisable
  until that date and ends it afterwards, with different codes for the two
- a renunciation whose effective date is determined by a named event leaves the
  grant exercisable until a record of that event from a party with standing
  reaches the action instant
- a trigger record from an attestor the registry does not place in the required
  role establishes nothing, in either direction
- a renunciation of this grant signed by a party that is not this grant's
  subject is not a renunciation of it
- a renunciation delivered in the face of a recorded agreement not to leave
  reaches the same verdict and the same code as a clean one, whether or not a
  later determination is also on record
- the gate result contains no liability field
- a revoked or unknown revocation answer is reported at the chain stage and
  never collapses into valid

## Does not claim

- anything about either SDK's handling of renunciation. Neither has an API for
  it, which `--sdk-support` records per vector
- that any legal doctrine applies to AI agents. The two Delaware provisions
  quoted above are about human directors and human partners
- that these verdict names, stage names or codes are suite vocabulary
- that delivery is the right default for agent renunciation in general. It is
  the rule the fetched source states, and `CASES.md` records that another domain
  has a different one
- anything about liability, fault, wrongfulness or damages
- anything about what happens to the work the agent was doing
- completeness. `chain.json` is the complete universe of records this family
  defines
