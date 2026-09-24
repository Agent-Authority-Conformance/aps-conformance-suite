# lifecycle-principal-events: what happens to an agent's authority when something happens to the principal

Seven questions, one family. A principal dies, or is found to lack capacity.
A designation that depended on a relationship outlives the relationship. A
fiduciary is later found to have forfeited the appointment. An authority that
was never a party to the delegation is appointed over the principal and then
acts on the delegation. A grant claims on its own say-so that it survives the
principal's death. A successor named inside the original instrument steps in
with nothing new issued.

Each one is a record set a verifier could check, and in each one a naive
implementation gets a definite answer for a definite reason. Those reasons are
the negative controls.

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`.
The proposed text is `aeoess/agent-authority-lifecycle`,
`AUTHORITY-LIFECYCLE.md` at commit `7796e22` (version 0.1.2-draft in the
document), and the cases are `LC-A-001`, `LC-A-005`, `LC-A-006`, `LC-A-009`,
`LC-A-010`, `LC-A-012` and `LC-A-016` in that repository's `CASES.md` at
version 0.2-draft.

The concepts and invariants each vector tests, as named in `vectors.json`:

| proposed text | vectors |
|---|---|
| Parties and standing > Issuer standing | every vector: no record decides anything without a role the model accepts for that record type |
| Parties and standing > Lifecycle standing | `LPE-A-010-*` |
| Authority lifecycle state > Suspension, Revocation | `LPE-A-010-b`, `LPE-A-010-c` |
| Verification and evidence > Notice | `LPE-A-001-b`, `LPE-A-001-c`, `LPE-A-001-i` |
| Verification and evidence > Status observation | `LPE-A-001-g`, `LPE-A-001-h`, `LPE-A-010-d` |
| What changes when a person leaves | `LPE-A-001-*`, `LPE-A-016-*` |
| L1, L3 | `LPE-A-009-*`: a rule that reaches an appointment, which L3 does not provide |
| L10 (expiry is not revocation) | `LPE-A-005-a`, `LPE-A-006-a`: authority that ends with no revocation record anywhere |
| OPEN-QUESTIONS.md > Grants signed just before departure | untested here, see the vagueness section |

### This is not a draft-03 conformance case

draft-pidlisnyi-aps-03 states no rule for death, incapacity, notice,
relationship-dependent designations, retroactive forfeiture, lifecycle standing
held by a party outside the chain, coupled-interest survival or pre-committed
succession. Its authority vector (Section 3.2) is a closed set of seven facets
with no slot for any of the grant terms this family needs.

The one draft-03 surface every vector does touch is Section 3.3 chain
verification, quoted here from the published draft
(<https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt>):

> "A verifier processes a root-to-leaf chain in this order: closed schema and
> canonical values; delegation_id; historical signing-key resolution and
> signature; duplicate identifiers; root trust; parent_delegation_id;
> issuer-to-subject continuity; child issuance time; the seven facet comparisons
> in Section 3.2; current validity; and revocation state for every member."

and:

> "A caller MUST NOT collapse indeterminate or unsupported into valid."

Every vector records `chain_state` separately from its verdict, and two
chain-stage controls (`LPE-A-001-j`, `LPE-A-001-k`) pin that a revoked answer
and an unknown answer are reported at the chain stage without reaching any
principal-event reasoning.

### The verdict names are not suite vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended` and
`restricted` are this family's local labels for discussion. `CONTRIBUTING.md`
reserves failure-class names and verifier semantics to the maintainer, so these
are a proposal and not a minted taxonomy. `restricted` is declared in the
vocabulary and no vector in this family uses it.

## Sources

Every source below was fetched while this fixture was authored, and every quote
is verbatim and under forty words. None of these sources says anything about AI
agents. The translation into agent terms is this fixture's, and a precedent is a
source of cases, not a claim that a legal doctrine applies to AI agents.

**LC-A-001, death.** Restatement (Third) of Agency §3.07(2), reproduced text at
<https://staff.washington.edu/djdrake/RESt-Agency.doc>:

> "The death of an individual principal terminates the agent's actual authority.
> The termination is effective only when the agent has notice of the principal's
> death."

**LC-A-001, the scope of durability.** Uniform Power of Attorney Act (2006)
§110(a), text at
<https://www.sos.ms.gov/content/documents/pol_res/power%20of%20attorney/5upoaa_final_may08.pdf>,
as enacted at N.H. RSA 564-E:110
(<https://gc.nh.gov/rsa/html/LVI/564-E/564-E-110.htm>): a power of attorney
terminates when

> "(1) the principal dies; (2) the principal becomes incapacitated, if the power
> of attorney is not durable"

Death terminates whether or not the instrument is durable. Incapacity
terminates only where it is not. That asymmetry is what vectors
`LPE-A-001-d`, `LPE-A-001-e` and `LPE-A-001-f` encode.

**LC-A-005, a designation that depends on a relationship.** California Probate
Code §4154(a), <https://law.onecle.com/california/probate/4154.html>:

> "If after executing a power of attorney the principal's marriage to the
> attorney-in-fact is dissolved or annulled, the principal's designation of the
> former spouse as an attorney-in-fact is revoked."

**LC-A-006, the trigger event differs by jurisdiction.** Florida Statutes
§709.2109(2)(b), <https://www.flsenate.gov/Laws/Statutes/2023/709.2109>, an
agent's authority terminates when

> "An action is filed for the dissolution or annulment of the agent's marriage
> to the principal or for their legal separation, unless the power of attorney
> otherwise provides"

One instrument ties the end to the decree and another to the filing. The two
sources disagree on the trigger and agree that the instrument can state it,
which is why the fixture reads the trigger off the grant's own terms and
returns not established when the terms are silent.

**LC-A-009, forfeiture reaching the appointment.** Uniform Probate Code §2-803
as enacted at Mass. Gen. Laws c.190B §2-803,
<https://malegislature.gov/Laws/GeneralLaws/PartII/TitleII/Chapter190B/Section2-803>,
subsection (c)(1)(iii), the killing revokes

> "nomination of the killer in a governing instrument, nominating or appointing
> the killer to serve in any fiduciary or representative capacity, including as
> personal representative, executor, trustee, or agent."

and subsection (e) provides that the instrument operates

> "as if the killer predeceased the decedent."

**LC-A-010, lifecycle standing from outside the chain.** Uniform Power of
Attorney Act §108 as enacted at RCW 11.125.080,
<https://wa-law.org/rcw/11_probate_and_trust_law/11.125_uniform_power_of_attorney_act.html>:

> "The power of attorney is not terminated and the agent's authority continues,
> subject to the provisions of RCW 11.130.335(1) and 11.130.435(4), unless
> limited, suspended, or terminated by the court."

Both halves matter. The appointment alone changes nothing, and the appointed
authority can then suspend or terminate an instrument it never issued.

**LC-A-012, a survival claim the grant makes about itself.** Hunt v.
Rousmanier's Administrators, 21 U.S. (8 Wheat.) 174 (1823),
<https://www.law.cornell.edu/supremecourt/text/21/174>. The general rule, which
is dictum in that opinion:

> "If a power be coupled with an 'interest,' it survives the person giving it,
> and may be executed after his death."

The actual holding on the power before the court:

> "It is, then, deemed perfectly clear, that the power given in this case, is a
> naked power, not coupled with an interest, which, though irrevocable by
> Rousmanier himself, expired on his death."

The party claiming the exception lost. That is why `LPE-A-012-a` returns not
established on the grant's own flag, and why `LPE-A-012-c` separates an
interest in the subject matter from an interest in the proceeds.

**LC-A-016, succession pre-committed at issuance.** Uniform Power of Attorney
Act (2006) §111(b), same PDF as above:

> "A principal may designate one or more successor agents to act if an agent
> resigns, dies, becomes incapacitated, is not qualified to serve, or declines
> to serve."

and, in the same subsection, unless the instrument provides otherwise a
successor agent

> "(1) has the same authority as that granted to the original agent; and (2) may
> not act until all predecessor agents have resigned, died, become
> incapacitated, are no longer qualified to serve, or have declined to serve."

Clause (1) is why the successor's authority is this instrument's authority and
not the predecessor's whole tree (`LPE-A-016-f`). Clause (2) is why a successor
whose predecessor has no recorded exit is not yet effective rather than
rejected (`LPE-A-016-c`, `LPE-A-016-d`).

## What the SDKs supply, and what this fixture supplies

| layer | supplied by |
|---|---|
| chain structure, signatures, historical key resolution, attenuation, validity window, revocation state | `verifyAuthorityDelegationChain` / `verify_authority_delegation_chain`, the real SDK |
| RFC 8785 canonical bytes for every fixture-local record | `canonicalizeJCS` / `canonicalize_jcs`, the real SDK |
| Ed25519 signature over those bytes | `verify` / `verify`, the real SDK |
| minting of the delegations | `issueAuthorityDelegation`, `issueSubAuthorityDelegation`, the real SDK |
| grant terms, principal-event records, the attestor-role registry, the event-standing table, notice, retroactive forfeiture, external lifecycle standing, coupled-interest survival, successor activation, the six verdict names | `harness.ts` and `validate.py`, this fixture |

Neither reference SDK exposes an API for anything in the last row. Run
`npx tsx fixtures/lifecycle-principal-events/verify.ts --sdk-support` or
`python3 fixtures/lifecycle-principal-events/validate.py --sdk-support` to get
the per-vector record of exactly what each SDK decided and what it was asked
about and has no API for. **A pass is a result about this gate, not a
conformance result about either SDK.**

## Records

`chain.json` is minted by `mint.ts` from published seed labels, so it carries no
secret material and regenerates byte for byte. Two fixture-local record types,
neither of which is an APS record type and neither of which any SDK claims:

- `fixture:grant-terms:v0`. Signed by the delegation's own issuer, bound to a
  `delegation_id`. Carries what `AuthorityVectorV1`'s seven closed facets have
  no slot for: `durability` and its declared scope, a `relationship_binding`
  with or without a `termination_trigger`, a `survives_principal_death` claim
  with its `survival_basis` and `subject_matter_ref`, and a `successor_order`.
- `fixture:principal-event:v0`. Signed by an attestor, naming an `event_type`,
  a `subject_ref`, an `occurred_at` (when the thing happened) and a
  `recorded_at`. Nineteen of them.

Two tables decide whose records count. `event_standing` maps an event type to
the role that has standing for it. `attestor_role_registry` maps a party to the
role the model places it in. Two event types bypass the registry on purpose:
`notice_of_principal_death` requires the attestor to be the grant's own subject,
because "the subject of this grant" is read off the grant and is not a registry
fact.

Ten chains, each a valid `AuthorityDelegationV1` chain whose time window covers
every action instant in `vectors.json`, so a non-valid verdict never comes from
the chain.

## The gate

`harness.ts` (TypeScript) and `validate.py` (Python) are two independent
implementations of the same gate, not a shared library with two wrappers. Both
run every vector and both must agree. Evaluation order, which the code follows
and the README states so it is reviewable:

1. **Chain.** `verifyAuthorityDelegationChain`. A non-valid state returns at the
   chain stage with the SDK's own failure code. `invalid` maps to `invalid`,
   `indeterminate` and `unsupported` map to `not_established`, never to `valid`.
2. **Terms.** Signature, and the named `delegation_id` has to be a member of the
   presented chain whose issuer signed the terms.
3. **Classification.** Per presented record: signature over the SDK's canonical
   bytes, the verification method has to belong to the attestor the body names,
   the registry role has to agree with the attestor's own claimed role, and the
   registry role has to be the one with standing for that event type. A rejected
   record is not evidence in either direction: it does not establish the event
   and it does not establish that the event did not happen. Every rejection
   reason travels in `notes`.
4. **Who may act.** An actor that is not the leaf subject has to appear in the
   instrument's own `successor_order`, past position zero, with a recorded exit
   for every predecessor.
5. **Forfeiture.** A finding naming any party in the chain returns invalid
   regardless of whether the action instant precedes the finding.
6. **Standing from outside the chain.** Terminate order, then suspend order,
   then guardian appointment, which changes nothing by itself.
7. **Death**, including the coupled-interest branch.
8. **Incapacity**, where the declared durability decides.
9. **The relationship the designation depends on.**

## Vectors

Thirty-two, in `vectors.json`. Every case names what it tests and its polarity.
The grouping by case id:

- `LPE-A-001-a` through `LPE-A-001-k` (11): the baseline, death without notice,
  death with notice, the durability pair in both directions, a death record
  without standing, a death record with a self-declared role, notice from
  another party, and the two chain-stage controls.
- `LPE-A-005-a` (1): the decree ends the designation with no revocation record.
- `LPE-A-006-a` through `LPE-A-006-c` (3): the filing trigger, the decree
  trigger not reached by a filing, and the silent trigger.
- `LPE-A-009-a` through `LPE-A-009-c` (3): forfeiture forward, forfeiture
  reaching an earlier instant, and a finding without standing.
- `LPE-A-010-a` through `LPE-A-010-d` (4): appointment, suspension,
  termination, and an order without standing.
- `LPE-A-012-a` through `LPE-A-012-d` (4): the self-declared survival claim, an
  interest in the subject matter, an interest in proceeds only, and an interest
  in a different thing.
- `LPE-A-016-a` through `LPE-A-016-f` (6): the primary, the first successor
  activated, two not-yet-effective states, the second successor activated, and
  the successor that does not reach the predecessor's own tree.

### The receipt that does not change

`LPE-A-009-b` carries a `prior_receipt`: the same grant, actor, instant and
revocation answer with the forfeiture finding not presented. That is the receipt
a boundary produced before the finding existed. Its canonical bytes are hashed
under RFC 8785 and the digest is pinned in `vectors.json`. Both runners
recompute it and fail the vector if it changed. A later finding is a new record
that references the appointment. It never rewrites an earlier receipt, and this
is the assertion that holds that property rather than asserting it in prose.

## Negative controls

Eight defective configurations, in `harness.ts` and mirrored in `validate.py`.
Each one is a plausible implementation, not a strawman. `vectors.json`
`declared_fail_sets` names exactly which vectors each configuration gets wrong,
and both runners fail if a configuration gets more or fewer wrong than declared.
A configuration that got everything right would mean the vectors do not separate
it from the reference gate.

| configuration | what it does | vectors it gets wrong |
|---|---|---|
| `defective-durability-survives-death` | reads `durable` as blanket death-immunity | 1 |
| `defective-revoke-only` | ends authority only on an explicit revocation answer | 12 |
| `defective-forfeiture-forward-only` | applies a forfeiture finding forward from the instant it was recorded | 1 |
| `defective-guardian-appointment-is-revocation` | reads the appointment of an outside authority as a revocation | 1 |
| `defective-trusts-self-declared-role` | reads an attestor's role off the record body | 2 |
| `defective-trusts-self-declared-survival` | honours the issuer's own survival flag | 3 |
| `defective-silent-trigger-defaults-to-decree` | supplies the missing termination trigger | 1 |
| `defective-successor-inherits-tree` | lets a successor reach whatever the predecessor issued | 1 |

## Running

From the conformance-suite root:

    npm ci --include=dev
    npm run verify:lifecycle-principal-events

It also runs as part of `npm test`. Expected final line:

    lifecycle-principal-events TypeScript: 32/32 vectors, 8/8 negative controls

Python, against the published PyPI package:

    python3 fixtures/lifecycle-principal-events/validate.py

Expected final line:

    lifecycle-principal-events Python: 32/32 vectors, 8/8 negative controls

SDK support records:

    npx tsx fixtures/lifecycle-principal-events/verify.ts --sdk-support
    python3 fixtures/lifecycle-principal-events/validate.py --sdk-support

Regenerating the records:

    npx tsx fixtures/lifecycle-principal-events/mint.ts

`git diff` on `chain.json` must then be empty. This was checked while authoring
by re-running `mint.ts` and comparing the SHA-256 of `chain.json` before and
after.

## Results

Both runners were executed locally on one machine, on 2026-09-23, against npm
`agent-passport-system` 7.1.0 (pinned in `package.json`) and PyPI
`agent-passport-system` 4.1.0.

    lifecycle-principal-events reference gate: 32/32 passed
    lifecycle-principal-events negative controls: 8/8 behaved as declared

for both. `CHECKSUMS.sha256` pins the bytes of every file in this directory.

## Verification split

One entry per distinct verification claim, in the form
`layer / claim; runner; Mode A | Mode B; author-produced | independent;
implementation`.

- chain verification of the ten delegation chains at each vector's action
  instant / draft-03 Section 3.3 state and failure code; `verify.ts`; Mode A;
  author-produced; npm `agent-passport-system` 7.1.0. Author-produced because
  the person who wrote these vectors also ran this runner.
- chain verification of the same chains / the same claim recomputed by a second
  implementation; `validate.py`; Mode B; author-produced; PyPI
  `agent-passport-system` 4.1.0. Author-produced for the same reason. The
  implementation supplying the recomputation is the Python SDK, which this
  fixture's author did not write, but the runner and the vectors are the same
  author's.
- RFC 8785 canonical bytes and Ed25519 verification of the nine grant-terms and
  nineteen principal-event records / each record's signature verifies under the
  key its verification method names; `verify.ts`; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.
- the same signature claim / recomputed by the second implementation;
  `validate.py`; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- the lifecycle verdict for each of the 32 vectors / the gate returns the
  declared verdict, stage and code; `verify.ts`; Mode A; author-produced;
  `fixtures/lifecycle-principal-events/harness.ts`, which is this fixture's own
  code. This is the layer where the harness decides the claimed semantic result,
  so under `CONTRIBUTING.md` the harness is part of the recomputation
  implementation and the record cannot be independent.
- the same lifecycle verdict / recomputed by an independent reimplementation of
  the gate; `validate.py`; Mode B; author-produced;
  `fixtures/lifecycle-principal-events/validate.py`. The two gate
  implementations were written separately and agree on all 32 vectors, which is
  evidence about the specification of the gate and not about either SDK.
- the pinned prior receipt for `LPE-A-009-b` / the earlier receipt's canonical
  bytes are unchanged; both runners; Mode A and Mode B; author-produced; the
  same two gate implementations.
- the eight defective configurations / each gets wrong exactly the declared set
  of vectors; both runners; Mode A and Mode B; author-produced; the same two
  gate implementations.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

Written down rather than resolved, because resolving it in a fixture would mint
a rule the proposed text has not stated.

1. **How notice is established over an agent that does not record it.**
   Restatement §3.07(2) makes termination effective on the agent's notice. This
   fixture models notice as a record signed by the grant's own subject, which is
   the only party the source names. That gives an agent a way to withhold the
   record and keep the grant verifying valid. `AUTHORITY-LIFECYCLE.md` lists
   Notice as a concept and says only that "Recording a transition and observing
   it are different events". It does not say who else may attest an agent's
   notice, or whether delivery by a party with standing substitutes for the
   agent's own acknowledgement. No vector here tests that, and
   `LPE-A-001-b` deliberately returns valid with a code that names the gap
   rather than guessing.
2. **Whether a designation can come back.** California Probate Code §4154(b)
   restores the designation if the same two people remarry. Invariant L3 says
   reauthorization never reverses a revocation. Whether a relationship-dependent
   termination is a revocation at all, and so whether L3 reaches it, is not
   stated. No vector presents a remarriage record.
3. **Who has lifecycle standing, in general.** The concept entry says an
   organization, a quorum, a successor, a court or a security function can have
   standing to change authority it never issued. It does not say how a verifier
   learns which parties those are. This fixture supplies a registry and an
   event-standing table, both of which are the fixture's invention. A different
   design with the same source material would produce different codes.
4. **Where retroactive voiding stops.** `LPE-A-009-b` establishes that the
   finding reaches an instant before it was recorded. It does not establish what
   happens to effects already produced under that authority, which
   `OPEN-QUESTIONS.md` leaves open under "Work in flight". No vector presents an
   effect.
5. **Whether suspension composes.** `LPE-A-010-b` returns suspended on one
   order. `OPEN-QUESTIONS.md` under "Release from suspension" says multiple
   causes probably need to compose, with each released separately, and that this
   is not specified. No vector presents two suspensions or a release.
6. **Grants signed just before departure.** `OPEN-QUESTIONS.md` names this and
   states no answer. Nothing here bounds the lifetime of a grant by the
   issuer's remaining time in a role, and no vector tests one.
7. **How narrow "coupled with an interest" is.** The source shows one party
   failing the test. It does not give a general rule for which interests
   qualify. This fixture encodes one distinction the case's own facts support,
   subject matter against proceeds, and nothing broader.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that these
two independently written gate implementations agree, on all 32 vectors and all
8 defective configurations, that:

- a recorded death from a party with standing, with nothing establishing the
  subject's notice of it, leaves the grant exercisable and the record says which
  of the two it is reporting
- adding the notice record ends the grant, with no revocation record anywhere
- a grant whose terms declare it durable with a declared scope of surviving
  incapacity ends at death and survives incapacity, and one that declares itself
  not durable ends at both
- a designation bound to a relationship ends on the event its own terms name,
  and a different relationship event does not end it
- a relationship binding with no declared trigger produces not established
  rather than either answer
- a forfeiture finding from a party with standing produces invalid at an action
  instant before the finding was recorded, and the receipt taken at that instant
  before the finding existed is byte-identical afterwards
- the appointment of an authority outside the chain does not terminate the
  delegation, and an order from that authority suspends or terminates it
- an issuer's own claim that a grant survives death produces not established
  until a record from a registry with standing shows an interest in the very
  subject matter the terms name
- a successor named in one instrument is exercisable under that instrument once
  every predecessor has a recorded exit, is not yet effective before then, and
  is invalid against a different delegation the predecessor issued
- a record whose attestor the registry places in a role without standing changes
  no verdict, in either direction
- a revoked or unknown revocation answer is reported at the chain stage and
  never collapses into valid

## Does not claim

A pass does **not** establish, and this fixture does not test:

- anything about either SDK's handling of death, notice, forfeiture, standing,
  survival or succession. No SDK has an API for any of them, which
  `--sdk-support` records per vector
- that any legal doctrine applies to AI agents. The instruments quoted above are
  the source of the cases. The translation into agent terms is this fixture's
- that these six verdict names, these stage names or these codes are suite
  vocabulary. `CONTRIBUTING.md` reserves that to the maintainer
- that the attestor-role registry and event-standing table are the right design.
  They are one design that makes the cases checkable
- anything about effects already produced, work in flight, or compensation after
  a verdict changes. No vector presents an effect
- completeness. `chain.json` is the complete universe of records this family
  defines, not a claim about every record that could exist for these parties
- that the defective configurations are the only ways to get these cases wrong.
  They are eight that the vectors separate
- anything about execution-time rechecking. Each vector calls the chain verifier
  once, at one fixed instant
