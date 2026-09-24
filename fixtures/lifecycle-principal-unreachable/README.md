# lifecycle-principal-unreachable: an action waiting on a confirmation nobody can get is not established, not approved and not denied

A grant is valid. Nothing is revoked. The chain verifies at every instant in
this family. And one action under that grant still cannot go ahead, because the
grant's own terms make that action class effective only once an agreed
confirmation procedure with the principal has actually been completed, and the
principal cannot be reached to complete it.

The two wrong answers are the obvious ones. Treat silence past the deadline as
approval, because nothing said no. Or treat the unreachable principal as a
denial, because nothing was confirmed. Both manufacture a decision. Both are
negative controls here.

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`.
The proposed text is `aeoess/agent-authority-lifecycle`,
`AUTHORITY-LIFECYCLE.md` at commit `7796e22` (version 0.1.2-draft in the
document), and the case is `LC-H-012` in that repository's `CASES.md` at version
0.2-draft.

| proposed text | vectors |
|---|---|
| Decisions and effects > Approval | every vector: an approval with its own scope and binding, and an action that waits on it |
| Decisions and effects > Authorization decision | the verdict is the record an enforcement point makes, and here it is neither allow nor deny |
| Verification and evidence > Status observation | `LPU-H-012-b`, `LPU-H-012-c`, `LPU-H-012-i` |
| Verification and evidence > Notice | `LPU-H-012-d`, `LPU-H-012-e`: a confirmation reaches an action only from the instant it exists |
| Verification and evidence > Coverage and completeness | `LPU-H-012-f`, `LPU-H-012-g`: an authentic record that does not cover this order or this procedure |
| L7 (unknown revocation state is not active) | the boundary this family draws, see below |

### This family is next to L7, not inside it

L7 says an unavailable or stale revocation answer is indeterminate and does not
become active. That is about authority that existed and might have ended. This
family is about whether this action was ever established as authorized in the
first place. Nothing is revoked anywhere in it.

Every vector except the two chain-stage controls answers `active` to the
revocation resolver, and the chain verifies `valid` at every action instant. So
a `not_established` verdict in this family is never an unknown revocation state.
`LPU-CTRL-b` is the vector that makes that boundary explicit: it is the only one
where `not_established` comes from the chain stage with the SDK's own
`REVOCATION_UNKNOWN` code.

### How this differs from the wave 2 `activation-not-established` family

That family gates the **grant**. An activation condition decides when already
issued authority becomes exercisable at all, and its records attest that a named
event occurred. This family gates **one action** under a grant that is already
exercisable, and its records attest that a procedure was completed for one named
order. The grant here is exercisable throughout, which `LPU-H-012-j` shows by
taking a different action class under the same grant at the same instant while
the principal is unreachable, and getting `valid`.

### This is not a draft-03 conformance case

draft-pidlisnyi-aps-03 states no per-action confirmation rule and defines no
unreachability record. The one draft-03 surface every vector touches is Section
3.3 chain verification, quoted in full in the sibling
`lifecycle-principal-events` README.

### The verdict names are not suite vocabulary

`CONTRIBUTING.md` reserves failure-class names and verifier semantics to the
maintainer. `not_yet_effective`, `suspended` and `restricted` are declared in
the vocabulary and no vector here uses them.

## Source

Fetched while this fixture was authored. The quote is verbatim and under forty
words. This source says nothing about AI agents and nothing here claims a legal
doctrine applies to AI agents.

Uniform Commercial Code §4A-202(b), Cornell LII,
<https://www.law.cornell.edu/ucc/4A/4A-202>. A payment order is effective as the
customer's order

> "whether or not authorized, if (i) the security procedure is a commercially
> reasonable method of providing security against unauthorized payment orders,
> and (ii) the bank proves that it accepted the payment order in good faith and
> in compliance with the security procedure"

What makes the order effective as the customer's is the receiving party's actual
compliance with the agreed procedure. Not elapsed time, and not a good-faith
guess in the customer's absence. That is the whole of the rule this family
encodes: completion of the procedure is the fact, and its absence is the absence
of a fact rather than a decision in either direction.

## What the SDKs supply, and what this fixture supplies

| layer | supplied by |
|---|---|
| chain structure, signatures, key resolution, attenuation, validity window, revocation state | the real SDK chain verifier |
| RFC 8785 canonical bytes and Ed25519 verification for every fixture-local record | the real SDK |
| minting of the delegation | `issueAuthorityDelegation`, the real SDK |
| the confirmation procedure, the per-action confirmation record, the unreachability and deadline observations, the six verdict names | `harness.ts` and `validate.py`, this fixture |

`--sdk-support` on either runner prints the per-vector record. **A pass is a
result about this gate, not a conformance result about either SDK.**

## Records

`chain.json` is minted by `mint.ts` from published seed labels and regenerates
byte for byte. One chain, principal to agent, granting two scopes, valid at
every action instant. One `fixture:grant-terms:v0` record declaring the
confirmation procedure: its identifier, the party that may confirm, the action
classes it covers, and a deadline. Eight `fixture:confirmation-event:v0`
records: five confirmations varying one binding each, two unreachability
observations with and without standing, and one deadline-elapsed observation.

The deadline is in the terms and the deadline-elapsed record exists, so the
family can state that a deadline is real and still show that its passing decides
nothing on its own.

`principal_confirmation` bypasses the attestor-role registry. Who may confirm is
a term of the procedure, read off the grant's terms.

## The gate

`harness.ts` and `validate.py` are two independent implementations. Evaluation
order:

1. **Chain**, then **terms**.
2. If the procedure does not cover this action class, the answer is `valid` with
   code `no_confirmation_required`, and none of the records below are consulted.
3. **Classification** per record, including the check that a confirmation came
   from the confirmer the terms name.
4. A confirmation bound to this procedure and this order, whose `confirmed_at`
   is at or before the action instant, gives `valid`.
5. A confirmation bound to this order that does not reach the action instant
   gives `not_established` with code `confirmation_after_action`, which is a
   different finding from having no answer at all.
6. Otherwise `not_established` with code
   `confirmation_procedure_not_completed`. An unreachability observation, if
   one was presented and accepted, is recorded in `notes` and changes nothing.

## Vectors

Twelve. Ten for `LC-H-012` and two chain-stage controls.

## Negative controls

Five defective configurations. `declared_fail_sets` names exactly which vectors
each one gets wrong.

| configuration | what it does | vectors it gets wrong |
|---|---|---|
| `defective-silence-after-deadline-is-approval` | reads elapsed time as the principal answering | 1 |
| `defective-unreachable-is-denial` | reads an unreachable principal as a refusal | 5 |
| `defective-accepts-confirmation-from-any-party` | checks the signature and not who signed | 1 |
| `defective-ignores-confirmation-binding` | checks the signature and not what it covers | 2 |
| `defective-accepts-confirmation-after-the-action` | lets a later answer authorize an earlier act | 1 |

The first two are the pair the case is about. They fail different vectors and
they fail for the same reason: each invents a decision the underlying rule does
not make.

## Running

    npm ci --include=dev
    npm run verify:lifecycle-principal-unreachable
    python3 fixtures/lifecycle-principal-unreachable/validate.py

Expected final lines:

    lifecycle-principal-unreachable TypeScript: 12/12 vectors, 5/5 negative controls
    lifecycle-principal-unreachable Python: 12/12 vectors, 5/5 negative controls

SDK support records:

    npx tsx fixtures/lifecycle-principal-unreachable/verify.ts --sdk-support
    python3 fixtures/lifecycle-principal-unreachable/validate.py --sdk-support

Regenerating:

    npx tsx fixtures/lifecycle-principal-unreachable/mint.ts

`git diff` on `chain.json` must then be empty.

## Results

Both runners were executed locally on one machine, on 2026-09-23, against npm
`agent-passport-system` 7.1.0 and PyPI `agent-passport-system` 4.1.0. Both
report 12/12 vectors and 5/5 negative controls. `CHECKSUMS.sha256` pins the
bytes of every file in this directory.

## Verification split

- chain verification of the delegation chain at each vector's action instant /
  draft-03 Section 3.3 state and failure code; `verify.ts`; Mode A;
  author-produced; npm `agent-passport-system` 7.1.0. Author-produced because
  the person who wrote these vectors also ran this runner.
- the same chain claim / recomputed by a second implementation; `validate.py`;
  Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- RFC 8785 canonical bytes and Ed25519 verification of the one grant-terms and
  eight confirmation-event records / each signature verifies under the key its
  verification method names; `verify.ts`; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.
- the same signature claim / recomputed by the second implementation;
  `validate.py`; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.
- the confirmation verdict for each of the 12 vectors / the gate returns the
  declared verdict, stage and code; `verify.ts`; Mode A; author-produced;
  `fixtures/lifecycle-principal-unreachable/harness.ts`. The harness decides the
  claimed semantic result, so under `CONTRIBUTING.md` it is part of the
  recomputation implementation and the record cannot be independent.
- the same confirmation verdict / recomputed by an independent reimplementation
  of the gate; `validate.py`; Mode B; author-produced;
  `fixtures/lifecycle-principal-unreachable/validate.py`.
- the five defective configurations / each gets wrong exactly the declared set
  of vectors; both runners; Mode A and Mode B; author-produced; the same two
  gate implementations.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

1. **What a deployment should do with a `not_established` action.**
   `AUTHORITY-LIFECYCLE.md` says under L7 that an enforcement point may deny on
   indeterminate and that the denial should say why. It does not say whether the
   same applies to an action that was never established, or whether such an
   action should queue, expire or be abandoned. No vector here takes a position.
   The verdict names the state and stops.
2. **Whether an unreachability observation is worth recording at all.** The gate
   accepts it and does nothing with it. It appears in `notes` because the
   distinction between "nobody tried" and "three attempts are on record" is
   real, and the proposed text names Coverage and completeness as a concept
   without saying what a coverage record establishes. No vector turns on it.
3. **Whether a confirmer can be delegated.** `LPU-H-012-h` rejects a
   confirmation from a party the terms do not name, even one the registry places
   in a plausible role. Whether a principal can authorize somebody else to
   complete a procedure on its behalf is a question the proposed text does not
   reach, and this fixture answers it only for the terms as written.
4. **How long a completed confirmation lasts.** `LPU-H-012-e` shows a
   confirmation covering a later action under the same order. The proposed text
   says nothing about whether a confirmation for one order can be reused, or
   when it goes stale. The fixture binds it to one order and one procedure and
   leaves staleness untested.
5. **What "unreachable" means.** The record here carries an attempt count and a
   window. Nothing establishes how many attempts over what interval make a
   principal unreachable, and nothing in the proposed text does either.
6. **Where the gap between this and activation actually is.** This family and
   the wave 2 `activation-not-established` family both return a not-established
   state from a missing record, at two different layers. Whether the model wants
   one concept or two is not stated. The README sections above say which layer
   each one gates, and that is a description and not a resolution.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that two
independently written gate implementations agree, on all 12 vectors and all 5
defective configurations, that:

- an action whose class the procedure covers is exercisable once a confirmation
  from the named confirmer, bound to this procedure and this order, reaches the
  action instant
- the same action with repeated unreachability attempts on record and no
  confirmation is `not_established`, with the revocation answer `active` and the
  chain `valid`
- the agreed deadline passing with no answer does not change that
- a confirmation whose own instant is after the action does not reach that
  action, and does reach a later one
- a confirmation naming a different order, a different procedure, or signed by a
  party the terms do not name, establishes nothing
- an action class the procedure does not cover is exercisable under the same
  grant at the same instant while the principal is unreachable
- an unreachability observation from a party without standing changes no verdict
- a revoked or unknown revocation answer is reported at the chain stage, and the
  `not_established` it produces there carries the SDK's own code, which no other
  vector in this family produces

## Does not claim

- anything about either SDK's handling of confirmation procedures. Neither has
  an API for one, which `--sdk-support` records per vector
- that any legal doctrine applies to AI agents. The UCC provision quoted above
  is about a bank and its customer
- that these verdict names, stage names or codes are suite vocabulary
- that a deployment should hold, queue, retry or abandon a `not_established`
  action. The fixture names the state and takes no position on the response
- that the confirmation procedure modelled here is a good design for one. It is
  one design that makes the case checkable
- completeness. `chain.json` is the complete universe of records this family
  defines
- anything about execution-time rechecking. Each vector calls the chain verifier
  once, at one fixed instant
