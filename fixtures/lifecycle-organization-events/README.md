# lifecycle-organization-events

Candidate vectors for seven of the eight cases in the proposed model's
**Organization events** section. Thirty-five vectors at two layers, seven named
policies, four ordered timelines, two reference SDKs.

**Every vector here is `candidate_against_proposed`.** Nothing in this family
is a conformance claim about draft-pidlisnyi-aps-03 or any published
specification. Draft-03 states no rule for principal binding across a corporate
succession, none for an external restriction that narrows scope, none for a
third-party consent gate, and none for an acceptance boundary. Where a
reference SDK decides something anyway, which is every chain verdict below,
this README records that as observed implementation behavior at a pinned
version.

## The proposed text under test

| what | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| commit | `2bf5c7e` |
| earliest commit carrying these concepts | `7796e22` |
| documents | `AUTHORITY-LIFECYCLE.md` 0.1.2-draft, `CASES.md` 0.2-draft, `OPEN-QUESTIONS.md` |

Named text, restated in `vectors.json` under `proposed_text.named_text`: the
`Principal binding`, `Issuer standing`, `Lifecycle standing`, `External
restriction`, `In-flight state` and `Evidence` concepts, invariants L1, L3, L4,
L6 and L8, the operational case "an action already in flight when authority
changes", and the `Work in flight` open question.

## The cases

| case id | question | vectors |
|---|---|---|
| `LC-B-004` | Is a successor's fresh grant bounded by the successor's own ceiling rather than the predecessor's? | `LC-B-004-a` to `LC-B-004-e` |
| `LC-B-012` | What does a verifier return when corporate authority has moved and the delegation layer has not? | `LC-B-012-a` to `LC-B-012-c` |
| `LC-B-013` | Does automatic corporate-law vesting reach the delegation layer? | `LC-B-013-a`, `LC-B-013-b` |
| `LC-B-016` | Can an external record narrow what an otherwise valid authority covers, without revoking it? | `LC-B-016-a` to `LC-B-016-d` |
| `LC-B-028` | Is the recheck window for a stop bounded by an event rather than by a duration? | `LC-B-028-a` to `LC-B-028-h` |
| `LC-B-029` | What does a mid-flight revocation do on each side of that same event? | `LC-B-029-a` to `LC-B-029-i` |
| `LC-B-030` | Can a party outside the principal-agent-successor structure impose its own gate? | `LC-B-030-a` to `LC-B-030-d` |

### LC-B-002 is not built here

Two live, reachable status sources disagreeing about the same delegation is
already tested by the `conflicting-status-sources` family, vectors
`CSS-04-fresh-conflict-denies-with-conflict-reason`,
`CSS-05-stale-revoked-against-fresh-active-denies` and
`CSS-08-no-usable-answer-not-established`. That family covers the conflict, the
stale-against-fresh trap and the coverage question, which is the whole of what
`LC-B-002` asks. Re-testing it here would add a second answer to one question
rather than a first answer to another. Recorded in `vectors.json` under
`not_built_here`.

## Verdict vocabulary

Recorded results use `valid`, `invalid`, `not established`, `not yet
effective`, `suspended`, `restricted`. Three of them do real work here, and
which one appears is the substance of several vectors:

- **`invalid`** is a chain that failed verification. `LC-B-004-c` is invalid.
- **`not established`** is a chain that verified and a question the records do
  not answer. `LC-B-012-b` is not established, not invalid: the chain is fine
  and what has not been shown is the binding to the required principal. Same at
  `LC-B-030-b`, where the gate is held by someone outside the chain.
- **`restricted`** is authority that continues while what it covers has
  narrowed. `LC-B-016-b` is restricted and not revoked. `LC-B-016-c` is
  admitted and still recorded as restricted, because an admitted action does
  not erase the narrowing.

Every `not_after` in `chains.json` is `2026-09-30T00:00:00.000Z`, past every
instant in the family, so no vector here reaches its verdict through expiry.

## Files

| file | what it is |
|---|---|
| `mint.py` | Regenerates `chains.json` byte for byte from published seed labels. No secret material. |
| `chains.json` | Eight pinned chains, the issuance refusal the SDK raised, which principal each root was issued for, which attestors the trust policy accepts, and six external records. |
| `generate_vectors.py` | Regenerates `vectors.json`. Computes no expected outcome: every expectation is written out and the runners check it. |
| `vectors.json` | Thirty-five vectors, the declared fail sets, the record divergences and the four timelines. |
| `harness.ts` | `AuthorityBoundary` (four declared axes) and `InFlightBoundary` (one ordered timeline per order). |
| `verify.ts` | npm runner. |
| `verify.py` | PyPI runner. Both models are implemented again rather than ported. |
| `sdk-probe.mjs`, `sdk_probe.py` | Which of this family's claims each SDK exposes an API for. |
| `CHECKSUMS.sha256` | Pins `vectors.json` and `chains.json`. |

Regenerate and run:

    python3 fixtures/lifecycle-organization-events/mint.py             # git diff should be empty
    python3 fixtures/lifecycle-organization-events/generate_vectors.py # git diff should be empty
    npm run verify:lifecycle-organization-events
    python3 fixtures/lifecycle-organization-events/verify.py

## Determinism and timeline order

Keys are SHA-256 over published labels of the form
`aps-conformance-suite:oev:<label>`, listed in `mint.py`. Nonces are supplied,
not generated. External records are signed over their own RFC 8785 canonical
bytes, so both runners rebuild the identical material. No network access, no
wall-clock read, no random source.

The boundary vectors are order independent: each is one evaluation against a
fresh instance. The in-flight vectors are not. Each of the four timelines is
replayed in file order against one `InFlightBoundary` instance, and the pairs
are constructed so that the only difference between `TL_STOP_BEFORE` and
`TL_STOP_AFTER`, and between `TL_REVOKE_BEFORE` and `TL_REVOKE_AFTER`, is which
side of the acceptance event one instruction fell on. Same chain, same order
shape, same authority.

## The seven policies

Each defective policy differs from its reference along exactly one declared
axis, so a divergence is attributable to that axis and to nothing else. The
boundary axes are declared as booleans in `POLICY_PROFILES` in `harness.ts`.

**Boundary**

| policy | the one axis |
|---|---|
| `reference` | all four set the strict way |
| `successor-exists-in-role` | does not compare a presented child against the parent it names |
| `corporate-record-as-delegation-event` | treats an authentic corporate succession record from a party with standing as establishing principal binding |
| `restriction-blind` | ignores external restriction records |
| `internal-chain-only` | ignores third-party consent gates |

**In flight**

| policy | the one axis |
|---|---|
| `reference` | the model in `harness.ts` |
| `approval-time-check-only` | checks for a stop only when the order was authorized, so a later stop is never effective |
| `revocation-halts-everything` | treats any recorded revocation as halting every submitted order, accepted or not |

## Two kinds of divergence, checked apart

`declared_fail_sets` names the vectors where a defective policy reaches a
different **outcome**. `record_divergence` names the vectors where it reaches
the **same outcome** and records something different about it.

- `LC-B-016-c`: both boundaries admit settling an existing obligation. The
  reference records `restricted`, the restriction-blind boundary records plain
  `valid`. Same admission, different lifecycle state.
- `LC-B-028-g`: both report the late stop as ineffective. The reference says it
  arrived after acceptance. The defective boundary says authorization was
  settled at submission, which is the same answer reached from a rule that also
  produces the wrong answer at `LC-B-028-b`.

Both kinds are checked by both runners, so neither can drift, and a same-outcome
record difference never reads as a wrong decision.

## The case that is easy to get backwards

`LC-B-029` has two halves that are both true at the same instant, and a family
that recorded only one of them would misread the case in one direction or the
other:

- `LC-B-029-h`: the already-accepted order settles, despite the revocation.
- `LC-B-029-i`: a new order on the same chain, twenty minutes later, is not
  admitted.

`revocation-halts-everything` gets the first wrong. A policy that concluded
from the first that revocation never matters for in-flight work would get the
second wrong. Both vectors are in the same timeline for that reason.

## Sources

Every claim about an external document below was fetched in the session that
built this family and is quoted verbatim at forty words or fewer. The
translation into agent terms is ours. None of these sources says anything about
AI agents, and nothing here claims any of them applies to them.

**Delaware General Corporation Law § 259**, *Status, rights, liabilities, of
constituent and surviving or resulting corporations following merger or
consolidation*. Fetched from
`https://delcode.delaware.gov/title8/c001/sc09/index.html`. On what a merger
moves: rights, powers and property of each constituent "shall be vested in the
corporation surviving or resulting from such merger or consolidation." The
statute performs that vesting with no issuance event, which is the contrast
`LC-B-012` and `LC-B-013` are built on. It says nothing about keys, service
accounts or delegation records.

**Delaware General Corporation Law § 278**, *Continuation of corporation after
dissolution for purposes of suit and winding up affairs*. Fetched from
`https://delcode.delaware.gov/title8/c001/sc10/index.html`. On what a dissolved
corporation continues for: "of enabling them gradually to settle and close
their business", and expressly "but not for the purpose of continuing the
business for which the corporation was organized." Authority that continues
while what it covers narrows, with no revocation and no new grant, is the shape
`LC-B-016` models as `restricted`.

**UCC § 4-403(a)**, *Customer's right to stop payment*. Fetched from
`https://www.law.cornell.edu/ucc/4/4-403`. On the boundary a stop order has to
beat: an order "received at a time and in a manner that affords the bank a
reasonable opportunity to act on it before any action by the bank with respect
to the item described in Section 4-303." The boundary is the bank's own action,
an event, not a fixed window. That is what `LC-B-028-b` and `LC-B-028-g` place
on either side of.

**UCC § 4A-211(c)**, *Cancellation and amendment of payment order*. Fetched
from `https://www.law.cornell.edu/ucc/4A/4A-211`. On what acceptance does:
"After a payment order has been accepted, cancellation or amendment of the
order is not effective unless the receiving bank agrees or a funds-transfer
system rule allows cancellation or amendment without agreement of the bank."
That is the boundary `LC-B-029-c` and `LC-B-029-h` sit on either side of.

No source is cited for `LC-B-004` or `LC-B-030`. `CASES.md` records both as
hypothetical scenarios with no legal claim attached, and they stay that way
here.

This family cites no fixture, repository or open question of this project's own
as an external source. `CASES.md`, `AUTHORITY-LIFECYCLE.md` and
`OPEN-QUESTIONS.md` are named as the proposed text under test, which is what
`candidate_against_proposed` means.

## What the SDKs decide, and what they do not

Both reference SDKs decide every chain verdict in this family and refuse the
over-broad successor grant at issuance with `SCOPE_WIDENING`. Neither exposes
an API for principal binding, attestor standing, an external restriction, a
consent gate or an acceptance boundary. `sdk-probe.mjs` and `sdk_probe.py`
print the list, and every `not_supported` line names the missing API rather
than being filled in by the harness.

## Verification split

One entry per distinct verification claim.
Format: `layer / claim; runner; Mode A | Mode B; author-produced | independent; implementation`.

- chain verdicts, thirty-four vectors / the chain verdict, failure code and
  index each presented chain receives at each vector's instant;
  `fixtures/lifecycle-organization-events/verify.ts`; Mode A; author-produced;
  npm `agent-passport-system` 7.1.0. Author-produced because the vectors, both
  harness models and this runner were written in the same lab and reviewed by
  nobody outside it.
- chain verdicts, thirty-four vectors / the same claim recomputed against a
  second implementation; `fixtures/lifecycle-organization-events/verify.py`;
  Mode B; author-produced; PyPI `agent-passport-system` 4.1.0. Author-produced
  for the same reason, and the two SDKs share an author.
- issuance refusal, one vector / the code the SDK's child issuer raised when
  asked to mint the over-broad successor grant;
  `fixtures/lifecycle-organization-events/mint.py`; Mode A; author-produced;
  PyPI `agent-passport-system` 4.1.0. Pinned in `chains.json` and read back by
  both runners.
- external record authenticity, six records / that each external record's
  detached signature verifies over its own RFC 8785 canonical bytes; both
  runners; Mode B; author-produced; the Ed25519 `sign` and `verify` primitives
  in npm `agent-passport-system` 7.1.0 and PyPI `agent-passport-system` 4.1.0,
  with the canonicalizer vendored at `runners/ts/canonicalize.ts` and its
  Python mirror in `verify.py`. Author-produced because this lab wrote the
  records, the canonicalizers and both runners.
- boundary decisions, eighteen vectors / outcome, authority verdict, reason,
  failure code, failure index and established principal for each boundary
  vector under each of five policies; both runners; Mode A; author-produced;
  `AuthorityBoundary` in `harness.ts` and its mirror in `verify.py`, which this
  lab wrote. Neither SDK exposes an API that decides any of it, so this layer
  asserts nothing about either SDK.
- in-flight timelines, seventeen vectors / outcome, order state and reason for
  each event in each of four ordered timelines under each of three policies;
  both runners; Mode A; author-produced; `InFlightBoundary` in `harness.ts` and
  its mirror in `verify.py`. Same reasoning.
- defective-policy behavior, all vectors / that every declared fail set and
  every declared record divergence is one a defective policy actually produces,
  and that no undeclared divergence exists; both runners; Mode A;
  author-produced; the policies in `harness.ts` and `verify.py`. A property of
  the fixture, not of either SDK.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

Six things the model names that this family could not turn into a vector, with
what would have to be settled first.

1. **What a principal binding record looks like.** `LC-B-012-b` is `not
   established` and `LC-B-012-c` is `valid`, and the difference between them is
   that the second is a delegation issued by an officer of the surviving
   company. That is this family's stipulation. The model's `Principal binding`
   concept says it "says which principal an agent acts for" and that it can
   exist before any grant and outlive one, which means it is not the same
   object as a delegation. What record carries it, and what a verifier reads to
   establish it, is unstated. `chains.json` supplies it as a
   `principal_of_root` map, which is a fixture convenience, not a proposal.

2. **Whether a corporate succession record should have any delegation-layer
   effect at all.** `LC-B-013-a` records that treating it as an issuance is
   wrong. Whether it should instead trigger a review, suspend the constituent
   company's grants, or do nothing until someone acts is not stated. The three
   answers are operationally very different and the text supports none of them
   over the others.

3. **Which party holds standing for an external restriction.** `chains.json`
   declares a registry office and the boundary checks against that list. The
   model's `Lifecycle standing` concept says standing "is not always the
   issuer" and names an organization, a quorum, a successor, a court or a
   security function as possibilities. It gives no way for a verifier to
   establish which of those applies to a particular restriction, so
   `attestor_standing` in this fixture is a stipulation and `LC-B-013-b` tests
   the fixture's own trust policy rather than a rule.

4. **Whether `restricted` composes.** `LC-B-016-c` is admitted and recorded as
   `restricted`. Two restrictions from two authorities, partially overlapping,
   would need a composition rule, and the `Release from suspension` open
   question says multiple suspension causes "probably need to compose, with
   each one released separately. Not yet specified." Restriction is not
   suspension and the text does not say whether the same reasoning carries
   over. No vector here presents two restrictions.

5. **What the acceptance boundary is for anything other than a payment order.**
   `LC-B-028` and `LC-B-029` get a concrete boundary event from the two UCC
   sections, for one instrument type. The model's operational case names "an
   action already in flight when authority changes" generally, and
   `OPEN-QUESTIONS.md` says "We do not yet have a general model for it." This
   family supplies a resolution for payment orders and nothing beyond them.
   Whether a tool call, a long-running job or a multi-step workflow has an
   analogous boundary, and what names it, is open.

6. **What happens to the work itself after an ineffective stop or a mid-flight
   revocation.** `LC-B-029-d` records that an unaccepted order does not settle.
   Whether the workflow around it then resumes under new authority, restarts,
   compensates or stops is the `Work in flight` open question verbatim, and no
   vector here goes near it. `LC-B-029-i` deliberately stops at the next
   authorization boundary, which is the furthest the text supports.
