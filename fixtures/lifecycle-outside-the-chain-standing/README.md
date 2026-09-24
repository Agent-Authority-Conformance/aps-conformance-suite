# `lifecycle-outside-the-chain-standing`

Standing held from **outside** the chain a grant runs through.

Three questions, one per case in the "Outside-the-chain standing" section of
`CASES.md` v0.2 in `aeoess/agent-authority-lifecycle`:

- **LC-H-004.** A collective body's own composition as a precondition for the
  validity of what it issued. Without quorum there is no body action to
  evaluate, which is a different answer from a defective but real action.
- **LC-H-005.** A replacement grant issued by a body outside the original
  principal-agent relationship, with terms that body supplies, rather than a
  revival of the exact terminated grant.
- **LC-H-006.** A disputed root held by a neutral forum, in a state that is
  neither valid nor invalid, with the current holder discharged from picking a
  claimant.

22 vectors. Every one is **`candidate_against_proposed`**. Nothing here tests
draft-pidlisnyi-aps-03 or any other published specification.

## Status

**candidate.** Each vector names the proposed text it exercises and the
`CASES.md` case id it comes from. The proposed text is in
`aeoess/agent-authority-lifecycle` at commit `7796e22` or later. A pass says the
reference boundary in `harness.ts` behaves as the vectors record and that the
SDK layers behave as recorded. It does not say the proposed text is right, and
it is not a conformance result for any implementation.

`CASES.md` marks all three cases **proposed**, and this fixture does not change
that.

## Proposed text under test

Per case, the concept or invariant in `AUTHORITY-LIFECYCLE.md`:

| Case | Proposed text |
|---|---|
| LC-H-004 | **Issuer standing** ("A valid signature establishes who signed. It does not by itself establish standing."), **Lifecycle standing** ("Who may suspend, revoke, replace or reaffirm an authority artifact."), and **L8** (suspension is not revocation) |
| LC-H-005 | **L3** ("Continuity after revocation means a new grant from a principal who currently holds authority. It never means reversing the revocation or re-parenting the old chain.") and **L4** |
| LC-H-006 | **L7** ("A revocation answer that is unavailable or stale is indeterminate. It does not become active") and the **Status observation** concept, plus `OPEN-QUESTIONS.md` "Notice and relying parties" |

None of L1 to L12 addresses a collective body's own internal standing
requirement, a grant issued by a body entirely outside the chain, or a root
parked with a neutral forum. Those are the extensions the three cases make and
what these vectors exercise.

## Case sources

Each case in `CASES.md` rests on a human or institutional precedent. Every
source quoted below was fetched while this fixture was built. **None of them
says anything about AI agents.** The translation into agent terms belongs to
`CASES.md`, and a precedent is a source of cases rather than a claim that a
legal doctrine applies to AI agents.

- **LC-H-004.** Delaware General Corporation Law §141(b),
  [delcode.delaware.gov](https://delcode.delaware.gov/title8/c001/sc04/index.html):
  "A majority of the total number of directors shall constitute a quorum for the
  transaction of business unless the certificate of incorporation or the bylaws
  require a greater number."
- **LC-H-005.** 29 U.S.C. §160(c),
  [Cornell LII](https://www.law.cornell.edu/uscode/text/29/160): "order
  requiring such person to cease and desist from such unfair labor practice, and
  to take such affirmative action including reinstatement of employees with or
  without back pay, as will effectuate the policies of this subchapter". The same
  subsection: "No order of the Board shall require the reinstatement of any
  individual as an employee who has been suspended or discharged, or the payment
  to him of any back pay, if such individual was suspended or discharged for
  cause."
- **LC-H-006.** 28 U.S.C. §1335(a)(2),
  [Cornell LII](https://www.law.cornell.edu/uscode/text/28/1335): "into the
  registry of the court, there to abide the judgment of the court, or has given
  bond payable to the clerk of the court in such amount and with such surety as
  the court or judge may deem proper".

The Delaware quote is why the reference boundary treats a bylaw number as a
floor that can only rise. The §160(c) exception is why the order in LC-H-005 is
conditional on a fact its own record carries. The §1335 disjunction is why a
bond and a deposit are equally effective in LC-H-006-g.

## Setup

```
npm ci --include=dev
python3 -m venv /tmp/g2-venv
/tmp/g2-venv/bin/pip install 'agent-passport-system>=4.1,<5'
```

Five two-hop `AuthorityDelegationV1` chains, minted by `mint.py`:

| Chain | Shape | Used by |
|---|---|---|
| `OFFICER` | `body -> officer -> agent_o` | LC-H-004, the chain a board suspension targets |
| `TERMINATED` | `employer -> employer_hr -> agent_r` | LC-H-005, the chain the termination ends |
| `REINSTATED` | `order_root -> designee -> agent_r` | LC-H-005, the chain the external order creates |
| `CLAIM_P` | `claimant_p -> p_ops -> agent_d` | LC-H-006, one claimed root |
| `CLAIM_Q` | `claimant_q -> q_ops -> agent_d` | LC-H-006, the rival claimed root |

Three facts are readable off the bytes rather than asserted in prose.
`agent_r` is the same subject DID with the same generated key in `TERMINATED`
and `REINSTATED`, so the reinstated chain is a new grant to the same identity
rather than a revival of the old one. `agent_d` is likewise one identity under
both claimed roots. `REINSTATED`'s root carries `backpay:read`, which no record
of `TERMINATED` carries, so "the terms come from the reinstating body" is
checkable rather than stated.

## Decision boundaries

`harness.ts` holds one reference boundary and four defective ones. Each
defective boundary drops exactly one part of the proposed text, so a divergence
is attributable to the part it dropped rather than to a blend of defects. Each
runs against **every** vector for the concepts it covers, not only the ones
predicted to diverge, so an undeclared divergence and a declared divergence that
stops happening are both loud.

| Boundary | What it drops | Diverges on |
|---|---|---|
| `reference` | nothing | none, it must match all 22 |
| `well-formed-record-suffices` | the issuing body's quorum check. Verifies the suspension record is well formed and signed by somebody the roster lists, and never asks whether the body had quorum to transact business. | `LC-H-004-b`, `-c`, `-e`, `-g`, `-h` |
| `bylaw-number-wins` | the majority floor. Takes the declared bylaw number in either direction, so a declared number below the default silently lowers it. | `LC-H-004-g` |
| `revival-restores` | the new-grant reading of an external order. Flips the terminated chain back to valid instead. | `LC-H-005-a` |
| `forced-binary` | the held-pending-forum state. Forces an answer by honouring whichever claimed root was issued first. | `LC-H-006-a`, `-c`, `-d`, `-e`, `-f`, `-h` |

No control diverges on `LC-H-004-f`. Both quorum controls keep the
signature-and-roster check, which is the check that vector defeats, so a naive
boundary gets it right for the wrong reason. The fixture says so rather than
claiming a divergence it does not observe.

## Vectors

Verdicts come from the settled vocabulary only: `valid`, `invalid`,
`not_established`, `not_yet_effective`, `suspended`, `restricted`. The runners
fail the run if an expected verdict falls outside it. Codes are fixture-local
detail and are not proposed conformance vocabulary.

### LC-H-004, an issuing body's own quorum

Seven seats throughout. The effective quorum is the larger of the majority
default (four) and any number the bylaws declare.

| Vector | Records | Verdict | Code |
|---|---|---|---|
| `LC-H-004-a` | 4 seated participants, no bylaw number, all 4 sign | `suspended` | `SUSPENDED_BY_BODY` |
| `LC-H-004-b` | 3 seated participants, no bylaw number | `not_established` | `ISSUING_BODY_QUORUM_NOT_ESTABLISHED` |
| `LC-H-004-c` | bylaws require 5, 4 participate | `not_established` | `ISSUING_BODY_QUORUM_NOT_ESTABLISHED` |
| `LC-H-004-d` | bylaws require 5, 5 participate | `suspended` | `SUSPENDED_BY_BODY` |
| `LC-H-004-e` | 4 participants, one not a seated director | `not_established` | `ISSUING_BODY_QUORUM_NOT_ESTABLISHED` |
| `LC-H-004-f` | quorum met, record signed only by a non-participant | `not_established` | `BODY_ACTION_NOT_SIGNED_BY_PARTICIPANT` |
| `LC-H-004-g` | bylaws name 3, 3 participate | `not_established` | `ISSUING_BODY_QUORUM_NOT_ESTABLISHED` |
| `LC-H-004-h` | one director, properly signed | `not_established` | `ISSUING_BODY_QUORUM_NOT_ESTABLISHED` |

In every negative the targeted delegation's own verdict stays `valid`. The
absence of a body action does not make the target invalid, and the fixture
asserts `body_action_exists: false` separately from the verdict.

### LC-H-005, a grant from an issuer outside the relationship

`TERMINATED`'s root is revoked in every vector, so the old chain is
`invalid`/`REVOKED@0` throughout and the fixture asserts
`old_chain_verdict_unchanged_by_order: true` in all six.

| Vector | Records | Verdict | Code |
|---|---|---|---|
| `LC-H-005-a` | order with standing, predicate not met for the exception, replacement chain issued | `valid` | `NEW_GRANT_FROM_EXTERNAL_ISSUER` |
| `LC-H-005-b` | order records the discharge was for cause | `not_established` | `ORDER_PREDICATE_NOT_MET` |
| `LC-H-005-c` | order from a body the registry does not place standing with | `not_established` | `ORDER_STANDING_NOT_ESTABLISHED` |
| `LC-H-005-d` | order with standing, no replacement chain issued yet | `not_established` | `NO_REPLACEMENT_GRANT` |
| `LC-H-005-e` | order with no `standing_ref` a verifier could follow | `not_established` | `ORDER_STANDING_NOT_ESTABLISHED` |
| `LC-H-005-f` | no order at all | `not_established` | `NO_REPLACEMENT_GRANT` |

`LC-H-005-a` additionally asserts `new_chain_root_issuer_differs: true` and
`new_chain_carries_grant_absent_from_old: ["backpay:read"]`, both read off the
minted bytes.

### LC-H-006, a disputed root held by a forum

| Vector | Records | Verdict | Code | Holder must choose |
|---|---|---|---|---|
| `LC-H-006-a` | secured deposit, no determination | `not_established` | `HELD_PENDING_FORUM` | no |
| `LC-H-006-b` | determination from the named forum choosing the first claimant | `valid` | `FORUM_DETERMINED` | no |
| `LC-H-006-c` | determination from a different forum | `not_established` | `DETERMINATION_FORUM_MISMATCH` | no |
| `LC-H-006-d` | deposit record secured by neither a deposit nor a bond | `not_established` | `HOLD_NOT_SECURED` | **yes** |
| `LC-H-006-e` | no deposit record at all | `not_established` | `DISPUTE_UNRESOLVED_NO_FORUM` | **yes** |
| `LC-H-006-f` | determination names a claimant the deposit does not list | `not_established` | `DETERMINATION_CLAIMANT_NOT_A_PARTY` | no |
| `LC-H-006-g` | bond rather than deposit, determination choosing the second claimant | `valid` | `FORUM_DETERMINED` | no |
| `LC-H-006-h` | determination dated before the deposit was made | `not_established` | `DETERMINATION_PRECEDES_DEPOSIT` | no |

In every `not_established` vector both claimed chains read `not_established`,
neither `valid` nor `invalid`. That per-chain assertion is the point of the
case, and it is what `forced-binary` gets wrong.

## Determinism

- **Seed.** One published prefix,
  `aps-conformance-suite:lifecycle-outside-the-chain-standing:`, recorded in
  `chain.json` as `seed_prefix`. Every Ed25519 private key is
  `sha256(prefix + label)` for a label published in `mint.py`, so the file
  carries no secret material and anyone can regenerate it.
- **Nonces** are supplied, not generated, which the Python SDK documents as the
  path that keeps issuance deterministic.
- **`now`** is the fixed string `2026-09-20T12:00:00.000Z`. No runner reads the
  clock, the network or any file outside its own directory.
- **Regeneration.** `python3 mint.py` rewrites `chain.json` and
  `python3 generate.py` rewrites `vectors.json`. Both leave `git diff` empty.
  Verified in this session by running each twice and diffing.
- **Canonical bytes.** Both runners recompute the RFC 8785 JCS canonical form
  of all 10 signed records with the SDK's own canonicalizer and print the
  SHA-256 of each. The 10 digests are byte-identical between npm
  `canonicalizeJCS` at 7.1.0 and PyPI `canonicalize_jcs` at 4.1.0.
- **Checksums.** `CHECKSUMS.sha256` pins `chain.json` and `vectors.json`. The
  suite's `npm run test:digest-integrity` gate recomputes them.

RFC 8785 is the [JSON Canonicalization Scheme
(JCS)](https://www.rfc-editor.org/rfc/rfc8785.html), whose abstract states:
"This specification defines how to create a canonical representation of JSON
data by building on the strict serialization methods for JSON primitives defined
by ECMAScript, constraining JSON data to the Internet JSON (I-JSON) subset, and
by using deterministic property sorting."

## TypeScript

```
npx tsx fixtures/lifecycle-outside-the-chain-standing/verify.ts
```

Wired into `npm test` as `verify:lifecycle-outside-the-chain-standing`.
Exit 0 when the reference matches all 22 vectors, every control diverges on
exactly its declared set, and every supported npm probe matches. Exit 1 on any
mismatch, 2 on a malformed fixture.

Observed in this session: reference 22/22, four controls each on their declared
set, 41/41 npm probes.

## Python

```
/tmp/g2-venv/bin/python fixtures/lifecycle-outside-the-chain-standing/verify_python_sdk.py
```

Not in `npm test`, the same convention
`fixtures/ancestor-revocation-chain/validate.py` and
`fixtures/runtime-authority-denial-continuity/verify.py` already follow for a
Python side kept out of the Node-only CI gate.

This runner does not reimplement the deciders. It reads the same two files and
calls the PyPI SDK for every layer that SDK exposes, printing `not_supported`
with a reason for every layer it does not. Observed in this session: 33/33
supported PyPI probes.

## What the SDKs do not support

Enumerated by the runs, not written by hand, so these lines cannot go stale.

| Layer | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|
| chain state | `verifyAuthorityDelegationChain` | `verify_authority_delegation_chain` |
| RFC 8785 canonical bytes | `canonicalizeJCS` | `canonicalize_jcs` |
| office holder count | `checkQuorum` | **absent.** `dir(agent_passport)` matches nothing on quorum, charter or office. The only match on `threshold` is the unrelated `ThresholdDispute` type, asserted by the run. |
| issuing body quorum as a precondition for a suspension record | **absent** | **absent** |
| a grant issued by an external body under a conditional order | **absent** | **absent** |
| a root held pending a neutral forum | **absent** | **absent** |

Three notes on `checkQuorum`, all observed in this session:

1. Called with no `QuorumFailurePolicy` at all, it answers
   `{"hasQuorum":true,"holders":2,"required":1}` for a two-holder office. Its
   default floor is one holder, not a majority of total seats. The
   majority-of-total-seats default that LC-H-004 turns on is supplied by this
   fixture.
2. It counts an `Office`'s `holderSet`. It has no notion of a participant who is
   not a holder, so the filter of participants against seated directors in
   `LC-H-004-e` is this fixture's.
3. It takes no suspension record. In `LC-H-004-f` it answers `hasQuorum: true`
   while the reference boundary answers `not_established`, because holder count
   alone does not establish that the record in hand is that body's action.

## Verification split

One entry per verification claim, in the form
`layer / claim; runner; Mode; authorship; implementation`, per `CONTRIBUTING.md`.

- **Chain state / claim: `OFFICER`, `REINSTATED`, `CLAIM_P` and `CLAIM_Q` verify
  `valid` on their own records, and `TERMINATED` verifies `invalid` with
  `REVOKED` at index 0 under its declared revoked role**; runner: the lab, via
  `fixtures/lifecycle-outside-the-chain-standing/verify.ts`; Mode A;
  author-produced; implementation: `agent-passport-system` 7.1.0 (npm), 33/33
  chain probes. Authorship relationship preventing an independent label: the lab
  authored the vectors and the claim inputs, and the implementation is a
  reference SDK from the same project.
- **Chain state / same claim, recomputed by the Python reference SDK**; runner:
  the lab, via `verify_python_sdk.py`; Mode B; author-produced; implementation:
  `agent-passport-system` 4.1.0 (PyPI), 33/33 probes. Authorship relationship:
  as above. The two SDKs are separate implementations and the Python run
  supplies the substantive recomputation, but both are reference SDKs of the
  same project and the lab authored the vectors, so the record is not
  independent.
- **Office holder count / claim: `checkQuorum` answers `hasQuorum`, `holders`
  and `required` as each LC-H-004 vector records, for an `Office` built from the
  vector's seated participants and a `minimumHolders` this fixture computed**;
  runner: the lab, via `verify.ts`; Mode A; author-produced; implementation:
  `agent-passport-system` 7.1.0 (npm), 8/8 probes. Authorship relationship: as
  above, and the `minimumHolders` input is the fixture's rather than the SDK's.
- **RFC 8785 JCS canonical digest of the 10 signed records / claim: the 10
  SHA-256 digests are identical across both canonicalizers**; runner: the lab;
  Mode B; author-produced; implementation: `canonicalizeJCS` (npm 7.1.0) and
  `canonicalize_jcs` (PyPI 4.1.0), recomputed independently in each runner,
  10/10 identical.
- **Reference boundary verdicts, 22 vectors / claim: the verdict, code and
  per-case assertions each vector records**; runner: the lab, via `verify.ts`;
  Mode A; author-produced; implementation: `harness.ts`, which is this fixture
  rather than any implementation under test, so no independent classification is
  possible for this layer, 22/22.
- **Negative control divergence sets, 4 controls / claim: each control diverges
  on exactly the vectors it declares and on no others**; runner: the lab, via
  `verify.ts`; Mode A; author-produced; implementation: `harness.ts`, as above,
  4/4 controls over 30 control runs.
- **Absence of a PyPI quorum, charter or office API / claim: no such name
  exists at 4.1.0**; runner: the lab, via `verify_python_sdk.py`; Mode A;
  author-produced (author of the survey); implementation: `dir(agent_passport)`
  enumerated in the run and compared against the fixture's expected-absent list,
  so a later release that adds one fails the run.
- **Chain minting determinism / claim: `mint.py` re-run reproduces
  `chain.json` byte for byte**; runner: the lab; Mode A; author-produced (author
  of the generator); implementation: `mint.py` against the committed
  `chain.json`, empty diff.
- **Vector generation determinism / claim: `generate.py` re-run reproduces
  `vectors.json` byte for byte**; runner: the lab; Mode A; author-produced;
  implementation: `generate.py` against the committed `vectors.json`, empty
  diff.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that:

- a suspension record from a body below its effective quorum leaves the targeted
  delegation `valid` and the suspension `not_established`, under five separate
  ways of falling below it (bare count, a higher bylaw number, a participant who
  is not seated, a declared lesser number, and a single director)
- a bylaw number above the majority default raises the bar and one below it does
  not lower it
- quorum alone does not establish a body action: a record signed only by a
  non-participant is `not_established` even when quorum was met
- an order from a body with recorded standing produces a `valid` replacement
  chain rooted in a different issuer and carrying a grant the terminated chain
  never carried, while the terminated chain stays `invalid`/`REVOKED`
- an order does not issue where its own record states the exception, and an
  order without a followable standing reference does not establish standing
- an order alone is not a grant: with no replacement chain, replacement
  authority is `not_established`
- a secured deposit with no determination leaves both claimed chains
  `not_established` and discharges the holder from choosing
- a determination resolves the hold only when it comes from the named forum,
  names a listed party, and postdates the deposit
- a bond and a deposit are equally effective as a secured hold
- an unsecured hold record and no hold record at all both leave the holder
  facing the choice
- all 10 signed records canonicalize identically under both SDKs' RFC 8785
  implementations
- the four declared defective boundaries diverge on exactly the vectors the
  fixture predicts

## Does not claim

- That draft-pidlisnyi-aps-03 requires any of this. It does not. Every vector is
  `candidate_against_proposed`.
- That a legal doctrine applies to AI agents. The quoted sources are sources of
  cases. None of them mentions AI agents.
- That the reference boundary is the right design. It is one reading of the
  proposed text, and where the text is silent the reading is recorded below
  rather than presented as settled.
- That `checkQuorum` is defective. It counts holders against a supplied minimum
  and does that correctly. The gap is that nothing in either SDK takes an
  issuing body's composition as an input to the validity of what it issued.
- That any run here is independent. Every record above is `author-produced` and
  says why.
- That the divergence sets are exhaustive descriptions of how a real
  implementation fails. They are four deliberately narrow defects.

## Where the proposed text was too vague to test

Recorded rather than resolved.

1. **`checkQuorum` has no majority default, and the proposed text names none
   either.** `AUTHORITY-LIFECYCLE.md` names **Lifecycle standing** without
   saying what quorum is or who declares it. `CASES.md` LC-H-004 takes the
   number from the bylaws. The majority-of-total-seats floor in this fixture
   comes from the Delaware quote above and is a fixture parameter rather than
   proposed text. A body whose governing instrument names no number is not
   tested.
2. **Holders against participants.** LC-H-004 turns on how many directors were
   "present or participating". The proposed text distinguishes neither, and
   `checkQuorum` counts holders. This fixture carries both `seated_directors`
   and `participants` and intersects them. Whether a protocol should model
   attendance at all is open.
3. **"No valid board action at all" has no verdict name in the model.** LC-H-004
   says the answer is not established rather than invalid, and the **Issuer
   standing** concept names no verdict. This fixture returns `not_established`
   with `body_action_exists: false` and leaves the target `valid`. Whether the
   target should instead be `suspended` pending resolution is not decided
   anywhere.
4. **What record establishes an external body's standing.** LC-H-005 says the
   body has "standing from outside the original principal-agent relationship"
   without saying what a verifier checks. This fixture requires a registry entry
   plus a followable `standing_ref` and returns `not_established` without both.
   Both are fixture inventions.
5. **"Held pending resolution" is not in the settled vocabulary.** LC-H-006 asks
   for "a state distinct from valid, revoked, or suspended". The six settled
   verdicts have no such state, so this fixture maps it onto `not_established`
   with a `HELD_PENDING_FORUM` code, following the case's own closing sentence
   that "it is not established which claimant's authority, if any, currently
   governs". Whether the model should mint a seventh verdict is a vocabulary
   decision and not a fixture's to make.
6. **How a hold ends other than by determination.** LC-H-006 names deposit with
   a forum and a determination. It says nothing about a forum that never
   determines, a maximum duration for the hold, who may withdraw a deposit, or
   what a relying party who acted during the hold is entitled to. None of that
   is tested here, and `OPEN-QUESTIONS.md` "Notice and relying parties" is the
   nearest the model comes to it.
7. **Four of the six settled verdicts have no SDK state.** The chain verifier's
   `resolveRevocation` answers `active`, `revoked` or an unrecognized value, and
   its state vocabulary is `valid`, `invalid` and `indeterminate`. `verify.ts`
   runs the assertion rather than stating it: a resolver answering `"suspended"`
   for a chain member yields `indeterminate` under `REVOCATION_UNKNOWN`, not a
   suspended state, so LC-H-004's `suspended` verdict and LC-H-006's
   `not_established` live only in this fixture's boundary. A later SDK release
   that adds such a state fails the run rather than leaving this line stale. The
   forward-compatibility half of that behaviour is already tested by
   `fixtures/revocation-resolution-forward-compat` on `main`, and this family
   does not duplicate it.

## Provenance

Built by the lab in one session against `CASES.md` v0.2 at commit `2bf5c7e`
and `AUTHORITY-LIFECYCLE.md` at `7796e22` or later. Both commits are reachable
from the public default branch of that repository. `chain.json` minted with PyPI `agent-passport-system` 4.1.0.
`vectors.json` generated by `generate.py`. Verified with npm
`agent-passport-system` 7.1.0 and PyPI 4.1.0. No network access in any runner.

Related fixtures on `main`, not duplicated here: `ancestor-revocation-chain`
(L1), `sponsor-handover` (L2 and L4), `single-chain-selection` and
`chain-selection-no-union` (L5 and L11), `revocation-resolution-forward-compat`
(L7), `approval-single-use` and `cached-authorization-revocation` (L6).
