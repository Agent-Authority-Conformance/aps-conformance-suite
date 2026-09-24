# lifecycle-purpose-exhaustion: a grant that has done its one job is not thereby revoked

A grant authorizes buying one replacement compressor for chiller CH-3, valid until Friday.
An authenticated completion record says the compressor was installed Tuesday. A second
purchase Wednesday, under the same grant, still inside its time window and still inside
its declared purpose, must not be admitted. The grant is not revoked. It is not expired.
It is exhausted, and nothing in draft-03 chain verification can see that.

A permit authorizes exactly one act, and using it is the same recorded event as spending
it. A second presentation is refused before its stated end date arrives, no later record
makes it usable again, and a detected reuse reaches what was already issued out of it.

Twenty-one ordered events across two record sets. Five named boundary configurations. Two
reference SDKs.

**Every vector in this family is labelled `candidate_against_proposed`.** No vector here
is a draft-pidlisnyi-aps-03 conformance case for purpose exhaustion, use-count exhaustion,
a reuse cascade or the irreversibility of an exhaustion, because draft-03 states no rule
for any of them. Two vectors additionally exercise a rule draft-03 does state, and say so
per vector.

## One family, reconciled from two builds

Two independent builds landed on this directory name with different case sets, different
record shapes and no common ancestor for any shared file. They are now one family. What
the reconciliation did and did not do:

- **Vector ids are unchanged from both builds.** `CASES.md` at the pinned commit already
  names `PXE-01` through `PXE-12` and `LC-I-013-a` through `LC-I-014-e` in its Fixture
  lines, and it already attributes all of them to this one path. Renaming any of them
  would break links the upstream document already carries.
- **No vector was dropped and none was collapsed into another.** The union is 21.
- **Duplicated case attribution was merged rather than duplicated.** A vector that
  `CASES.md` names under more than one case carries every one of those ids in its
  `case_ids` array. `PXE-03` carries three.
- **The one real overlap in substance is now a checked field rather than a README claim.**
  See "The overlap the two builds had", below.
- **Both builds' pins were moved forward to one commit that is public on
  `aeoess/agent-authority-lifecycle` `main`.** One of the two builds had pinned `1642093`,
  which is not reachable from that repository's `main` and therefore cannot be resolved by
  a reader.

## Two tracks in one family

The two tracks share a lifecycle concept and nothing else. Different record sets,
different boundary classes, different state vocabularies. They are never mixed in one run
and each has its own declared defective policies.

| | bounds | single-use |
|---|---|---|
| records | `records-bounds.json` | `records-single-use.json` |
| minted by | `mint-bounds.ts` (npm SDK) | `mint_single_use.py` (PyPI SDK) |
| boundary class | `AuthorityBoundary` in `harness.ts` | `ExhaustionBoundary` in `harness.ts` |
| vectors | 12, `PXE-01` to `PXE-12` | 9, `LC-I-013-a` to `LC-I-014-e` |
| how a bound is reached | an observed fulfillment record, an admission, or the SDK budget ledger | the admission itself, always |
| `bound_state` values | `not_reached`, `exhausted`, `not_established` | `not_reached`, `exhausted`, `invalid` |
| compared fields | `outcome`, `reason`, `bound_state`, `exhaustion_basis`, `chain_state`, `detail` | `outcome`, `reason`, `exhaustion_basis`, `chain_verdict`, `chain_failure_code`, `bound_state`, `records_written` |
| defective policies | `defective-boundary-chain-validity-only`, `defective-boundary-trusts-unauthenticated-completion` | `reuse-rejecting-only`, `validity-window-only` |

The two `bound_state` vocabularies differ on purpose and the difference is unresolved in
the proposed text, not settled here. See item 7 of "Where the proposed text was too vague
to test".

## Case ids

From `CASES.md` at the pinned commit. A vector with no case id was built from an entry in
`AUTHORITY-LIFECYCLE.md` rather than from a case.

| vector | case ids |
|---|---|
| `PXE-01`, `PXE-02` | LC-A-008 |
| `PXE-03` | LC-A-008, LC-D-010, LC-D-034 |
| `PXE-04`, `PXE-05` | LC-I-013 |
| `PXE-06`, `PXE-07` | none, built from the `Expiry or exhaustion` entry |
| `PXE-08` | LC-D-034 |
| `PXE-09`, `PXE-10`, `PXE-11` | none, built from the `Issuer standing` and `Evidence attestor` entries |
| `PXE-12` | LC-D-010 |
| `LC-I-013-a` to `LC-I-013-d` | LC-I-013 |
| `LC-I-014-a` to `LC-I-014-e` | LC-I-014 |

`LC-I-013` is the case both builds reached. `PXE-04` and `PXE-05` cover its plain half, a
one-use bound consumed by admission. `LC-I-013-a` to `LC-I-013-d` cover the half the plain
half does not reach, which is what a second presentation does to artifacts already issued
out of that grant and how far that must not go. Both sets are kept, and the two readings
they encode are named below rather than reconciled.

## The proposed text under test

[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle)
at commit `bbb4709`, which is the head of that repository's `main`.

| document | version in the document |
|---|---|
| `AUTHORITY-LIFECYCLE.md` | 0.2.0-draft |
| `CASES.md` | v0.2 |

Section **"Lifecycle concepts are separate" > "Authority lifecycle state"**, the
load-bearing entry, quoted in full:

    Expiry or exhaustion. Ends authority because a declared time, use count, budget,
    purpose or other bound has been reached. Expiry is not revocation.

Invariant **L10. Expiry is not revocation**, quoted in full:

    Both stop authority from being used. Expiry says the grant reached its planned end.
    Revocation says someone with authority ended it early. That difference matters for
    evidence and for whether a replacement is expected.

Its status line in that document reads: "Status **proposed** as a lifecycle distinction.
Current validity is part of draft-03 Section 3.3 chain verification."

Section **"Parties and standing" > "Issuer standing"**:

    Why the issuer was allowed to create, narrow, suspend, revoke or replace authority
    for the principal. A valid signature establishes who signed. It does not by itself
    establish standing.

Section **"Parties and standing" > "Lifecycle standing"**, which is what the two void
refusals are measured against:

    Who may suspend, revoke, replace or reaffirm an authority artifact. This is not
    always the issuer.

Section **"Verification and evidence" > "Evidence attestor"**:

    Who produced or signed a piece of evidence, and in what role. A gateway attesting an
    execution makes a different claim from an issuer signing a grant, and its key has its
    own lifecycle.

Invariant **L7**, for the shape of the indeterminate answer the bounds track returns:

    An enforcement point may deny on indeterminate, and the denial should say why.

The full list of named sections is in `vectors.json` under `proposed_text.named_text`.

## Where draft-03 does and does not state a rule

**Purpose exhaustion: no rule.** draft-pidlisnyi-aps-03 section 3.2's authority vector is
a closed set of seven facets, enumerated as "scope, spend, depth, time, reputation,
values, and reversibility". There is no purpose facet and no use-count facet, so a purpose
bound or a use-count bound cannot be carried inside a signed delegation at all.

**Use-count exhaustion: no rule for a delegation.** draft-03 does use "single-use", but
only of an approval, never of a grant. Section 4.3, verbatim:

    the enforcement boundary first evaluates the policy chain and, on a permit or narrow
    verdict, issues an approval bound to the authority the verdict grants: a first-class
    consumable artifact, bound to the action_ref it approves, single-use, and carrying a
    bounded lifetime.

That is an approval's consumption, which
[`fixtures/approval-single-use/`](../approval-single-use/) already tests against section
5.3.2. It is a different object from a grant, and this family does not conflate them.

**Reuse cascade and irreversibility: no rule.** draft-03 states neither.

**Budget exhaustion: draft-03 does state a rule.** Section 3.4, "Cumulative Spend Across
a Delegation Subtree", on why the grant's own bytes cannot answer the question:

    Signatures establish static limits; they do not establish the current cumulative
    total.

Vectors `PXE-06` and `PXE-07` carry `draft03_basis` naming section 3.4. They stay labelled
`candidate_against_proposed` because what the family asserts about them is the lifecycle
claim, that budget exhaustion is a third route to the same state and that it is not
revocation. That claim is the proposed text's and not draft-03's.

**Completion evidence: draft-03 states what an action-result record does and does not
establish.** Section 5.3.3, verbatim:

    An action-result record attests to what the enforcement boundary observed after
    dispatch. External occurrence or settlement requires separately resolved evidence.

That sentence is why the fulfillment record on the bounds track is an
`aps:action-result:v1` receipt issued by the enforcement boundary, and why the
vendor-issued variant in `PXE-09` is a record about the world rather than a record of what
the boundary observed.

**Revocation is irreversible under draft-03, section 3.5**, which is the neighbouring rule
the single-use track's two void refusals are deliberately not resting on:

    Revocation is irreversible.

An exhaustion is not a revocation, so that sentence does not reach it. `LC-I-014-c` and
`LC-I-014-d` are this family's proposal, not a reading of that text.

## What exists in the reference SDKs

Both runners print their own support table, so what follows is produced by the run rather
than typed. The claim-by-claim probe in `sdk-probe.mjs` and `sdk_probe.py` reports the
same picture from the other direction: 5 of 11 claims have an npm API, 4 of 11 have a PyPI
API. `SDK-RUNS.md` records both verbatim.

    TypeScript SDK support, agent-passport-system 7.1.0:
      supported      chain state, including time and revocation  (verifyAuthorityDelegationChain, both tracks)
      supported      purpose membership  (isPurposePermitted)
      supported      completion record authenticity  (verifyReceiptV1)
      supported      completion attestor standing  (verifyReceiptV1 boundary_identity axis)
      supported      budget exhaustion  (InMemoryAuthorityBudgetLedger reserve/markDispatched/commit)
      supported      purpose bound signature  (verify over canonicalizeJCS)
      not_supported  purpose exhaustion  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  use_count exhaustion  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  single-use reuse detection and cascade  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  irreversibility of an exhaustion  (no export in agent-passport-system 7.1.0, supplied by harness.ts)

Two notes on the `not_supported` entries.

**Purpose membership is TypeScript-only.** `isPurposePermitted` is exported from
`agent-passport-system` 7.1.0. A walk of every module in `agent_passport` 4.1.0 finds no
function whose name contains `purpose_permitted`, `purpose_category` or `purpose_drift`,
so `verify.py` applies the same documented hierarchical-prefix rule itself and labels the
step `not_supported`.

**Membership is not exhaustion, and that is the whole point.** `isPurposePermitted`
answers `true` for the Wednesday purchase exactly as it does for the Tuesday one: the
requested purpose is inside the grant's allowed purposes both times. `mint-bounds.ts`
records that as a fact in `records-bounds.json`:

    "is_purpose_permitted_first_purchase": true,
    "is_purpose_permitted_second_purchase": true

An implementation that checks scope, time, revocation and purpose membership, which is
everything both SDKs supply, admits the second purchase. That implementation is
`defective-boundary-chain-validity-only` below.

`harness.ts` supplies the missing boundaries, the same way
[`fixtures/approval-single-use/harness.ts`](../approval-single-use/harness.ts) and
[`fixtures/runtime-authority-denial-continuity/harness.ts`](../runtime-authority-denial-continuity/harness.ts)
do for their families. **Every exhaustion decision in this family is implemented by this
fixture, not by either APS SDK. The SDKs are used only for what they actually expose.**

## Vectors

One clock per track, one boundary instance per configuration, replayed in file order.
Order is part of the fixture: the ledger each event sees is the one every earlier event
left behind.

### Track: bounds

| id | covers | expected |
|---|---|---|
| `PXE-01-accept-first-purchase-tuesday` | positive control, first purchase | admitted, `dispatch_admitted`, bound_state `not_reached` |
| `PXE-02-observe-authenticated-completion` | fulfillment established from a boundary-issued action-result record | `completion_accepted`, `fulfillment_recorded`, bound_state `exhausted` |
| `PXE-03-reject-second-purchase-wednesday` | **the headline case.** Second purchase, chain still `valid` | not admitted, `purpose_exhausted`, bound_state `exhausted`, chain_state `valid` |
| `PXE-04-accept-first-use-under-use-count-grant` | positive control for `use_count` 1 | admitted, `dispatch_admitted` |
| `PXE-05-reject-use-count-consumed` | `use_count` 1 consumed by the admission itself | not admitted, `use_count_exhausted`, chain_state `valid` |
| `PXE-06-accept-first-purchase-under-budget-grant` | positive control for the budget bound, full cumulative reserved and settled | admitted, `dispatch_admitted` |
| `PXE-07-reject-budget-exhausted` | one more minor unit against an exhausted cumulative | not admitted, `budget_exhausted`, detail `CUMULATIVE_EXCEEDED` |
| `PXE-08-reject-unauthenticated-completion` | **negative control.** Completion record present, signature does not verify | `completion_rejected`, `completion_signature_invalid`, bound_state `not_established` |
| `PXE-09-reject-completion-from-party-without-standing` | **negative control.** Genuinely signed, issued by a party the bound does not name | `completion_rejected`, `completion_attestor_without_standing`, bound_state `not_established` |
| `PXE-10-reject-purchase-after-unauthenticated-completion` | **the vector a naive implementation passes wrongly** | not admitted, `bound_state_not_established`, bound_state `not_established` |
| `PXE-11-reject-purchase-after-completion-without-standing` | the same trap through the standing route | not admitted, `bound_state_not_established`, bound_state `not_established` |
| `PXE-12-reject-after-grant-not_after-...` | expiry and exhaustion coexist and stay distinct | not admitted, `grant_chain_not_valid`, detail `invalid/EXPIRED`, bound_state `exhausted` |

`PXE-03` is the case the bounds track exists for. At that instant
`verifyAuthorityDelegationChain` returns `valid` and `isPurposePermitted` returns `true`.
Every check both reference SDKs supply passes. The grant has still done its one job.

`PXE-12` separates the two states a single "cannot use this grant" bit would collapse: the
chain is `invalid`/`EXPIRED` and the bound_state is `exhausted`, and neither is revocation.

### Track: single-use

| id | covers | expected |
|---|---|---|
| `LC-I-013-a` | positive control. The admission is what consumes the artifact, in one record | admitted, `admitted_and_exhausted`, bound_state `exhausted`, 1 record |
| `LC-I-013-b` | a second presentation is a signal about the artifact, not a retry | not admitted, `single_use_reuse_detected`, bound_state `invalid` |
| `LC-I-013-c` | **negative control.** The artifact issued out of the first use, after the reuse | not admitted, `ancestor_invalidated_by_reuse`, bound_state `invalid` |
| `LC-I-013-d` | the blast radius bounded from the other side, an independently rooted artifact | admitted, `derived_artifact_chain_valid` |
| `LC-I-014-a` | positive control for the notch bound, and the atomicity claim | admitted, `admitted_and_exhausted`, exactly 1 record |
| `LC-I-014-b` | **negative control.** An exhausted permit eight days before its `not_after` | not admitted, `purpose_exhausted`, bound_state `exhausted` |
| `LC-I-014-c` | a record asking to undo the exhaustion, signed by a party that does hold standing to revoke | `void_refused`, `exhaustion_is_not_reversible` |
| `LC-I-014-d` | the same request from a party with no standing | `void_refused`, `void_attestor_without_standing` |
| `LC-I-014-e` | the permit again, after both refused void records. Nothing moved | not admitted, `purpose_exhausted`, bound_state `exhausted` |

Every `not_after` in `records-single-use.json` is `2026-09-30T00:00:00.000Z`, past every
instant in that track's event list, so no vector there can reach its verdict through
expiry even by accident.

## The overlap the two builds had

`PXE-03` and `LC-I-014-b` reach an identical `outcome`, `reason` and `bound_state`:
`not_admitted`, `purpose_exhausted`, `exhausted`, each on a chain that verifies `valid`
and before its own `not_after`. That was the one place the two builds genuinely tested the
same shape. They are not the same test, because the evidence route behind them differs:
`PXE-03`'s exhaustion turns on a separately observed fulfillment record, and
`LC-I-014-b`'s on the admission itself.

Leaving that difference in prose would have made it an unchecked claim. Both boundaries
therefore report an `exhaustion_basis`, it is a compared field on both tracks, and both
runners assert the pair directly:

    cross-track overlap check, PXE-03 against LC-I-014-b:
      same outcome, reason and bound_state: true (not_admitted/purpose_exhausted/exhausted)
      different exhaustion_basis:           true
        PXE-03    basis: "an authenticated fulfillment record from a party with standing"
        LC-I-014-b basis: "the admission itself"

If a later change collapses the two routes, that check fails.

## Negative controls

### Vector-level

`PXE-08` and `PXE-09` both present a fulfillment claim the boundary cannot establish, and
both give `not_established` rather than `exhausted`. They fail for different reasons and
the family keeps them apart: `PXE-08`'s record is unauthenticated, `PXE-09`'s is
authenticated by someone without standing. `mint-bounds.ts` records that the vendor's own
signature is genuine:

    "completion_no_standing_status_expecting_vendor": "valid",
    "completion_no_standing_status_expecting_boundary": "invalid",
    "completion_no_standing_boundary_identity_axis": "mismatch"

**`PXE-10` and `PXE-11` are the pair a naive implementation passes wrongly.** Under both
the reference boundary and `defective-boundary-trusts-unauthenticated-completion` the
outcome is `not_admitted`. The admit bit is identical. They differ only in `reason` and
`bound_state`: the reference says `bound_state_not_established`, the defective one says
`purpose_exhausted` with bound_state `exhausted`. A checker comparing only whether the
action was admitted passes it. What the defective boundary has actually done is convert an
unverified claim into a terminal lifecycle state and write that into its record.

**`LC-I-013-c` and `LC-I-014-b`** are the single-use track's, each named in a declared fail
set.

### Boundary-level, bounds track

`defective-boundary-chain-validity-only` does everything draft-03 section 3.3 chain
verification does and nothing else. It verifies the chain, checks purpose membership with
the SDK, ingests completion records with the same standing and authenticity checks the
reference boundary uses, and never gates on any exhaustion state. That is the shape of a
deployment that logs fulfillment and enforces nothing. Declared failing set, five vectors,
all wrongly admitted:

    PXE-03, PXE-05, PXE-07, PXE-10, PXE-11

`defective-boundary-trusts-unauthenticated-completion` tracks exhaustion in full but reads
`result.status` out of any completion record without establishing who signed it or whether
that party had standing. Declared failing set, four vectors:

    PXE-08, PXE-09, PXE-10, PXE-11

### Boundary-level, single-use track

`reuse-rejecting-only` rejects a second presentation of a single-use grant and stops there:
nothing issued out of that grant is reached. It is the shape of an implementation that
treats a replay as a bad request rather than as information about what the grant already
produced. Declared failing set: `LC-I-013-c`.

`validity-window-only` holds no exhaustion ledger at all. A grant is issued, valid until a
date, then expired. Declared failing set: `LC-I-013-b`, `LC-I-013-c`, `LC-I-014-b`,
`LC-I-014-e`.

### Two kinds of divergence, checked apart

`declared_fail_sets` names the vectors where a defective policy reaches a different
**admission decision**. On the single-use track, `record_divergence` additionally names
the policies that reach the **same decision** and record a different lifecycle state for
it. The split matters at the first use: `validity-window-only` admits `LC-I-013-a` and
`LC-I-014-a` exactly as the reference does and records `not_reached` where the reference
records `exhausted`. The two boundaries are already distinguishable before any refusal,
and only the recorded state shows it.

Both runners check both directions for every control. An undeclared divergence and a
declared divergence that quietly starts passing are both loud.

## Files

| file | what it is |
|---|---|
| `README.md` | this document |
| `vectors.json` | 21 ordered events across both tracks, with `track`, `case_ids`, the expected block, the four declared fail sets and the per-vector record divergences |
| `harness.ts` | both boundary classes and all five configurations |
| `mint-bounds.ts` | regenerates `records-bounds.json` byte for byte, npm SDK 7.1.0, 17 mint-time assertion sites |
| `records-bounds.json` | 5 grants, 5 purpose bounds, 9 actions, 9 receipts, recorded mint-time SDK observations |
| `mint_single_use.py` | regenerates `records-single-use.json` byte for byte, PyPI SDK 4.1.0 |
| `records-single-use.json` | 4 pinned chains, the bound each grant declares, which grant each derived artifact was issued out of, and who holds standing to revoke the permit |
| `verify.ts` | npm runner over all 21 vectors, wired into `npm test` |
| `verify.py` | PyPI runner over all 21 vectors. Both boundaries are implemented again rather than ported |
| `sdk-probe.mjs`, `sdk_probe.py` | which of this family's 11 claims each SDK exposes an API for |
| `SDK-RUNS.md` | the exact commands, exit codes and verbatim output of all four runs |
| `CHECKSUMS.sha256` | pins `vectors.json` and both record files |

`fixtures/manifest.json` is **not** touched. No lifecycle family in this repository is in
the manifest: they are class-2 families with a dedicated verifier, per
`docs/fixture-format.md`.

Both runners refuse to start if the merged vector list has drifted: wrong total, a
duplicated id, a missing `case_ids` array, a track with the wrong count, or a fail set
naming a vector from the other track. A merge that quietly dropped a vector would
otherwise still exit 0.

## Running

TypeScript, wired into `npm test` as its last step:

    npm ci --include=dev
    npm run verify:lifecycle-purpose-exhaustion

Expected final line:

    PASSED: 21/21 vectors, both reference boundaries matched every event in their track, every defective policy diverged on exactly its declared set

Python, against the pinned Python SDK. A manual run and not part of `npm test`, the same
convention `fixtures/lifecycle-subdelegation-edges/verify.py` and
`fixtures/runtime-authority-denial-continuity/verify.py` already follow for a Python side
kept out of the hermetic Node-only CI gate:

    python3 -m venv /tmp/aac-work/pyenv
    /tmp/aac-work/pyenv/bin/pip install agent-passport-system==4.1.0
    /tmp/aac-work/pyenv/bin/python fixtures/lifecycle-purpose-exhaustion/verify.py

Regenerating either record set gives the same bytes, and `git diff --exit-code` returns 0
after a second run of each:

    npm run generate:lifecycle-purpose-exhaustion-bounds
    npm run generate:lifecycle-purpose-exhaustion-single-use

## Determinism and event order

Every key on the bounds track is an Ed25519 seed derived from a published label under the
prefix `aps-conformance-suite:lifecycle-purpose-exhaustion:`, recorded in
`records-bounds.json` as `seed_label_prefix`. Every key on the single-use track is SHA-256
over a published label of the form `aps-conformance-suite:pxs:<label>`, listed in
`mint_single_use.py`. No secret material, no clock read, no randomness drawn: every
timestamp, nonce and payload is a pinned constant. Canonical bytes are RFC 8785 JCS
throughout, through each SDK's own canonicalizer. `records-bounds.json` is written with
keys sorted at every depth, so the file is a function of its content.

**Event order matters.** The whole list is replayed against one boundary instance per
configuration, in file order. `LC-I-013-c` means nothing until `LC-I-013-b` has run, and
`PXE-03` means nothing until `PXE-02` has. Reordering the list changes the answers, which
is the property both tracks are about.

Checksums of the committed files, as generated:

    8ad0c18bf50f747a6b8ba29b4630ce094ad273f1fe31fa229310f826fbe96a09  vectors.json
    d6d9ba1330f1a77ce0fd6328a5385eb2f9f626673f9f5b172cfb018133299893  records-bounds.json
    432188b883d4d60964c128ce34e5f94e76e32766657e3058170dc7c113a93864  records-single-use.json

## Sources

Every claim about an external document below was fetched in the session that reconciled
this family and is quoted verbatim at forty words or fewer. The translation into agent
terms is ours. Neither source says anything about AI agents, and nothing here claims
either one applies to them.

**RFC 6749**, *The OAuth 2.0 Authorization Framework*, section 4.1.2. Fetched from
`https://www.rfc-editor.org/rfc/rfc6749.txt`. On what an authorization server does with a
code presented twice:

    If an authorization code is used more than once, the authorization server MUST deny
    the request and SHOULD revoke (when possible) all tokens previously issued based on
    that authorization code.

That second clause is the half `LC-I-013-c` builds: the reuse reaches what was already
issued. The suite already tests the first clause in
[`fixtures/approval-single-use/`](../approval-single-use/).

**4VAC15-40-290**, Virginia Administrative Code, Title 4, Agency 15, Chapter 40,
*Validating tags and reporting bear, deer, elk, turkey, and bobcat*. Fetched from
`https://law.lis.virginia.gov/admincode/title4/agency15/chapter40/section290/`. On when a
permit may be marked used:

    It shall be unlawful for any person to validate (i.e., notch) a paper tag prior to
    the killing of a bear, deer, elk, or turkey.

and on whether a spent permit can be made usable again:

    All electronically notched tags are permanent and cannot be voided.

Together those are what `LC-I-014-a`, `LC-I-014-c` and `LC-I-014-d` build: using the
permit and spending it are one act, and no later record reverses it. The regulation says
nothing about who may or may not void one, which is why this family keeps "nobody may do
this" and "you in particular may not" as two separate refusals rather than reading a
standing rule into a permanence rule.

**draft-pidlisnyi-aps-03**, fetched from
`https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt`. Quoted above under "Where
draft-03 does and does not state a rule". It is the specification the suite tests against,
named here as the text that does not state a rule for this family's claims.

This family cites no fixture, repository or open question of this project's own as an
external source. `AUTHORITY-LIFECYCLE.md` and `CASES.md` are named as the proposed text
under test, which is what `candidate_against_proposed` means.

## Verification split

One entry per distinct verification claim, in the form
`layer / claim; runner; Mode; authorship; implementation`, per `CONTRIBUTING.md`.

- **Chain state, both tracks, 21 events / claim: the chain verdict each presented chain
  receives at that event's instant, including that every bounds-track grant verifies
  `valid` on Tuesday and Wednesday and `invalid`/`EXPIRED` on Saturday**; runner:
  `fixtures/lifecycle-purpose-exhaustion/verify.ts`; Mode A; author-produced;
  implementation: `agent-passport-system` 7.1.0 (npm). Author-produced because the lab
  wrote the vectors, both harness classes and this runner, and the implementation is a
  reference SDK of the same project.

- **Chain state, both tracks, 21 events / the same claim recomputed against a second
  implementation**; runner: `fixtures/lifecycle-purpose-exhaustion/verify.py`; Mode B;
  author-produced; implementation: `agent-passport-system` 4.1.0 (PyPI). The two SDKs are
  separate implementations and the Python run is the substantive recomputation, but both
  are reference SDKs of the same project, so the record is not independent.

- **Completion record authenticity and enforcement-boundary identity axis / claim:
  `completion_authentic` is `valid`, `completion_bad_signature` is `invalid`,
  `completion_no_standing` is `invalid` against the boundary and `valid` against the
  vendor, with the axis reading `mismatch`**; runner: both runners; Mode A and Mode B;
  author-produced; implementation: `verifyReceiptV1` in npm 7.1.0 and
  `receipt_core.verify_receipt_v1` in PyPI 4.1.0. The lab authored the records being
  checked.

- **Budget exhaustion / claim: reserving the full signed cumulative succeeds, committing
  it succeeds, and reserving one further minor unit returns `CUMULATIVE_EXCEEDED`**;
  runner: both runners; Mode A and Mode B; author-produced; implementation:
  `InMemoryAuthorityBudgetLedger` in both SDKs. The lab authored the grant whose limit is
  spent against.

- **Exhaustion decisions, 21 events / claim: both reference boundaries match every event
  in their track, in order, on every compared field including `exhaustion_basis`**;
  runner: both runners; Mode A and Mode B; author-produced; implementation: `harness.ts`
  and its mirror in `verify.py`, both written in this lab. Neither SDK exposes an API that
  decides this, so there is no implementation under test here other than the harness
  itself, and this layer asserts nothing about either SDK.

- **Defective-policy behavior / claim: every declared fail set and every declared record
  divergence is one a defective policy actually produces, and no undeclared one appears**;
  runner: both runners; Mode A and Mode B; author-produced; implementation: the five
  configurations in `harness.ts` and `verify.py`. A property of the fixture, not of either
  SDK.

- **Cross-track overlap / claim: `PXE-03` and `LC-I-014-b` agree on outcome, reason and
  bound_state and disagree on `exhaustion_basis`**; runner: both runners; Mode A and Mode
  B; author-produced; implementation: both harness classes. A property of the fixture.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundaries:

- a grant whose declared purpose has been fulfilled, on an authenticated record from a
  party the grant names as a fulfillment attestor, does not admit a second action for the
  same purpose, while its chain still verifies `valid`, unrevoked and inside its time
  window
- a grant with a `use_count` bound of 1 admits exactly one action, and the admission
  itself consumes the bound with no completion record involved
- a grant with a bounded cumulative spend, fully committed through the SDK's own ledger,
  refuses one further minor unit, and the SDK supplies the refusal code
- a fulfillment claim whose signature does not verify gives `not_established`, never
  `exhausted`
- a fulfillment claim genuinely signed by a party the grant does not name as a fulfillment
  attestor gives `not_established`, never `exhausted`, and is a different failure from an
  unauthenticated one
- expiry and exhaustion coexist on one grant, are reported separately, and neither is
  revocation
- a permit whose admission is its exhaustion writes exactly one record for that event, and
  a second presentation is refused before its stated end date
- a detected reuse reaches the artifact issued out of the reused grant and does not reach
  an independently rooted one
- two records asking to undo an exhaustion are refused under two different reasons, one
  naming reversibility and one naming standing, and neither moves the state
- the same recorded verdict can rest on two different evidence routes, and the route is a
  field rather than a comment

It also establishes that a boundary implementing everything both reference SDKs supply and
no exhaustion gate admits every second action this family presents, that a boundary that
trusts a completion record without authenticating it records a terminal lifecycle state on
evidence that establishes nothing, and that a boundary modelling a grant only as a
validity window is already distinguishable at the first admission.

## Does not claim

A pass does **not** establish:

- anything about a deployed enforcement gateway, MCP server or agent runtime. No network
  call is made and no protocol is spoken. `harness.ts` holds this family's own in-process
  reference models.
- that purpose exhaustion, use-count exhaustion, the reuse cascade, the irreversibility
  rule or the purpose-bound artifact shape here is required, recommended or recognised by
  draft-pidlisnyi-aps-03. Only the budget dimension rests on stated draft-03 text, and
  only for the spend rule, not for the lifecycle claim.
- that this family's reading of "Expiry or exhaustion" is the only defensible one, or that
  denying on `not_established` is what the proposed text requires. See item 3 below.
- that the two tracks' `bound_state` vocabularies are reconcilable. They are not
  reconciled here. See item 7 below.
- that a verifier with no access to a boundary's ledgers can reach any of these verdicts
  from signed records alone. It cannot. See item 6 below.
- anything about a legal doctrine. A procurement scenario and a harvest permit were chosen
  because they are machine-checkable, not because any body of law is being applied to an
  AI agent.
- real concurrency. The events run synchronously, one after another, on one boundary
  instance per configuration.
- that the reference SDKs are wrong to omit an exhaustion API. Neither SDK claims to have
  one, and no published text requires one. The `not_supported` entries are a record of
  what exists, not a defect report.
- anything about partial fulfillment, cancellation, or a bound that is reached and then
  reopened. No vector here covers any of those.

## Where the proposed text was too vague to test

Findings, not defects in the fixture. Each is a place the family had to choose something
the proposed text does not say, and each choice is marked in the code. The first six come
from the bounds track, items 7 to 11 from the single-use track and from the reconciliation
itself.

1. **The bound has no declared home.** "a declared time, use count, budget, purpose or
   other bound" does not say where the bound is declared. draft-03's authority vector is
   closed and has no purpose or use-count facet, so the bound cannot live in the signed
   delegation. This family invented
   `aps-conformance-suite:lifecycle-purpose-exhaustion:purpose-bound-v0` to carry it. Any
   other implementation would invent a different one and the two would not interoperate.
   Nothing here tests interoperability of the bound, because there is nothing to test it
   against.

2. **Nobody is named as a fulfillment attestor.** The text says a bound can be "reached"
   and never says who may state that it was. This family put `fulfillment_attestors` in
   its own bound artifact and pointed two negative controls at it. Without that invented
   field, "a party without standing" has nothing to be measured against and `PXE-09` is
   not decidable.

3. **Fail-open against fail-closed on `not_established` is unresolved.** L7 says an
   enforcement point "may deny on indeterminate, and the denial should say why", but L7 is
   about revocation state. Nothing says what a boundary should do when a *fulfillment*
   claim is indeterminate. This fixture denies, with reason `bound_state_not_established`.
   A boundary that admits in that state is not thereby non-conforming under any text this
   family cites. `PXE-10` and `PXE-11` therefore compare the recorded lifecycle state,
   which the text does constrain, and pin the admit decision to this fixture's own
   declared policy.

4. **"Purpose" is not defined as a comparable value.** String, scope grant, structured
   object, reference to an out-of-band statement of work: the text does not say. This
   family made it a hierarchical colon-separated string so the SDK's own membership check
   could be used. That was a convenience, not a reading of the text.

5. **Fulfillment has no relation to partial completion.** One bound, one "reached". An
   order placed, partly shipped and then cancelled has no state in this model. No vector
   covers it and none could.

6. **Exhaustion has no evidence record of its own, and this is the consequential one.**
   Revocation under draft-03 section 3.5.1 must produce a signed revocation record with a
   time, a revoking authority and a machine-readable reason code. Exhaustion produces
   nothing comparable in either text. This family derives the state from a completion
   record and the boundary's ledgers, which means a verifier with no access to those
   ledgers cannot reach any of these verdicts from signed records alone. That is the same
   shape as the gap `OPEN-QUESTIONS.md` records for teardown completeness, and it suggests
   the lifecycle document needs either an exhaustion record with the shape of a revocation
   record, or an explicit statement that exhaustion is boundary state and not a verifiable
   claim.

7. **The two tracks disagree about what a reused one-use grant is, and the text cannot
   settle it.** This is the finding the reconciliation produced. `PXE-05` records a
   consumed `use_count` bound as `exhausted`. `LC-I-013-b` records a reused `single_use`
   bound as `invalid`, on the reading that a second presentation is a signal about the
   artifact rather than a retry. Both are answers to `LC-I-013`. The proposed text has
   `Expiry or exhaustion` and `Revocation` and nothing between them for "treat this
   artifact as compromised", so it does not choose. Both vectors are kept, both are
   labelled, and `CONTRIBUTING.md` is explicit that vocabulary is not settled by a fixture.

8. **How far a reuse signal should reach.** `LC-I-013-c` stops the cascade at artifacts
   issued out of the reused grant and `LC-I-013-d` checks it goes no further. Both
   boundaries are this family's choice. RFC 6749 reaches "all tokens previously issued
   based on that authorization code". Whether the agent-authority analogue is every
   descendant, every descendant issued inside the grant's own window, or only direct
   children is unstated, and the two vectors are worth nothing as evidence for a radius
   until it is settled.

9. **Who, if anyone, may reverse an exhaustion.** `LC-I-014-c` refuses a party with
   standing to revoke the grant and `LC-I-014-d` refuses one without. Both refusals are
   this family's proposal. `Lifecycle standing` names who may suspend, revoke, replace or
   reaffirm an artifact, and exhaustion is not on that list. Whether it is deliberately
   absent, or absent because nobody wrote it down, cannot be read off the text.

10. **What an exhausted grant's remaining `not_after` means.** `LC-I-014-b` pins that a
    grant can be exhausted well before its stated end date, and `PXE-12` records that both
    states coexist in one implementation. Whether an exhausted grant then also expires on
    schedule, whether that produces a second state change worth recording, or whether the
    remaining window means anything at all, is unstated.

11. **Whether an ordinary exhaustion is a revocation-relevant event for a descendant.** L1
    covers a revoked ancestor invalidating what depends on it. An exhausted ancestor is
    not revoked. `LC-I-013-c` invalidates a descendant on a reuse signal, and no vector
    here asks what an ordinary, unremarkable exhaustion does to a descendant issued before
    it, because the text gives no basis for an expected answer. That is the clearest
    single gap this family found.

## Provenance

Every file in this directory is authored for this suite. The bounds track's minting,
key-resolution and seed-label pattern follows
[`fixtures/approval-single-use/mint.ts`](../approval-single-use/mint.ts). The single-use
track's follows [`fixtures/sponsor-handover/`](../sponsor-handover/). The
reference-boundary-plus-declared-defective-control pattern follows
[`fixtures/runtime-authority-denial-continuity/harness.ts`](../runtime-authority-denial-continuity/harness.ts).
All code was written in this lab. Neither runner was reviewed by anyone outside it, and no
independent third party has run either of them. The two SDKs also share an author, so
agreement between them is weaker evidence than agreement between two independently
authored implementations would be.
