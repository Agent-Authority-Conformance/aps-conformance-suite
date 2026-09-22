# approval-single-use: a permit is a bounded single-use approval

This fixture exercises draft-pidlisnyi-aps-03 section 5.3.2's rule that a permit or
narrow policy-decision record is a bounded, single-use approval, and that an enforcement
boundary must enforce that at consumption time, not only at decision time.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/), section 5.3.2, "Policy
Decision", lines 1069-1099 of the plain-text rendering. The two load-bearing paragraphs,
quoted in full:

    1086    verdict is permit, deny, or narrow. constraints is a duplicate-free
    1087    array of NFC strings sorted by UTF-8 bytes.  effective_authority_ref
    1088    identifies the exact effective authority admitted by the decision.
    1089    It is null for deny and a lowercase hexadecimal SHA-256 digest for
    1090    permit or narrow. valid_until is null for deny and an exact UTC-
    1091    millisecond timestamp later than issued_at for permit or narrow.
    1092
    1093    A permit or narrow policy-decision record is a bounded, single-use
    1094    approval for its action_ref.  Before dispatch, the enforcement
    1095    boundary MUST verify that it has not expired, atomically consume its
    1096    receipt_id, recheck time and revocation state, and complete any spend
    1097    reservation.  An already consumed, expired, or stale approval MUST
    1098    NOT admit dispatch.  A deny record is terminal and MUST NOT be
    1099    consumed as an approval.

This is plain draft-03 conformance, not a proposal. The rule is stated with `MUST` twice
in one paragraph and states the deny prohibition as its own `MUST NOT`, so this fixture
makes the existing required behavior executable and reviewable rather than proposing new
wording.

## What exists

Both reference SDKs validate a policy-decision record's shape, signature and section 5.3
stage rules. Neither exposes a consume-once boundary API for a policy-decision record.
Both say so in their own documentation, at the exact lines this family's obligation comes
from:

    node_modules/agent-passport-system/dist/src/v2/receipt-core/stage.d.ts, lines 58-64:

    "What this function does NOT establish, so that a caller cannot read more into a
    valid result than it carries: ... does not enforce the approval obligations of
    lines 1093-1099, which are enforcement-boundary state rather than properties of one
    record. Those are the section 5.6 composition points."

The Python SDK's `agent_passport/receipt_core/stage.py` lines 9-19 carry the same
disclaimer for the same reason. Neither SDK's `receipt_core/decision_ref.py` (content
addressing only) nor its TypeScript mirror, nor either SDK's `authority-boundary`
surface (envelope shape and signature over an already-recorded ruling, not a consumption
decision), supplies a single-use ledger keyed by `receipt_id`. The one genuine
replay-protection primitive either SDK ships,
`dist/src/v2/revocation-enforcement/index.js` lines 165-186
(`validateEphemeralToken` / `checkReplay` / `InMemorySeenSet`), targets an ephemeral
capability-token `jti`, not a `receipt_id` or a policy-decision verdict, and its own
file header says the single-use state it tracks "lives in-process for a single process
lifetime ... the integrator's responsibility" (same file, lines 34-36).

Following the prompt this family was built from and the precedent set by
[`fixtures/runtime-authority-denial-continuity/`](../runtime-authority-denial-continuity/),
this fixture supplies that missing boundary itself, in `harness.ts`. **The reference
boundary is this family's own code, not an SDK conformance result.** It calls the real
SDK for the two things the SDK does establish, a policy-decision receipt's signature and
section 5.3 stage validity (`verifyReceiptV1`), and the backing
`AuthorityDelegationV1` chain's structural, temporal and revocation state
(`verifyAuthorityDelegationChain`). It supplies the single-use ledger, the expiry gate,
the action_ref binding check and the deny-is-terminal rule itself, because no SDK
function produces or checks any of those four.

### SDK finding

`verifyAuthorityDelegation`, a single-delegation verifier, is declared in
`node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.d.ts` line
31, but the published `agent-passport-system` 7.0.0 package does not export it at
runtime: `import { verifyAuthorityDelegation } from 'agent-passport-system'` fails with
`SyntaxError: The requested module 'agent-passport-system' does not provide an export
named 'verifyAuthorityDelegation'`. This family works around it the way
`fixtures/ancestor-revocation-chain/` already does, by calling
`verifyAuthorityDelegationChain` with a single-element array, which is exported and
behaves correctly for a one-hop chain (`mint.ts` asserts this at mint time). This is
recorded here as a finding, not as a vector: the workaround changes nothing this family
tests, and no vector exists to test the missing export itself.

## What the family does

`mint.ts` mints, with the pinned TypeScript SDK, `agent-passport-system` 7.0.0:

- two one-hop `AuthorityDelegationV1` records, principal to acting agent, identical
  except for their nonce: `DELEGATION_MAIN` backs every decision except one,
  `DELEGATION_FOR_REVOCATION_CASE` backs only the decision case ASU-05 presents, so that
  marking one revoked at consumption time cannot leak into any other vector's chain
- two action-intent records (section 5.3.1) and their action references, computed with
  `computeActionRefV2`, `createActionReferenceInputV2` and `computePayloadRefV1`: action
  A (primary), and action C (a narrower operation, distinct target and
  `scope_required`). Action B is referenced only as the mismatched target case
  ASU-04 presents against; no decision is minted for it.
- seven policy-decision records (section 5.3.2): five permit and one deny bound to
  action A, one narrow bound to action C. Every decision's `decision_ref` is built with
  `buildDecisionRefV1` over real `DecisionEvidenceV1` material (`authority_state`,
  `policy_input`, `decision_context`, `decision_output`), committed in `chain.json`
  alongside the receipts, the same pattern `fixtures/action-result-binding/` uses.

`mint.ts` asserts at mint time, and aborts writing `chain.json` if any assertion fails,
that: the two delegations verify `valid` when their resolver answers `active` and
`DELEGATION_FOR_REVOCATION_CASE` verifies `invalid`/`REVOKED` when its resolver answers
`revoked`; every action pair has a distinct `action_ref`; every decision has a distinct
`receipt_id`; and every one of the nine minted receipts verifies `status: "valid"` under
the SDK's own `verifyReceiptV1`, called with the same `boundaryIdentity` `harness.ts`
uses at consumption time.

`harness.ts` implements `DispatchBoundary`, one class with two configurations:

- **`reference-boundary`** (`makeReferenceBoundary`): implements every step lines
  1093-1099 state, in this order: signature and stage validity (`verifyReceiptV1`), deny
  is terminal (line 1098), action_ref binding (line 1093), expiry (line 1095), atomic
  single-use consumption (lines 1095-1096), and a fresh
  `verifyAuthorityDelegationChain` recheck of the backing chain at the consumption
  instant, which folds the paragraph's "recheck time and revocation state" into one real
  SDK call rather than a second implementation of either half.
- **`defective-boundary-never-consumes-never-rechecks`**: the prompt's negative control.
  Runs the identical signature, deny, binding and expiry steps, then skips consumption
  and skips the revocation recheck. Its declared failing set is exactly the three
  vectors that turn on those two removed steps.

Line 1097's "complete any spend reservation" is not modeled by either boundary
configuration; see "Does not claim".

`verify.ts` loads `chain.json` and `vectors.json`, runs both boundary configurations
over the same nine ordered presentations, and checks each against its expected outcome.
`verify.py` is a second, independently written implementation of the same boundary rules
(steps 1-4 and 6 above; it does not call `verifyReceiptV1` or
`verifyAuthorityDelegationChain` and does not reproduce step 0's signature check or the
chain-recheck's own cryptography, and says so in its own module docstring), run over the
same `chain.json` records and the same `vectors.json` presentations.

## Vectors, timeline style, one clock

Nine ordered presentations in `vectors.json`, against one shared `DispatchBoundary`
instance per boundary configuration and one shared, fixture-pinned clock. Presentation
order matters: the single-use ledger a boundary instance holds is shared across every
presentation in the list, in this order, the same way section 5.3.2 describes one
boundary consuming one stream of approvals rather than nine independent evaluations.

| id | covers | differs from ASU-01 by | expected |
|---|---|---|---|
| ASU-01-accept-permit-before-expiry | positive control | nothing, this is the control | admitted, `dispatch_admitted` |
| ASU-02-reject-already-consumed | single-use | the same permit presented a second time | not admitted, `already_consumed` |
| ASU-03-reject-expired | expiry | presented after its own `valid_until` | not admitted, `expired` |
| ASU-04-reject-action-binding-mismatch | action binding | presented for a different action_ref than the permit names | not admitted, `action_binding_mismatch` |
| ASU-05-reject-revoked-at-consumption | revocation recheck | the backing chain is revoked by the time the boundary rechecks it | not admitted, `authority_chain_not_valid_at_consumption` |
| ASU-06-reject-deny-not-consumed-as-approval | deny is terminal | the presented record is a deny, not a permit | not admitted, `deny_terminal_not_approval` |
| ASU-07a-accept-race-first-consumption | race, first of two | same permit as ASU-07b, first presentation | admitted, `dispatch_admitted` |
| ASU-07b-reject-race-second-consumption | race, second of two | the same permit, presented again immediately, no dispatch between | not admitted, `already_consumed` |
| ASU-08-accept-narrow-for-narrowed-action | narrow decisions | verdict is narrow, action is the narrowed one the decision names | admitted, `dispatch_admitted` |

ASU-07's two presentations model the prompt's race case deterministically: one
`DispatchBoundary.consume()` call, then a second at the same instant with nothing
dispatched between them. Both calls run synchronously on one instance, so there is no
real concurrency to simulate; the atomicity being tested is that the second call sees
the first call's ledger write, not that two threads contend for a lock.

## Negative control

`defective-boundary-never-consumes-never-rechecks` still checks signature, verdict,
action binding and expiry, so it matches the reference boundary on ASU-01, ASU-03,
ASU-04, ASU-06, ASU-07a and ASU-08. It never consumes a `receipt_id` and never rechecks
the authority chain, so it wrongly admits ASU-02 (a second presentation looks identical
to a first one when nothing is tracked), ASU-05 (a chain revoked after the decision is
never re-examined) and ASU-07b (the same untracked-reuse defect as ASU-02). The declared
failing set:

    ASU-02-reject-already-consumed
    ASU-05-reject-revoked-at-consumption
    ASU-07b-reject-race-second-consumption

Both `verify.ts` and `verify.py` check this in both directions: every declared id must
actually diverge from its expected outcome under the defective boundary, and every
other id must still match, so an undeclared failure or a declared failure that quietly
starts passing is loud in either runner's output.

## Running

TypeScript, wired into `npm test` as its last step:

    npm ci --include=dev
    npm run verify:approval-single-use

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set

Regenerating `chain.json` (byte for byte; `git diff` is empty after a second run):

    npx tsx fixtures/approval-single-use/mint.ts

Python, independently written, a manual run and not part of `npm test`, the same
convention `fixtures/runtime-authority-denial-continuity/verify.py` and
`fixtures/ancestor-revocation-chain/validate.py` already follow for a Python side kept
out of the hermetic Node-only CI gate:

    python3 fixtures/approval-single-use/verify.py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)

## Results

Both runners were executed locally against the pinned TypeScript SDK
(`agent-passport-system` 7.0.0, `package.json`). `reference-boundary` matched all 9/9
presentations under both runners. `defective-boundary-never-consumes-never-rechecks`
failed exactly the declared set of 3 under both runners, and matched the remaining 6
under both. This is an author-produced record, not an independent one, per
`CONTRIBUTING.md`'s admission rules for run records.

## Provenance

Vectors, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts` and `verify.py` are authored
for this suite. The minting, key-resolution and seed-label pattern follows
`fixtures/action-result-binding/mint.ts` and `fixtures/ancestor-revocation-chain/mint.py`.
The reference-boundary-plus-declared-defective-control pattern follows
`fixtures/runtime-authority-denial-continuity/harness.ts`. All code was written in this
lab; neither runner was reviewed by anyone outside it, and no independent third party
has run either of them.

## What a pass establishes

For the exact SDK revision run, a pass establishes that, for this family's own
reference boundary:

- a permit presented once before its `valid_until`, for the action_ref it names, is
  admitted, and its `receipt_id` becomes unusable for a second presentation
- a permit presented after its own `valid_until` is not admitted, whether or not it was
  ever consumed
- a permit presented for an action_ref other than the one it names is not admitted
- a permit backed by an authority chain that verifies revoked at the consumption instant
  is not admitted, even though the decision itself, and the chain at decision time, were
  fine
- a deny record is never admitted as an approval, under any of the same checks a permit
  passes
- of two back-to-back presentations of one never-before-used permit, exactly one is
  admitted
- a narrow verdict is single-use and action-bound the same way a permit is

It also establishes that a boundary implementation missing only the consumption step and
the revocation recheck predictably fails exactly the three vectors that isolate those
two steps, and none of the other six.

## Does not claim

A pass does **not** establish:

- anything about a deployed enforcement gateway, MCP server or agent runtime. No
  network call is made and no protocol is spoken; `harness.ts` is this family's own
  in-process reference model.
- anything about AuthZEN or any other approval protocol. This family is scoped to
  draft-pidlisnyi-aps-03 section 5.3.2 alone.
- anything about spend reservation or cumulative ledger behavior under
  draft-pidlisnyi-aps-03 section 3.4 ("Cumulative Spend Across a Delegation Subtree").
  Line 1097's "complete any spend reservation" is the one clause of the quoted paragraph
  neither boundary configuration implements; no vector here mints or checks a bounded
  spend facet, a reservation, or a commit/cancel transition.
- real concurrency or a race between independent threads or processes. ASU-07's two
  presentations run synchronously, one after the other, on one boundary instance; see
  "Vectors, timeline style, one clock".
- that this family's `DispatchBoundary` is the only correct reading of lines 1093-1099,
  or that its consume-before-recheck ordering (a permit revoked at the recheck step is
  still marked consumed, since consumption in this reference model precedes the
  revocation recheck, following the paragraph's stated order) is the only defensible one.
  It is one literal reading of the stated order, made executable.
- that every independent draft-03 implementation behaves this way, or that the SDK
  finding above (the undocumented-at-runtime `verifyAuthorityDelegation` export) is the
  only such gap in either SDK.
- anything about `agent-passport-system` for Python. This family's reference boundary
  and its records are minted and verified in TypeScript only; `verify.py` is a
  from-scratch, no-dependency reimplementation of the boundary rules, not a Python SDK
  run, and its own module docstring says so.
