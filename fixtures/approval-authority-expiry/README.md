# approval-authority-expiry: authority that expires between approval and consumption

**Candidate fixture.** This family is a candidate against the draft-03 text quoted below.
It is not yet cited by `docs/ID-COVERAGE.md`, and nothing here changes any row of that
inventory until a revision of it does so.

This fixture exercises draft-pidlisnyi-aps-03 section 4.3's rule that a boundary
re-validates temporal validity at consumption, for the one case
[`fixtures/approval-single-use/`](../approval-single-use/) does not present: an approval
issued while its authority was valid, still unexpired itself when it is consumed, whose
backing authority has passed its `not_after` by then.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/), sha256
`59b9547a20c6d514eceb97d169b92b2f9c70a231f5b914e8fc1b478c7f359fca`, section 4.3,
"Two-Phase Execution", lines 909-918 of the plain-text rendering:

    909    In two-phase execution, the enforcement boundary first evaluates the
    910    policy chain and, on a permit or narrow verdict, issues an approval
    911    bound to the authority the verdict grants: a first-class consumable
    912    artifact, bound to the action_ref it approves, single-use, and
    913    carrying a bounded lifetime.  Execution then presents and consumes
    914    the approval.  At consumption the boundary MUST re-validate what can
    915    have changed since issuance, including revocation status and temporal
    916    validity, as required by Section 3.5.  An approval that has expired,
    917    has already been consumed, or fails re-validation MUST NOT admit
    918    execution.

The requirement sentence this family targets is the one on lines 914-916: "At
consumption the boundary MUST re-validate what can have changed since issuance,
including revocation status and temporal validity". Section 3.2 (lines 535-536) defines
the authority's validity as the half-open interval `[not_before, not_after)`.

## The gap this closes

`approval-single-use` covers the approval's own expiry (ASU-03) and a revoked authority
at consumption (ASU-05). Every presentation in it is consumed while its backing
delegation is inside its validity window (`2026-09-22T08:00:00.000Z` to
`2026-09-23T00:00:00.000Z`; every presentation is at `09:00:xx` on 2026-09-22). So a
boundary that rechecked revocation at consumption but took the authority's temporal
validity as fixed at issuance would pass all of it. That family's reference boundary
does recheck time (its `harness.ts` lines 172-177 call `verifyAuthorityDelegationChain`
at the consumption instant), so the gap is a missing vector, not missing logic.

## Why a new family

The alternative was new vectors in `approval-single-use`. That family's `vectors.json`,
`chain.json` and README results are cited by `docs/ID-COVERAGE.md` revision 3 with
counts ("matched 9 of 9 presentations on the reference boundary, and the defective
boundary failed exactly its declared set"). Adding vectors there would change the
corpus that sentence describes, and its defective boundary would need a third flaw. No
`CHECKSUMS.sha256` or `SHA256SUMS.txt` currently covers either family, so no published
digest set forced the choice. Leaving a cited record unchanged did.

## What exists

Neither reference SDK exposes a consumption boundary for an approval.
`fixtures/approval-single-use/README.md`, "What exists", records this with the SDK's own
doc comments. This family follows that family's precedent: **the consumption boundary
is implemented by this fixture in `harness.ts`, not by any APS SDK.** The pinned SDK,
`agent-passport-system` 7.1.0, is called only for what it establishes: a policy-decision
receipt's signature and section 5.3 stage validity (`verifyReceiptV1`), and the backing
`AuthorityDelegationV1` chain's state at a given instant
(`verifyAuthorityDelegationChain`; the temporal check is phase 10 at
`node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.js` lines
234-242, and revocation is phase 11 starting line 244).

## What the family does

`mint.ts` mints with the pinned SDK:

- two one-hop `AuthorityDelegationV1` records, principal to acting agent, identical
  except for their nonce, both valid `[2026-09-24T08:00:00.000Z,
  2026-09-24T09:00:00.000Z)`. `DELEGATION_MAIN` backs every decision except the one
  AEX-02 presents; that one is backed by `DELEGATION_FOR_REVOCATION_CASE` alone.
- one action-intent and its action reference.
- four permit policy-decision receipts for that action, each issued between
  `08:59:40` and `08:59:43`, inside the authority window. Three carry `valid_until`
  `2026-09-24T09:00:30.000Z`, thirty seconds after the authority's `not_after`. One
  (`decision_permit_approval_expired`) carries `valid_until` `08:59:44`.

`mint.ts` asserts at mint time, and writes nothing if any assertion fails: the authority
verifies `valid` at every decision's `evaluated_at`; `DELEGATION_MAIN` verifies `valid`
at `08:59:50` and `invalid`/`EXPIRED` at `09:00:10`; the revocation-case delegation
verifies `invalid`/`REVOKED` when its resolver answers `revoked`; `09:00:10` is before
the permits' `valid_until`; every decision has a distinct `receipt_id`; and every receipt
verifies `status: "valid"` under `verifyReceiptV1`.

`harness.ts` implements `ConsumptionBoundary`, one class with two configurations that
differ in one thing, the instant the authority chain is re-verified at:

- **`reference-boundary`**: signature and stage validity, deny is terminal, action_ref
  binding, the approval's own expiry, single-use consumption, then
  `verifyAuthorityDelegationChain` at the consumption instant with the consumption-time
  revocation answer (`harness.ts` lines 120-134).
- **`defective-boundary-authority-time-frozen-at-issuance`**: every step identical,
  except the chain is re-verified at the decision's own `issued_at`. It still uses the
  consumption-time revocation answer and still enforces the approval's own
  `valid_until`. This is the defect the Revision 5 review described: a boundary that
  rechecks revocation and approval expiry but not the authority's temporal validity.

`verify.ts` runs both configurations over the same four ordered presentations.
`verify.py` is a second, independently written, stdlib-only implementation of the same
boundary rules. It applies the half-open window to the delegation's `authority.time`
directly rather than calling the SDK, and does not re-verify any signature; its module
docstring says so.

## Vectors, timeline style, one clock

Four ordered presentations against one boundary instance per configuration and one
fixture-pinned clock.

| id | covers | differs from AEX-01 by | expected |
|---|---|---|---|
| AEX-01-accept-authority-valid-at-consumption | positive control | nothing; consumed at `08:59:50`, authority valid, approval unexpired | admitted, `dispatch_admitted` |
| AEX-02-reject-authority-revoked-at-consumption | revocation recheck still present | authority answers `revoked` at consumption | not admitted, `authority_chain_not_valid_at_consumption`, `invalid/REVOKED` |
| AEX-03-reject-approval-expired | approval expiry still present | the approval's own `valid_until` has passed; authority still valid | not admitted, `expired` |
| AEX-04-reject-authority-expired-approval-unexpired | **the gap** | consumed at `09:00:10`: after the authority's `not_after` (`09:00:00`), before the approval's `valid_until` (`09:00:30`) | not admitted, `authority_chain_not_valid_at_consumption`, `invalid/EXPIRED` |

AEX-01 and AEX-04 present two distinct permits minted identically except for
`evaluated_at` (`08:59:40` and `08:59:43`), because a single-use ledger would otherwise
refuse the second presentation as `already_consumed`. The input that decides the outcome
is the consumption instant.

AEX-02 and AEX-03 exist so the declared failing set is meaningful. With only AEX-01 and
AEX-04, a boundary that rechecked nothing would also "fail exactly AEX-04". AEX-02 shows
the defective boundary still rechecks revocation, and AEX-03 shows it still enforces the
approval's own expiry, so the one vector it fails isolates the authority-time recheck.

## Negative control

The defective boundary matches the reference on AEX-01, AEX-02 and AEX-03. On AEX-04 it
re-verifies the chain at `08:59:43`, when the authority was valid, and admits. The
declared failing set:

    AEX-04-reject-authority-expired-approval-unexpired

Both runners check this in both directions: the declared id must diverge from its
expected outcome, and every other id must still match.

## Running

TypeScript, wired into `npm test`:

    npm ci --include=dev
    npm run verify:approval-authority-expiry

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set

Regenerating `chain.json` gives the same bytes:

    npx tsx fixtures/approval-authority-expiry/mint.ts

Python, independently written, a manual run and not part of `npm test`, following
`fixtures/approval-single-use/verify.py`:

    python3 fixtures/approval-authority-expiry/verify.py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)

## Results

Both runners were executed locally against the pinned TypeScript SDK
(`agent-passport-system` 7.1.0, `package-lock.json`). `reference-boundary` matched 4/4
presentations under both runners. `defective-boundary-authority-time-frozen-at-issuance`
failed exactly the declared set of 1 under both, admitting AEX-04, and matched the other
3. `mint.ts` run twice produced byte-identical `chain.json`. This is an author-produced
record, not an independent one, per `CONTRIBUTING.md`'s admission rules for run records.

## Provenance

Vectors, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts` and `verify.py` are authored
for this suite. The minting, seed-label, decision-evidence and
reference-plus-declared-defective-boundary patterns follow
`fixtures/approval-single-use/`. All code was written in this lab. No one outside it
has reviewed or run either runner.

## What a pass establishes

For the exact SDK revision run, a pass establishes that, for this family's own reference
boundary, a permit issued under valid authority and presented before its own
`valid_until` is not admitted if its backing authority's `not_after` has passed at the
consumption instant. It also establishes that a boundary that differs only in evaluating
the authority's temporal validity at issuance predictably fails exactly AEX-04 and none
of the other three.

## Does not claim

A pass does **not** establish:

- anything about a deployed enforcement gateway, MCP server or agent runtime.
  `harness.ts` is this family's own in-process reference model, not an SDK API.
- whether a boundary should have issued an approval whose `valid_until` outlives its
  authority's `not_after` in the first place. Draft-03 does not say, and this family
  takes no position. It tests only what happens at consumption when one exists.
- anything about a not-yet-valid authority at consumption. An approval issued under
  valid authority cannot meet a not-yet-valid authority later on a forward-moving clock,
  so no vector presents one.
- anything about multi-hop chains, ancestor expiry, or a parent expiring before a child.
  Every chain here is one hop.
- anything about spend reservation (section 4.3 lines 920 onward), single-use
  consumption, deny handling or action binding beyond what `approval-single-use`
  already covers. The harness implements those steps so the boundary is complete. No
  vector here targets them.
- that `authority_chain_not_valid_at_consumption`, `invalid/EXPIRED` or any other reason
  string is normative. They are this family's labels, reused from `approval-single-use`
  for consistency.
- that this family's ordering (consumption before the chain recheck, following
  `approval-single-use`) is the only defensible one.
- anything about `agent-passport-system` for Python. `verify.py` is a from-scratch,
  no-dependency reimplementation of the boundary rules, not a Python SDK run.
