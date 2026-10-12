# approval-authority-expiry: authority that expires between approval and consumption

This is plain draft-03 conformance, not a proposal. It cites published draft-03 text and
carries no candidate label. It is built for the temporal-validity clause of `REQ-4.3-1`
in `docs/ID-COVERAGE.md`, which revision 5 holds at PARTIAL because "no vector presents
an authority chain that expired between approval issuance and consumption". The same
vectors bear on the "recheck time" clause of `REQ-5.3.2-1` (section 5.3.2 line 1096),
whose revision 5 note credits only the expiry, consumption and revocation clauses. This
family is not yet cited by `docs/ID-COVERAGE.md`, and nothing here changes any row of
that inventory until a revision of it does so.

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
including revocation status and temporal validity". Section 3.2 (line 535) writes a
child's time facet as the half-open interval `[not_before, not_after)`, and both runners
read the temporal validity of every chain member at an instant against its interval.

## The `not_after` edge

AEX-05 consumes at exactly a child delegation's `not_after`, while that child's parent
is still valid, and expects a refusal. Its basis is the text, not the SDK. Section 3.2,
line 535:

    535    Time  The half-open child interval [not_before, not_after) MUST be

The interval is named half-open and closed with `)`, so the child's `not_after` is not
in it. Section 3.3 line 584 lists "current validity" among the chain verification steps
for every member, so at that instant the chain is not currently valid. AEX-05's chain is
two hops: a root from the principal to a coordinator, valid `[08:00, 10:00)`, and a
child from the coordinator to the acting agent, valid `[08:00, 09:00)`. At `09:00:00`
the root is inside its window and only the child is at its excluded end.

The vector uses a child on purpose. Line 535 states the half-open interval for a child.
For a root, the draft states no endpoint rule of its own, so an instant equal to a root's
`not_after` is not presented. AEX-04 is backed by a root, but it is consumed ten seconds
after that root's `not_after`, which is outside the window under either endpoint reading.

The pinned SDK agrees with this vector (`now >= time.not_after` returns `EXPIRED`,
phase 10). `mint.ts` asserts before writing that the root alone is valid at `09:00:00`,
that the two-hop chain is valid at `08:59:59.999`, and that it is `invalid`/`EXPIRED`
at `09:00:00`.

## The gap this closes

`approval-single-use` covers the approval's own expiry (ASU-03) and a revoked authority
at consumption (ASU-05). Every presentation in it is consumed while its backing
delegation is inside its validity window (`2026-09-22T08:00:00.000Z` to
`2026-09-23T00:00:00.000Z`, and every presentation is at `09:00:xx` on 2026-09-22). So a
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
(`verifyAuthorityDelegationChain`, whose temporal check is phase 10 at
`node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.js` lines
234-242, and revocation is phase 11 starting line 244).

## What the family does

`mint.ts` mints with the pinned SDK:

- two one-hop `AuthorityDelegationV1` records, principal to acting agent, identical
  except for their nonce, both valid `[2026-09-24T08:00:00.000Z,
  2026-09-24T09:00:00.000Z)`. `DELEGATION_MAIN` backs the decisions AEX-01, AEX-03 and
  AEX-04 present. AEX-02's is backed by `DELEGATION_FOR_REVOCATION_CASE` alone.
- one two-hop chain for AEX-05: `EDGE_ROOT`, principal to coordinator, valid
  `[08:00:00.000Z, 10:00:00.000Z)` with one hop of depth remaining, and `EDGE_CHILD`,
  coordinator to acting agent, valid `[08:00:00.000Z, 09:00:00.000Z)`.
- one action-intent and its action reference.
- five permit policy-decision receipts for that action, each issued between
  `08:59:40` and `08:59:44`, inside every authority window. Each names the leaf of its
  chain as `delegation_ref`, and its decision evidence lists the whole chain as
  `selected_chain`. Four carry `valid_until` `2026-09-24T09:00:30.000Z`, thirty seconds
  after the `09:00:00` `not_after`. One (`decision_permit_approval_expired`) carries
  `valid_until` `08:59:44`.

`chain.json` names the root-to-leaf chains in a `chains` map (`main`,
`for_revocation_case`, `edge`), and each presentation names one of them.

`mint.ts` asserts at mint time, and writes nothing if any assertion fails: every
decision's chain verifies `valid` at its `evaluated_at`, `DELEGATION_MAIN` verifies
`valid` at `08:59:50` and `invalid`/`EXPIRED` at `09:00:10`, the revocation-case
delegation verifies `invalid`/`REVOKED` when its resolver answers `revoked`, the edge
root alone verifies `valid` at `09:00:00` while the edge chain verifies `valid` at
`08:59:59.999` and `invalid`/`EXPIRED` at `09:00:00`, `09:00:00` and `09:00:10` are
before the permits' `valid_until`, every delegation and every decision has a distinct
id, and every receipt verifies `status: "valid"` under `verifyReceiptV1`.

`harness.ts` implements `ConsumptionBoundary`, one class with two configurations that
differ in one thing, the instant the authority chain is re-verified at:

- **`reference-boundary`**: signature and stage validity, deny is terminal, action_ref
  binding, the approval's own expiry, single-use consumption, then
  `verifyAuthorityDelegationChain` at the consumption instant with the consumption-time
  revocation answer (`harness.ts` lines 120-134).
- **`defective-boundary-authority-time-frozen-at-issuance`**: every step identical,
  except the chain is re-verified at the decision's own `issued_at`. It still uses the
  consumption-time revocation answer and still enforces the approval's own
  `valid_until`. This is the boundary the revision 5 note on `REQ-4.3-1` cannot yet rule
  out: one that rechecks revocation and approval expiry but not the authority's
  temporal validity.

`verify.ts` runs both configurations over the same five presentations, in clock order.
Before either boundary runs, it exits 2 if either file's `profile` is not
`aps-approval-authority-expiry-v0`, if the presentations are not exactly AEX-01, AEX-02,
AEX-03, AEX-05 and AEX-04 in that order, if the declared failing set is not exactly
AEX-04 and AEX-05, if a field has the wrong type, if a `now` is not a UTC millisecond
instant, if a `revocation` is anything other than `active` or `revoked`, if a
presentation is earlier than the one before it, if a decision, chain, delegation or
action name is unknown, if a chain's leaf is not the decision's `delegation_ref`, or if
a chain is not the decision evidence's `selected_chain`. The case inventory is fixed
because AEX-02 and AEX-03 are what give the declared failing set its meaning. A corpus
without them is malformed, not a smaller pass. Its key resolvers return a key only for
the signer or issuer whose identifier prefixes the key id, so a receipt signed with
another party's key does not verify as the boundary's.

`verify.py` is a second, separately written, stdlib-only implementation of the same
boundary rules, with the same input checks. It does not call the SDK and verifies no
signature and no chain structure (parent links, issuer continuity, facet narrowing). It
applies the half-open window to each chain member's `authority.time`, then the
presentation's revocation answer, to fields `mint.ts` already verified with the SDK. Its
module docstring says so.

## Vectors, timeline style, one clock

Five presentations, listed in clock order, against one boundary instance per
configuration and one fixture-pinned clock. AEX-05 is listed before AEX-04 because it
is earlier.

| id | covers | differs from AEX-01 by | expected |
|---|---|---|---|
| AEX-01-accept-authority-valid-at-consumption | positive control | nothing, consumed at `08:59:50`, authority valid, approval unexpired | admitted, `dispatch_admitted` |
| AEX-02-reject-authority-revoked-at-consumption | revocation recheck still present | authority answers `revoked` at consumption | not admitted, `authority_chain_not_valid_at_consumption`, `invalid/REVOKED` |
| AEX-03-reject-approval-expired | approval expiry still present | the approval's own `valid_until` has passed, authority still valid | not admitted, `expired` |
| AEX-05-reject-authority-at-exact-not-after | the half-open child edge | backed by the two-hop `edge` chain, consumed at exactly `09:00:00`, the child's `not_after`, while the parent is valid until `10:00:00` and before the approval's `valid_until` | not admitted, `authority_chain_not_valid_at_consumption`, `invalid/EXPIRED` |
| AEX-04-reject-authority-expired-approval-unexpired | **the gap** | consumed at `09:00:10`: after the authority's `not_after` (`09:00:00`), before the approval's `valid_until` (`09:00:30`) | not admitted, `authority_chain_not_valid_at_consumption`, `invalid/EXPIRED` |

AEX-01, AEX-04 and AEX-05 present three distinct permits minted identically except for
`evaluated_at` (`08:59:40`, `08:59:43` and `08:59:44`), because a single-use ledger would otherwise
refuse the second presentation as `already_consumed`. The input that decides the outcome
is the consumption instant.

AEX-02 and AEX-03 exist so the declared failing set is meaningful. With only AEX-01,
AEX-04 and AEX-05, a boundary that rechecked nothing would also fail exactly the two
authority-time vectors. AEX-02 shows the defective boundary still rechecks revocation,
and AEX-03 shows it still enforces the approval's own expiry, so a boundary that fails
AEX-04 and AEX-05 and passes the other three is missing the authority-time recheck at
consumption. The set does not tell apart a boundary that evaluates authority time at
issuance from one that never evaluates it. Every permit here is issued inside its
authority window, so both behave the same on these five vectors. AEX-05 separates a
boundary that compares `now > not_after` from one that compares `now >= not_after`.
AEX-04 alone does not.

## Negative control

The defective boundary matches the reference on AEX-01, AEX-02 and AEX-03. On AEX-05 and
AEX-04 it re-verifies the chain at the decision's `issued_at` (`08:59:44` and
`08:59:43`), when the authority was valid, and admits. The declared failing set:

    AEX-05-reject-authority-at-exact-not-after
    AEX-04-reject-authority-expired-approval-unexpired

Both runners check this in both directions. On each declared id the defective boundary
must admit, with `admitted` true, reason `dispatch_admitted` and no detail. A refusal
for any other reason is reported as `DEFECT DID NOT REPRODUCE` and fails the run, since
the declared defect is wrongful admission, not any divergence. Every other id must still
match its expected outcome.

## Running

TypeScript, wired into `npm test`:

    npm ci --include=dev
    npm run verify:approval-authority-expiry

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set

Regenerating `chain.json` gives the same bytes:

    npx tsx fixtures/approval-authority-expiry/mint.ts

Python, separately written, not part of `npm test` (which also runs on the Windows job
with Node only). The tests workflow's suite job runs it after setting up Python 3.12,
the same way it runs `fixtures/teardown-accounting/verify.py`:

    npm run verify:approval-authority-expiry:py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)

## Results

Both runners were executed locally on the branch rebased onto suite `main` at
`53ee63f`, after `npm ci --include=dev`. `verify.ts` (Node 24.11.1) ran against the
pinned TypeScript SDK (`agent-passport-system` 7.1.0, `package-lock.json`), and
`verify.py` (Python 3.14.6) read `chain.json` and `vectors.json` alone. `reference-boundary`
matched 5/5 presentations under both runners. `defective-boundary-authority-time-frozen-at-issuance`
admitted exactly the declared set of 2 under both, AEX-05 and AEX-04, with reason
`dispatch_admitted`, and matched the other 3. `mint.ts` run twice produced byte-identical
`chain.json`. This is an author-produced record, not an independent one, per
`CONTRIBUTING.md`'s admission rules for run records.

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
consumption instant, and is not admitted at exactly a child delegation's `not_after`
while its parent is still valid (see "The `not_after` edge" for the textual basis of
that case). It also establishes that the declared defective boundary, which differs only
in evaluating the authority's temporal validity at the decision's `issued_at`, admits
AEX-04 and AEX-05 and matches the other three. That pattern is consistent with the
declared defect. It does not identify it uniquely.

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
- anything about a root delegation at exactly its own `not_after`. Line 535 writes the
  half-open interval for a child, and the draft states no separate endpoint rule for a
  root, so no vector presents that instant. AEX-05's expected result rests on line 535
  read with "current validity" in section 3.3 line 584. If a later draft defines
  delegation validity differently, AEX-05 is the vector to revisit.
- anything about the `not_before` edge. No vector consumes at exactly `not_before`.
- anything about longer chains, ancestor expiry, or a parent expiring before a child.
  AEX-05 is two hops with the parent outliving the child. Every other chain is one hop.
- a difference between a boundary that evaluates authority time at issuance and one
  that never evaluates it. Both admit AEX-04 and AEX-05 and match the other three.
- anything about spend reservation (section 4.3 lines 920 onward). The harness does not
  implement it.
- anything about single-use consumption, deny handling or action binding beyond what
  `approval-single-use` already covers. The harness carries those steps so the other
  checks run in the same order as that family's boundary. No vector here targets them.
- that `authority_chain_not_valid_at_consumption`, `invalid/EXPIRED` or any other reason
  string is normative. They are this family's labels, reused from `approval-single-use`
  for consistency.
- that this family's ordering (consumption before the chain recheck, following
  `approval-single-use`) is the only defensible one.
- anything about `agent-passport-system` for Python. `verify.py` is a from-scratch,
  no-dependency reimplementation of the boundary rules, not a Python SDK run.
