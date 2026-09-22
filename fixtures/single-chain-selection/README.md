# Single-chain selection: no union of scopes or budgets across chains

This fixture exercises one property of `AuthorityDelegationV1` chain
verification: an action is evaluated against exactly one presented
root-to-leaf chain, and a verifier must not combine the scope grants or spend
ceilings of a second, independently held chain into that evaluation, even
when the same leaf agent holds both chains and could present either one.

This is plain draft-03 conformance, not a proposal. draft-pidlisnyi-aps-03
already states this rule for a verifier evaluating one presented chain. This
fixture makes that existing required behavior executable and reviewable, the
same way [C19](../revocation-resolution-forward-compat/README.md) and
[AAC](../ancestor-revocation-chain/README.md) did for two other verifier
boundaries. It does not propose new wording.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/), Section 3.3,
"Chain Verification", lines 578-596 of the plain-text rendering:

    578 3.3.  Chain Verification
    579
    580    A verifier processes a root-to-leaf chain in this order: closed
    581    schema and canonical values; delegation_id; historical signing-key
    582    resolution and signature; duplicate identifiers; root trust;
    583    parent_delegation_id; issuer-to-subject continuity; child issuance
    584    time; the seven facet comparisons in Section 3.2; current validity;
    585    and revocation state for every member.  A cycle, repeated identifier,
    586    broken parent link, or issuer discontinuity invalidates the chain.
    587
    588    Verification returns one of valid, invalid, indeterminate, or
    589    unsupported with a stable failure code.  An unavailable or stale
    590    revocation result is indeterminate.  An unsupported facet profile is
    591    unsupported.  Cryptographic or attenuation failure is invalid.  A
    592    caller MUST NOT collapse indeterminate or unsupported into valid.
    593
    594    Each action selects one root-to-leaf authority chain.  A verifier
    595    MUST NOT union scopes or budgets from multiple chains.  Cross-
    596    principal composition requires a separate profile.

The load-bearing sentences are lines 594-596: an action selects a single
chain, and scopes or budgets from a second chain the same agent may also hold
must not be combined into the evaluation of that action. Lines 588-592
immediately above set the four-valued result vocabulary (valid, invalid,
indeterminate, unsupported) this fixture's expected results are drawn from,
and state that attenuation failure is invalid, which is the failure category
every reject vector here falls into.

## Primary path

As of `agent-passport-system` 7.1.0, both reference SDKs' published packages
export the real scope-covering and budget-ledger primitives from their
package root, not only the chain-level `verifyAuthorityDelegationChain` /
`verify_authority_delegation_chain` entry point. This fixture's primary path
(vectors SCS-01 to SCS-05) uses those primitives directly, one call per
decision, on the one chain (`chains.json`'s `chain_1` or `chain_2`, the root
alone, no synthetic hop) each vector's `primary_chain` field names:

1. **Chain state.** `verifyAuthorityDelegationChain(chain, { now, resolveVerificationKey, trustRoot, resolveRevocation })`
   (`verify_authority_delegation_chain` in Python), with `now` and
   `verification_keys` taken from `chains.json`, revocation resolved `active`,
   and the root trusted. All five vectors' chains resolve `valid` here. This
   phase exists so a chain failure, were one introduced, would be reported by
   its own failure code rather than mistaken for a scope or budget rejection.
2. **Scope.** For every grant the action needs (`vector.action.scope_needed`),
   `isValidScopeGrant(needed)` / `is_valid_scope_grant(needed)` must hold, and
   some grant on the chain's leaf (`chain[chain.length - 1].authority.scope.grants`,
   the last, and here the only, member of the presented chain) must cover it:
   `scopeGrantCovers(grant, needed)` / `scope_grant_covers(grant, needed)`. A
   need not covered by any leaf grant is rejected with reason
   `scope_not_covered`.
3. **Budget.** A fresh `new InMemoryAuthorityBudgetLedger()` /
   `InMemoryAuthorityBudgetLedger()` per vector reserves the action's amount
   against the chain: `.reserve(chain, actionRef, unit, amount)`, with
   `actionRef` a deterministic 64-character lowercase hex string, the SHA-256
   hex digest of the vector's own id. The ledger's own result code, `RESERVED`
   on success or a rejection code such as `PER_ACTION_EXCEEDED` on failure, is
   recorded as the reason.

An action is admitted only if all three pass. `verify.ts` and `validate.py`
each run this exact sequence and record, per vector, in `vectors.json`'s
`primary_expected` field, the resulting state and reason.

SCS-06 has no `primary_chain`: it is a concatenation of both chains' roots,
not a selection of one, so the primary path does not run for it. It is
decided only by the cross-check below, unchanged.

## Cross-check: the synthetic-hop path

The fixture's original technique, from before 7.1.0 exported the primitives
above, remains as a cross-check that must agree with the primary path on
every vector's state. It models each action's scope and spend requirement as
a second, synthetic `AuthorityDelegationV1` hop appended after the leaf,
signed by the leaf's own key, then relies on `verifyAuthorityDelegationChain`
itself, called on the two-element array, to decide whether that hop's
authority is covered by the presented chain. This reaches the same Section
3.2 narrowing check (`compareAuthority` / `compare_authority`, run as chain
verification's phase 9) that the primary path's scope and budget primitives
apply directly. `mint.py` documents this technique in full and signs the
reject vectors' widening hops by calling the SDK's lower-level
`compute_authority_delegation_id_for_write` and `sign_authority_delegation`
primitives directly, bypassing `issue_sub_authority_delegation`'s own
cooperative-issuance narrowing check, because that check would otherwise
refuse to sign a hop wide enough to demonstrate a reject vector. What is
tested is chain verification's refusal of a widening record that is
nonetheless syntactically valid and correctly signed, not the issuer's
willingness to create one. Do not read the synthetic action hop as new
protocol wire format, or as a claim that an action is issued as a delegation
on any real wire. It is this fixture's own second route to the same
rejection, kept as a cross-check precisely because it was, until 7.1.0, the
only route.

`verify.ts` and `validate.py` both run the primary path and the synthetic-hop
path for every vector and fail if the two paths' states (valid or invalid)
differ on any of SCS-01 to SCS-05. Their reasons are expected to differ in
name: the primary path names the check that actually rejected (a scope
predicate, or the budget ledger's own code), while the synthetic-hop path
names whichever chain-verification failure code
`verifyAuthorityDelegationChain` attached to the synthetic hop. SCS-05 is the
clearest case: the primary path's ledger rejects with `PER_ACTION_EXCEEDED`
because the action's amount, evaluated as a spend reservation against chain
1's own ceiling, exceeds it. The synthetic-hop path rejects with
`SPEND_WIDENING` because chain verification's phase 9 sees the synthetic
hop's own declared spend facet as wider than its parent's. Both names
describe the same fact, chain 1 alone cannot cover the requested amount, seen
through two different checks.

## Case

**Setup:** one leaf agent L holds two independent single-hop
`AuthorityDelegationV1` chains from two different roots, P1 and P2
(`chains.json`, `chain_1` and `chain_2`). Chain 1 grants scope
`calendar:write` with a bounded spend ceiling of 60 (`per_action` and
`cumulative`, unit `iso4217:USD:minor`). Chain 2 grants a disjoint scope,
`payments:refund`, with an equal ceiling of 60 in the same unit. Neither
chain's ceiling is derived from or aware of the other's.

**Input:** six presented chains (`chains.json`'s `presented` map), each
either chain 1 or chain 2 with a second hop appended encoding one action's
scope and spend requirement, or, for the sixth case, chain 1's root directly
followed by chain 2's root with no requirement hop at all.

**Expected outcome:** an action whose requirement is fully covered by the one
chain it is presented with is valid. An action whose requirement exceeds what
that one chain grants, in scope or in spend, is invalid with an attenuation
failure code at the second hop. An action amount that chain 1 alone cannot
cover is rejected even though chain 1 and chain 2's ceilings would together
be enough, because chain 2 is never consulted. A presentation that
concatenates both chains' roots into one array is rejected as a malformed
chain before any scope or spend evaluation runs, never evaluated as a union
of the two.

## Controls

Cases 1 and 2 are the positive controls: chain 1 covers its own action and
chain 2 covers its own action, each shown valid before any reject case is
introduced. Every reject case differs from its nearest control by exactly one
stated change.

## Vectors

There are 6 cases in `vectors.json`, run against `chains.json`. The `action`
field on each vector records the action's scope and spend requirement. The
primary path reads it directly (`scope_needed`, `unit`, `amount`), and it
also matches what `mint.py` baked into the named presented chain's synthetic
second hop, which the cross-check path reads instead, through
`presented_chain`.

| id | primary chain | action requirement | change from its control | primary: state, reason | synthetic: state, reason |
|---|---|---|---|---|---|
| SCS-01 | chain 1 | needs `calendar:write`, amount 50 | control | valid, `RESERVED` | valid |
| SCS-02 | chain 2 | needs `payments:refund`, amount 50 | control | valid, `RESERVED` | valid |
| SCS-03 | chain 1 | needs `calendar:write`+`payments:refund`, amount 50 | scope widened to add `payments:refund`, which chain 1 never granted | invalid, `scope_not_covered` | invalid, `SCOPE_WIDENING`, index 1 |
| SCS-04 | chain 2 | needs `calendar:write`+`payments:refund`, amount 50 | scope widened to add `calendar:write`, which chain 2 never granted | invalid, `scope_not_covered` | invalid, `SCOPE_WIDENING`, index 1 |
| SCS-05 | chain 1 | needs `calendar:write`, amount 100 | amount raised from 50 to 100, above chain 1's own 60 ceiling | invalid, `PER_ACTION_EXCEEDED` | invalid, `SPEND_WIDENING`, index 1 |
| SCS-06 | (none, concatenation) | needs `calendar:write`, amount 50 | presentation is a concatenation of both chains' roots, not chain 1 alone | not run | invalid, `PARENT_MISMATCH`, index 1 |

The primary path's state and reason above are recorded in each vector's
`primary_expected` field, and the synthetic path's, in `expected`. Both
`verify.ts` and `validate.py` check both fields, plus that the two paths'
states agree, on SCS-01 to SCS-05. See "Primary path" and "Cross-check" above
for what each column's reason names.

### SCS-05 is the union check

SCS-05's amount, 100, exceeds chain 1's own ceiling of 60 but not the sum of
chain 1's and chain 2's ceilings, 120. On the primary path,
`InMemoryAuthorityBudgetLedger.reserve` is called with chain 1's own
one-element array only. Chain 2's record never appears in that call's
argument, or anywhere else reachable from it, so there is no way for its
ceiling to be added in. On the synthetic-hop path,
`verifyAuthorityDelegationChain` is likewise called with chain 1's
two-element presented array only. A verifier that somehow unioned the two
chains' budgets would wrongly accept 100 against a combined 120. Both paths'
inputs structurally cannot supply that union, because neither the ledger's
`reserve` nor the chain verifier takes more than the one chain array each is
given. The rejection here is therefore evidence of the single-chain-selection
property lines 594-596 requires, not only of chain 1's own ceiling being
enforced.

### SCS-06 is not a union either

SCS-06 does not test what a union of the two chains would decide once
formed. It tests that the SDK never gets that far. `parent_delegation_id` is
null on both records (each is a root), so `verifyAuthorityDelegationChain`'s
existing phase 6 check (parent_delegation_id, draft lines 580 and 582) fails
at index 1 before phase 9's facet comparisons, where a scope or spend union
would have to be computed, ever runs. This fixture does not construct any
input that reaches phase 9 with both chains' authority present at once: the
SDK's own chain-continuity check refuses the concatenation first, and no
input this fixture could construct through either SDK's public issuance or
parsing surface reaches further than that. That absence is itself the
evidence: neither SDK offers a way to present two chains as if they were one
that gets past the existing continuity check.

## chains.json

`chains.json` holds `chain_1`, `chain_2`, and `presented`, a map from each
vector's `presented_chain` key to the exact array `verifyAuthorityDelegationChain`
is called with. It is generated by `mint.py` from published seed labels, so
it carries no secret material and regenerates byte for byte:

    python3 fixtures/single-chain-selection/mint.py

After regeneration `git diff` on `chains.json` should be empty (verified as
part of authoring this fixture by regenerating and diffing, since it is
newly added and not yet tracked at a prior revision).

## TypeScript

The repository root currently pins the published `agent-passport-system`
package at 7.1.0, the first version whose `package.json` `exports` map
re-exports `isValidScopeGrant`, `scopeGrantCovers`, `scopeNarrows` and
`InMemoryAuthorityBudgetLedger` from the package root (`dist/src/index.js`),
alongside `verifyAuthorityDelegationChain`. That is what makes the primary
path possible. See "Primary path" above.

From the conformance-suite root:

    npm ci --include=dev
    npm run verify:single-chain-selection

It also runs as part of `npm test`.

Expected final line:

    single-chain-selection TypeScript: 6/6 passed

## Python

Run against the published `agent-passport-system` 4.0.0 in a clean virtual
environment, for example:

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install agent-passport-system==4.0.0
    /path/to/venv/bin/python fixtures/single-chain-selection/validate.py

`agent_passport.v2.authority_delegation` has exposed `is_valid_scope_grant`,
`scope_grant_covers` and `InMemoryAuthorityBudgetLedger` as ordinary public
names since before this fixture existed. Python never had the packaging
restriction TypeScript had before 7.1.0 (see "Primary path" above), so its
primary path runs against the same published 4.0.0 the synthetic-hop path
already used.

Expected final line:

    single-chain-selection Python: 6/6 passed

## Provenance

Vectors, `chains.json`, `mint.py`, `verify.ts` and `validate.py` are authored
for this suite, adapting the minting, key-resolution and resolver pattern
already established by
[`fixtures/ancestor-revocation-chain/`](../ancestor-revocation-chain/README.md)
and
[`fixtures/revocation-resolution-forward-compat/`](../revocation-resolution-forward-compat/README.md)
to two independent single-hop chains, a synthetic per-action requirement hop,
and, since 7.1.0, a primary path calling the same SDKs' scope and budget
primitives directly. Both runners were executed locally: the TypeScript
runner against the published `agent-passport-system` 7.1.0 from npm
(`package.json`, `node_modules/agent-passport-system/package.json`), the
Python runner against the published `agent-passport-system` 4.0.0 installed
in a clean virtual environment (`importlib.metadata.version("agent-passport-system")`
reports `4.0.0` in that environment), not a local source checkout. This is an
author-produced record, not an independent one, per `CONTRIBUTING.md`'s
admission rules for run records.

## What a pass establishes

For the exact SDK revision that was run, a pass establishes that:

- an action whose scope and spend requirement is fully covered by the one
  chain it is presented with verifies valid on the primary path (the ledger
  reserves it, code `RESERVED`) and on the synthetic-hop cross-check
- an action whose scope requirement exceeds what the presented chain granted
  is rejected on the primary path (`scope_not_covered`) and on the
  synthetic-hop cross-check (`SCOPE_WIDENING`), regardless of whether a
  second chain the same leaf agent holds would have covered the missing scope
- an action whose amount exceeds the presented chain's own spend ceiling is
  rejected on the primary path, by the budget ledger's own
  `PER_ACTION_EXCEEDED` code, and on the synthetic-hop cross-check
  (`SPEND_WIDENING`), even when a second chain the same leaf agent holds has
  its own separate ceiling that would, summed, have been enough
- a presentation that concatenates two chains' roots into one array is
  rejected as a malformed chain, at the existing parent-linkage check, before
  any scope or spend comparison runs (the synthetic-hop path only, since the
  primary path does not run on this vector, having no single chain to select)
- both reference SDKs' primary and cross-check paths agree on state for
  every vector they both decide, through the real scope and budget
  primitives and through the one chain-verification entry point,
  respectively, that their published packages export for this check

## Does not claim

A pass does **not** establish:

- anything about cross-principal composition. Line 596 states explicitly
  that cross-principal composition requires a separate profile. This fixture
  does not define, approximate, or test that profile. P1 and P2 here are two
  separate roots delegating to the same leaf, not a composition of two
  principals' authority into one grant
- anything about cumulative spend across a delegation subtree tracked over
  more than one action, Section 3.4's running reserved/committed ledger
  behavior across a sequence of reservations. The primary path does call
  `InMemoryAuthorityBudgetLedger.reserve` (see "Primary path" above), but with
  a fresh ledger per vector and exactly one reservation against it, so what
  it exercises is a single reservation's own per-action and cumulative
  ceiling check, not the ledger's behavior across multiple actions,
  dispatch, commit, or cancellation
- which chain an implementation should choose when a leaf holds several
  chains that would each independently authorize an action. Every vector
  here presents the runner with exactly one chain already selected. This
  fixture says nothing about how that selection is made or whether a
  particular selection policy is required
- that the synthetic action-as-delegation-hop technique the cross-check path
  uses is itself a protocol mechanism, a recommended enforcement pattern, or
  anything an implementation needs to replicate internally. It is this
  fixture's own second route to the same rejection the primary path reaches
  directly. See "Cross-check: the synthetic-hop path" above
- that this behavior is unique to the SDKs run here, or that every
  independent draft-03 implementation has been checked
- anything about revocation, chain depth beyond the two hops each presented
  array uses, or any of the other chain-verification phases lines 580-592
  list. Every record in every presented chain here resolves `active` and
  passes every phase before the one under test in each vector
