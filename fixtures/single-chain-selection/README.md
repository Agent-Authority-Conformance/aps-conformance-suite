# Single-chain selection: no union of scopes or budgets across chains

This fixture exercises one property of `AuthorityDelegationV1` chain
verification: an action is evaluated against exactly one presented
root-to-leaf chain, and a verifier must not combine the scope grants or spend
ceilings of a second, independently held chain into that evaluation, even
when the same leaf agent holds both chains and could present either one.

This is plain draft-03 conformance, not a proposal. draft-pidlisnyi-aps-03
already states this rule for a verifier evaluating one presented chain; this
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

## SDK surface

Both reference SDKs' one exported entry point for checking a proposed
authority vector against a chain is `verifyAuthorityDelegationChain` /
`verify_authority_delegation_chain` itself: its phase 9 runs the seven-facet
narrowing check of Section 3.2 (`compareAuthority` / `compare_authority`)
between every adjacent pair in the presented chain array. Neither published
package exports a separate function for checking an action's scope or spend
need against an already-verified chain.

TypeScript specifically: `agent-passport-system`'s `package.json` declares an
`exports` map with exactly two entries, `"."` and `"./core"`
(`node_modules/agent-passport-system/package.json`). The modules that hold
the draft-03-conformant scope and spend checks,
`dist/src/v2/authority-delegation/scope.js` (`scopeGrantCovers`,
`scopeNarrows`) and `dist/src/v2/authority-delegation/budget.js`
(`InMemoryAuthorityBudgetLedger.reserve`), are not re-exported from
`dist/src/index.js` and are therefore unreachable by a normal import of the
published package; importing either module path directly raises
`ERR_PACKAGE_PATH_NOT_EXPORTED`, confirmed while authoring this fixture. The
package's public surface does export `scopeCovers` / `scopeAuthorizes`
(`core/delegation.js`), but that pair is explicitly documented in the SDK's
own source, `dist/src/core/delegation.d.ts` lines 55-57, as "the pre-draft
rule", distinct from the draft-path narrowing check, so it is not used here.

Given that, this fixture models each action's scope and spend requirement as
a second, synthetic `AuthorityDelegationV1` hop appended after the leaf,
signed by the leaf's own key, then relies on `verifyAuthorityDelegationChain`
itself, called on the two-element array, to decide whether that hop's
authority is covered by the presented chain. This reaches exactly the same
Section 3.2 narrowing check that a direct call to `scopeNarrows` or the
budget ledger would apply, through the one entry point both SDKs' published
packages actually export in both languages. `mint.py` documents this
technique in full and signs the reject vectors' widening hops by calling the
SDK's lower-level `compute_authority_delegation_id_for_write` and
`sign_authority_delegation` primitives directly, bypassing
`issue_sub_authority_delegation`'s own cooperative-issuance narrowing check,
because that check would otherwise refuse to sign a hop wide enough to
demonstrate a reject vector. What is tested is chain verification's refusal
of a widening record that is nonetheless syntactically valid and correctly
signed, not the issuer's willingness to create one. Do not read the
synthetic action hop as new protocol wire format, or as a claim that an
action is issued as a delegation on any real wire; it is this fixture's own
technique for reaching the SDKs' one exported narrowing check, stated here so
it cannot be mistaken for either.

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
field on each vector records what the named presented chain's second hop
encodes; it is documentation, matching what `mint.py` minted, and is never
read by `verify.ts` or `validate.py`, which read only `presented_chain`.

| id | presented chain | change from its control | expected |
|---|---|---|---|
| SCS-01 | chain 1 + hop(needs `calendar:write`, amount 50) | control | valid |
| SCS-02 | chain 2 + hop(needs `payments:refund`, amount 50) | control | valid |
| SCS-03 | chain 1 + hop(needs `calendar:write`+`payments:refund`, amount 50) | scope widened to add `payments:refund`, which chain 1 never granted | invalid, `SCOPE_WIDENING`, index 1 |
| SCS-04 | chain 2 + hop(needs `calendar:write`+`payments:refund`, amount 50) | scope widened to add `calendar:write`, which chain 2 never granted | invalid, `SCOPE_WIDENING`, index 1 |
| SCS-05 | chain 1 + hop(needs `calendar:write`, amount 100) | amount raised from 50 to 100, above chain 1's own 60 ceiling | invalid, `SPEND_WIDENING`, index 1 |
| SCS-06 | chain 1's root immediately followed by chain 2's root, no requirement hop | presentation is a concatenation of both chains' roots, not chain 1 alone | invalid, `PARENT_MISMATCH`, index 1 |

### SCS-05 is the union check

SCS-05's amount, 100, exceeds chain 1's own ceiling of 60 but not the sum of
chain 1's and chain 2's ceilings, 120. `verifyAuthorityDelegationChain` is
called with chain 1's two-element presented array only; chain 2's record
never appears in that call's argument, in the verification-key resolver, or
anywhere else reachable from it. A verifier that somehow unioned the two
chains' budgets would wrongly accept 100 against a combined 120; this
fixture's presented array structurally cannot supply that union, because the
one exported entry point takes a single chain array and nothing else. The
rejection here is therefore evidence of the single-chain-selection property
lines 594-596 requires, not only of chain 1's own ceiling being enforced.

### SCS-06 is not a union either

SCS-06 does not test what a union of the two chains would decide once
formed; it tests that the SDK never gets that far. `parent_delegation_id` is
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
package.

From the conformance-suite root:

    npm ci --include=dev
    npm run verify:single-chain-selection

It also runs as part of `npm test`.

Expected final line:

    single-chain-selection TypeScript: 6/6 passed

## Python

Run against the actual Python SDK under test, for example:

    PYTHONPATH=/path/to/agent-passport-python/src \
      python3 fixtures/single-chain-selection/validate.py

Expected final line:

    single-chain-selection Python: 6/6 passed

## Provenance

Vectors, `chains.json`, `mint.py`, `verify.ts` and `validate.py` are authored
for this suite, adapting the minting, key-resolution and resolver pattern
already established by
[`fixtures/ancestor-revocation-chain/`](../ancestor-revocation-chain/README.md)
and
[`fixtures/revocation-resolution-forward-compat/`](../revocation-resolution-forward-compat/README.md)
to two independent single-hop chains and a synthetic per-action requirement
hop. Both runners were executed locally against the pinned TypeScript SDK
(`agent-passport-system`, package.json) and the Python SDK checkout at
`agent-passport-python/src` on this machine; this is an author-produced
record, not an independent one, per `CONTRIBUTING.md`'s admission rules for
run records.

## What a pass establishes

For the exact SDK revision that was run, a pass establishes that:

- an action whose scope and spend requirement is fully covered by the one
  chain it is presented with verifies valid
- an action whose scope requirement exceeds what the presented chain granted
  is rejected with `SCOPE_WIDENING`, regardless of whether a second chain the
  same leaf agent holds would have covered the missing scope
- an action whose amount exceeds the presented chain's own spend ceiling is
  rejected with `SPEND_WIDENING`, even when a second chain the same leaf
  agent holds has its own separate ceiling that would, summed, have been
  enough
- a presentation that concatenates two chains' roots into one array is
  rejected as a malformed chain, at the existing parent-linkage check, before
  any scope or spend comparison runs
- both reference SDKs decide all six cases identically through the one
  entry point their published packages export for this check

## Does not claim

A pass does **not** establish:

- anything about cross-principal composition. Line 596 states explicitly
  that cross-principal composition requires a separate profile; this fixture
  does not define, approximate, or test that profile. P1 and P2 here are two
  separate roots delegating to the same leaf, not a composition of two
  principals' authority into one grant
- anything about cumulative spend across a delegation subtree, Section 3.4's
  ledger. Both chains here are single-hop with no descendants, and the
  budget check this fixture exercises is the static per-hop attenuation
  ceiling of Section 3.2, not the running reserved/committed ledger of
  Section 3.4. `InMemoryAuthorityBudgetLedger`, the SDK's runtime ledger for
  that section, is not used by this fixture; see "SDK surface" above for why
- which chain an implementation should choose when a leaf holds several
  chains that would each independently authorize an action. Every vector
  here presents the runner with exactly one chain already selected; this
  fixture says nothing about how that selection is made or whether a
  particular selection policy is required
- that the synthetic action-as-delegation-hop technique this fixture uses is
  itself a protocol mechanism, a recommended enforcement pattern, or
  anything an implementation needs to replicate internally. It is this
  fixture's way of reaching the one check both SDKs export publicly; see
  "SDK surface" above
- that this behavior is unique to the SDKs run here, or that every
  independent draft-03 implementation has been checked
- anything about revocation, chain depth beyond the two hops each presented
  array uses, or any of the other chain-verification phases lines 580-592
  list. Every record in every presented chain here resolves `active` and
  passes every phase before the one under test in each vector
