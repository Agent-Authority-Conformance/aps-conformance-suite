# Chain selection with no union: write of resource 1 is not read of 1 plus write of 2

One leaf agent holds more than one independently rooted authority chain. This
family asks two questions about that situation:

1. Can an action be admitted on the strength of grants and budgets that are
   spread across those chains rather than present in the one chain the action
   selected? It must not be.
2. When the chain an action selected turns out to be revoked, can an
   implementation quietly decide the action against a different chain the same
   agent happens to be holding? It must not, not without that switch being an
   explicit decision.

Question 1 is stated normatively in draft-pidlisnyi-aps-03 Section 3.3.
Question 2 is not stated anywhere in draft-03, and this family says so rather
than implying otherwise.

## Status

Every vector in this family carries `status: "candidate_against_proposed"`. It
is a candidate case against proposed text, not a draft-03 conformance family,
and merging it would not make it one. The proposed text under test is:

- **L5. Independent chains are not combined** and
- **L11. No silent authority resurrection**

both in `AUTHORITY-LIFECYCLE.md` of `aeoess/agent-authority-lifecycle` at
commit `5c1bf09ee29d517f2f19c9bb9212543a7c44b227`, cited by section name above
and in each vector's `tests` field. That document is the proposal this family
is a candidate against. It is not offered here as independent corroboration of
anything.

Where draft-03 does state the rule, each vector names the section. Vectors
CSNU-01 to CSNU-08 carry `draft03: {"section": "3.3 Chain Verification",
"lines": "594-596"}`, quoted below. Vectors CSNU-09 to CSNU-11 carry
`draft03: null`, because the proposed text they exercise, L11, has no
counterpart in draft-03. `fallback`, `fall back`, `resurrect` and `reselect`
occur zero times in the published draft. For those three vectors the only
source is the proposed text, and their `single_chain` results are consequences
of ordinary Section 3.3 revocation checking rather than of any published rule
about what to do next.

## Source, draft-03

`draft-pidlisnyi-aps-03` as published, fetched this session from
https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt, sha256
`59b9547a20c6d514eceb97d169b92b2f9c70a231f5b914e8fc1b478c7f359fca`, which is
the same digest `docs/ID-COVERAGE.md` pins. Section 3.3, "Chain Verification",
lines 594-596 of the plain-text rendering:

    594    Each action selects one root-to-leaf authority chain.  A verifier
    595    MUST NOT union scopes or budgets from multiple chains.  Cross-
    596    principal composition requires a separate profile.

Lines 588-592, immediately above, set the four-valued result vocabulary and
state that attenuation failure is invalid:

    588    Verification returns one of valid, invalid, indeterminate, or
    589    unsupported with a stable failure code.  An unavailable or stale
    590    revocation result is indeterminate.  An unsupported facet profile is
    591    unsupported.  Cryptographic or attenuation failure is invalid.  A
    592    caller MUST NOT collapse indeterminate or unsupported into valid.

Line 585 is what the revoked vectors turn on, "and revocation state for every
member".

`docs/ID-COVERAGE.md` records line 594's requirement as `REQ-3.3-2`, **NOT
EXERCISED**, with the note "Every fixture carries exactly one delegation chain,
so multi-chain union has no surface." That inventory is pinned at suite commit
`b46568e8947291e553c6392403226e8d05be31d2` and does not reflect
`fixtures/single-chain-selection/`, which landed later. Reconciling that row is
a maintainer edit to a normative inventory, not part of this family, and is
left alone here.

## Relationship to `fixtures/single-chain-selection`

`fixtures/single-chain-selection/` already exercises Section 3.3 lines 594-596
directly, on two chains with **disjoint** scopes (`calendar:write` and
`payments:refund`) and equal spend ceilings of 60, and reads itself as plain
draft-03 conformance. Read it first. This family does not restate it. What is
here and not there:

- **A scope pair that overlaps on one axis.** There, the two chains' grants
  share nothing, so any way of combining them fails the needed scope as well.
  Here one chain grants `resource1:read` and the other `resource2:write`, and
  the action needs `resource1:write`. Set-union of the two grant sets still
  rejects that, which is why a fixture built only on disjoint scopes cannot see
  the interesting bug. Splitting each grant into a resource and an action and
  unioning those two axes separately **accepts** it, on a resource-and-action
  pair neither principal ever granted. CSNU-04 and CSNU-05 are that case.
- **A budget pair whose sum matters.** Ceilings of 5 and 5 against an action of
  8. CSNU-07 and CSNU-08.
- **Revocation, and what an implementation does next.** The other family
  resolves every record `active` and states that it tests nothing about
  revocation. CSNU-09 to CSNU-11 are the L11 case, and are the reason this
  family exists as more than a variant.
- **Named models of the wrong behaviors.** See "Decision policies". The other
  family decides each vector once. Here each vector is decided four times, so a
  negative vector's discriminating power is recorded rather than asserted in
  prose.

There is also no synthetic action-as-delegation-hop anywhere in this family.
Every decision runs through the SDKs' own scope and budget primitives on the one
presented chain, so no record here is ever wider than its parent and `mint.py`
needs only the ordinary `issue_authority_delegation` path.

## Setup

Three single-hop `AuthorityDelegationV1` root delegations, three different root
principals, all three naming the same leaf agent `L` as subject
(`chains.json`, `chains`):

| chain | root | scope grants | spend, unit `iso4217:USD:minor` |
|---|---|---|---|
| `chain_read_r1` | P1 | `["resource1:read"]` | `per_action` 5, `cumulative` 5 |
| `chain_write_r2` | P2 | `["resource2:write"]` | `per_action` 5, `cumulative` 5 |
| `chain_read_r1_alt` | P3 | `["resource1:read"]` | `per_action` 5, `cumulative` 5 |

No chain's ceiling is derived from or aware of another's. The two ceilings a
vector ever pools are equal, so their sum, 10, is strictly larger than either,
which is what makes an action of 8 discriminate between the two readings.

`chain_read_r1_alt` exists only for the L11 vectors, where the fallback has to
have somewhere to go: it independently covers exactly what `chain_read_r1`
covers, from a different root.

Each vector names the full ordered set of chains the agent has stored
(`stored_chains`), which one the action selected (`selected_chain`), a
revocation answer for **every** stored chain (`revocation`), and the action's
scope, unit and amount (`action`). A resolver that is handed a delegation with
no declared answer raises rather than defaulting to `active`.

## Decision policies

Each vector is decided under four named policies, and `vectors.json` records
the expected result of all four. Only the first is a claim about the reference
SDKs.

**`single_chain`, the conformant one.** Verify the selected chain alone with
`verifyAuthorityDelegationChain` / `verify_authority_delegation_chain`. If that
is not `valid`, report its first failure code. Otherwise require every needed
grant to satisfy `isValidScopeGrant` / `is_valid_scope_grant` and to be covered
by some grant on that chain's leaf, via `scopeGrantCovers` /
`scope_grant_covers`. Otherwise reserve the amount against that chain alone with
a fresh `InMemoryAuthorityBudgetLedger` and report the ledger's own code. No
other chain the agent holds is read at any step. This is the only column built
out of SDK behavior, and the only one a pass says anything about.

The remaining three are **models of specific non-conformant behaviors, authored
by this fixture**. They are not SDK behavior, they are not proposed behavior,
and no SDK was observed doing any of them. This follows the pattern
[`fixtures/approval-single-use/`](../approval-single-use/README.md) already
established in this suite, where a reference boundary and a
`defective-boundary-never-consumes-never-rechecks` are both run and the
defective one is required to fail exactly the declared set. They exist so that each negative
vector's discriminating power is recorded as data rather than asserted in prose:
a negative vector whose wrong-policy columns all agree with `single_chain` is
not discriminating anything.

**`union_pooled`.** Verify every stored chain, keep the valid ones, pool their
leaf scope grants as a set, sum their `per_action` ceilings in the action's
unit, and decide against the pool. Reasons are `no_valid_chain`,
`scope_not_covered`, `PER_ACTION_EXCEEDED_POOLED`, `RESERVED_POOLED`.

**`union_axis`.** `union_pooled`, except that scope coverage splits each pooled
grant at its last colon into a resource prefix and an action suffix and unions
those two axes independently, admitting a needed grant whose resource appears
in one chain and whose action appears in another.

**`silent_fallback`.** `single_chain` on the selected chain. If that does not
return `valid`, retry the agent's other stored chains in stored order and
return the first `valid` result. It reports no switch of its own, which is the
point: the only way to see the switch is to compare the chain it decided
against with the chain the action selected. Both runners assert the chain it
used and a `switched` flag, and separately assert that the flag and the chain
agree, so a fallback cannot be recorded as a plain rejection or a plain
acceptance.

## Vectors

11 cases in `vectors.json`. Every reject case differs from its nearest control
by exactly one stated change, recorded in the vector's `change_from_control`
field.

| id | tests | selected | needs | amount | `single_chain` | `union_pooled` | `union_axis` | `silent_fallback` |
|---|---|---|---|---|---|---|---|---|
| CSNU-01 | L5 | `chain_read_r1` | `resource1:read` | 3 | valid, `RESERVED` | valid | valid | valid, own chain |
| CSNU-02 | L5 | `chain_write_r2` | `resource2:write` | 3 | valid, `RESERVED` | valid | valid | valid, own chain |
| CSNU-03 | L5 | `chain_read_r1` | `resource1:read` | 5 | valid, `RESERVED` | valid | valid | valid, own chain |
| CSNU-04 | L5 | `chain_read_r1` | `resource1:write` | 3 | invalid, `scope_not_covered` | invalid | **valid** | invalid, own chain |
| CSNU-05 | L5 | `chain_write_r2` | `resource1:write` | 3 | invalid, `scope_not_covered` | invalid | **valid** | invalid, own chain |
| CSNU-06 | L5 | `chain_read_r1` | `resource1:read` + `resource2:write` | 3 | invalid, `scope_not_covered` | **valid** | **valid** | invalid, own chain |
| CSNU-07 | L5 | `chain_read_r1` | `resource1:read` | 8 | invalid, `PER_ACTION_EXCEEDED` | **valid** | **valid** | invalid, own chain |
| CSNU-08 | L5 | `chain_write_r2` | `resource2:write` | 8 | invalid, `PER_ACTION_EXCEEDED` | **valid** | **valid** | invalid, own chain |
| CSNU-09 | L11 | `chain_read_r1` | `resource1:read` | 3 | valid, `RESERVED` | valid | valid | valid, own chain |
| CSNU-10 | L11 | `chain_read_r1`, revoked | `resource1:read` | 3 | invalid, `REVOKED` | **valid** | **valid** | **valid, via `chain_read_r1_alt`, switched** |
| CSNU-11 | L11 | `chain_read_r1`, revoked | `resource1:read` | 3 | invalid, `REVOKED` | invalid, `no_valid_chain` | invalid, `no_valid_chain` | invalid, own chain |

Bold marks a wrong-policy column that admits an action `single_chain` refuses.
That divergence is the vector's discriminating power, and it is asserted, not
described: a runner that produced the bold column from `single_chain` would
fail on the `single_chain` assertion in the same vector.

Positive controls are CSNU-01, CSNU-02, CSNU-03 and CSNU-09. CSNU-01 and
CSNU-02 show each chain covering its own action before any reject case is
introduced. CSNU-03 sits the amount exactly on the selected chain's own ceiling
of 5, so CSNU-07's rejection at 8 cannot be an off-by-one at the boundary.
CSNU-09 is the control for the fallback pair.

### CSNU-04 and CSNU-05 are the negative control a naive implementation passes

Neither principal ever granted write of resource 1. P1 granted read of resource
1, P2 granted write of resource 2. An implementation that pools what the agent
holds and then reasons about resources and actions as independent sets
concludes that resource 1 is among the resources and write is among the
actions, and admits the action. Both vectors are that case, once with each
chain selected, and `union_axis` records the wrong acceptance.

This is the shape a fixture built on disjoint scopes cannot reach. `union_pooled`
rejects CSNU-04 and CSNU-05, so those two vectors alone would not catch a plain
pooling bug either, which is why CSNU-06 is also here.

### CSNU-06 is the plain pooling case

The action needs one grant from each chain at once. Set-union of the pooled
grants covers both, so `union_pooled` accepts. `single_chain` rejects, because
`chain_read_r1`'s leaf never carried `resource2:write`.

### CSNU-07 and CSNU-08 are the budget case

Two chains each allow 5. The action is 8. `single_chain` reserves against the
selected chain alone and the ledger returns `PER_ACTION_EXCEEDED`. A policy
that sums the two ceilings sees 10 and accepts. On the conformant path,
`InMemoryAuthorityBudgetLedger.reserve` is called with the selected chain's own
one-element array only: the other chain's record never appears in that call's
arguments, or anywhere reachable from it, so there is no route by which its
ceiling could be added in.

### CSNU-10 is the silent-fallback case, and CSNU-11 is why it is the fallback

CSNU-10 and CSNU-09 differ by exactly one thing: the selected chain's
revocation answer. `single_chain` returns `invalid` with `REVOKED` at the
selected chain's own index, which is ordinary Section 3.3 revocation checking
and the only part of this pair draft-03 speaks to. `silent_fallback` then finds
`chain_read_r1_alt`, which independently covers the same action, and returns
`valid`. The switch is recorded: the runners assert the fallback decided against
`chain_read_r1_alt` with `switched: true`.

CSNU-11 changes exactly one more thing, revoking the other stored chain too.
`silent_fallback` now has nowhere to go and stops diverging from
`single_chain`. Without CSNU-11, CSNU-10's divergence could be read as a
difference in how the two policies handle revocation rather than as the
fallback itself. With it, the divergence is located in the fallback.

What CSNU-10 establishes and what it does not: it establishes that an
implementation with a fallback of this shape would admit an action that the
chain the action selected cannot authorize, and that the difference is visible
from records. It does **not** establish that any implementation does this, that
draft-03 forbids it, or what an authorized re-selection would have to look
like. L11's own status in the proposed text is `proposed`, and this family does
not raise it.

## Determinism

`chains.json` is generated from published seed labels and carries no secret
material:

    /path/to/venv/bin/python fixtures/chain-selection-no-union/mint.py

After regeneration `git diff` on `chains.json` is empty. Checked while authoring
this family by regenerating and diffing the output against the committed file.

Seeds are recorded in `chains.json`'s own `seeds` block, not only in the
script: `seed_prefix` is `aps-conformance-suite:csnu:`, a private key is
`sha256(seed_prefix + label)` used as the RFC 8032 Ed25519 seed, and a nonce is
the first 32 hex characters of the same digest. Every key label and nonce label
is listed there, so the file is rederivable without reading `mint.py`.

`chains.json`'s `canonical_sha256` block pins the sha256 over the RFC 8785 JCS
canonical bytes of each signed record, computed by the SDKs' own canonicalizers
(`canonicalizeJCS`, `canonicalize_jcs`). Both runners recompute all three and
exit 2 on a mismatch before deciding any vector, so no verdict here can be
reported against bytes that drifted. The two runners' recomputations agree,
which is a cross-language check on the canonicalization as well as on the
digests.

`CHECKSUMS.sha256` pins the bytes of `chains.json` and `vectors.json`, the two
files every recorded result rests on. `npm run test:digest-integrity` verifies
it as part of `npm test`. Verify it by hand from this directory with:

    shasum -a 256 -c CHECKSUMS.sha256

The action reference each ledger reservation is keyed by is
`sha256(vector.id)` in lowercase hex, so it is fixed by the vector's own name
and not by run order.

## Falsifiability

Two mutations were run while authoring this family, neither committed, to check
that the runners fail where they should:

1. `CSNU-07`'s `single_chain` expectation flipped from `invalid`,
   `PER_ACTION_EXCEEDED` to `valid`, `RESERVED`, which is the answer a
   budget-unioning implementation would give. Both runners reported
   `FAIL CSNU-07-reject-amount-8-above-read-r1-ceiling-5` and 10/11, exit 1.
2. `chain_read_r1`'s `per_action` edited from `"5"` to `"10"` in `chains.json`
   without re-signing. Both runners stopped before deciding any vector with
   `JCS canonical digest mismatch for chain_read_r1`, exit 2. The recomputed
   digest was identical in both languages.

Both files were restored afterwards, and `shasum -a 256 -c CHECKSUMS.sha256`
and both runners were re-run clean.

The two runners' full output is byte-identical apart from the language name on
the final line, checked by diffing them with that word normalized.

## TypeScript

From the suite root, no network:

    npm ci --include=dev
    npm run verify:chain-selection-no-union

It also runs as part of `npm test`. The repository root pins the published
`agent-passport-system` at 7.1.0, which is also the current `latest` on npm.

Expected final line:

    chain-selection-no-union TypeScript: 11/11 passed

## Python

Against the published PyPI `agent-passport-system` 4.1.0 in a clean virtual
environment, no network at run time:

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install agent-passport-system==4.1.0
    /path/to/venv/bin/python fixtures/chain-selection-no-union/validate.py

`mint.py` runs in the same environment. Expected final line:

    chain-selection-no-union Python: 11/11 passed

## What the SDKs do not support

Recorded as `not_supported`, with the reason, rather than worked around
silently:

- **Chain selection.** Neither SDK exposes any API that takes a set of chains
  an agent holds and selects one for an action. The npm package's 1179 root
  exports contain no such entry point, and
  `agent_passport.v2.authority_delegation` contains none either. `selectKey`
  resolves a signing key, not a chain. `verifyBatchChain` verifies a sequence of
  receipt batches, a different object. Every chain-level and budget-level entry
  point in both packages takes exactly one chain: `verifyAuthorityDelegationChain(chain, ...)`,
  `InMemoryAuthorityBudgetLedger.reserve(verifiedChain, actionRef, unit, amount)`.
  So there is no SDK surface on which "which chain did this action select" can be
  asked or answered, and this family supplies the selection itself, per vector,
  through `selected_chain`.
- **Multi-chain pooling.** Following from the above, there is no SDK call that
  could pool two chains' budgets even wrongly. `union_pooled`'s and
  `union_axis`'s ceiling arithmetic is this fixture's own code. This is the
  structural reason the conformant path cannot union anything: not a check that
  refuses to, but an interface that never receives the second chain.
- **Silent fallback detection.** Neither SDK has a notion of a stored chain set,
  so neither can detect, report or refuse a fallback across one.
  `silent_fallback` is this fixture's own model.

The first two absences are the strongest single-chain-selection evidence
available from these SDKs, and they are also the reason a passing run here is
narrower than the proposed text. See "Where the proposed text was too vague to
test" below.

## Verification split

One entry per verification claim: layer / claim; runner; Mode A | Mode B;
author-produced | independent; implementation.

- `single_chain` verdict and reason, 11 vectors; aeoess; Mode A; author-produced (author of the vectors and of the implementation under test); published npm `agent-passport-system` 7.1.0 via `fixtures/chain-selection-no-union/verify.ts`, 11/11
- `single_chain` verdict and reason, same claim; aeoess; Mode A; author-produced (author of the vectors and of the implementation under test); published PyPI `agent-passport-system` 4.1.0 via `fixtures/chain-selection-no-union/validate.py`, 11/11
- RFC 8785 JCS canonical digest of the 3 signed records; aeoess; Mode B; author-produced (author of the vectors and of both canonicalizers); `canonicalizeJCS` (npm 7.1.0) and `canonicalize_jcs` (PyPI 4.1.0) recomputed independently in each runner, 3/3 in both
- `union_pooled`, `union_axis` and `silent_fallback` results, 11 vectors each; aeoess; Mode A; author-produced (these three policies are implemented by this fixture, not by any implementation under test, so no independent classification is possible for them); `verify.ts` and `validate.py`, 33/33 in both
- chain minting determinism; aeoess; Mode A; author-produced (author of the generator); `mint.py` re-run against the committed `chains.json`, empty diff
- absence of a chain-selection API; aeoess; Mode A; author-produced (author of the survey); export enumeration of npm 7.1.0 and `dir()` of `agent_passport.v2.authority_delegation` at 4.1.0, recorded under "What the SDKs do not support"

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, on the
`single_chain` path:

- an action whose needed scope and amount are both covered by the one chain it
  selected is admitted, and the ledger reserves it with code `RESERVED`
- an action needing write of resource 1 is rejected `scope_not_covered` when the
  selected chain grants read of resource 1, and also when the selected chain
  grants write of resource 2, in both cases while the agent is holding the other
  chain as well
- an action needing one grant from each of two chains is rejected
  `scope_not_covered` against either chain alone
- an action of 8 is rejected `PER_ACTION_EXCEEDED` against a chain whose own
  ceiling is 5, while a second chain with its own separate ceiling of 5 is held,
  in the same unit
- an action against a revoked selected chain is `invalid` with `REVOKED` at that
  chain's index, and stays so when another stored chain independently covers the
  same action
- the two reference SDKs agree on state and reason for all 11 vectors under all
  four policies, and agree on the JCS canonical digest of all three records

and, about the vectors themselves rather than about the SDKs:

- each of CSNU-04 to CSNU-08 and CSNU-10 is admitted by at least one named
  wrong policy, so none of them is a vector a naive implementation would pass
  by accident
- a fallback across stored chains is reportable from records: the chain a
  decision was reached against can be compared with the chain the action
  selected

## Does not claim

A pass does **not** establish:

- that L5 or L11 is correct, adopted, or specified. Both are proposed text at
  one commit of one repository, and this family is labeled
  `candidate_against_proposed` for that reason. L11 in particular has no
  draft-03 counterpart
- anything about cross-principal composition. Line 596 states that it requires
  a separate profile. The three roots here are three principals delegating
  separately to the same leaf, not a composition of their authority
- that any implementation performs `union_pooled`, `union_axis` or
  `silent_fallback`. Those three are models written here to make the negative
  vectors discriminating. No implementation was observed doing any of them, and
  nothing here surveys real implementations for them
- how a chain should be selected when several would each independently
  authorize an action. Every vector states its selection. Neither SDK has an
  API for selection at all
- what an implementation should do after the selected chain is found revoked.
  CSNU-10 shows a fallback is visible from records. It does not say the action
  should stop, restart, or continue under new authority, and it does not define
  what "explicitly authorized" fallback would look like
- anything about cumulative spend across a subtree over a sequence of actions,
  Section 3.4's running ledger. Each vector uses a fresh ledger and exactly one
  reservation, so what is exercised is one reservation's per-action and
  cumulative check, not commit, cancellation, or retry idempotence
- anything about chains deeper than one record, key rotation, indeterminate or
  unsupported revocation answers, or root trust. Every chain here is one root,
  every key resolves, every root is trusted, and every revocation answer is
  `active` or `revoked`
- that this behavior is unique to the SDKs run here, or that any other draft-03
  implementation was checked

## Where the proposed text was too vague to test

Recorded because the gap matters as much as the vectors do.

1. **L5 does not say what a chain is selected for, or by whom.** "Each grant
   follows one parent chain" is about issuance. Draft-03 line 594 is about an
   action. This family had to supply the selection itself, per vector, because
   neither the proposed text nor either SDK gives selection an interface. So the
   vectors test that a **given** selection is not widened by other chains. They
   cannot test that an implementation selected one chain at all, which is the
   half of line 594 that reads "each action selects one root-to-leaf authority
   chain". An implementation that evaluated an action against three chains and
   returned the union would fail these vectors only if it happened to route
   through the one-chain entry points these runners call.
2. **Neither L5 nor draft-03 defines the granularity of a scope grant.** The
   `union_axis` bug, and CSNU-04 and CSNU-05 with it, exist only because
   `resource1:read` has internal structure that an implementation might take
   apart. `aps-hierarchical-v1` is named as a profile, `isValidScopeGrant`
   accepts `res:1:read` as readily as `resource1:read`, and nothing in the
   proposed text says whether a grant's segments are meaningful to a verifier or
   opaque to it. A conformance requirement that a verifier must not decompose a
   grant would make CSNU-04 testable against text. As written, CSNU-04 is
   testable only against this fixture's own model of the wrong behavior.
3. **L5 says "cannot use them together to create a grant broader than either
   chain allows", which is about creating a grant.** The budget vectors are not
   about creating anything, they are about spending. Draft-03 line 595 does name
   budgets, so CSNU-07 and CSNU-08 have text behind them. L5's own wording does
   not reach them, and a reader who had only L5 would not know whether the
   budget case was in scope.
4. **L11 does not say what makes a fallback "explicitly authorized".** "Unless
   that fallback was itself explicitly authorized" is the whole exception, and
   nothing says whether the authorization is a record, a policy, a field on the
   grant, or an operator action, or who may give it. So CSNU-10 can only test
   the unauthorized case. The authorized case has no testable shape, and this
   family has no positive vector for it. That is the largest single gap here.
5. **L11 says "should not quietly fall back" without saying what makes a switch
   visible.** This family chose to make it visible by recording which chain the
   decision was reached against. That choice is the fixture's, not the text's.
   A different implementation could make the switch visible in a receipt, in a
   denial reason, or in an operator notification, and the proposed text does not
   distinguish those or say which would satisfy it.
6. **L5's own status line is stale.** At commit `5c1bf09` it reads "No public
   case yet", while `fixtures/single-chain-selection/` is on this repository's
   `main`. That is a bookkeeping error in the proposed document rather than a
   gap in the rule, and fixing it is not this family's to do.

## Provenance

`vectors.json`, `chains.json`, `mint.py`, `verify.ts` and `validate.py` are
authored for this suite, adapting the minting, key-resolution and
revocation-resolver-by-name pattern established by
[`fixtures/ancestor-revocation-chain/`](../ancestor-revocation-chain/README.md),
[`fixtures/sponsor-handover/`](../sponsor-handover/README.md) and
[`fixtures/single-chain-selection/`](../single-chain-selection/README.md), and
the declared-defective-implementation pattern from
[`fixtures/approval-single-use/`](../approval-single-use/README.md). Both
runners were executed locally with no network: the TypeScript runner against the
published `agent-passport-system` 7.1.0 from npm, the Python runner against the
published `agent-passport-system` 4.1.0 from PyPI installed in a clean virtual
environment, not a local source checkout. This is an author-produced record,
not an independent one, per `CONTRIBUTING.md`'s admission rules for run records.

`CONTRIBUTING.md` reserves family names, failure-class names and normative
README wording to the maintainer, and says a new family name does not land by
pull request. `chain-selection-no-union`, and the four policy names
`single_chain`, `union_pooled`, `union_axis` and `silent_fallback`, are proposed
names on a candidate branch, not minted vocabulary.
