# token-exchange-attenuation-v0: an engine-neutral vector family for the attenuation invariant

An RFC 8693 token exchange takes a subject token T1 and returns an exchanged token T2. This family
pins one property of what a policy engine may conclude from T2: **exchanging a token must not let
an evaluation of T2 reach authority that was only ever available in T1.**

The vectors are authority shapes, not cryptography. Nothing here is signed and nothing here needs
to be: every case is decided from claim structure alone, so a reader can check it by hand. That is
deliberate, and it is why this directory carries no keys, no digests and no signature fixtures.

## Where the invariant comes from, and what it is not

The invariant was stated by darklordVirtual (Stian Skogbrott) on stacklok/toolhive#6424, comment
5401328084, 2026-08-24. In his words:

> delegated authority is not reconstructed upstream authority.
>
> With RFC 8693, the request token is intentionally a new authority artifact. Its sub, act, scopes,
> audience and delegation constraints should be evaluated as such rather than used as a lossy
> substitute for the original interactive identity.

and, on how upstream-only claims should behave:

> while upstream-only claims remain absent rather than silently inherited.

stacklok/toolhive#6511 (jhrozek, 2026-09-04) adopts it as an acceptance criterion: "A conformance
test pinning the attenuation invariant: a subject token with broader upstream authority, exchanged,
must not let Cedar reach authority available only to the subject."

**RFC 8693 does not impose this invariant.** The RFC supplies the exchanged-token representation
and the `act` chain that expresses who acted; it does not say that an evaluation of the exchanged
token must be unable to reach the subject's authority. The invariant is ToolHive's framing, adopted
by #6511 as an acceptance criterion. APS 6.0.0's `oauth-rfc8693` bridge is one implementation that
narrows a delegation chain before mapping it into RFC 8693 claims. This family never asserts the
invariant as a requirement of RFC 8693, and records it policy-engine-neutrally so that any engine
can be measured against the same cases.

## The three properties

The invariant is not one rule. It is three independent properties, and a system can satisfy any two
while failing the third, so each has its own cases and its own mutation.

- **P1, scope monotonicity.** T2's scope is a subset of T1's scope. A vector whose T2 scope is not
  a subset is INVALID: a runner must reject the vector and must not evaluate its requests. A
  widening token exchange is not a case with a deny answer, it is a case that should never have
  been minted.
- **P2, claim locality.** Evaluating T2 uses only claims present on T2. The evaluator never reads
  T1. T1 appears in each case solely to record the contrast, so a reader can see what was given up.
- **P3, transcription creates no authority.** A T1 attribute carried onto T2, by whatever
  transcription scheme, satisfies an attribute predicate only when T2's own scope, audience and
  actor conditions independently permit the action. Carrying an attribute across never supplies a
  scope, an audience or an actor that T2 does not have.

## The vectors

`vectors.json`, 12 cases, 17 requests, 10 valid vectors and 2 invalid ones. Every case names the
properties it exercises.

Each case carries:

- `subject_token_claims` (T1): `sub`, `scope` as a space-separated string, `aud`, an optional
  `may_act`, and upstream-asserted attributes under `upstream_claims`. **`may_act` is recorded and
  is not an input to any decision here.** RFC 8693 Section 4.4 calls it forward authorization, a
  statement of who is permitted to become the actor, and says it is permission rather than proof.
  The actor step below asks who actually acted, which is a different question, so a reader should
  not expect `may_act` to satisfy it. It is carried because a case that names an accepted actor
  should show where that acceptance was written.
- `exchanged_token_claims` (T2): `sub`, an `act` chain per RFC 8693 Section 4.1 (`act: {sub, act?}`,
  outermost is the current actor), `scope`, `aud`, and whichever T1 attributes the case carries
  across under its own `upstream_claims`, if any.
- `vector_valid`, and `invalid_reason` when it is false.
- `requests`: `{id, action, resource, requires, audience?, required_actor?}`. `requires` names the
  authority the policy needs: `{"scope": "<token>"}`, or
  `{"attribute": {"name": "<claim>", "contains": "<member>"}}` for an array-valued attribute, or
  `{"attribute": {"name": "<claim>", "equals": "<value>"}}` for a scalar. A request may carry both
  a `scope` and an `attribute` requirement.
- `expected`: per request, `against_t2` and `against_t1`, each `permit` or `deny`, plus
  `deny_reason` for the T2 decision from the closed set below, and `t1_deny_reason` on the one case
  where T1 also denies and the reason is worth recording.

The closed deny-reason set is `scope_not_granted`, `attribute_not_carried`, `actor_not_permitted`,
`audience_mismatch`. A runner that needs a fifth reason has found a case this family does not
describe.

## The decision procedure a runner must implement

Given a token T and a request, in this order, stopping at the first deny:

1. **audience.** If the request names an `audience` and T's `aud` (a string or an array of strings)
   does not include it, deny `audience_mismatch`.
2. **actor.** If the request names a `required_actor` and T's current actor is not that party, deny
   `actor_not_permitted`. T's current actor is the `sub` of the outermost `act`, or T's own `sub`
   when there is no `act`. `may_act` is not consulted. A consequence worth stating because it looks
   like a bug the first time you see it: a subject token has no service actor, so an actor-gated
   request denies against T1 as well as against T2, and the contrast column for such a request
   reads deny on both sides.
3. **scope.** If `requires.scope` is present and that token is not in T's scope, deny
   `scope_not_granted`. Scope is the space-separated `scope` member split on whitespace; an absent
   `scope` member is the empty set.
4. **attribute.** If `requires.attribute` is present and T's own `upstream_claims` does not carry
   that claim with a satisfying value, deny `attribute_not_carried`. `contains` is satisfied when
   the claim is an array holding the member; `equals` when the claim equals the value.
5. Otherwise permit.

The order is fixed so two independent implementations report the same reason, not merely the same
verdict. When evaluating T2, step 4 reads T2's `upstream_claims` and nothing else: that is P2, and
it is the step a mutation attacks.

P1 is checked before any of this: if T2's scope is not a subset of T1's scope, the vector is
rejected and its requests are never evaluated.

## What this family establishes

P1, P2 and P3 as decidable vectors, in a form any policy engine can be measured against. A runner
that reproduces the `expected` decisions has shown that its evaluation of T2 does not reach
authority present only in T1, on these twelve cases.

## What this family does NOT establish

- **Nothing about Cedar, ToolHive, or any implementation.** No case runs Cedar, no case runs
  ToolHive, and nothing here reports on whether any project satisfies the invariant.
- **Nothing about missing-attribute semantics in any policy language.** A case where an absent
  attribute makes a forbid-style rule fail to fire is deliberately excluded: #6511 records that
  Cedar's `has` guard makes such a forbid not fire, which is a property of Cedar's evaluation of
  missing attributes, not a property of attenuation. Including it would smuggle one engine's
  semantics into an engine-neutral family.
- **Nothing about how attributes should be transcribed.** The cases use a namespaced
  `upstream_claims` object because #6511 proposes one, but the family takes no position on the
  scheme. P3 is about what a transcribed attribute may achieve, not about how to spell it.
- **Not a requirement of RFC 8693.** See above.
- **No adoption, endorsement or interoperability claim about any project**, and nothing here has
  been posted to any thread.
- **Nothing about signatures, issuers, expiry or replay.** The tokens are claim sets. A real
  deployment must verify T2's signature and freshness before any of this applies, and none of that
  is exercised here.
- **Nothing about scope semantics beyond set membership.** Scope tokens are compared as opaque
  strings. Hierarchical or wildcard scope languages are out of scope for v0.

## Reproducing this family

A cross-stack family is outside the generic runner and is not executed by `npm test`; it carries
its own commands, which is the convention `runners/ts/fail-loud-and-wire.test.ts` states. From the
repository root:

    npx tsx runners/ts/token-exchange-attenuation.test.ts     Mode A, writes results.json
    python3 fixtures/cross-stack/token-exchange-attenuation-v0/recompute.py
                                                              Mode B, writes results-recompute.json

Both exit 0 only when every request matches its expectation and every invalid vector was rejected.

## Verification split

- Scope and chain axis, 12 cases; runner aeoess; Mode A; **author-produced**; implementation:
  `runners/ts/token-exchange-attenuation.test.ts` using the `oauth-rfc8693` bridge of
  agent-passport-system 6.0.0, the version this suite already pins, plus an explicit attribute
  evaluator written for this family.
- Clean-room recompute of the same 12 cases; runner aeoess; Mode B; **author-produced**;
  implementation: `recompute.py`, Python 3 standard library only, written from this SOURCE.md and
  `vectors.json` alone.

Both layers are author-produced: the lab wrote the vectors, both runners and the invariant's
encoding here. No independent record exists for either layer, and both are queued in
docs/OPEN-RUNS.md. These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.
