# Ancestor revocation fails a deeper descendant with no descendant records

This fixture exercises one property of `AuthorityDelegationV1` chain
verification: when the revocation resolver reports a revoked ancestor,
verification of the whole root-to-leaf chain fails at that ancestor's index,
regardless of how deep the presented chain runs below it, and regardless of
whether any descendant has its own revocation record.

This is plain draft-03 conformance, not a proposal. draft-pidlisnyi-aps-03
already requires a verifier to check revocation state for every chain member,
so this fixture makes that existing required behavior executable and
reviewable, the same way
[C19](../revocation-resolution-forward-compat/README.md) did for the
unrecognized-resolver-answer boundary. It does not propose new wording.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/), Section 3.3,
"Chain Verification", lines 578-592 of the plain-text rendering:

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

The load-bearing phrase is "revocation state for every member": the check is
defined over the whole presented chain, not only over the leaf or only over
the member nearest the action being authorized. Nothing in Section 3.3 scopes
the check to descendants of a revoked record, or exempts it once a
sufficiently deep descendant is being checked. The reference TypeScript and
Python SDKs implement this as one phase that walks the full chain array index
by index and returns at the first revoked member it finds (see
`verify_authority_delegation_chain`'s phase 11 in both SDKs), so a revoked
ancestor is reported at its own index even when every record after it in the
array is itself unrevoked.

## Case

**Input:** a native `AuthorityDelegationV1` chain with three hops: root R to
agent A, A to agent B, B to leaf L (`chain.json`, chain indices 0, 1, 2). The
revocation resolver answers `revoked` for one delegation and `active` for
every other member; no revocation record or resolver answer marks any
descendant as revoked in any case.

**Expected outcome:** whenever any ancestor of the leaf is revoked, chain
verification of the full root-to-leaf chain is `invalid`, failure code
`REVOKED`, at the revoked ancestor's own index. This holds whether the revoked
member is the root (index 0) or a middle delegation (index 1); no case here
revokes the leaf's own delegation (index 2).

## Controls

Case 1 is the positive control: every member reports `active`, and the same
minted chain, key resolution, root trust, signatures, time window,
attenuation and linkage that the other cases reuse are shown valid before any
revoked answer is introduced.

## Vectors

There are 4 cases in `vectors.json`, run against the same `chain.json`:

1. **AAC-01-active-control.** Every member `active`. Expected: `valid`.
2. **AAC-02-root-revoked-full-chain.** Root delegation (index 0) `revoked`,
   both descendants `active`, full chain presented. Expected: `invalid`,
   `REVOKED`, index 0.
3. **AAC-03-root-revoked-leaf-not-in-recorded-children.** Same resolver
   answers as case 2 (root revoked, both descendants active). The vector
   additionally carries a `context.recorded_children` field naming only agent
   A and agent B, deliberately omitting leaf L, to model a decommissioning
   process's bookkeeping list that has not (or not yet) enumerated every
   descendant. Expected: `invalid`, `REVOKED`, index 0, identical to case 2.
4. **AAC-04-middle-delegation-revoked.** The A-to-B delegation (index 1)
   `revoked`, root and B-to-L `active`. Expected: `invalid`, `REVOKED`, index
   1. This shows the rule is about any ancestor being revoked, not only the
   root: a verifier does not stop checking ancestors after the root passes.

### Vector 3 is not a completeness test

`context.recorded_children` in vector 3 is recorded for documentation only.
Neither `verify.ts` nor `validate.py` reads `vectors[i].context` for any
purpose; `resolverFor` / `resolver_for` in both runners is called with only
`vector["resolver"]`, never `vector["context"]`, so the list cannot influence
the resolver's answers or the expected result. The vector exists to show that
the leaf fails because its ancestor is revoked, a fact establishable purely
from walking the presented chain, not because of anything an external
"recorded children" list does or does not enumerate. If that list omitted
agent A or agent B by mistake, or is missing leaf L because a decommissioning
process has not finished, verification of the presented chain is unaffected
either way: it never consults that list.

## chain.json

`chain.json` holds one root `AuthorityDelegationV1` and two children (three
hops total: R to A, A to B, B to L), all valid at the fixture's `now` when
the revocation resolver answers `active` for every member. It is generated by
`mint.py` from published seed labels, so it carries no secret material and
regenerates byte for byte:

    python3 fixtures/ancestor-revocation-chain/mint.py

After regeneration `git diff` on `chain.json` should be empty (verified as
part of authoring this fixture by hashing the file before and after
regeneration, since it is newly added and not yet tracked at a prior
revision). The active control case checks that the chain really is valid
before any synthetic revocation answer is introduced.

## TypeScript

The repository root currently pins the published `agent-passport-system`
package.

From the conformance-suite root:

    npm ci --include=dev
    npm run verify:ancestor-revocation-chain

It also runs as part of `npm test`.

Expected final line:

    ancestor-revocation-chain TypeScript: 4/4 passed

## Python

Run against the actual Python SDK under test, for example:

    PYTHONPATH=/path/to/agent-passport-python/src \
      python3 fixtures/ancestor-revocation-chain/validate.py

Expected final line:

    ancestor-revocation-chain Python: 4/4 passed

## Provenance

Vectors, `chain.json`, `mint.py`, `verify.ts` and `validate.py` are authored
for this suite, adapting the minting, key-resolution and resolver pattern
already established by
[`fixtures/revocation-resolution-forward-compat/`](../revocation-resolution-forward-compat/)
(C19) to a three-hop chain and a revoked-ancestor resolver. Both runners were
executed locally against the pinned TypeScript SDK (`agent-passport-system`,
package.json) and the Python SDK checkout at
`agent-passport-python/src` on this machine; this is an author-produced
record, not an independent one, per `CONTRIBUTING.md`'s admission rules for
run records.

## What a pass establishes

For the exact SDK revision that was run, a pass establishes that:

- a fully active three-hop chain verifies valid
- a revoked root fails the full chain at index 0, even though two
  unrevoked descendant delegations follow it in the chain
- a revoked middle delegation fails the full chain at its own index, even
  though root and leaf are both unrevoked
- an external list of a decommissioning process's "recorded children" that
  omits the leaf does not change the failure index or code
- the failure is surfaced as `REVOKED`

## Does not claim

A pass does **not** establish:

- anything about cascade revocation evidence or Section 3.5.1's
  cascade-completion record; this fixture never mints, checks, or requires
  one
- anything about a derived or synthesized revocation record for a
  descendant; every descendant's own revocation answer in every case here is
  `active`, exactly as resolved, not derived from the ancestor's revoked
  state
- anything about completion records generally
- that any enumeration of a delegation's children (recorded, cached, or
  otherwise) is, or needs to be, complete. Vector 3 exists specifically to
  show the opposite: the leaf's failure does not depend on whether any
  external children list is exhaustive. This is not a completeness test of
  that list or of any similar bookkeeping structure
- that this behavior is unique to the SDKs run here, or that every
  independent draft-03 implementation has been checked
- anything about execution-time re-checking (Section 3.5, "the enforcement
  gateway MUST recheck revocation status at execution time, not only at
  approval time"); this fixture calls the chain verifier once, at one `now`

This fixture is evidence about the chain-verification revocation phase, over
a chain deeper than two records, not a conformance verdict about cascade
revocation, derived revocation records, or completion records as protocol
features.
