# AAE chain-envelope interop vectors

Four chain-envelope conformance vectors in MoltyCel's **AAE** shape
(`{"chain": [parent, child]}`), each decided by the **shipped APS verifier** via a
small AAE→APS delegation-chain adapter. They show how APS's narrowing, expiry, and
revocation checks decide a two-hop credential chain.

**V4 tests check-time cascade, not next-lookup:** a revoked parent invalidates the
child subtree in the same verification pass, when the chain is verified against
current revocation state.

## How the decision is made

Each AAE credential is mapped to a real APS delegation by [`verify.ts`](./verify.ts):

- `mandate.actions[]` → APS `scope` tokens
- `validity.not_before` / `validity.not_after` → APS `notBefore` / `expiresAt`
- `validity.revocation_check.status == "revoked"` → APS `cachedRevocationState` at check time
- keys are generated per DID so `child.delegatedBy == parent.delegatedTo` (the chain link),
  signed with the SDK's own `canonicalize` + `sign`

The chain is then decided with the **shipped** primitives from
`agent-passport-system` (built `dist`):

- `verifyDelegation`: signature, expiry, `notBefore`, revocation (from supplied state), depth
- `scopeCovers`: monotonic narrowing (`child_scope ⊆ parent_scope`)

The verifier cascades root→leaf: an expired or revoked **ancestor** rejects the whole
chain even when the child hop is independently valid.

## Vectors

| Vector | Expected | Reason | AAE section | APS reason code | APS reference (existing) |
|---|---|---|---|---|---|
| **V1-narrowing-valid** | ACCEPT | child `[read]` ⊆ parent `[read, write]`, both windows current, not revoked | §2.2/2.3 scope | n/a | `tests/property-delegation.test.ts` (INV-2 Scope Monotonic Narrowing); `scopeCovers` |
| **V2-widened-scope-reject** | REJECT | scope-widening: child `[read, write, delete]` ⊄ parent `[read]` (`child_scope ⊄ parent_scope`) | §6 attenuation/cycle | `SCOPE_WIDENING` | `tests/property-delegation.test.ts` (INV-2) and `tests/v2/delegation-escalation.test.ts` (`delegation_scope_expansion`); `subDelegate` raises `Scope violation: [..] not in parent scope [..]` |
| **V3-expired-parent-reject** | REJECT | parent `validity.not_after` in the past; an expired ancestor invalidates the subtree | §2.4 validity (temporal) | `DELEGATION_EXPIRED` | `tests/conformance/golden-fixtures/NEG-DELEGATION-EXPIRED.json`; `verifyDelegation` emits `Delegation expired` |
| **V4-revoked-parent-cascade-reject** | REJECT | parent `revocation_check` resolves to revoked; cascades to the subtree **at verification time** | §6.5 revocation | `DELEGATION_REVOKED` | `tests/conformance/golden-fixtures/NEG-STALE-REVOCATION.json`; `verifyDelegation` marks the node revoked from supplied revocation state |

## V4: check-time cascade (the important one)

In V4 the **child credential is fully valid on its own**: it narrows the parent
correctly, its window is current, and its own `revocation_check` is active. The chain
is rejected solely because the **parent** is revoked, and that decision is taken **when
the chain is verified**: the verifier consults revocation state during this pass and
rejects the subtree. This is the same semantics as
`tests/conformance/golden-fixtures/NEG-STALE-REVOCATION.json`: *"a verifier that ignores
[stale] revocation state would wrongly accept it."* It is **not** a next-lookup model
where the child stays usable until some later refresh; revoking the parent invalidates
the child immediately at check time.

## Run

```
npx tsx interop/aae-envelope/verify.ts
# or
npm run verify:aae-envelope
```

The runner walks all four vectors, maps each to an APS delegation chain, runs the
shipped verifier, and asserts the expected result + reason code per vector. Exit code is
non-zero if any vector's actual decision differs from its AAE-stated expectation.

> Convention note: this repo's fixtures use `tsx` runner scripts (see
> `fixtures/composition/*/verify.ts`), not vitest, so this runner follows that pattern.
> It is a real load-adapt-verify-assert test of the shipped APS verifier.

## Constraint-monotonicity (parallel to MoltyCel 08/15)

Two additional cross-encoded vectors live under
[`moltycel-format/constraint-monotonicity/`](./moltycel-format/constraint-monotonicity/),
closing the constraint-monotonicity gap relative to AAE:

- `aae-vector-95` (cap-relaxing): child raises a numeric cap (1000 USD vs parent 500 USD).
  REJECT @ step 9 `delegated_constraint_relaxed`. APS core `subDelegate` enforces this
  natively (a child cap above the parent throws).
- `aae-vector-96` (currency-change): child changes the cap currency (300 EUR vs parent
  500 USD). REJECT @ step 9 `delegation_currency_mismatch`. APS enforces currency at the
  v2 payment-rails layer (`preAuthorize`), not in core narrowing; see the subfolder README
  for that documented divergence.

Both are REJECTED by MoltyCel's reference verifier (`crossverify.py`: 2/2).

Classification, added 2026-08-29: Mode A (the shipped APS verifier decided the vectors
through an adapter); author-produced (the runner authored the implementation under test
and the adapter). The vectors are MoltyCel's; the decisions recorded above are unchanged.

## Clarification, 2026-10-05: scope, revocation input, V3, section references

This section is appended under CONTRIBUTING's rule for files not covered by a
published digest set (no `CHECKSUMS.sha256` or `SHA256SUMS.txt` in the repository lists
any file in this directory). Text and results above are unchanged and stay as the
dated record they were. Read them with the corrections below.

**What these vectors are.** V1 to V4 are APS-encoded vectors written in the AAE
chain-envelope shape (`{"chain": [parent, child]}`), authored in this repository at
commit `1e75a47` (2026-06-18). The decision comes from the APS verifier through the
adapter in `verify.ts`, not from an AAE verifier. They are not AAE-conformant
envelopes: unsigned JSON, no Verifiable Credential wrapper, no JWS, no resolvable DIDs.
The 2026-08-29 line above, "The vectors are MoltyCel's", refers to the shape; the
files were written here.

**`constraints.resource`.** Every vector, parent and child, carries
`constraints.resource` (`repo:acme/*`, `repo:acme/colmena`). `resource` is not an AAE
constraint type and carries no `required` member. AAE -02 section 2.3 (same number in
-00) treats an absent `required` as `required: true` and requires rejecting an
unrecognized required constraint, as does -02 section 5 step 7. Every vector is
therefore non-conforming AAE input as published. The vector files are not edited
because pinned runs reference them. The cross-encoded set under `moltycel-format/`
is a separate artifact with empty `constraints`; it was not re-run for this note.

**`revocation_check`.** AAE -02 section 2.4 defines `revocation_check` as an HTTPS URI
template the relying party queries. The vectors carry an inline status object
(`{mechanism, status}`) instead. `verify.ts` reads that status as fixture-supplied
revocation state: `active` becomes fresh `{revoked: false}` evidence, `revoked`
becomes `{revoked: true}`, and a missing or unrecognized status is absent evidence,
which `fail_closed` rejects. This is never live revocation resolution. No endpoint
is queried.

**MoltyCel's run.** MoltyCel ran the four vectors against their AAE reference
verifier and reported it on
[decentralized-identity/trusted-ai-agents#37](https://github.com/decentralized-identity/trusted-ai-agents/issues/37#issuecomment-6002011527)
(2026-10-05T20:03:23Z), at suite `5500a562`, vectors from `1e75a47`, reference
verifier `531f880`. As reported there: with the original vectors, all four reject at
step 7 with `unrecognized_required_constraint`. In MoltyCel's reported modified run,
removing resource made the compared decisions agree: V1 ACCEPT, V2
`delegated_actions_not_subset`, V3 `expired_not_after`, V4 `ancestor_revoked`. That
modified variant is MoltyCel's, not one of the files here. This repository did not
re-run their verifier. Per that report, the agreement covers monotonic narrowing on
the action axis, an expired ancestor, and check-time cascade on a revoked ancestor.
It does not cover `constraints`, `single_use`, `revocation_check` as a URI template,
DID resolution, `delegator_aae_hash`, action binding or grants. `verify.ts` also
generates a fresh key pair per DID and signs with the APS canonicaliser.

**Runner defect, corrected.** At `f8d6eb4` and earlier, `verify.ts` asked for
`fail_closed` but supplied revocation evidence only for `revoked`. Every `active`
node came back from the SDK `valid: false` with the single error
`fail_closed: no revocation evidence supplied, revocation status unknown`, and the
runner still decided V1 ACCEPT and reported 4/4 because it did not read `valid`. The
4/4 recorded in this directory before 2026-10-05 is that runner's output; it is
kept as the record of what was run, and V1's ACCEPT there was not backed by
SDK-valid nodes. Corrections on branch `fix/aae-envelope-scope`:

- `6fa874a`: `active` status is supplied as fresh `{revoked: false}` evidence.
- `fa276f5`: the SDK `valid` flag is read per node and a vector fails when it
  disagrees with the node-level conditions the decision uses. This is a per-node
  consistency guard. It is not compared with the chain verdict: V2's two nodes are
  both valid and the chain is still REJECT / `SCOPE_WIDENING`.
- `78f666f`: a node the SDK reports invalid for an unnamed reason rejects the chain
  (`NODE_INVALID`) instead of falling through to ACCEPT. The mapping is labeled
  fixture-supplied revocation state.
- `910b56c`: regression test `runners/ts/aae-envelope-revocation-evidence.test.ts`
  (`npm run test:aae-envelope-revocation-evidence`, wired into `npm test`).

**Run at `910b56c`.** `agent-passport-system` 7.1.0 installed (pinned in
`package.json`), Node v24.11.1. Command `node --import tsx interop/aae-envelope/verify.ts`,
exit 0, checked 2026-10-05T21:03:37Z. V1 ACCEPT, SDK valid `[true, true]`; V2 REJECT /
`SCOPE_WIDENING`, `[true, true]`; V3 REJECT / `DELEGATION_EXPIRED`, `[false, true]`; V4
REJECT / `DELEGATION_REVOKED`, `[false, true]`. 4/4 expected results, no valid-flag
disagreement. This is an author-produced Mode A run of the APS verifier through the
adapter, not an AAE verification.

**V3 is a masked interoperability gap, not a clean ancestor-expiry vector.** The
parent window is 2026-01-01T00:00:00Z to 2026-03-01T00:00:00Z and the child window
is 2026-01-01T00:00:00Z to 2030-01-01T00:00:00Z. AAE -02 section 3 (Validity) and
section 5 step 9 require the child window to nest inside the parent's, so the child
widens validity. MoltyCel reported that, on the AAE verification path, a run dated
before 2026-03-01 rejects V3 for validity widening rather than expiry. The APS
adapter checks each delegation's own window and never compares parent and child
windows, so it has no validity-widening reason at all. Its verdict depends on the
evaluation instant. `verifyDelegation` reads `Date.now()` and has no
evaluation-instant option (`agent-passport-system` 7.1.0,
`dist/src/core/delegation.js` lines 280, 294 and 332; options type at
`dist/src/core/delegation.d.ts` line 116), and the runner reads the same clock. So
the regression test overrides `Date.now` in its own process:

| Evaluation instant | APS adapter decision | SDK valid |
|---|---|---|
| 2025-12-01T00:00:00Z | REJECT / `DELEGATION_NOT_YET_VALID` | `[false, false]` |
| 2026-02-01T00:00:00Z | ACCEPT | `[true, true]` |
| 2026-04-01T00:00:00Z | REJECT / `DELEGATION_EXPIRED` | `[false, true]` |

At 2026-02-01T00:00:00Z the adapter accepts a chain AAE -02 rejects. Every run at an
instant after 2026-03-01T00:00:00Z gets REJECT / `DELEGATION_EXPIRED`, which hides
the gap. V3 is not edited. A nested replacement is not added here: CONTRIBUTING
asks for an issue first and keeps fixture additions out of verifier and README
changes.

**Section references by draft revision.** The table above and the `aae_section`
values in `INDEX.json` use `draft-kroehl-agentic-trust-aae-00` numbering. Read on
2026-10-05:
`https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-00.txt` (dated
2026-05-21, sha256 `2847f4daf3f0a088afb1bd1bd3b9c001947a9905426753673d9da8275a038b0a`)
and `https://www.ietf.org/archive/id/draft-kroehl-agentic-trust-aae-02.txt` (dated
2026-09-06, sha256 `08e202ecc06d245b287e60591098c22d8af480fc88cb455defc9e7612a473b4c`).
-02 was the latest revision in the datatracker listing that day; `-03` returned 404.

| Vector | Cited (-00) | -00 content | -02 equivalent |
|---|---|---|---|
| V1 | §2.2/2.3 scope | -00 §2.2 MANDATE, §2.3 CONSTRAINTS; actions-subset rule at -00 §3 | -02 §2.2 MANDATE, §2.3 CONSTRAINTS; actions-subset rule at -02 §3 and §5 step 9 |
| V2 | §6 attenuation/cycle | -00 §6 is Security Considerations; amplification at -00 §6.4; subset rule at -00 §3; cycle detection at -00 §5 step 9 | -02 §7.4 Delegation Amplification, §3, §5 step 9. -02 §6 is Verdicts and Ratification |
| V3 | §2.4 validity | -00 §2.4 VALIDITY; validity nesting at -00 §3 | -02 §2.4 VALIDITY; nesting at -02 §3 and §5 step 9; effective expiry is the minimum `not_after` over the chain (-02 §5 step 9) |
| V4 | §6.5 revocation | -00 §6.5: a relying party SHOULD treat descendants of a revoked parent as invalid | -02 §7.5 Delegation Revocation: a relying party that has determined a parent is revoked MUST treat every descendant as invalid |
