# lifecycle-policy-change: a policy version is a dependency the grant does not carry

**Status: candidate against proposed text. This is not a draft-03 conformance case.**
Every vector in `vectors.json` carries `status: "candidate_against_proposed"` and names
both the proposed text it tests and the `CASES.md` case id it comes from. `verify.ts` and
`verify.py` both refuse to run if any vector loses that label, names proposed text the
file does not define, or stops carrying its case id in its own vector id.

One grant, issued under one policy version and never revoked, expired or suspended. The
policy around it then changes: a version is added, a pointer moves, a pointer moves back,
two pointers land on the same instant, a version is authored that reproduces an older
version's rules exactly, and decisions made under the old version are read afterwards.
The question this family makes executable is what a verifier can say about the grant and
about those records once the policy has moved underneath them.

## Which cases this family covers

Three cases from the **Policy change** section of `CASES.md` in
[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle),
at commit `2bf5c7e2d07d41c13611478d6e5e47fcb4d3ceda` on branch `cases-v0.2`:

| case | vectors |
|---|---|
| LC-I-004, a policy rollback needs a defined "current" pointer, not a race to see which edit lands last | PC-01 to PC-05 |
| LC-I-005, what a past authorization decision is evidenced against has to be the policy version live at the moment it happened | PC-06 to PC-09 |
| LC-I-006, when a policy tightens after something was approved under the old rule, the old grant does not need to be revoked and the new rule does not reach backward on its own | PC-10 to PC-13 |

That commit was a local branch when this family was built and may not yet be reachable
from the public default branch. The proposed text the vectors actually test is pinned
separately, at a commit that is.

## What this tests, and against which text

The proposed text is the **Policy version** concept in
[`AUTHORITY-LIFECYCLE.md`](https://github.com/aeoess/agent-authority-lifecycle), version
0.1.2-draft, at commit `7796e22fb80480d0336ff0967a862c84284c15e4`, section **Lifecycle
concepts are separate > Decisions and effects**:

> Policy version. Which policy an approval or decision was evaluated against. The same
> action can be allowed under one version and denied under the next.

Vectors also test three neighbouring concepts at the same commit. **Authorization
decision**, in the same section:

> Authorization decision. The record an enforcement point makes that an action was
> allowed or denied, against the authority, policy and inputs it evaluated.

**Evidence**, in **Verification and evidence**:

> Evidence. Records a decision, transition, invocation, execution or effect. Ending
> authority does not by itself erase or invalidate evidence of earlier events.

**Issuer standing**, in **Parties and standing**:

> Issuer standing. Why the issuer was allowed to create, narrow, suspend, revoke or
> replace authority for the principal. A valid signature establishes who signed. It does
> not by itself establish standing.

That document states the status of all four entries itself:

> The grouping and every other entry are **proposed**, added in 0.1.1-draft or
> 0.1.2-draft. No public case tests them yet.

### Why this is not a draft-03 case

[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/) states
no rule for policy versioning, for resolving which version is operative at an instant, or
for rendering a past decision record. The closest text is section 3.5:

> The enforcement gateway MUST recheck revocation status at execution time, not only at
> approval time.

That is about revocation status, which is a fact about the authority artifact. It does not
say which policy version an evaluation runs under, how a verifier resolves that version at
an instant, or what a past decision renders as when it is read after the policy changed.

One piece of draft-03 every action vector does lean on unchanged is chain verification,
section 3.3:

> A verifier MUST NOT union scopes or budgets from multiple chains.

Each action vector selects the one grant and takes the SDK's chain result as given. The
policy layer sits on top of that result and never alters it, which is the whole point of
PC-11 and PC-13.

## What this family defines itself

The proposed text names the dependency in two sentences and stops. It does not say how a
policy version is identified, how a verifier learns which one is operative, what a
rollback is as distinct from an edit, or what verdict any of this produces. This family
supplies all four, because a runnable case cannot exist without them, and none of them is
a reading the proposed text compels:

1. **Version identity.** A policy version is a signed record carrying `version_id`, its
   `rules`, a `rules_digest` over the rules object alone, and a `version_digest` over the
   whole record. Both are `sha256:` over `DOMAIN || 0x00 || JCS(body)`, following the
   domain-separated digest style draft-03 uses for `payload_ref` and `action_ref`.
   Splitting the two digests is what lets v3, whose rules are byte-identical to v1's,
   still be a different version.
2. **The operative pointer.** Which version is operative at an instant is a separate
   signed record naming `operative_version_id`, `effective_from` and `kind`. The operative
   version at an instant is the target of the acceptable pointer with the greatest
   `effective_from` at or before it. Two acceptable pointers sharing that instant and
   naming different targets give `not_established`, not a winner.
3. **What a rollback is.** A pointer of `kind: "rollback"` is an established rollback only
   when the version it names was already operative under an earlier acceptable pointer.
   The pointer's own `kind` field never decides this. A version that reproduces older
   rules is a new version, whatever the pointer calls it.
4. **Verdict vocabulary.** `valid`, `restricted`, `not_established`, `invalid`, from the
   settled lifecycle vocabulary. A tightened policy that blocks an action gives
   `restricted`: the grant is a fine grant, the chain is valid, and what is blocked is
   this action at this authorization boundary. It never gives `invalid`, which is reserved
   for the chain actually failing. PC-11 against PC-13 is that distinction made executable.

Read 1 to 4 as this family's proposal for how the concept would be tested, not as the
concept's meaning. See "Where the proposed text was too vague to test".

## What exists

Neither reference SDK exposes an API that resolves an operative policy version at an
instant, classifies a pointer move as a rollback, or renders a past decision against the
version it was evaluated against. The reference boundary is therefore this family's own
code, in `harness.ts`, following the precedent set by
[`fixtures/runtime-authority-denial-continuity/`](../runtime-authority-denial-continuity/)
and [`fixtures/approval-single-use/`](../approval-single-use/). **The policy-change
boundary is implemented by this fixture, not by either APS SDK. The SDKs are used only for
the things they actually decide.**

`harness.ts` calls the TypeScript SDK for three of them:

- `verifyAuthorityDelegationChain` for the grant's structural, temporal, signature and
  revocation state
- `canonicalizeJCS` for the RFC 8785 canonical bytes every record in this family is signed
  over and digested from
- `verify` for the Ed25519 signatures on the policy version, pointer and decision records

Everything else, the operative-pointer resolution, the rollback classification, the
decision rendering, the standing rule and the verdict vocabulary, is the family's own.

### SDK findings

Two findings surfaced while building this family. They are recorded here because they
changed how the family is built, not as vectors: no vector tests an SDK's export list.

**1. The TypeScript SDK has a policy layer, and it answers a different question.**
`agent-passport-system` 7.1.0 exports `createPolicyBundle`, `verifyPolicyBundle`,
`verifyPolicyChain`, `createPolicyReceipt`, `verifyPolicyDecision`,
`computeScopeVersionHash` and `verifyScopeVersionMatch`. None of them resolves an
operative version at an instant. `verifyPolicyChain` walks an ordered entry list and
checks that each entry's `previousPolicyHash` back-links to the recomputed hash of the
entry before it. It carries no `effective_from`, no operative pointer and no notion of a
rollback, so under it a rollback is a new entry with a new hash and is indistinguishable
from any other edit. That is LC-I-004's failure mode showing up in a real implementation,
which is why this family models the pointer separately rather than as another chain entry.
`fixtures/lifecycle-policy-change/sdk-probe.mjs` records the whole probe: 11 of 18
supported.

**2. The Python SDK ships none of that layer.** `agent-passport-system` 4.1.0 on PyPI has
no `create_policy_bundle`, no `verify_policy_bundle`, no `verify_policy_chain` and no
`compute_scope_version_hash`. It does expose `verify_policy_decision`, alongside the
authority-chain verifier, the JCS canonicalizer and Ed25519 verify.
`fixtures/lifecycle-policy-change/sdk-probe.py` records it: 5 of 15 supported. `verify.py`
therefore writes the pointer resolution, the rollback classification and the decision
rendering out from `agent_passport.canonicalize_jcs` and `agent_passport.crypto.verify`.
That is a recorded gap, not a claim that the Python SDK decided any of it.

## What the family does

`mint.ts` mints, with `agent-passport-system` 7.1.0:

- one one-hop `AuthorityDelegationV1` grant, principal to agent, issued at
  `2026-09-20T09:00:00.000Z` with `ledger:export` and `ledger:read`, `not_after`
  `2026-09-30T00:00:00.000Z`, so it is valid at every instant any vector evaluates
- three signed policy-version records for `ledger-export-policy`. v1 is permissive
  (`max_amount` 5000, no approval required), v2 is tightened (`max_amount` 1000, approval
  required), and v3 carries an object byte-identical to v1's rules under RFC 8785 JCS,
  authored later
- six signed operative-pointer records: the initial pointer to v1, an upgrade to v2, a
  rollback to v1, a fourth pointer with standing that shares the rollback's
  `effective_from` and names v2 instead, a pointer claiming `kind: "rollback"` while naming
  v3, and a correctly formed pointer signed by an identity with no policy standing
- four signed authorization-decision records: one allow pinned to v1, one deny pinned to
  v2, one allow carrying no pin at all, and one allow pinning a digest no version carries

`mint.ts` asserts at mint time, and exits without writing `chain.json` if any assertion
fails, that: the grant verifies `valid` at `2026-09-23T12:00:00.000Z` with an active
resolver, v3's `rules_digest` equals v1's while its `version_digest` does not, v2's rules
differ from v1's, and the four decision records re-derive under the rule evaluator to
exactly the outcomes they record. It also asserts that D1's inputs re-derive to `deny`
under v2 and that D3's and D4's re-derive to `allow` under both versions, because the
first is what makes the pin visible and the second is what makes ignoring it invisible.

`harness.ts` implements `PolicyChangeBoundary` in three modes: `pointer` (which version is
operative at an instant, and is a named pointer a rollback), `render` (what does a past
decision record render as at a read instant) and `action` (what happens to an action under
the grant at an instant). `verify.ts` runs both configurations over the thirteen
presentations. `verify.py` is a second implementation of the same rules written against
the Python SDK's primitives. Both run with no network access.

Each presentation is an independent evaluation against a fresh boundary. Unlike
`fixtures/approval-single-use/`, no state is carried between presentations and
presentation order does not matter.

## Vectors

| id | case | covers | expected |
|---|---|---|---|
| PC-01-LC-I-004-a-operative-version-at-an-instant-control | LC-I-004 | control: one pointer in force | `valid`, `pointer_is_not_a_rollback_claim`, operative v1 |
| PC-02-LC-I-004-b-rollback-to-previously-operative-version | LC-I-004 | a real rollback | `valid`, `rollback_to_previously_operative_version` |
| PC-03-LC-I-004-c-competing-pointers-one-effective-from-not-established | LC-I-004 | two pointers, one instant, different targets | `not_established`, `operative_pointer_ambiguous` |
| PC-04-LC-I-004-d-claimed-rollback-to-never-operative-version-not-established | LC-I-004 | a fresh edit reproducing old rules, labelled a rollback | `not_established`, `rollback_target_never_previously_operative` |
| PC-05-LC-I-004-e-pointer-issuer-without-policy-standing-not-established | LC-I-004 | a valid signature from an issuer with no standing | `not_established`, `pointer_issuer_without_policy_standing` |
| PC-06-LC-I-005-a-pinned-decision-renders-under-its-own-version | LC-I-005 | the pinned version differs from the version operative at read time | `valid`, `decision_renders_under_the_version_used`, under v1 |
| PC-07-LC-I-005-b-pin-equals-current-version-renders-the-same-either-way | LC-I-005 | control: pinning and not pinning coincide | `valid`, under v2 |
| PC-08-LC-I-005-c-unpinned-decision-not-established | LC-I-005 | an outcome with no pin, whose inputs read cleanly under both versions | `not_established`, `decision_not_pinned_to_policy_version` |
| PC-09-LC-I-005-d-pinned-version-unresolvable-not-established | LC-I-005 | a pin that resolves to nothing | `not_established`, `pinned_policy_version_unresolvable` |
| PC-10-LC-I-006-a-action-under-the-version-in-force-at-the-time-control | LC-I-006 | control: action inside the permissive version | `valid`, chain `valid`, operative v1 |
| PC-11-LC-I-006-b-tightened-policy-restricts-the-action-not-the-grant | LC-I-006 | the same action after the policy tightened | `restricted`, chain still `valid` |
| PC-12-LC-I-006-c-tightened-policy-still-admits-a-conforming-action | LC-I-006 | the same grant, an action inside the tightened version | `valid`, chain `valid` |
| PC-13-LC-I-006-d-revoked-grant-is-invalid-not-restricted | LC-I-006 | the discriminator: an actual revocation | `invalid`, chain `invalid`, `REVOKED` |

PC-11 against PC-13 is the pair the family turns on. A tightened policy and a revocation
both stop an action, and they must not read the same, because one of them is something a
party with standing did to the grant and the other is not.

PC-08 is the vector most likely to be argued with, and it is deliberate. Its inputs
re-derive to `allow` under both versions, so a reader who ignores the pin gets a
clean-looking answer. `not_established` says only that the record never stated what it was
evaluated against, which is a different thing from the outcome being wrong.

## Negative control

`defective-boundary-current-policy-is-the-policy` is one coherent implementation of "the
policy is whatever is live now, and a record means what it would mean today". It runs the
identical SDK chain check, the identical Ed25519 signature checks over the identical JCS
bytes, and the identical rule evaluator. It removes exactly five things:

- standing is read from the record's own `authority` field instead of being resolved from
  the policy
- a tie on `effective_from` is broken, highest `pointer_id` winning, instead of being
  recorded
- a pointer's own `kind` field is taken as the rollback classification
- a decision is rendered against whatever is operative at read time instead of against its
  pin, and an unpinned decision is rendered the same way
- a denial under the operative version is reported as the grant being invalid

Those five removals account for exactly seven vectors. The declared diverging set:

    PC-03-LC-I-004-c-competing-pointers-one-effective-from-not-established
    PC-04-LC-I-004-d-claimed-rollback-to-never-operative-version-not-established
    PC-05-LC-I-004-e-pointer-issuer-without-policy-standing-not-established
    PC-06-LC-I-005-a-pinned-decision-renders-under-its-own-version
    PC-08-LC-I-005-c-unpinned-decision-not-established
    PC-09-LC-I-005-d-pinned-version-unresolvable-not-established
    PC-11-LC-I-006-b-tightened-policy-restricts-the-action-not-the-grant

This is the negative control a naive implementation passes wrongly, and it is not a straw
man. On PC-03, PC-04, PC-05, PC-08 and PC-09 it returns a confident `valid` where the
records establish nothing, and on PC-08 and PC-09 it reports a decision as cleanly
rendered when the record never said which rule produced it. It also matches the reference
boundary on PC-01, PC-02, PC-07, PC-10, PC-12 and PC-13, which is exactly why the defect
survives in production: six of thirteen presentations give it no signal at all. Both
`verify.ts` and `verify.py` check the control in both directions, so an undeclared
divergence or a declared divergence that quietly starts matching is loud in either
runner's output.

## Running

TypeScript, wired into `npm test` as a step:

    npm ci --include=dev
    npm run verify:lifecycle-policy-change

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/lifecycle-policy-change/mint.ts

Python, a manual run and not part of `npm test`, the same convention
`fixtures/approval-single-use/verify.py` and
`fixtures/ancestor-revocation-chain/validate.py` already follow for a Python side kept out
of the hermetic Node-only CI gate. Needs `agent-passport-system` 4.x installed:

    python3 fixtures/lifecycle-policy-change/verify.py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set (python)

The two SDK support probes, which print a per-API `supported` or `not_supported` line and
assert nothing:

    node fixtures/lifecycle-policy-change/sdk-probe.mjs
    python3 fixtures/lifecycle-policy-change/sdk-probe.py

## Determinism

Every Ed25519 key is the SHA-256 of a published label under the seed prefix
`aps-conformance-suite:lifecycle-policy-change`, recorded in `chain.json` as `seed_prefix`.
Every delegation and pointer nonce is derived the same way. Every timestamp is pinned: the
grant is issued at `2026-09-20T09:00:00.000Z`, the versions are authored at
`2026-09-19T08:00`, `2026-09-21T08:00` and `2026-09-22T20:00`, the pointers take effect at
`2026-09-19T12:00`, `2026-09-21T12:00`, twice at `2026-09-22T12:00` and twice at
`2026-09-23T06:00`, and `now` is `2026-09-23T12:00:00.000Z`. Every digest is taken over
RFC 8785 JCS canonical bytes produced by the SDK's own `canonicalizeJCS`, and `verify.py`
reproduces the same bytes with the Python SDK's `canonicalize_jcs`, which is what makes the
signature checks a cross-language claim. No secret material is in the file: every public
key is published and every private key is reproducible from its published label, which is
exactly why these keys are for test vectors and nothing else.

SHA-256 over the exact bytes of this family's files, at this commit:

    6090b8f283d098bc6382936235743b6c7b71588c0f893ec4e5d221ac9f9d2f08  chain.json
    6c9b6bfb3d4411e0d370571866e0d63137c96698172fa35e236222cd01d077c1  harness.ts
    f389e36f381c546906069046c2cc41282ccd940855d00953f451597d2454ead0  mint.ts
    9abb9c4ef1edf842dd5f8175e43b5cf4e484f90d0fea94fec84d066d00f8b34c  sdk-probe.mjs
    a5b7d94edd499f315e0b224fdf644e118bf92f162cf5217657e4879ed4b8bd85  sdk-probe.py
    940b59441565a9c14b2444df30f4f86978ed53089827b140264684664baeea6e  vectors.json
    3ca0925b199cd0577f28797745aa5b6c281b0443402eba99195efb9f87c5881b  verify.py
    6716c9d177640f802803df5856212fc4ca0dda648d1eae368501ad430b039bfc  verify.ts

These are listed here rather than in a `CHECKSUMS.sha256` file on purpose. Under
`CONTRIBUTING.md`, files covered by a record's published digest set are immutable and a
later correction goes to a `CLARIFICATIONS.md` rather than to the file. A candidate family
against proposed text should stay editable while the text it tests is still being argued
about, so it does not publish a digest set that the repository's own integrity gate would
then pin.

## Verification split

This family is lab-authored and APS-native, not an ingestion from an external system, so
`CONTRIBUTING.md` does not require this section of it. It is recorded anyway, in the same
format and with the same two label axes, because the family's verdicts come from its own
boundary rather than from either SDK and a reader deserves to see that split stated rather
than inferred. Nothing here asks for the family to be classified as an external-system
family, and it is not listed in `fixtures/cross-stack/index.json`.

- grant chain state at every evaluated instant (`valid` under an active resolver, `invalid`/`REVOKED` under a revoked one); runner aeoess; Mode A; author-produced, because this lab authored the vectors and `mint.ts` and the implementation under test is this lab's own `agent-passport-system`; recomputed by `agent_passport.v2.authority_delegation.verify_authority_delegation_chain` in `verify.py` under the same relationship.
- Ed25519 signatures on the policy version, operative pointer and decision records over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` plus `verify` on one side and the Python SDK's `canonicalize_jcs` plus `agent_passport.crypto.verify` on the other.
- policy version and rules digests over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` on one side and the Python SDK's `canonicalize_jcs` on the other.
- the thirteen policy-change verdicts and the declared defective diverging set; runner aeoess; Mode A; author-produced, because the boundary that decides each verdict is this family's own `harness.ts` and its Python counterpart in `verify.py`, both written in this lab.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Results

Both runners were executed locally against `agent-passport-system` 7.1.0 (npm) and
`agent-passport-system` 4.1.0 (PyPI, in a virtual environment). The `reference-boundary`
matched 13/13 presentations under both runners.
`defective-boundary-current-policy-is-the-policy` diverged on exactly the declared set of
7 under both runners and matched the remaining 6 under both. `npm ci --include=dev` and
`npm test` both exited 0 with this family wired in. These are author-produced records, not
independent ones, per `CONTRIBUTING.md`.

## Where the proposed text was too vague to test

This is a finding, and it matters at least as much as the fixture. The **Policy version**
entry names a real dependency in two sentences and leaves four things undetermined. Each
one had to be decided before a single vector could exist, and a different decision gives
different expected verdicts for the same records:

1. **No verdict for a tightening.** The text says the same action "can be allowed under one
   version and denied under the next" and stops. It does not say what happens to the grant.
   `invalid`, `restricted`, `suspended`, and "valid, and this action is denied" are all
   readings. This family chose `restricted`, which keeps the grant and the chain intact and
   says only that this action at this authorization boundary is blocked. Nothing in the text
   compels it, and PC-11 would change wholesale under any of the others.
2. **No identity for a version.** The text says "which policy" without saying what
   identifies one. A name, a sequence number, a digest over the rules, or a digest over the
   whole record are all candidates, and they are not equivalent: under a rules digest, v3 and
   v1 in this family are the same version, and PC-04 has no answer at all. This family pins
   both digests separately for exactly that reason, which is a structure the text never asks
   for.
3. **No rule for which version is operative.** The text names the dependency and says
   nothing about how a verifier resolves it at an instant, or what happens when two records
   with standing disagree about that instant. PC-03 is that gap made executable. A model with
   a total order over pointers, a sequence number, or a required `supersedes` back-link would
   answer PC-03 with a winner rather than with `not_established`, and would be equally
   consistent with the text as written. The `supersedes` field exists in this family's pointer
   record and is deliberately left `null` on every pointer, because the text gives no basis
   for requiring it.
4. **No distinction between an edit and a rollback.** The text does not separate them, and
   the TypeScript SDK's own `verifyPolicyChain` does not either, which is how the gap shows
   up in practice. This family's rule, that a rollback names a version that was already
   operative, is one answer. "A rollback restores the previous rules digest" is another, and
   it gives PC-04 the opposite verdict.

A fifth thing is under-determined rather than undetermined. The **Authorization decision**
entry says a decision is recorded "against the authority, policy and inputs it evaluated",
which reads as requiring a pin, but it does not say what a verifier should do with a record
that carries no pin. PC-08 makes `not_established` executable. Reading the same absence as
"render under the current version and say so" is a defensible alternative, and it is exactly
what the negative control does.

Until at least 1 to 4 are settled in the proposed text, no case in this family can move from
`candidate` to `tested` against it, because there is nothing yet to be conformant with. That
is the finding.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundary and its own record shapes:

- a policy tightening after issuance records the action as `restricted` and leaves the grant
  and its chain `valid`, and an actual revocation of the same grant records `invalid` with
  `REVOKED`, so the two are distinguishable from the output alone
- the same grant still admits an action that conforms to the tightened version, so nothing
  about the tightening was treated as an event on the grant
- a past decision record that pins the policy version it was evaluated against renders under
  that version, including when a later version would produce a different outcome
- a decision record carrying no pin, or a pin that resolves to no version this boundary holds,
  records that what it was evaluated against is not established, rather than being rendered
  under whatever is current
- two acceptable pointers sharing one `effective_from` and naming different versions record
  that the operative version is not established, rather than one of them winning
- a pointer that claims to be a rollback while naming a version no earlier pointer made
  operative records that the claim is not established, and names the version whose rules it
  reproduces
- a correctly signed pointer from an issuer this boundary does not resolve as having standing
  for the policy establishes nothing about the operative version
- an implementation that reads history under today's policy and treats a tightening as
  invalidity predictably diverges on exactly those seven vectors, and on none of the other six

## Does not claim

A pass does **not** establish:

- anything about draft-pidlisnyi-aps-03 conformance. draft-03 states no policy-versioning
  rule. Every vector is `candidate_against_proposed`, and a maintainer who disagrees with
  any of the four decisions under "What this family defines itself" should expect different
  expected verdicts, not a bug report.
- that this family's version identity, pointer record, rollback rule or verdict vocabulary
  is the right one, or the only defensible one. See "Where the proposed text was too vague
  to test".
- anything about a deployed policy engine, OPA, Cedar, IAM or any other policy system. No
  network call is made and no policy language is spoken. The rule evaluator here is an
  amount ceiling and an approval flag, authored for this family.
- that the Massachusetts zoning provision cited in `CASES.md` for LC-I-006, or any other
  legal doctrine, applies to AI agents. It is cited there as a source for the shape of the
  question, which is what the model document says about agency law too. This family tests
  record handling and nothing else.
- that either reference SDK implements policy versioning. Neither does. The TypeScript
  SDK's `verifyPolicyChain` checks hash back-links in an ordered entry list and carries no
  operative pointer, and the Python SDK ships no policy bundle or chain surface at all. See
  "SDK findings".
- anything about how a policy version should narrow across a delegation chain. The grant
  here is a one-hop root delegation, so no parent-to-child comparison is exercised.
- that any decision recorded here was ever executed. Nothing here executes anything.

## Provenance

`README.md`, `vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`,
`verify.py`, `sdk-probe.mjs` and `sdk-probe.py` are authored for this suite. The minting,
chain verification, canonicalization and signature primitives are
`agent-passport-system` 7.1.0 (npm) and `agent-passport-system` 4.1.0 (PyPI). The case
statements come from `CASES.md` in `aeoess/agent-authority-lifecycle` at commit
`2bf5c7e2d07d41c13611478d6e5e47fcb4d3ceda`, and the proposed text under test comes from
`AUTHORITY-LIFECYCLE.md` in the same repository at commit
`7796e22fb80480d0336ff0967a862c84284c15e4`.
