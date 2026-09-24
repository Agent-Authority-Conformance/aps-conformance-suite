# lifecycle-conferral-without-authority: holding a scope is not the right to confer it

An agent holds a grant for `calendar:*`. The grant verifies `valid`. It is unrevoked. It
is inside its time window. Its issuer had standing. The agent then issues a child to a
subagent for `calendar:*`, exactly what it holds, no more. That child must not verify.

Nothing about the child is wider than the parent, so a verifier that asks only "is the
child no wider than the parent?" admits it. The question that verifier never asks is
whether this agent was ever allowed to create a child at all. Monotonic narrowing
constrains what a child may receive. It does not say who may create one.

**Every vector in this family is labelled `candidate_against_proposed.`** The lifecycle
claim these vectors were built to test is the proposed text's, not draft-03's. Seven of
the ten vectors additionally exercise a rule draft-pidlisnyi-aps-03 Section 3.2 does
state, cited per vector in `draft03_basis`. One vector, CWA-07, is a case where the two
texts reach different verdicts, and it is marked as a divergence rather than asserted
either way.

## The proposed text this tests

[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle),
`AUTHORITY-LIFECYCLE.md` at commit `2bf5c7e`, document version 0.1.2-draft. `2bf5c7e` is
later than `5c1bf09`, and `AUTHORITY-LIFECYCLE.md` is byte-identical between the two
commits, which changed `CASES.md` and `BOUNDARY-CASES.md` only.

Section **"Lifecycle concepts are separate" > "Authority and dependencies"**, the
load-bearing entry, quoted in full:

    Delegated authority. Says X may do Y because principal Z granted it, under which
    constraints, for which targets and for what period, through a specific chain.

The adjacent entry, which is why the parent's own chain position is what the reject
vectors turn on:

    Authority path and dependency. Which other authority a grant currently depends on.
    Historical provenance and current dependency are not necessarily the same thing.

Section **"Parties and standing" > "Issuer standing"**, quoted in full, because the
question this family asks about a child's issuer is a standing question and not a
signature question:

    Why the issuer was allowed to create, narrow, suspend, revoke or replace authority
    for the principal. A valid signature establishes who signed. It does not by itself
    establish standing.

Invariant **L5. Independent chains are not combined**, quoted in full:

    An agent holding two valid chains cannot use them together to create a grant broader
    than either chain allows. Each grant follows one parent chain.

Its status line in that document reads: "Status **specified, not yet tested**." L5 is the
nearest published invariant to what this family tests, and it is not the same claim. L5
bounds what a holder of two chains may put into a child. This family bounds whether a
holder of one chain may create a child at all.

Invariant **L4. A successor does not inherit the predecessor's delegation tree**, quoted
in full, for the same reason: it is about what a grant covers, not about who may issue
one.

    A successor's grant covers what the successor issues. Other descendants of the
    departing principal stay invalid until someone with current authority issues them new
    grants.

**What the published document does not say.** No section of `AUTHORITY-LIFECYCLE.md` at
`2bf5c7e` names a conferral right, a delegation right, a delegation depth, or any
authority to create a child as a distinct thing from the authority a child receives. The
concept list under "Authority and dependencies" has six entries and none of them is it.
That absence is the first finding of this fixture and is recorded below under "Where the
proposed text was too vague to test".

## Where draft-03 does and does not state a rule

**The zero-remaining case: draft-03 states the rule.** draft-pidlisnyi-aps-03 Section
3.2, the Depth component order, verbatim:

    Depth  remaining is an integer from 0 through 255.  A parent with zero remaining
    cannot issue a child.  Otherwise child.remaining MUST be no greater than
    parent.remaining minus one.

That sentence is the whole of the reject rule CWA-02, CWA-03, CWA-04 and CWA-08 exercise,
and the narrowing half is what CWA-05 exercises. Those five vectors carry `draft03_basis`
naming this text. They stay labelled `candidate_against_proposed` because what this
family asserts about them is the lifecycle claim (that conferral authority is a separate
declared authority from the scope held, and that possession of a scope establishes
nothing about it), which is the proposed text's claim and not draft-03's.

**The undeclared case: draft-03 answers it differently.** Section 3.1, verbatim:

    authority contains exactly seven required facets: scope, spend, depth, time,
    reputation, values, and reversibility.  A missing facet is invalid rather than an
    implicit unconstrained value.

The proposed text's undeclared limb says conferral is then **not established**. draft-03
says the record is **invalid**. Both refuse the child, and they are not the same verdict.
CWA-07 records the divergence and asserts draft-03's answer, because that is the answer
both SDKs return and no vector this family could write would make them return the other
one. See "Where the proposed text was too vague to test", item 1.

**Conferral is not among draft-03's named core invariants.** Section 3.6 enumerates eight
invariants: "INV-1 (Identity Verifiability), INV-2 (Scope Monotonic Narrowing), INV-3
(Spend Limit Narrowing), INV-4 (Cascade Completeness), INV-5 (Revocation Irreversibility),
INV-6 (Intent-Receipt Binding), INV-7 (Authority Attribution Completeness), and INV-8
(Signature Integrity)". None of them is a depth or conferral invariant, and the clause
that pushes enforcement back to issuance names only three: "INV-2, INV-3, and INV-8 are
enforced at issuance, not only at verification." The depth rule is a component order in
Section 3.2 and a chain-verification phase in Section 3.3, and nothing in Section 3.6
requires an issuer to enforce it. Both reference SDKs enforce it at issuance anyway, which
this family records as observed behavior rather than as a conformance claim. See
`mint_time_sdk_observations.cooperative_issuance_refusal_from_zero_depth_parent`.

**The same reading appears in the draft's related-work section**, which is useful because
it names depth as one of three things a narrowing rule can be about:

    PEDIGREE [PEDIGREE] specifies signed JWT delegation chains for workload and agentic
    identity, with per-parent mandate narrowing: it requires each hop's scopes to be a
    subset of the immediate parent's, limits token lifetime to the parent's remaining
    lifetime, and checks chain depth against the parent chain.

## What exists in the reference SDKs

Both runners print their own support table, so the record below is produced by the run
rather than typed. Verbatim from the two runs recorded under "Results":

    TypeScript SDK support, agent-passport-system 7.1.0:
      supported      chain state, including time and revocation  (verifyAuthorityDelegationChain)
      supported      declared conferral right (depth facet)  (AuthorityVectorV1.depth.remaining, compareAuthority)
      supported      conferral refused when the right is exhausted  (DEPTH_EXHAUSTED)
      supported      conferral right narrows like any other facet  (DEPTH_WIDENING)
      supported      scope coverage  (scopeGrantCovers)
      supported      issuer-side refusal to mint an unauthorized conferral  (issueSubAuthorityDelegation)
      not_supported  undeclared conferral right as its own verdict  (no API: a missing facet is SCHEMA_INVALID, never not_established)

    Python SDK support, recorded by this run against 4.1.0:
      supported      chain state, including time and revocation  (verify_authority_delegation_chain)
      supported      declared conferral right (depth facet)  (compare_authority)
      supported      conferral refused when the right is exhausted  (DEPTH_EXHAUSTED)
      supported      conferral right narrows like any other facet  (DEPTH_WIDENING)
      supported      scope coverage  (scope_grant_covers)
      supported      issuer-side refusal to mint an unauthorized conferral  (issue_sub_authority_delegation)
      not_supported  undeclared conferral right as its own verdict  (no API: a missing facet is SCHEMA_INVALID, never not_established)

Unlike several sibling lifecycle families, this one needs no fixture-authored boundary for
its main claim. Both reference SDKs already carry the concept the proposed text is about,
as the `depth` facet, and both decide every reject vector themselves. The one
`not_supported` row is the undeclared case, and it is not a defect report: neither SDK
claims to have a `not_established` verdict, and no published text requires one. What the
row records is that the proposed text's second limb has no expressible form on this wire.

## What the family does

`mint.ts` mints, with the pinned TypeScript SDK `agent-passport-system` 7.1.0:

- **three one-hop roots**, the same scheduling principal to the same calendar agent, the
  same scope `calendar:*`, the same spend ceilings, the same week-long window, differing
  in exactly one value: `depth.remaining` of 2, 1 and 0. The agent's held authority is
  otherwise identical across all three, so no reject below can be explained by anything
  except the declared conferral right. `mint.ts` asserts that each root, presented alone,
  verifies `valid` at the fixture's single verification instant, and that the depth-0 root
  holds the same scope array as the depth-2 root.
- **three children the SDK's own cooperative issuance path produced**, through
  `issueSubAuthorityDelegation`, narrowing check and all: the positive controls.
- **six children signed through the lower-level primitives**, `computeAuthorityDelegationId`
  followed by `signAuthorityDelegation`, because `issueSubAuthorityDelegation` refuses to
  mint them. What is tested here is a **verifier's** refusal of a syntactically valid,
  correctly signed child that a cooperating issuer would never have produced, not an
  issuer's willingness to create one. The same technique and the same reasoning are used
  by [`fixtures/single-chain-selection/mint.py`](../single-chain-selection/mint.py). The
  issuer's refusal is recorded separately, in
  `mint_time_sdk_observations.cooperative_issuance_refusal_from_zero_depth_parent`, whose
  value is `authority delegation does not narrow (DEPTH_EXHAUSTED)`.

`mint.ts` aborts with nothing written if any of the following fails. Every minted record
has a distinct `delegation_id`. Every reject child's `delegation_id` recomputes from its
own body. Each of the three roots verifies `valid` alone. The depth-0 and depth-2 roots
hold identical scope. `scopeGrantCovers` confirms `calendar:*` covers both itself and
`calendar:write`. `compareAuthority` on the CWA-03 pair returns exactly one failure and
that failure is `DEPTH_EXHAUSTED`. `issueSubAuthorityDelegation` refuses the CWA-03 child
and refuses it for that reason. All three positive controls verify `valid` end to end.
Every SDK answer for every presented chain is then written into `chain.json` under
`mint_time_sdk_observations`, so this README quotes recorded values rather than remembered
ones.

`harness.ts` holds three verifier configurations. The reference one is deliberately thin:
it hands the presented chain and the three resolvers to
`verifyAuthorityDelegationChain` and returns what came back, unchanged. Nothing in the
harness decides the reference verdict, which is what keeps that record's recomputation
implementation the SDK rather than this fixture. The two defective ones do construct
verdicts, and are therefore part of the recomputation implementation for their own claims.

## Vectors

Ten vectors in `vectors.json`, against `chain.json`'s `presented` map. One verification
instant, `2026-09-22T12:00:00.000Z`, for all of them. Every record in every presented
chain is unrevoked and inside its own time window at that instant, so no reject can be
explained by time or by revocation.

| id | parent depth | child depth | change from its control | expected |
|---|---|---|---|---|
| CWA-01 | 2 | 1 | **positive control** | valid |
| CWA-02 | 0 | 0 | **the headline.** Parent declares zero hops, and the child is conferred exactly what the parent holds | invalid, `DEPTH_EXHAUSTED`, index 1 |
| CWA-03 | 0 | 0 | **the vector a naive implementation passes wrongly.** Child is strictly narrower in all six non-depth facets | invalid, `DEPTH_EXHAUSTED`, index 1 |
| CWA-04 | 0 (at hop 2) | 0 | one record appended to CWA-10, issued by a subagent whose own grant declares zero hops | invalid, `DEPTH_EXHAUSTED`, index 2 |
| CWA-05 | 2 | 2 | child keeps the parent's full remaining conferral right instead of consuming a hop | invalid, `DEPTH_WIDENING`, index 1 |
| CWA-06 | 2 | 1 | conferral authorized, and the child's scope adds `payments:refund`, which the parent never granted | invalid, `SCOPE_WIDENING`, index 1 |
| CWA-07 | 2 | (absent) | **divergence.** The child's authority vector omits `depth` entirely rather than setting it to zero | invalid, `SCHEMA_INVALID`, index 1 |
| CWA-08 | 0 | 0 | the child's subject is the issuing agent itself. A copy of itself, which the proposed text names | invalid, `DEPTH_EXHAUSTED`, index 1 |
| CWA-09 | 1 (at hop 2) | 0 | **positive control at chain length three.** Two hops declared, both spent, each consuming one | valid |
| CWA-10 | 1 | 0 | **positive control.** The last declared hop, spent. The parent of CWA-04 | valid |

CWA-02 is the case the family exists for. At that instant the parent verifies `valid`
alone, holds `calendar:*`, and the child asks for `calendar:*`. There is nothing wider
about the child. The only thing wrong with it is that this agent was never given the
right to make one.

CWA-06 is what keeps the two questions apart. Its conferral is authorized (the parent
declares two hops, the child consumes one) and it is still refused, on scope. Without it,
a reader could take this family to be claiming that declared conferral authority settles
what a child may receive. It does not.

### CWA-03 is the negative control a naive implementation passes wrongly

CWA-03's child narrows scope (`calendar:*` to `calendar:write`), spend (6000/60000 to
1000/10000), time (a four-day window to a two-day one), reputation (80 to 40),
reversibility (compensable to tentative) and adds a required value identifier. Six of the
seven facets move strictly inward. `compareAuthority` on the pair returns exactly one
failure, and both runners recompute that claim:

    compare_authority on the CWA-03 pair: ['DEPTH_EXHAUSTED'], one failure, facet depth

An implementation that enforces monotonic narrowing on every facet it knows how to compare,
and never asks who may create a child, admits this. That implementation is
`defective-verifier-narrowing-without-depth` below, and it is not a strawman: it still
catches scope widening, a broken signature, a broken parent link and a malformed record.

### Negative controls at the verifier level

`defective-verifier-narrowing-without-depth` is the reference verdict with every `DEPTH_*`
failure dropped, which is exactly what a six-facet narrowing check produces. This is the
failure the proposed text exists to block, written out. Its declared divergence set, five
vectors, every one in the wrongly-admits direction:

    CWA-02  CWA-03  CWA-04  CWA-05  CWA-08

`defective-verifier-scope-coverage-only` verifies every record's signature and checks only
that every child scope grant is covered by some parent grant, using the SDK's own coverage
predicate. It is the shape of a deployment that reads the scope array and treats the rest
of the authority vector as metadata. Its declared divergence set, six vectors, every one in
the wrongly-admits direction:

    CWA-02  CWA-03  CWA-04  CWA-05  CWA-07  CWA-08

Both runners check both directions for both controls: every declared id must actually
diverge from the reference verdict, and every other id must still agree with it, so an
undeclared divergence and a declared divergence that quietly starts agreeing are both loud
in either runner's output.

## Where the proposed text was too vague to test

These are findings, not defects in the fixture. Each one is a place the fixture had to
choose something the proposed text does not say. This section matters as much as the
fixture.

1. **The proposed text has no concept for conferral authority, and the invariant this
   family tests is not in the published document.** `AUTHORITY-LIFECYCLE.md` at `2bf5c7e`
   lists six entries under "Authority and dependencies" and none of them is the right to
   create a child. The nearest published invariant, L5, is about combining two chains, not
   about creating one child from one chain. This fixture therefore tests a claim that is
   forced by the published concept list's own logic (delegated authority runs "through a
   specific chain", and issuer standing is separate from signature validity) but is not
   itself stated there. A reviewer who wants this family to have a named invariant to
   point at has to add one first.

2. **"Where the model does not declare it, conferral is not established" has no
   expressible form on this wire.** draft-03's authority vector is closed and all seven
   facets are required, so a delegation cannot omit its conferral right: the case the
   proposed text scopes itself to, the undeclared one, is a schema error rather than a
   lifecycle state. CWA-07 records that as `SCHEMA_INVALID` and marks the divergence. The
   fixture does not assert the proposed text's `not established` verdict anywhere, because
   no input it could construct produces it from either SDK. If the proposed text means
   this limb to be testable, it needs either a wire format where a facet can be absent
   without the record being malformed, or a rewrite that drops the undeclared case.

3. **The text does not say whether conferral authority narrows.** It says conferral is
   "itself a declared authority" and stops. Whether a child may inherit the parent's full
   remaining conferral right, or must consume one hop, is a separate question the proposed
   text never reaches. CWA-05 tests the answer draft-03 gives (`DEPTH_WIDENING`), not an
   answer the proposed text gives, because there is none to test. A model where conferral
   authority is a boolean rather than a counter would answer CWA-05 the other way and
   would not thereby contradict the proposed text.

4. **A copy of itself is named and not defined.** The statement covers "a child it creates
   or a copy of itself". CWA-08 models a copy as a delegation whose subject equals its
   issuer, because that is the only form of self-conferral this wire format has. A process
   fork that carries the same key and the same grant bytes into a second runtime, with no
   new record at all, is the case the phrase most naturally describes, and no vector here
   covers it, because nothing is issued for a verifier to refuse. That gap is the same
   shape as the one `OPEN-QUESTIONS.md` records under "Teardown completeness": what happens
   off the wire is invisible to a records-based verifier.

5. **Nothing says at which boundary the conferral check belongs.** draft-03 Section 3.6
   pushes INV-2, INV-3 and INV-8 back to issuance and is silent about depth, while Section
   3.3 makes depth a verification phase. Both reference SDKs enforce it in both places.
   Whether a conforming implementation may enforce it only at verification, and admit a
   cooperating issuer that mints an unauthorized child for a later verifier to catch, is
   not settled by either text. This fixture records the SDKs' issuer-side refusal as an
   observation and gates on the verifier-side refusal only.

6. **Nothing distinguishes conferral authority from issuer standing.** The proposed text
   has a separate "Issuer standing" concept, defined as "why the issuer was allowed to
   create, narrow, suspend, revoke or replace authority for the principal". Read plainly,
   an agent's right to create a child is an instance of issuer standing, and CAND-10 would
   be a corollary of a concept already in the document rather than a new claim. The
   difference, if there is one, is that standing is asked about the issuer's relationship
   to the principal while conferral is asked about the issuer's position in one chain. No
   vector here can separate those two readings, because the depth facet answers both at
   once.

## Running

TypeScript, wired into `npm test` as its last step:

    npm ci --include=dev
    npm run verify:lifecycle-conferral-without-authority

Expected final line:

    PASSED: reference-verifier matched all 10/10 vectors, both defective verifiers diverged on exactly their declared sets

Python, against the pinned Python SDK, a manual run and not part of `npm test`, the same
convention [`fixtures/runtime-authority-denial-continuity/verify.py`](../runtime-authority-denial-continuity/verify.py)
and [`fixtures/ancestor-revocation-chain/validate.py`](../ancestor-revocation-chain/validate.py)
already follow for a Python side kept out of the hermetic Node-only CI gate:

    python3 -m venv /tmp/aac-cwa-work/pyenv
    /tmp/aac-cwa-work/pyenv/bin/pip install agent-passport-system==4.1.0
    /tmp/aac-cwa-work/pyenv/bin/python fixtures/lifecycle-conferral-without-authority/verify_python_sdk.py

Expected final line:

    PASSED: reference-verifier matched all 10/10 vectors, both defective verifiers diverged on exactly their declared sets (python SDK)

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/lifecycle-conferral-without-authority/mint.ts

## Determinism

Every key is an Ed25519 seed derived from a published label under the prefix
`aps-conformance-suite:lifecycle-conferral-without-authority:`, recorded in `chain.json`
as `seed_label_prefix`. Every nonce is derived the same way, from a published label under
`nonce:`. No clock is read and no randomness is drawn: every timestamp and every facet
value is a pinned constant. Canonical bytes are RFC 8785 JCS throughout, through the SDK's
own `canonicalizeJCS` on the TypeScript side and the same canonicalization inside
`compute_authority_delegation_id` on the Python side. `chain.json` is written with keys
sorted at every depth, so the file is a function of its content and not of insertion order.

`mint.ts` was run three times in a row during authoring and produced byte-identical output
each time.

Checksums of the committed files, as generated:

    ec62cca386991e6330fdde0b121804bd6546814ea0418562929b5c12e90517f2  chain.json
    406f689f987cb54cead9f99bf908cecaab2ececcfc7ccc97fcd21c71e947c782  vectors.json

The digest of the RFC 8785 JCS canonical form of `chain.json`'s content, printed by
`mint.ts` and independent of the file's indentation:

    537dba257855fdda333213c76767ce7b86e6ba12560a8c50e539ba85ea44e5b4

## Results

Both runners were executed locally, with no network access at run time. `reference-verifier`
matched all 10/10 vectors under both runners, with identical state, failure code and
failure index on every vector. `defective-verifier-narrowing-without-depth` diverged on
exactly its declared set of 5 under both runners, and agreed with the reference on the
remaining 5. `defective-verifier-scope-coverage-only` diverged on exactly its declared set
of 6 under both runners, and agreed on the remaining 4. The two SDKs agree on all 10
outcomes for all three configurations.

Both records are author-produced, not independent, per `CONTRIBUTING.md`'s admission rules
for run records. See the Verification split below.

## Verification split

One entry per distinct verification claim, in the form
`layer / claim; runner; Mode; authorship; implementation`, per `CONTRIBUTING.md`.

- **Chain verification of a conferral / claim: a chain whose parent declares zero
  remaining conferral hops is `invalid` with `DEPTH_EXHAUSTED` at the child's index, and a
  chain whose parent declares a remaining hop the child consumes is `valid`**; runner: the
  lab, via `fixtures/lifecycle-conferral-without-authority/verify.ts`; Mode A;
  author-produced; implementation: `agent-passport-system` 7.1.0 (npm). Authorship
  relationship preventing an independent label: the lab authored the vectors and the claim
  inputs, and the implementation is a reference SDK from the same project. The runner is
  thin for this claim, transporting inputs into `verifyAuthorityDelegationChain` and
  comparing outputs, so the SDK supplies the recomputation.

- **Chain verification of a conferral / same claim, recomputed by the Python reference
  SDK**; runner: the lab, via `verify_python_sdk.py`; Mode B; author-produced;
  implementation: `agent-passport-system` 4.1.0 (PyPI). Authorship relationship: as above.
  The two SDKs are separate implementations and the Python run supplies the substantive
  recomputation of this claim, but both are reference SDKs of the same project and the lab
  authored the vectors, so the record is not independent.

- **Facet comparison in isolation / claim: the CWA-03 pair fails on exactly one facet, and
  that facet is depth**; runner: the lab, via `mint.ts` (TypeScript, `compareAuthority`)
  and `verify_python_sdk.py` (Python, `compare_authority`); Mode A and Mode B
  respectively; author-produced; implementation: `agent-passport-system` 7.1.0 (npm) and
  4.1.0 (PyPI). Authorship relationship: the lab authored the authority vectors being
  compared. This claim is separated from the chain-verification claim because it is what
  makes CWA-03 a negative control rather than an ordinary reject: it establishes that no
  other facet contributes to the refusal.

- **Issuer-side refusal / claim: `issueSubAuthorityDelegation` refuses to mint a child
  from a parent with zero remaining depth, with `DEPTH_EXHAUSTED`**; runner: the lab, via
  `mint.ts`; Mode A; author-produced; implementation: `agent-passport-system` 7.1.0 (npm).
  Authorship relationship: the lab authored the parent grant. This is recorded as an
  observation and no vector gates on it, because draft-03 Section 3.6's issuance clause
  names INV-2, INV-3 and INV-8 and not depth.

- **Divergent-verifier decisions / claim: the reference verifier matches all 10 vectors and
  the two defective verifiers diverge on exactly their declared sets, in both directions**;
  runner: the lab, via `verify.ts` and `verify_python_sdk.py`; Mode A and Mode B
  respectively; author-produced; implementation:
  `fixtures/lifecycle-conferral-without-authority/harness.ts` and the verifier functions
  inside `verify_python_sdk.py`, both authored by the lab. Authorship relationship: the lab
  authored the vectors, both defective verifiers, and both runners. Neither runner is a
  thin harness for this claim: each constructs and interprets the defective verdicts, so
  both are part of the recomputation implementation for it.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that:

- an agent whose grant verifies `valid`, is unrevoked, is inside its time window and
  declares zero remaining conferral hops cannot confer the scope it holds, and the refusal
  names the conferral right rather than the scope
- that refusal survives the child being strictly narrower in all six non-depth facets, so
  it is not a narrowing result reported under another name
- the conferral right is consumed by the act of conferring and not by the scope conferred:
  a chain whose first conferral was authorized is refused at its second, at that record's
  own index, with the first conferral left standing
- a declared conferral right narrows like any other facet: a child that keeps its parent's
  full remaining right is refused
- declared conferral authority is not a licence to widen: an authorized conferral that names
  a scope grant the parent never held is still refused, on scope
- self-conferral, a delegation whose subject equals its issuer, is refused on the same
  ground as any other conferral, with no special case
- both reference SDKs agree on all ten outcomes, with identical failure codes and indices
- an implementation that enforces monotonic narrowing across six facets and never asks who
  may create a child admits five of these ten chains, and one that checks signatures and
  scope coverage alone admits six

## Does not claim

A pass does **not** establish:

- that the proposed text's undeclared case, where a model declares no conferral right at
  all, resolves to `not established`. It does not resolve to that on this wire, and CWA-07
  records the divergence rather than resolving it. See "Where the proposed text was too
  vague to test", item 2
- that conferral authority must be a counter rather than a boolean, or that a model in
  which it does not narrow is non-conforming under the proposed text. See item 3
- anything about a process fork, a runtime copy, or any duplication of an agent that issues
  no record. Nothing is issued in that case, so no verifier is asked anything. See item 4
- that a conforming implementation must enforce the conferral check at issuance. Both SDKs
  do, and draft-03 Section 3.6 does not require it. See item 5
- that conferral authority is a distinct concept from issuer standing rather than an
  instance of it. No vector here separates the two readings. See item 6
- anything about a deployed enforcement gateway, MCP server or agent runtime. No network
  call is made and no protocol is spoken
- that this behavior is unique to the SDKs run here, or that any independent draft-03
  implementation has been checked
- anything about revocation, expiry, suspension or spend accumulation. Every record in
  every presented chain resolves `active` and is inside its own time window at the single
  verification instant, and no budget ledger is used
- anything about a legal doctrine. A scheduling principal delegating calendar authority is
  a scenario chosen because it is machine-checkable, not because any body of law is being
  applied to an AI agent

## Provenance

`vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`, `verify_python_sdk.py`
and this README are authored for this suite. The seed-label and minting pattern follows
[`fixtures/approval-single-use/mint.ts`](../approval-single-use/mint.ts). The
signing-without-the-issuer-narrowing-check technique, and the reasoning for it, follow
[`fixtures/single-chain-selection/mint.py`](../single-chain-selection/mint.py). The
reference-plus-declared-defective-control pattern follows
[`fixtures/runtime-authority-denial-continuity/harness.ts`](../runtime-authority-denial-continuity/harness.ts)
and [`fixtures/approval-single-use/harness.ts`](../approval-single-use/harness.ts). All
code was written in this lab. Neither runner was reviewed by anyone outside it, and no
independent third party has run either of them.
