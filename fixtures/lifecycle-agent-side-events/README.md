# lifecycle-agent-side-events: the grant did not change, everything around it did

**Status: candidate against proposed text. This is not a draft-03 conformance case.**
Every vector in `vectors.json` carries `status: "candidate_against_proposed"` and names
both the proposed text it tests and the `CASES.md` case id it comes from. `verify.ts` and
`verify.py` both refuse to run if any vector loses that label, names proposed text the
file does not define, or stops carrying its case id in its own vector id.

Four one-hop grants that are valid under every lifecycle rule at every instant these
vectors evaluate. What changes is on the agent's side of them: a self-made copy and a new
instance carrying transferred memory present the same authority material, a still-fresh
credential is presented a second time and a boundary's record of what it has already spent
is lost, the executor a grant names is retired on a published schedule, a revocation notice
takes effect part way through the window, and an update gives the runtime a capability the
principal never consented to.

## Which cases this family covers

Six cases from the **Agent-side events** section of `CASES.md` in
[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle),
at commit `2bf5c7e2d07d41c13611478d6e5e47fcb4d3ceda`:

| case | vectors |
|---|---|
| LC-E-002, a valid, non-expired, non-revoked grant can become unexecutable, and that is a fourth state | ASE-01 to ASE-04 |
| LC-E-012, a valid timestamp alone does not stop replay, a maintained seen-cache does | ASE-05 to ASE-08 |
| LC-E-021, revoking a permission does not erase what a session already learned while it was valid | ASE-09 to ASE-11 |
| LC-E-025, a self-replicated copy holds no authority by default, no matter how identical it is | ASE-12, ASE-13 |
| LC-E-031, a memory architecture built for one continuous identity says nothing about whether its content is current authority once transferred | ASE-14, ASE-15 |
| LC-E-027, a real precedent exists for gating expanded capability behind mandatory re-consent | ASE-16 to ASE-20 |

That commit is reachable from the public default branch of that repository. The
proposed text the vectors actually test is pinned separately, at an earlier commit on
the same history.

The other six cases in that section are not built here. `HANDOFF-2026-09-24-lab-g5.md`
records why, case by case. In short, LC-E-001 and LC-E-033 are covered by
[`fixtures/capability-binding-drift/`](../capability-binding-drift/), LC-E-006 by
`fixtures/lifecycle-conferral-without-authority/`, LC-E-004 by
[`fixtures/ancestor-revocation-chain/`](../ancestor-revocation-chain/) together with
[`fixtures/sponsor-handover/`](../sponsor-handover/), LC-E-013 by
[`fixtures/cached-authorization-revocation/`](../cached-authorization-revocation/), and
LC-E-023 by `fixtures/authority-epoch-rollback/`.

## The real-world shapes behind the six cases

Each source below was fetched while this family was being built, and each quote is
verbatim from it. They are cited as the source of the shape of the question. None of them
is a statement about AI agents, and this family does not treat any of them as one.

**A retired executor (LC-E-002).** OpenAI's deprecation documentation,
[developers.openai.com](https://developers.openai.com/api/docs/deprecations):

> At the time of the shut down, the model or endpoint will no longer be accessible.

**A replay record, and losing one (LC-E-012).** RFC 4120, Kerberos, section 3.2.3,
[rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4120):

> the server MUST utilize a replay cache to remember any authenticator presented within
> the allowable clock skew

and, on what to do when that record is gone:

> If a server loses track of authenticators presented within the allowable clock skew, it
> MUST reject all requests until the clock skew interval has passed

ASE-07 and ASE-08 are that second sentence made executable.

**Revocation that is not retroactive erasure (LC-E-021).** PostgreSQL's own documentation
for the schema `USAGE` privilege, [postgresql.org](https://www.postgresql.org/docs/current/ddl-priv.html):

> Also, after revoking this permission, existing sessions might have statements that have
> previously performed this lookup, so this is not a completely secure way to prevent
> object access.

**A self-made copy (LC-E-025).** METR's published threat model for autonomous replication,
[metr.org](https://metr.org/blog/2024-11-12-rogue-replication-threat-model/):

> AI agents can set up, adapt, and orchestrate copies of themselves.

**Transferred memory (LC-E-031).** The MemGPT paper's own framing,
[arxiv.org/abs/2310.08560](https://arxiv.org/abs/2310.08560):

> MemGPT can create conversational agents that remember, reflect, and evolve dynamically
> through long-term interactions with their users.

The abstract describes continuity for an agent with its users. It says nothing either way
about transferring that store to a different identity, so this family does not assert that
the architecture was never designed for it. What ASE-14 and ASE-15 test is narrower and
entirely on the record side: a signed assertion by an agent about an agent is not a grant
by a principal, whatever produced it.

**Re-consent for expanded capability (LC-E-027).** Chrome's extension platform,
[developer.chrome.com](https://developer.chrome.com/docs/extensions/develop/concepts/permission-warnings):

> When a new permission that triggers a warning is added, the extension will be disabled
> until the user accepts the new permission.

Chrome disables the whole extension. This family restricts only the unconsented capability.
That difference is deliberate and is recorded under "Where the proposed text was too vague
to test".

## What this tests, and against which text

The proposed text is six concepts and one invariant in
[`AUTHORITY-LIFECYCLE.md`](https://github.com/aeoess/agent-authority-lifecycle), version
0.1.2-draft, at commit `7796e22fb80480d0336ff0967a862c84284c15e4`.

**Agent identity**, section **Lifecycle concepts are separate > Parties and standing**:

> Agent identity. Says which agent is acting. Identity continuity does not establish
> authority continuity.

**Presented credential or session**, in **Authority and dependencies**:

> Presented credential or session. A session or derived token used to exercise authority
> in a particular request. Ending a grant does not necessarily invalidate every session or
> derived token already issued, and ending a session does not by itself end the grant.

**Action or capability binding**, in the same section:

> Action or capability binding. Which operation, implementation or schema a grant refers
> to, where that distinction matters. A tool can keep its name while what it does changes,
> which widens effective authority without any change to the grant.

**Approval**, in **Decisions and effects**:

> Approval. A principal or approver allows a proposed action. It is an input to
> authorization, with its own scope, expiry and use count, and it can be withdrawn before
> dispatch.

**Evidence** and **Notice**, in **Verification and evidence**:

> Evidence. Records a decision, transition, invocation, execution or effect. Ending
> authority does not by itself erase or invalidate evidence of earlier events.

> Notice. That a particular party or enforcement point learned of a transition at a
> particular time. Recording a transition and observing it are different events.

That document states the status of all six entries itself:

> The grouping and every other entry are **proposed**, added in 0.1.1-draft or
> 0.1.2-draft. No public case tests them yet.

ASE-12 and ASE-13 also test invariant **L2**, whose status in that document is different:

> The same agent identity can appear under an old authority chain and under an independent
> replacement chain. Revoking the old chain's ancestor invalidates the old chain. The
> replacement chain stands on its own.

L2 is marked there as "**tested** as a scenario" by `fixtures/sponsor-handover/`. What
ASE-12 and ASE-13 add is the other direction: not one identity under two chains, but two
identities holding one chain's bytes. That part is candidate, not tested.

### Why this is not a draft-03 case

[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/) states
no rule for any of the five steps this family adds. The closest text is section 3.5:

> The enforcement gateway MUST recheck revocation status at execution time, not only at
> approval time.

That requires a recheck of revocation status. It says nothing about whether the process
presenting a grant is the grant's subject, whether a still-fresh credential has already
been spent, whether the executor a grant names still exists, or whether the capability an
action needs was consented to. Every one of those can fail with a perfectly current
revocation answer, which is exactly what ASE-02, ASE-05, ASE-12 and ASE-17 show.

One piece of draft-03 the family does lean on is the scope grammar, section 3.2:

> Scope grants use ASCII colon-separated segments. "\*" covers all grants; a wildcard is
> otherwise permitted only as the terminal segment ":\*".

The executor a grant names and the capabilities it carries are expressed as colon-separated
scope grants, so both stay inside the grammar draft-03 already defines. draft-03 defines no
executor grant and no capability grant.

## What this family defines itself

The proposed text names six distinctions and stops. It does not say what any of them
produces as a verdict, who has standing to assert any of the underlying facts, or how a
verifier obtains them. This family supplies five rules, because a runnable case cannot
exist without them, and none of them is a reading the proposed text compels:

1. **Presenter binding.** The identity presenting a grant has to equal the grant's
   `subject`. Holding the bytes is not being the subject. A signed assertion by an agent
   about an agent, which is what a transferred memory store carries, is named separately
   from there being no record at all, because the two are different evidence situations.
2. **Non-replay, and losing the record.** A credential declares an issuance instant and a
   freshness window. Freshness and non-replay are two properties and both are enforced. A
   boundary whose consumption record was lost refuses everything for one full freshness
   window from the loss, rather than falling back to freshness alone.
3. **Executor availability.** A grant names its executor as a scope grant. An attestor with
   standing publishes the executor's lifecycle. An action through a retired executor gives
   `not_established`, and an executor no record resolves gives a different reason.
4. **Capability consent.** The capability an action needs has to be declared by the runtime
   now and consented to by the principal as of an instant at or before the action. Consent
   reaches an action from the instant it is given, not earlier.
5. **Verdict vocabulary.** `valid`, `restricted`, `not_established`, `invalid`, from the
   settled lifecycle vocabulary. An unconsented capability gives `restricted`: the grant is
   valid and its consented capabilities still work. Everything else that cannot be shown
   gives `not_established`. `invalid` is reserved for the chain actually failing.

Read 1 to 5 as this family's proposal for how the concepts would be tested, not as their
meaning. See "Where the proposed text was too vague to test".

## What exists

Neither reference SDK exposes an API that decides any of the five. The reference boundary
is therefore this family's own code, in `harness.ts`, following the precedent set by
[`fixtures/runtime-authority-denial-continuity/`](../runtime-authority-denial-continuity/)
and [`fixtures/approval-single-use/`](../approval-single-use/). **The agent-side-event
boundary is implemented by this fixture, not by either APS SDK. The SDKs are used only for
the things they actually decide.**

`harness.ts` calls the TypeScript SDK for three of them:

- `verifyAuthorityDelegationChain` for the grant's structural, temporal, signature and
  revocation state
- `canonicalizeJCS` for the RFC 8785 canonical bytes every record in this family is signed
  over and digested from
- `verify` for the Ed25519 signatures on the executor lifecycle, credential, claim, consent
  and revocation-notice records

Everything else, the presenter comparison, the consumption record and its loss rule, the
executor lifecycle lookup, the consent resolution and the verdict vocabulary, is the
family's own.

### SDK findings

Three findings surfaced while building this family. They are recorded here because they
changed how the family is built, not as vectors: no vector tests an SDK's export list.

**1. `verifyBehavioralMemoryObject` verifies a signature and nothing else.**
`agent-passport-system` 7.1.0 exports it, and its whole body strips `issuer_signature`,
canonicalizes the rest and checks one Ed25519 signature. It is the nearest thing either SDK
has to the question LC-E-031 asks, and it establishes who signed a memory object, not
whether the authority the object describes is current or whether the identity holding it
now is the identity it was written for. That is the gap ASE-14 and ASE-15 make executable,
and it is why this family models the claim record itself rather than reaching for that API.

**2. `verifyApproval` binds an approval and keeps no consumption record.** The same SDK
exports `verifyApproval`, which checks that an approval names the right artifact id and
content hash and that its signature verifies. It has no expiry, no use count and no record
of whether the approval was already used, so it cannot answer ASE-05 or ASE-07. The
proposed **Approval** concept explicitly names "its own scope, expiry and use count", none
of which that function touches.
[`fixtures/approval-single-use/`](../approval-single-use/) supplies a single-use ledger for
a permit bound to an `action_ref`. This family supplies the narrower, mechanical rule for a
credential that is not declared single-use, plus the lost-record rule
`fixtures/approval-single-use/` does not have.
`fixtures/lifecycle-agent-side-events/sdk-probe.mjs` records the whole probe: 10 of 19
supported.

**3. The Python SDK has no agent-side surface at all.** `agent-passport-system` 4.1.0 on
PyPI has no `verify_approval`, no behavioral-memory module, no executor registry and no
consent record. It exposes the authority-chain verifier, `issue_authority_delegation`,
`issue_authority_revocation`, `verify_authority_revocation`, the JCS canonicalizer and
Ed25519 verify, and nothing else this family could use.
`fixtures/lifecycle-agent-side-events/sdk-probe.py` records it: 6 of 15 supported.
`verify.py` therefore writes all five steps out from `agent_passport.canonicalize_jcs` and
`agent_passport.crypto.verify`. That is a recorded gap, not a claim that the Python SDK
decided any of it.

## What the family does

`mint.ts` mints, with `agent-passport-system` 7.1.0:

- four one-hop `AuthorityDelegationV1` grants issued at `2026-09-19T09:00:00.000Z` with
  `not_after` `2026-09-30T00:00:00.000Z`: one to the agent, one to a copy of the agent in
  its own right, one naming an executor no registry resolves, and one whose scope omits the
  capability a presented memory record claims
- two attestor-signed executor lifecycle records for one executor id, one open-ended and one
  retired from `2026-09-22T00:00:00.000Z`
- six principal-signed action-authorization credentials, each declaring a ten-minute
  freshness window, at instants chosen so each vector's credential is fresh exactly where it
  needs to be
- two agent-signed authority-claim records: one about a new instance, carried across with the
  memory, and one about the agent itself claiming a capability its own grant does not carry
- three principal-signed capability-consent records: the base consent from
  `2026-09-19T09:00:00.000Z`, the extended consent from `2026-09-23T06:00:00.000Z`, and the
  copy's own consent
- one principal-signed revocation notice taking effect at `2026-09-23T06:00:00.000Z`

`mint.ts` asserts at mint time, and exits without writing `chain.json` if any assertion
fails, that: all four grants verify `valid` at `2026-09-23T12:00:00.000Z` with an active
resolver, the narrow grant really does omit the claimed capability, the two replay
credentials are distinct, the base consent covers the old capability and not the added one,
the extended consent covers the added one, the extended consent was given after the early
capability vector and before `now`, and the revocation notice takes effect after the
pre-revocation credential and before `now`.

`harness.ts` implements `AgentSideEventBoundary` in six ordered steps: the revocation
answer computed from the notice records and handed to the SDK chain verifier, the presenter
binding, the grant's own scope, the credential, the executor lifecycle, and the capability
consent. `verify.ts` runs both configurations over the twenty presentations. `verify.py` is
a second implementation of the same six steps written against the Python SDK's primitives.
Both run with no network access.

Each presentation is an independent evaluation against a fresh boundary. Unlike
`fixtures/approval-single-use/`, the consumed-credential set and the lost-record instant are
inputs to each presentation rather than state carried between them, so presentation order
does not matter.

## Vectors

| id | case | differs by | expected |
|---|---|---|---|
| ASE-01-LC-E-002-a-named-executor-live-control | LC-E-002 | control | `valid`, `action_established` |
| ASE-02-LC-E-002-b-named-executor-retired-not-established | LC-E-002 | the named executor was retired | `not_established`, `named_executor_retired` |
| ASE-03-LC-E-002-c-action-before-the-executor-was-retired | LC-E-002 | the same record, an earlier instant | `valid` |
| ASE-04-LC-E-002-d-named-executor-unresolvable-not-established | LC-E-002 | no record resolves the named executor | `not_established`, `named_executor_unresolvable` |
| ASE-05-LC-E-012-a-second-presentation-of-the-same-credential-not-established | LC-E-012 | the credential was already consumed | `not_established`, `credential_already_presented` |
| ASE-06-LC-E-012-b-credential-outside-its-freshness-window-not-established | LC-E-012 | past the declared window | `not_established`, `credential_outside_freshness_window` |
| ASE-07-LC-E-012-c-replay-record-lost-inside-the-window-not-established | LC-E-012 | the consumption record was lost 2 minutes ago | `not_established`, `replay_cache_lost_within_skew_window` |
| ASE-08-LC-E-012-d-replay-record-lost-and-the-window-has-passed | LC-E-012 | the same loss, a full window later | `valid` |
| ASE-09-LC-E-021-a-action-while-the-authority-is-live | LC-E-021 | control: no notice exists | `valid` |
| ASE-10-LC-E-021-b-action-after-the-revocation-takes-effect | LC-E-021 | the notice took effect six hours ago | `invalid`, chain `invalid`, `REVOKED` |
| ASE-11-LC-E-021-c-the-earlier-action-re-evaluated-with-the-notice-in-hand | LC-E-021 | the same notice, an action an hour before it took effect | `valid` |
| ASE-12-LC-E-025-a-a-copy-presents-the-originals-grant-not-established | LC-E-025 | a copy presents the agent's grant | `not_established`, `presenter_not_grant_subject` |
| ASE-13-LC-E-025-b-a-copy-with-its-own-grant-is-established | LC-E-025 | the copy has a grant of its own | `valid` |
| ASE-14-LC-E-031-a-transferred-memory-claim-is-not-a-grant | LC-E-031 | a new instance offers a signed claim carried with its memory | `not_established`, `self_asserted_authority_claim_is_not_a_grant` |
| ASE-15-LC-E-031-b-a-memory-claim-does-not-widen-the-grants-scope | LC-E-031 | the subject itself offers a claim for a capability its grant omits | `not_established`, `scope_not_granted` |
| ASE-16-LC-E-027-a-a-consented-capability-while-an-unconsented-one-is-present | LC-E-027 | control: an update added a capability, the action requests the old one | `valid` |
| ASE-17-LC-E-027-b-a-capability-an-update-added-and-nobody-consented-to | LC-E-027 | the action requests the added capability | `restricted`, `capability_not_consented` |
| ASE-18-LC-E-027-c-a-later-consent-covers-the-added-capability | LC-E-027 | the principal has since consented | `valid` |
| ASE-19-LC-E-027-d-consent-does-not-reach-back-before-it-was-given | LC-E-027 | the same consent, an action an hour before it was given | `restricted`, `capability_not_consented` |
| ASE-20-LC-E-027-e-a-capability-the-runtime-does-not-declare | LC-E-027 | consented, and the runtime cannot do it | `not_established`, `capability_not_declared_by_runtime` |

ASE-11 against ASE-10 and ASE-19 against ASE-18 are the same rule pointed in opposite
directions. A revocation notice reaches an action from the instant it takes effect, so
re-evaluating an earlier action with the notice in hand does not change what that action
was authorized by. A consent record reaches an action from the instant it is given, so
having it now does not authorize an action from before. Neither later record rewrites an
earlier one.

ASE-16 is the vector most likely to be argued with, and it is deliberate. The Chrome
precedent the case cites disables the whole extension. This family blocks only the
unconsented capability and leaves the consented one working. See the vagueness section.

## Negative control

`defective-boundary-same-agent-fresh-signature` is one coherent implementation of "this is
the same agent, and its credential is fresh and correctly signed". It keeps the SDK chain
check, the revocation-notice arithmetic, the scope check against the grant, the credential
signature check, the credential binding check and the freshness window unchanged. It
removes exactly five things:

- the comparison of the presenting identity to the grant's `subject`
- the refusal to let a self-asserted authority claim supply scope
- the consumption record and the lost-record refusal window
- the executor lifecycle lookup
- the separation of what the runtime can do now from what the principal consented to

Those five removals account for exactly ten vectors. The declared diverging set:

    ASE-02-LC-E-002-b-named-executor-retired-not-established
    ASE-04-LC-E-002-d-named-executor-unresolvable-not-established
    ASE-05-LC-E-012-a-second-presentation-of-the-same-credential-not-established
    ASE-07-LC-E-012-c-replay-record-lost-inside-the-window-not-established
    ASE-12-LC-E-025-a-a-copy-presents-the-originals-grant-not-established
    ASE-14-LC-E-031-a-transferred-memory-claim-is-not-a-grant
    ASE-15-LC-E-031-b-a-memory-claim-does-not-widen-the-grants-scope
    ASE-17-LC-E-027-b-a-capability-an-update-added-and-nobody-consented-to
    ASE-19-LC-E-027-d-consent-does-not-reach-back-before-it-was-given
    ASE-20-LC-E-027-e-a-capability-the-runtime-does-not-declare

This is the negative control a naive implementation passes wrongly, and it is not a straw
man. Every check it keeps is a real check, including a live SDK chain verification with a
correct revocation answer and two Ed25519 signature verifications per presentation. On all
ten it returns `valid`. It is exactly what an implementation looks like when it reads
draft-03 section 3.5 carefully and stops there, which is why ASE-06, ASE-09, ASE-10 and
ASE-11 give it no signal at all: it gets those four right for the same reasons the
reference boundary does. Both `verify.ts` and `verify.py` check the control in both
directions, so an undeclared divergence or a declared divergence that quietly starts
matching is loud in either runner's output.

## Running

TypeScript, wired into `npm test` as a step:

    npm ci --include=dev
    npm run verify:lifecycle-agent-side-events

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/lifecycle-agent-side-events/mint.ts

Python, a manual run and not part of `npm test`, the same convention
`fixtures/approval-single-use/verify.py` and
`fixtures/ancestor-revocation-chain/validate.py` already follow for a Python side kept out
of the hermetic Node-only CI gate. Needs `agent-passport-system` 4.x installed:

    python3 fixtures/lifecycle-agent-side-events/verify.py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set (python)

The two SDK support probes, which print a per-API `supported` or `not_supported` line and
assert nothing:

    node fixtures/lifecycle-agent-side-events/sdk-probe.mjs
    python3 fixtures/lifecycle-agent-side-events/sdk-probe.py

## Determinism

Every Ed25519 key is the SHA-256 of a published label under the seed prefix
`aps-conformance-suite:lifecycle-agent-side-events`, recorded in `chain.json` as
`seed_prefix`. Every delegation and record nonce is derived the same way. Every timestamp is
pinned: the grants are issued at `2026-09-19T09:00:00.000Z`, the executor retires at
`2026-09-22T00:00:00.000Z`, the revocation notice takes effect and the extended consent is
given at `2026-09-23T06:00:00.000Z`, the credentials are issued at `2026-09-21T11:55`,
`2026-09-23T04:55`, `2026-09-23T11:55` and `2026-09-23T12:20`, the declared freshness
window is 600000 ms, and `now` is `2026-09-23T12:00:00.000Z`. Every window and every
lifecycle interval is half-open, so an instant exactly at a retirement or at the end of a
freshness window falls outside it and not inside. Every record digest is taken over RFC 8785
JCS canonical bytes produced by the SDK's own `canonicalizeJCS`, and `verify.py` reproduces
the same bytes with the Python SDK's `canonicalize_jcs`, which is what makes the signature
checks a cross-language claim. No secret material is in the file: every public key is
published and every private key is reproducible from its published label, which is exactly
why these keys are for test vectors and nothing else.

SHA-256 over the exact bytes of this family's files, at this commit:

    c843787f82771781d66738aa49f33ca50a4289709ff5cfdcd0b6108a7e3e1446  chain.json
    8aa63f233c6cdc3b2cc288d4ee1b72b439880f35ed024343039b220ea9748119  harness.ts
    6ed8bdcf2c8d9a0e668951487c38ddfb40f5c39d68702242021f55e0bab35ec5  mint.ts
    0beb55d82f5b72f723d09b53dd8d57c1547cd997288268b86f2df52e6cf34521  sdk-probe.mjs
    e517452b6b7b551a9609e0e88560cda0cb85fe19e190963d8334b1523ef3fa2b  sdk-probe.py
    a5ee9f773273bbbc4c3def7fd84f574f29391d7456c09105474b0eaa289a3bf5  vectors.json
    93d72c0604fcc5576d7120111fd3165a9c0dc97012afd26fc5df9ada4ab165df  verify.py
    b0bd174a846d063c34352918b6f5e9525e7f0bc36add703021ae7647f93e036f  verify.ts

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

- grant chain state for all four grants at every evaluated instant (`valid` under a computed active answer, `invalid`/`REVOKED` under a computed revoked one); runner aeoess; Mode A; author-produced, because this lab authored the vectors and `mint.ts` and the implementation under test is this lab's own `agent-passport-system`; recomputed by `agent_passport.v2.authority_delegation.verify_authority_delegation_chain` in `verify.py` under the same relationship.
- Ed25519 signatures on the executor lifecycle, action-authorization credential, authority claim, capability consent and revocation notice records over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` plus `verify` on one side and the Python SDK's `canonicalize_jcs` plus `agent_passport.crypto.verify` on the other.
- record digests over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` on one side and the Python SDK's `canonicalize_jcs` on the other.
- the twenty agent-side-event verdicts, the freshness and lost-record window arithmetic behind them, and the declared defective diverging set; runner aeoess; Mode A; author-produced, because the boundary that decides each verdict is this family's own `harness.ts` and its Python counterpart in `verify.py`, both written in this lab.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Results

Both runners were executed locally against `agent-passport-system` 7.1.0 (npm) and
`agent-passport-system` 4.1.0 (PyPI, in a virtual environment). The `reference-boundary`
matched 20/20 presentations under both runners.
`defective-boundary-same-agent-fresh-signature` diverged on exactly the declared set of 10
under both runners and matched the remaining 10 under both. `npm ci --include=dev` and
`npm test` both exited 0 with this family wired in. These are author-produced records, not
independent ones, per `CONTRIBUTING.md`.

## Where the proposed text was too vague to test

This is a finding, and it matters at least as much as the fixture. Six things had to be
decided before a single vector could exist, and a different decision gives different
expected verdicts for the same records:

1. **The settled verdict vocabulary has no state for LC-E-002.** The case argues for a
   status distinct from valid, revoked, suspended and expired, because the authority is
   intact under every lifecycle rule while the thing it authorizes has become impossible to
   carry out. The settled vocabulary this family is required to use, `valid`, `invalid`,
   `not established`, `not yet effective`, `suspended`, `restricted`, contains no such
   state. `not_established` is the nearest fit and it is not a good one: it says continuity
   of the named executor was not shown, when the records show it positively and show that it
   ended. This is the clearest gap the family found, and it is a gap in the vocabulary
   rather than in any one concept's wording.
2. **No rule for who presents.** **Agent identity** says identity continuity does not
   establish authority continuity, and says nothing about the case where the identity is not
   continuous at all because something else is holding the bytes. Reading the silence as
   requiring `presenter == subject` is this family's choice. A model where a grant names a
   process lineage, or where a fork inherits by construction, would answer ASE-12 the other
   way and be equally consistent with the text.
3. **No verdict for a self-asserted claim.** **Evidence** says records of earlier events
   survive, which is about evidence outliving authority rather than about evidence
   substituting for it. Nothing says what a verifier returns when an agent presents a signed
   assertion about its own authority. ASE-14 and ASE-15 make `not_established` executable, and
   "ignore it silently and fall through" and "treat it as a widening attempt and return
   invalid" are both defensible and both give different vectors.
4. **No decomposition of the capability response.** **Action or capability binding** says
   capability can widen with no change to the grant. It does not say whether the response is
   to block the new capability, to suspend the agent entirely, or to require re-consent
   before anything runs. The cited Chrome precedent disables the whole extension. This
   family restricts one capability. ASE-16 exists precisely to make that choice visible, and
   it would flip to `restricted` under the whole-agent reading.
5. **No lost-record rule.** **Presented credential or session** names the object and says
   nothing about what a boundary does when its own record of what it has spent is gone. RFC
   4120 has an answer and the proposed text does not adopt it. ASE-07 and ASE-08 implement
   the RFC's rule because it is the only worked answer available, not because the proposed
   text points at it.
6. **No effective-instant on a transition.** **Notice** separates recording a transition
   from observing it, and says nothing about a third instant: when the transition takes
   effect. This family gives every revocation notice and every consent record an explicit
   effective instant and compares the action to it, which is what makes ASE-11 and ASE-19
   decidable at all. Without that field the whole LC-E-021 group has no answer, and with a
   different field, such as effect from the moment of recording, ASE-11 flips.

A seventh thing is outside what any record set can settle, and no vector claims it. LC-E-021
is partly about what an already-open session retains in memory after a permission is
revoked. Nothing a verifier holds establishes that, and this family tests only the part that
records can answer: that a new action after the notice takes effect is `invalid`, and that
re-evaluating an earlier action with the notice in hand does not change it. The residual
knowledge inside the session is stated here as untestable rather than tested.

Until at least 1 to 6 are settled in the proposed text, no case in this family can move
from `candidate` to `tested` against it, because there is nothing yet to be conformant
with. That is the finding.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundary and its own record shapes:

- an action through an executor the attestor's record says was retired before the action
  instant is not established, while the grant and its chain stay `valid`, and the same
  record evaluated before the retirement instant admits
- an executor no record from the attestor with standing resolves gives a different answer
  from one a record says was retired
- a credential that is authentic and inside its declared freshness window is still refused on
  a second presentation to a boundary that has already consumed it
- a boundary whose consumption record was lost refuses for one full freshness window from
  the loss and admits again once that window has passed, so freshness alone never becomes the
  fallback
- a revocation notice reaches an action from the instant it takes effect, so an action after
  it is `invalid` with `REVOKED` and an action before it stays `valid` even when the notice is
  in the record set being evaluated
- a copy presenting the original's grant is not established, and the same copy with a grant
  issued to it in its own right is, so byte-identity is neither a bar nor a basis
- a signed assertion by an agent about an agent's authority is named as not a grant, and the
  same assertion never contributes scope to a grant that does not carry it
- a capability the runtime gained without consent records `restricted` while the consented
  capabilities under the same grant still admit, and a later consent record admits it from the
  instant it was given and not before
- consent to a capability the runtime does not declare establishes nothing about the action
- an implementation that takes identity and a fresh signature as sufficient predictably
  diverges on exactly those ten vectors, and on none of the other ten

## Does not claim

A pass does **not** establish:

- anything about draft-pidlisnyi-aps-03 conformance. draft-03 states no rule for any of the
  five steps this family adds. Every vector is `candidate_against_proposed`, and a maintainer
  who disagrees with any of the five decisions under "What this family defines itself" should
  expect different expected verdicts, not a bug report.
- that this family's presenter rule, replay rule, executor model, consent model or verdict
  vocabulary is the right one, or the only defensible one. See "Where the proposed text was
  too vague to test".
- that the MemGPT architecture, or any other memory architecture, was not designed for
  transfer between identities. The fetched abstract does not address that either way, and
  this family asserts nothing about it. What ASE-14 and ASE-15 test is a record-side rule.
- anything about a deployed agent runtime, model provider, extension platform, Kerberos
  realm or database. No network call is made and no protocol is spoken. `harness.ts` is this
  family's own in-process reference model.
- that Chrome's extension behaviour, PostgreSQL's privilege behaviour, RFC 4120's replay
  requirement or any model provider's deprecation policy applies to AI agents. The six
  sources above are cited for the shape of the question, which is what the model document
  says about agency law too.
- that either reference SDK implements any of this. Neither does. The TypeScript SDK's
  behavioral-memory verifier checks one signature, its approval verifier checks a binding and
  a signature and keeps no consumption record, and the Python SDK has no agent-side surface at
  all. See "SDK findings".
- anything about how an executor grant or a capability grant should narrow across a
  delegation chain. Every grant here is a one-hop root delegation, so no parent-to-child
  comparison is exercised.
- anything about what an already-open session retains in memory after a permission is
  revoked. That is the part of LC-E-021 no record set answers, and nothing here tests it.
- that any of these actions was executed. Nothing here executes anything.

## Provenance

`README.md`, `vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`,
`verify.py`, `sdk-probe.mjs` and `sdk-probe.py` are authored for this suite. The minting,
chain verification, canonicalization and signature primitives are
`agent-passport-system` 7.1.0 (npm) and `agent-passport-system` 4.1.0 (PyPI). The case
statements come from `CASES.md` in `aeoess/agent-authority-lifecycle` at commit
`2bf5c7e2d07d41c13611478d6e5e47fcb4d3ceda`, and the proposed text under test comes from
`AUTHORITY-LIFECYCLE.md` in the same repository at commit
`7796e22fb80480d0336ff0967a862c84284c15e4`.
