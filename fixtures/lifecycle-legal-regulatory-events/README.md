# lifecycle-legal-regulatory-events: an authority change that arrives from outside the graph

A chain verifies valid. Every record in it is well formed, correctly signed, inside its time
window and unrevoked. And the action must not go through, because a party outside the
delegation graph has ended, paused, narrowed, gated or re-rooted the authority the chain
stands on, and nothing inside the graph says so.

Forty-four vectors across fourteen cases, one reference boundary, four declared defective
boundaries, two runners over two reference SDKs.

**Every vector in this family is labelled `candidate_against_proposed.`** No vector here is a
draft-pidlisnyi-aps-03 conformance case for an external authority event, for suspension, for
a restricted state, for an off-graph dependency or for ratification, because draft-03 states
no rule for any of them. Where a vector rests on a rule draft-03 does state, it says so.

## The proposed text this tests

[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle),
`AUTHORITY-LIFECYCLE.md` at commit `7796e22`, document version 0.1.2-draft. The load-bearing
entries, quoted in full:

    External restriction. A block from outside the grant chain, such as a sanction, a court
    order, or a legal hold that blocks a deletion. It can stop some effects while the grant
    itself stays valid.

    Lifecycle standing. Who may suspend, revoke, replace or reaffirm an authority artifact.
    This is not always the issuer. An organization, a quorum, a successor, a court or a
    security function can have standing to change authority it never issued.

    Suspension. Pauses or narrows the use of authority without permanently ending it.

    Status observation. What authority state a verifier could establish, from which source,
    at what time and with what freshness. Current authority and observed authority can
    differ.

    Authority path and dependency. Which other authority a grant currently depends on.
    Historical provenance and current dependency are not necessarily the same thing.

    Target binding. Which resource, counterparty or object the authority applies to.
    Continuity of a name does not by itself establish continuity of the thing named.

    Verifier trust policy. Which issuers, roots, status sources and rules a verifier
    accepts. A verifier can stop trusting an issuer without anything being revoked.

Invariant **L8. Suspension is not revocation**, quoted in full:

    Suspension stops the use of authority and of everything that depends on it, and can be
    lifted. Revocation is terminal for the artifact it names. A restricted state is different
    again and does not have to pause descendants.

Its status line reads "Status **proposed**." Invariant **L10. Expiry is not revocation** is
`proposed` as a lifecycle distinction. `OPEN-QUESTIONS.md`'s "Release from suspension" section
states the composition problem this family's suspension vectors exercise:

    Lifting one suspension should not clear another, bypass a revocation that happened while
    the agent was suspended, or recreate rights that changed in the meantime. Multiple
    suspension causes probably need to compose, with each one released separately. Not yet
    specified.

The cases are the **Legal and regulatory events** section of `CASES.md` at commit `2bf5c7e`.
Every vector id carries its case id: `LRE-B-018-b` is the second vector for `LC-B-018`.

## Where draft-03 does and does not state a rule

Fetched this session from
[draft-pidlisnyi-aps-03](https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt). What
draft-03 does state, and what every vector here relies on:

    A verifier processes a root-to-leaf chain in this order: closed schema and canonical
    values; delegation_id; historical signing-key resolution and signature; duplicate
    identifiers; root trust; parent_delegation_id; issuer-to-subject continuity; child
    issuance time; the seven facet comparisons in Section 3.2; current validity; and
    revocation state for every member.

and

    Verification returns one of valid, invalid, indeterminate, or unsupported with a stable
    failure code.

and, from Section 3.5:

    Revocation is irreversible.

What draft-03 does not state: any of the seven proposed-text entries above. Its authority
vector is a closed seven-facet set with no slot for an off-graph dependency, its revocation
model names exactly one authorized revoker, and it has no record type for a court order, a
sanction, a licence, a suspension cause or a ratification.

## What the reference SDKs supply, and what they do not

Both runners print their own support table, so the record below is produced by the run rather
than typed. Verbatim from the two runs recorded under "Results":

    TypeScript SDK support, agent-passport-system 7.1.0:
      supported      chain state, including time and root trust  (verifyAuthorityDelegationChain)
      supported      revocation resolution, including unknown for uncovered evidence  (createAuthorityRevocationResolver over InMemoryAuthorityRevocationStore)
      supported      direct revocation by the delegation issuer  (issueAuthorityRevocation, verifyAuthorityRevocation, recordAuthorityRevocation)
      supported      gate scope match  (scopeGrantCovers)
      supported      external event, dependency binding and certification signatures  (verify over canonicalizeJCS)
      not_supported  revocation by a party other than the issuer  (issueAuthorityRevocation refuses with REVOKER_NOT_ISSUER, see chain.json mint_time_sdk_observations)
      not_supported  suspension state  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  restricted state  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  external authority event record  (no export in agent-passport-system 7.1.0, supplied by this fixture)
      not_supported  off-graph dependency binding  (no export in agent-passport-system 7.1.0, supplied by this fixture)
      not_supported  ratification of a past act  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  lifecycle standing registry  (no export in agent-passport-system 7.1.0, supplied by this fixture)

    Python SDK support, agent-passport-system 4.1.0:
      supported      chain state, including time and root trust  (verify_authority_delegation_chain)
      supported      revocation resolution, including unknown for uncovered evidence  (create_authority_revocation_resolver over InMemoryAuthorityRevocationStore)
      supported      gate scope match  (scope_grant_covers)
      supported      external event, dependency binding and certification signatures  (verify over canonicalize_jcs)
      not_supported  revocation by a party other than the issuer  (issue_authority_revocation admits only the target delegation's issuer as revoker)
      not_supported  suspension state  (no Python SDK export, supplied by this runner)
      not_supported  restricted state  (no Python SDK export, supplied by this runner)
      not_supported  external authority event record  (no Python SDK export, supplied by this fixture)
      not_supported  off-graph dependency binding  (no Python SDK export, supplied by this fixture)
      not_supported  ratification of a past act  (no Python SDK export, supplied by this runner)
      not_supported  lifecycle standing registry  (no Python SDK export, supplied by this fixture)

### The sharpest thing this family found

`issueAuthorityRevocation` refuses to mint a revocation whose revoker is not the target
delegation's own issuer. Recorded by `mint.ts` into `chain.json` rather than remembered:

    "external_revoker_refusal": "authority revocation revoker is not the target delegation issuer (REVOKER_NOT_ISSUER)"

That is correct behaviour for draft-03 section 3.5, which names one authorized revoker. It
also means the proposed text's **Lifecycle standing** entry has no wire expression at all:
a court, a receiver, a regulator or a security function with standing to end an authority it
never issued cannot produce an `AuthorityRevocationV1` for it, and a verifier reading only
delegation and revocation records will never see the event. Everything in this family exists
in the gap that refusal opens.

## The record this fixture invented

An `external-authority-event-v0`, profile
`aps-conformance-suite:lifecycle-legal-regulatory-events:external-authority-event-v0`, signed
over the domain string `APS-CONFORMANCE-LRE-EXTERNAL-EVENT-V0`, a space, and the RFC 8785 JCS
canonical bytes of the body. Its `event_id` is the SHA-256 of that same preimage, so the
identifier is content-addressed and the signature covers it. **This shape is this fixture's
invention.** Neither the proposed text nor draft-03 defines one. See "Where the proposed text
was too vague to test".

The fields that carry the weight:

| field | what it decides |
|---|---|
| `effect` | one of eleven named effects, the fixture's own vocabulary |
| `target` | `{kind, id}`, where kind is principal, counterparty, resource, dependency, action, root or event |
| `effective_at` | when the effect began |
| `recorded_at` | when a verifier could observe the record |
| `standing_basis` | free text naming the external instrument, never read as authorization |
| `parameters` | effect-specific: a certifier, a gate scope, a threshold, a sunset, a cause id, a successor, a new owner |

`effective_at` and `recorded_at` are separate because the proposed text keeps "Status
observation" and "Notice" as separate entries. An event whose effect began before an
observation time but whose record was made after it is invisible to that observation, and
that invisibility is the whole content of `LC-B-009`.

Two more fixture-local records: a `dependency-binding-v0` signed by a grant's own issuer,
declaring which off-graph dependencies that grant rests on, and a `gate-certification-v0`
signed by the certifier a gate names, covering one `action_ref`.

`chain.json` also carries a `verifier_trust_policy`: a `lifecycle_standing` map from effect
to the issuers a verifier accepts for that effect, and two named `trust_roots` bases. It is
not signed, because it is the verifier's own policy rather than anybody's record.

## What the family does

`mint.ts` mints, with the pinned TypeScript SDK `agent-passport-system` 7.1.0:

- **fourteen chains.** Twelve verify `valid` at every observation time under a fully trusting
  root policy, which is the load-bearing fact of the whole family. `unsigned_claim` names one
  issuer and is signed with another key, so it verifies `invalid` / `SIGNATURE_INVALID`.
  `trustee_deferred` declares a `not_before` after the observation times, so it verifies
  `invalid` / `NOT_YET_VALID`. Both codes are recorded from the SDK, not written by hand.
- **three dependency bindings.** Two declare the same off-graph licence, one declares nothing.
- **twenty-one external authority events**, four of which are re-minted in a second pass so
  that a release event's own `event_id` covers the id of the event it releases.
- **two gate certifications**, each bound to one `action_ref` and one gate `event_id`.
- **one real draft-03 section 3.5.1 revocation** of the finance office's own grant, by its own
  issuer, which verifies, records and drives the chain to `invalid` / `REVOKED`.
- **fourteen action references** under `aps-action-ref-v2`, one per presentation.
- **one action-intent receipt** recording the historical act the ratification vectors name.

`mint.ts` asserts every one of those SDK answers at mint time and aborts with nothing written
on any failure. Each is written into `chain.json` under `mint_time_sdk_observations`, so this
README quotes a recorded value rather than a remembered one.

`harness.ts` implements `AuthorityBoundary` in five configurations. Its ordered steps for a
presentation: status observation (this fixture), chain state (SDK), principal termination or
replacement, declared dependency, target ownership, suspension causes, execution blocks, then
approval gates with the SDK's own scope primitive. Its second request kind, `assess_act`,
answers a question about one named past act rather than a proposed one.

### Two request kinds, and why

`present` asks what happens at the next authorization boundary. `assess_act` asks what the
record now says about one act that already happened. They are separate because a ratification
reaches backward to one named act and does not make the chain that act cited verify. The
runner asserts that the receipt's own JCS digest is identical across all three ratification
vectors and equal to `chain.json`'s recorded value: the later record never edits the earlier
one.

### The status source is per vector

Every vector names an `event_set`, the external records **that verifier's status source
holds**. Two verifiers reading two status sources are two different observations of one
world, which is what the "Status observation" entry says. Nothing carries between vectors:
every vector is a fresh evaluation, and this family's state lives in the records rather than
in the boundary.

## The vectors

Forty-four across fourteen cases. `tests` and `differs_from` on each vector in `vectors.json`
name what it exercises and the single change from its nearest control.

| case | vectors | what the case turns on |
|---|---|---|
| LC-B-007 | `LRE-B-007-a` to `-d` | ratification is a new record naming one past act, and it never edits that act's receipt or validates the chain the act cited |
| LC-B-008 | `-a` to `-c` | an external record ends an office's authority while its chain still verifies `valid`, and no revocation record exists or could |
| LC-B-009 | `-a` to `-c` | an effect that began before it was observable, and a record that is observable before it is in force |
| LC-B-010 | `-a` to `-d` | a threshold approval gate: `restricted`, not revoked, not suspended, and it does not pause a descendant delegation |
| LC-B-011 | `-a`, `-b` | the release has to be a record from outside the graph, and time passing is not one |
| LC-B-017 | `-a` to `-c` | a root that appears in no other chain, and the verifier trust policy that decides whether to accept it |
| LC-B-018 | `-a` to `-c` | chain validity and permission to execute are two answers, and the block is bound to its target |
| LC-B-019 | `-a`, `-b` | the release restores execution on the same `delegation_id`, with no fresh grant from anyone |
| LC-B-022 | `-a`, `-b` | pruned revocation evidence gives `not established`, never `valid` and never `invalid` |
| LC-B-024 | `-a` to `-d` | two suspension causes, each released by its own record |
| LC-B-025 | `-a` to `-d` | one record revokes an off-graph dependency and invalidates every chain that declared it, and no chain that did not |
| LC-B-026 | `-a` to `-c` | a third party's certification gate, and its own sunset date ending it with no release record |
| LC-B-027 | `-a` to `-d` | a reversible block against an ownership change: a release lifts the first and not the second |
| LC-B-031 | `-a` to `-c` | one event category, two authority outcomes, and `not yet effective` kept apart from `invalid` |

### The whole settled vocabulary appears

The reference boundary returns, across the forty-four vectors, exactly `valid`, `invalid`,
`suspended`, `restricted`, `not established` and `not yet effective`. Both runners assert
that no other string is ever returned, and print the observed set:

    ok   verdict vocabulary: observed [invalid, not established, not yet effective, restricted, suspended, valid]

## Negative controls

**Vector-level.** Every case has at least one vector that differs from its nearest positive
control by exactly one stated change and must not be admitted, or must be admitted for a
reason the naive answer gets wrong. The ones worth naming:

- `LRE-B-008-c` and `LRE-B-007-c`. The same statement, genuinely signed, from a party the
  trust policy names for no effect. The claim is **not established**, which is not the same as
  false. The termination vector stays admissible on the evidence and the reason says why
  (`external_claim_not_established`). The ratification vector returns `not established`
  outright. See item 3 under "Where the proposed text was too vague to test" for why the
  admit direction differs between them and why it is this fixture's choice.
- `LRE-B-018-c` and `LRE-B-025-d`. A block and a dependency revocation that are correctly
  **not** applied: to a counterparty the record does not name, and to a chain whose signed
  binding declares no dependency. Without these two, a boundary that treated every observed
  event as global would pass the family.
- `LRE-B-017-c`. The trust-establishing record exists and was not yet made at this observation
  time, so the root is still untrusted. A root becomes acceptable when the verifier can
  establish the basis, not when the basis exists in the world.
- `LRE-B-027-c`. A release naming an ownership transfer. Still `invalid`. This is where
  treating a transfer as a stronger freeze gives the wrong answer.
- `LRE-B-031-c`. `not yet effective` with the SDK's own `NOT_YET_VALID`, not `invalid`.

**Boundary-level. Four declared defective boundaries**, each with its failing set declared in
`vectors.json`. Both runners check both directions: every declared id must actually diverge,
and every other id must still match, so an undeclared failure or a declared failure that
quietly starts passing is loud in either runner's output.

`defective-boundary-chain-validity-only` does everything draft-03 section 3.3 chain
verification does and nothing else. It reads no external record at all. This is what a fully
draft-03-conformant implementation looks like, and it is exactly the deployment this family
exists to catch. Eighteen declared failures, every one in the wrongly-admits or
wrongly-terminal direction.

**`defective-boundary-collapses-restricted-into-revoked` is the control a naive checker
passes wrongly.** It tracks every external record correctly and reports a restricted or
suspended authority as `invalid`. Its admit-or-deny bit is **identical to the reference
boundary's on all forty-four vectors**. It differs only in the lifecycle state it writes into
its own record, and what it has written is that an authority which is paused or narrowed, and
which comes back with no new grant at all, was terminally ended. That is the exact distinction
L8 and L10 draw. A checker that compares only whether the action was allowed passes it
everywhere. That is why `verdict` is a compared field and not a log line. Eight declared
failures.

`defective-boundary-single-suspension-flag` holds one boolean for suspension and clears it on
any release for the principal, whatever cause that release names. One declared failure,
`LRE-B-024-c`, which is the vector `OPEN-QUESTIONS.md`'s "Release from suspension" section
describes.

`defective-boundary-trusts-event-without-standing` verifies every record's signature and never
asks whether the signer may make the statement. Two declared failures. Both are the
not-established-becomes-settled direction: it turns a claim nobody could establish into a
terminated authority and a ratified act.

## Where the proposed text was too vague to test

These are findings, not defects in the fixture. Each one is a place this family had to choose
something the proposed text does not say, and the choice is marked in the code.

1. **An external authority event has no record shape, and cannot have one inside draft-03.**
   "A block from outside the grant chain" names the concept and defines nothing. draft-03's
   authority vector is a closed seven-facet set, and its revocation record admits one revoker,
   the delegation's own issuer, which the SDKs enforce. So the event cannot live in a
   delegation, cannot live in a revocation, and has nowhere else to live. This family invented
   `external-authority-event-v0`. Any other implementation would invent a different one and
   the two would not interoperate. Nothing here tests interoperability of the record, because
   there is nothing to test it against. This is the same shape of gap
   `fixtures/lifecycle-purpose-exhaustion` recorded for a purpose bound.

2. **Nobody is named as having lifecycle standing, and the text says standing is not the
   issuer's.** "An organization, a quorum, a successor, a court or a security function can
   have standing to change authority it never issued" is the strongest sentence in the
   proposed text for this family, and it has no mechanism behind it. This fixture put a
   `lifecycle_standing` map keyed by effect into its own verifier trust policy. Without that
   invented field, "a party with no standing" has nothing to be measured against and
   `LRE-B-008-c` is not decidable at all.

3. **Fail-open against fail-closed on an unestablished external claim is unresolved, and this
   family answers it two different ways on purpose.** L7 says an enforcement point "may deny
   on indeterminate, and the denial should say why", but L7 is about revocation state.
   Nothing says what a boundary should do with an external termination claim it cannot
   establish. This fixture admits the action (`external_claim_not_established`) because
   denying would let any party with a keypair disable any agent by asserting an authority it
   does not have. For an unestablished ratification it returns `not established` rather than
   admitting, because there the claim is the only thing that could make the act authorized.
   Both directions are this fixture's declared policy and neither is required by any text
   cited here. A boundary that chose the other direction in either place is not thereby
   non-conforming.

4. **"Can be lifted" does not say by whom, or how a release names what it releases.** L8 says
   suspension "can be lifted" and stops there. This family made a release name the `event_id`
   of the event it lifts, and made a suspension release name a `cause_id`. Two different
   mechanisms for two different effects, both invented here. The `cause_id` is what makes
   independent composition checkable at all, and `OPEN-QUESTIONS.md` says the composition
   itself is not specified.

5. **A restricted state has no content beyond the word.** L8 says a restricted state "does not
   have to pause descendants" and says nothing about what it does do. This family gave
   `restricted` two producers, an execution block on a target and an unsatisfied approval
   gate, and one consequence, the action is not admitted. Whether a restricted authority
   should be presentable as `restricted` to a downstream verifier, whether it can be
   subdelegated, and whether a descendant inherits the restriction are all undefined and no
   vector here covers them. `LRE-B-010-d` shows only that this family's gate does not stop a
   descendant's below-threshold action.

6. **An off-graph dependency has no declaration mechanism, which makes the critical-revocation
   question unanswerable as posed.** `OPEN-QUESTIONS.md`'s "Critical revocation" section says
   "Revoking a high-level authority can disable a large set of agents" and proposes binding an
   approval to a snapshot of its impact. A verifier cannot compute that impact at all unless
   dependencies are declared somewhere it can read, and nothing declares them. This family's
   `dependency-binding-v0` is signed by each grant's own issuer, which means an issuer who
   omits the binding silently escapes the dependency. That is a real hole in this fixture's
   own model and it is the honest consequence of the text having no mechanism.

7. **A resource's ownership is outside every model here.** "Continuity of a name does not by
   itself establish continuity of the thing named" is the closest the text comes, and it is
   about names rather than about owners. This family made `transfer_resource_ownership` an
   effect and made it terminal for grants from the former owner. Whether a delegation layer
   should represent resource ownership at all is not a question either text asks.

8. **An observation time is not a freshness policy.** "at what time and with what freshness"
   puts freshness in the same sentence as observation time, and nothing defines a staleness
   bound for an external status source. This family compares `recorded_at` and `effective_at`
   against a supplied `now` and has no freshness rule, so a verifier reading a status source
   that stopped updating a month ago answers exactly as one reading a live source. No vector
   here covers that, and none could without a freshness field the text does not define.

9. **Ratification has no record shape and no bound on what it can reach.** The text does not
   mention ratification at all, and the case comes from `CASES.md`. This family made it an effect
   naming one `action_ref`. Whether a ratification can name a class of acts, a time interval
   or a whole chain, and whether a ratification can itself be withdrawn, are undefined. The
   family pins only the narrow direction: `LRE-B-007-d` shows the ratification reaches the one
   act it names and not the chain that act cited.

## What this family does not do

`LC-B-023` is the one case in this section with no vector. Its content is *when* a retention
policy must stop pruning, which is a policy trigger inside an organization rather than a state
a verifier can read from records: there is no record set whose presence or absence a verifier
could check to decide whether pruning should have stopped earlier. The adjacent decidable
question, what a verdict becomes once the records are gone, is `LC-B-022` and is covered by
`LRE-B-022-b`. See the handoff for the decision table.

## Running

TypeScript, wired into `npm test` as one of its last steps:

    npm ci --include=dev
    npm run verify:lifecycle-legal-regulatory-events

Expected final line:

    PASSED: reference-boundary matched every vector, all four defective boundaries diverged on exactly their declared sets

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/lifecycle-legal-regulatory-events/mint.ts

Python, against the pinned Python SDK, a manual run and not part of `npm test`, the same
convention `fixtures/ancestor-revocation-chain/validate.py` and
`fixtures/runtime-authority-denial-continuity/verify.py` already follow for a Python side kept
out of the hermetic Node-only CI gate:

    python3 -m venv /tmp/aac-lc-g3-venv
    /tmp/aac-lc-g3-venv/bin/pip install 'agent-passport-system==4.1.0'
    /tmp/aac-lc-g3-venv/bin/python fixtures/lifecycle-legal-regulatory-events/verify_python_sdk.py

Expected final line:

    PASSED: reference-boundary matched every vector, all four defective boundaries diverged on exactly their declared sets (python SDK)

## Determinism

Every key is an Ed25519 seed derived from a published label under the prefix
`aps-conformance-suite:lifecycle-legal-regulatory-events:`, recorded in `chain.json` as
`seed_label_prefix`. No clock is read and no randomness is drawn: every timestamp, nonce and
payload is a pinned constant. Canonical bytes are RFC 8785 JCS throughout, through the SDK's
own `canonicalizeJCS` on the TypeScript side and `canonicalize_jcs` on the Python side.
`chain.json` is written with keys sorted at every depth, so the file is a function of its
content.

Checksums of the committed data files, as generated, and also in `CHECKSUMS.sha256`:

    49ef6fd169517fdfdb6ed0b23ebe619825e55afba13845379949ffc63a8b0da4  chain.json
    35e2e1157a9b771338a37713ff744fed2b9fdca8c6189b9e41274e6217f82d92  vectors.json

## Results

Both runners were executed locally. `reference-boundary` matched 44/44 vectors under both, and
the five structural checks passed under both. All four defective boundaries diverged on exactly
their declared sets under both runners: 18, 8, 1 and 2 respectively. The two runners agree on
all 44 outcomes for all five configurations.

Both records are author-produced, not independent, per `CONTRIBUTING.md`'s admission rules for
run records. See the Verification split below.

## Verification split

One entry per distinct verification claim, in the form
`layer / claim; runner; Mode; authorship; implementation`, per `CONTRIBUTING.md`.

- **Chain state, including temporal, root-trust and revocation validity / claim: twelve of the
  fourteen chains verify `valid` at every observation time under a fully trusting root policy,
  `unsigned_claim` verifies `invalid`/`SIGNATURE_INVALID`, and `trustee_deferred` verifies
  `invalid`/`NOT_YET_VALID`**; runner: the lab, via
  `fixtures/lifecycle-legal-regulatory-events/verify.ts`; Mode A; author-produced;
  implementation: `agent-passport-system` 7.1.0 (npm). Authorship relationship preventing an
  independent label: the lab authored the vectors and the claim inputs, and the implementation
  is a reference SDK from the same project.

- **Chain state / same claim, recomputed by the Python reference SDK**; runner: the lab, via
  `fixtures/lifecycle-legal-regulatory-events/verify_python_sdk.py`; Mode B; author-produced;
  implementation: `agent-passport-system` 4.1.0 (PyPI). Authorship relationship: as above. The
  two SDKs are separate implementations and the Python run supplies the substantive
  recomputation of this claim, but both are reference SDKs of the same project and the lab
  authored the vectors, so the record is not independent.

- **Verifier root trust / claim: the receiver-rooted chain verifies `invalid`/`ROOT_UNTRUSTED`
  under the closed policy and `valid` once the root is added to the trusted set**; runner: the
  lab, via `verify.ts`; Mode A; author-produced; implementation: `agent-passport-system` 7.1.0
  (npm), `verifyAuthorityDelegationChain`'s own root-trust phase. Authorship relationship: the
  lab authored the chain and the policy.

- **Verifier root trust / same claim**; runner: the lab, via `verify_python_sdk.py`; Mode B;
  author-produced; implementation: `agent-passport-system` 4.1.0 (PyPI). Authorship
  relationship: as above.

- **Revocation resolution and evidence coverage / claim: a store that covers a delegation and
  holds no record answers `active`, a store that does not cover it answers `unknown`, and chain
  verification reports the second as `indeterminate`/`REVOCATION_UNKNOWN`**; runner: the lab,
  via `verify.ts`; Mode A; author-produced; implementation
  `createAuthorityRevocationResolver` over `InMemoryAuthorityRevocationStore` in
  `agent-passport-system` 7.1.0 (npm). Authorship relationship: the lab authored the
  delegations and chose which the store covers.

- **Revocation resolution and evidence coverage / same claim**; runner: the lab, via
  `verify_python_sdk.py`; Mode B; author-produced; implementation
  `create_authority_revocation_resolver` over `InMemoryAuthorityRevocationStore` in
  `agent-passport-system` 4.1.0 (PyPI). Authorship relationship: as above.

- **Direct revocation by the delegation's own issuer, and refusal of any other revoker /
  claim: the finance office's revocation of its own grant verifies `valid`, records, and drives
  the chain to `invalid`/`REVOKED`, and `issueAuthorityRevocation` refuses a receiver-as-revoker
  record with `REVOKER_NOT_ISSUER`**; runner: the lab, via
  `fixtures/lifecycle-legal-regulatory-events/mint.ts` with the result written into
  `chain.json`'s `mint_time_sdk_observations` and printed by `verify.ts`; Mode A;
  author-produced; implementation: `agent-passport-system` 7.1.0 (npm). Authorship
  relationship: the lab authored the records being checked.

- **Gate scope match / claim: `scopeGrantCovers` accepts the gate's own scope against the
  action's and rejects an unrelated scope**; runner: the lab, via `verify.ts` and `mint.ts`;
  Mode A; author-produced; implementation: `agent-passport-system` 7.1.0 (npm). Authorship
  relationship: the lab authored the scopes.

- **Gate scope match / same claim**; runner: the lab, via `verify_python_sdk.py`; Mode B;
  author-produced; implementation `scope_grant_covers` in `agent-passport-system` 4.1.0
  (PyPI). Authorship relationship: as above.

- **External authority event, dependency binding and gate certification signatures / claim:
  every one of the twenty-one events, three bindings and two certifications verifies under the
  domain-separated JCS rule, and every event's `event_id` recomputes from its own preimage**;
  runner: the lab, via `mint.ts` and `verify.ts`; Mode A; author-produced; implementation:
  `verify` and `canonicalizeJCS` in `agent-passport-system` 7.1.0 (npm). Authorship
  relationship: the lab authored the records and the signing rule.

- **External record signatures / same claim**; runner: the lab, via `verify_python_sdk.py`;
  Mode B; author-produced; implementation: `verify` and `canonicalize_jcs` in
  `agent-passport-system` 4.1.0 (PyPI). Authorship relationship: as above.

- **External-event authority decisions / claim: the reference boundary matches all 44 vectors
  and the four defective boundaries diverge on exactly their declared sets of 18, 8, 1 and 2**;
  runner: the lab, via `verify.ts` and `verify_python_sdk.py`; Mode A and Mode B respectively;
  author-produced; implementation:
  `fixtures/lifecycle-legal-regulatory-events/harness.ts` and the boundary logic inside
  `verify_python_sdk.py`, both authored by the lab. Authorship relationship: the lab authored
  the vectors, the boundary, the record shapes and both runners. Neither runner is a thin
  harness for this claim: each constructs and interprets the claimed semantic result, so both
  are part of the recomputation implementation.

- **Receipt immutability across ratification / claim: the historical act's JCS digest is
  identical across all three ratification vectors and equal to `chain.json`'s recorded value**;
  runner: the lab, via `verify.ts` and `verify_python_sdk.py`; Mode A and Mode B respectively;
  author-produced; implementation: `canonicalizeJCS` / `canonicalize_jcs` in the two reference
  SDKs, with the comparison in the runners. Authorship relationship: the lab authored the
  receipt and the comparison.

These records are attributed per layer. Merge of this family is not an end-to-end verification
or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundary:

- an external record from a party the verifier's trust policy recognises can change the
  authority verdict from `valid` to `invalid`, `suspended` or `restricted` while the presented
  chain keeps verifying `valid` on both reference SDKs, with no revocation record anywhere
- a suspension with two unreleased causes stays `suspended` after one of them is released by a
  record naming only that cause, and becomes `valid` again with no new grant once both are
  released
- a restriction and an approval gate are lifted only by a record from outside the graph:
  neither time passing nor a later grant from the principal lifts either
- an execution block and an ownership change of the same target are different states, and a
  release record lifts the first and not the second, including against a later, entirely valid
  grant from the former owner
- one record revoking an off-graph dependency invalidates every chain whose signed binding
  declares that dependency, at the same observation time, and no chain whose binding does not
- a record whose effect began before an observation time and whose own `recorded_at` is after
  it is invisible to that observation, and the verdict reached then is not rewritten by the
  later record: the historical receipt's digest is byte-identical before and after
- a root that appears in no other chain is accepted or rejected by the verifier's trust policy,
  and becomes acceptable when the verifier can establish the basis rather than when the basis
  exists
- revocation evidence that no longer covers a delegation gives `not established` through the
  SDK's own `indeterminate` / `REVOCATION_UNKNOWN`, never `valid` and never `invalid`
- a claim from a party with no lifecycle standing for its effect is `not established`, which is
  reported separately from both `valid` and `invalid`
- a grant waiting on its own `not_before` is `not yet effective`, with the SDK's own
  `NOT_YET_VALID`, and not `invalid`
- the reference boundary returns only the six settled verdicts, on both runners

It also establishes that a boundary implementing exactly draft-03 section 3.3 chain
verification and nothing else wrongly admits or wrongly settles eighteen of these vectors, and
that a boundary which reports every restricted or suspended authority as `invalid` reaches the
reference boundary's admit-or-deny answer on all forty-four vectors while writing a terminal
lifecycle state for an authority that comes back with no new grant.

## Does not claim

A pass does **not** establish:

- anything about a deployed enforcement gateway, MCP server or agent runtime. No network call
  is made and no protocol is spoken. `harness.ts` and the boundary in `verify_python_sdk.py`
  are this family's own in-process reference model.
- that the `external-authority-event-v0`, `dependency-binding-v0` or `gate-certification-v0`
  shapes here are required, recommended or recognised by draft-pidlisnyi-aps-03, or that any
  other implementation would produce interoperable records. They are this fixture's invention.
  See "Where the proposed text was too vague to test", items 1 and 6.
- that the eleven effect names, the `lifecycle_standing` map or the two trust-root bases are
  vocabulary anything downstream should bind to. `CONTRIBUTING.md` reserves conformance
  vocabulary to the maintainer, and nothing here proposes any.
- that admitting on an unestablished external claim, or denying on an unestablished
  ratification, is what the proposed text requires. Both are this fixture's declared policy.
  See item 3.
- that a verifier with no access to an external status source can reach any of these verdicts
  from signed delegation and revocation records alone. It cannot, and the
  `REVOKER_NOT_ISSUER` refusal recorded above is why.
- **anything about any body of law, and nothing about whether any legal doctrine applies to an
  AI agent.** The scenarios are named after institutional situations because those situations
  are where the machine-checkable distinctions come from. A court order, a sanction, a licence
  revocation, a bankruptcy posture and a consent decree appear here as *record shapes with an
  effective time, a target and a signer*, and every legal effect they would have in the world
  is outside this fixture entirely. No vector decides liability, entitlement or lawfulness.
- anything about completeness. `LRE-B-022-b` shows what a verdict becomes when evidence no
  longer covers a delegation. It says nothing about establishing that a set of records was
  complete, which `OPEN-QUESTIONS.md` records as open.
- real concurrency. Every vector is evaluated synchronously against a fixed status source at a
  pinned observation time.
- that the reference SDKs are wrong to omit any of this. Neither SDK claims to have an external
  authority event, a suspension or a restricted state, and no published text requires one. The
  `not_supported` entries are a record of what exists, not a defect report.

## Provenance

`vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`, `verify_python_sdk.py`,
`CHECKSUMS.sha256` and this README are authored for this suite. The minting, key-resolution and
seed-label pattern follows [`fixtures/approval-single-use/mint.ts`](../approval-single-use/mint.ts)
and [`fixtures/single-chain-selection/mint.py`](../single-chain-selection/mint.py). The
reference-boundary-plus-declared-defective-control pattern follows
[`fixtures/runtime-authority-denial-continuity/harness.ts`](../runtime-authority-denial-continuity/harness.ts)
and [`fixtures/approval-single-use/harness.ts`](../approval-single-use/harness.ts). All code was
written in this lab. Neither runner was reviewed by anyone outside it, and no independent third
party has run either of them.
