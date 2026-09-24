# lifecycle-third-party-reliance-notice: two records, two answers

A principal ends an agent's authority. The chain stops verifying that instant. Whether any
particular outside party was told is a different record, with a different answer, that nobody
can read off the first one. And a second grant issued later to the same agent is not a
revocation of the first.

Twelve vectors across three cases, one reference boundary, four declared defective boundaries,
two runners over two reference SDKs.

**Every vector in this family is labelled `candidate_against_proposed.`** No vector here is a
draft-pidlisnyi-aps-03 conformance case for notice, because draft-03 states no rule for it and
neither reference SDK exports anything for it. The revocation half of every vector is ordinary
draft-03 section 3.5 behaviour and says so per vector.

## What this family does not answer

Whether an outside party's reliance is protected, what that party is entitled to, or what
evidence of notice a principal would need to show anyone. Those are legal effects settled off
the wire, and no verifier computes them from records. **Nothing here states or assumes that any
legal doctrine applies to an AI agent.** The cases are named after institutional situations
because that is where the machine-checkable distinctions come from, and the machine-checkable
part is all this fixture tests: what a verifier can establish about a chain, and separately
what it can establish about notice.

`OPEN-QUESTIONS.md` in the proposed text says the same thing about its own scope, quoted in
full:

    A revocation can be recorded at one moment and reach an agent, a gateway and an outside
    counterparty at different moments. What a relying party that acted on stale but authentic
    evidence is entitled to, and what evidence of notice a principal needs to show, is not
    defined here. Agency law offers answers for human agents. This document does not assume
    they apply.

## The proposed text this tests

[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle),
`AUTHORITY-LIFECYCLE.md` at commit `7796e22`, document version 0.1.2-draft. The load-bearing
entries, quoted in full:

    Notice. That a particular party or enforcement point learned of a transition at a
    particular time. Recording a transition and observing it are different events.

    Status observation. What authority state a verifier could establish, from which source,
    at what time and with what freshness. Current authority and observed authority can
    differ.

    Lifecycle standing. Who may suspend, revoke, replace or reaffirm an authority artifact.
    This is not always the issuer. An organization, a quorum, a successor, a court or a
    security function can have standing to change authority it never issued.

Invariant **L5. Independent chains are not combined**, quoted in full:

    An agent holding two valid chains cannot use them together to create a grant broader than
    either chain allows. Each grant follows one parent chain.

Its status line reads "Status **specified, not yet tested**." L5 is the closest invariant to
this family's third case and it is not the same claim: L5 forbids combining two chains, and
`LC-A-033` forbids treating the newer of two chains as having killed the older. One is a wrong
reason to widen and the other is a wrong reason to invalidate.

The cases are the **Third-party reliance and notice** section of `CASES.md` at commit
`2bf5c7e`. Every vector id carries its case id: `TPR-A-028-b` is the second vector for
`LC-A-028`.

## Where draft-03 does and does not state a rule

Fetched this session from
[draft-pidlisnyi-aps-03](https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt):

    Verification returns one of valid, invalid, indeterminate, or unsupported with a stable
    failure code.

and, from Section 3.5:

    Revocation is irreversible.

Every vector's chain and revocation half rests on that. draft-03 says nothing about notice, has
no notice record, and defines no way to name a recipient or distinguish a broadcast from an
individually addressed record.

## What the reference SDKs supply, and what they do not

Both runners print their own support table, so the record below is produced by the run rather
than typed. Verbatim from the two runs recorded under "Results":

    TypeScript SDK support, agent-passport-system 7.1.0:
      supported      chain state, including time and root trust  (verifyAuthorityDelegationChain)
      supported      direct revocation by the delegation issuer  (issueAuthorityRevocation, verifyAuthorityRevocation, recordAuthorityRevocation)
      supported      revocation resolution, including unknown for a record that does not verify  (createAuthorityRevocationResolver over InMemoryAuthorityRevocationStore)
      supported      notice record and register signatures  (verify over canonicalizeJCS)
      not_supported  revocation by a party other than the issuer  (issueAuthorityRevocation refuses with REVOKER_NOT_ISSUER, see chain.json mint_time_sdk_observations)
      not_supported  notice record  (no export in agent-passport-system 7.1.0, supplied by this fixture)
      not_supported  notice state for a named counterparty  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  prior-dealing register  (no export in agent-passport-system 7.1.0, supplied by this fixture)
      not_supported  two-tier notice sufficiency  (no export in agent-passport-system 7.1.0, supplied by harness.ts)

    Python SDK support, agent-passport-system 4.1.0:
      supported      chain state, including time and root trust  (verify_authority_delegation_chain)
      supported      direct revocation by the delegation issuer  (record_authority_revocation, verify_authority_revocation)
      supported      revocation resolution, including unknown for a record that does not verify  (create_authority_revocation_resolver over InMemoryAuthorityRevocationStore)
      supported      notice record and register signatures  (verify over canonicalize_jcs)
      not_supported  revocation by a party other than the issuer  (issue_authority_revocation admits only the target delegation's issuer as revoker)
      not_supported  notice record  (no Python SDK export, supplied by this fixture)
      not_supported  notice state for a named counterparty  (no Python SDK export, supplied by this runner)
      not_supported  prior-dealing register  (no Python SDK export, supplied by this fixture)
      not_supported  two-tier notice sufficiency  (no Python SDK export, supplied by this runner)

## The records this fixture invented

A `notice-record-v0`, profile
`aps-conformance-suite:lifecycle-third-party-reliance-notice:notice-record-v0`, signed over the
domain string `APS-CONFORMANCE-TPR-NOTICE-RECORD-V0`, a space, and the RFC 8785 JCS canonical
bytes of the body. It carries a `mode` of `individual` or `publication`, a `counterparty` which
is `null` on a publication record because that record names no recipient at all, the
`revocation_id` it gives notice of, and an `issued_at`.

A `prior-dealing-register-v0`, signed by the principal, naming the counterparties that had a
recorded dealing under one delegation before the termination. One record, one fact.

**Both shapes are this fixture's invention.** Neither the proposed text nor draft-03 defines
one. See "Where the proposed text was too vague to test".

## What the family does

`mint.ts` mints, with the pinned TypeScript SDK `agent-passport-system` 7.1.0:

- **three one-hop grants** from one principal to one agent. `terminated` is the grant the notice
  half is about. `older` and `newer` are the same principal to the same agent, `newer` issued
  two days later and carrying a broader scope, with nothing in either naming the other.
- **three real draft-03 section 3.5.1 revocation records.** Two are minted through
  `issueAuthorityRevocation`, the supported path, by each target grant's own issuer. The third
  names a revoker who is not the target's issuer, which `issueAuthorityRevocation` refuses
  outright, so it is built from the same public canonical primitives issuance uses internally:
  cascade transaction id, then revocation id, then signature. The result is a well-formed,
  correctly signed `AuthorityRevocationV1` that no resolver may ever read as `revoked`.
- **four notice records.** A publication record naming no recipient, an individual record to
  the counterparty in the register, an individual record to a different counterparty, and an
  individual record to the right counterparty from a principal who did not revoke the grant.
- **one prior-dealing register** listing exactly one of the three counterparties.

`mint.ts` asserts every one of these SDK answers at mint time, aborting with nothing written on
any failure, and writes each into `chain.json` under `mint_time_sdk_observations`. This README
quotes recorded values:

    "terminated_chain_after_revocation": {"first_failure_code": "REVOKED", "state": "invalid"},
    "older_chain_with_newer_grant_and_no_revocation": {"first_failure_code": null, "state": "valid"},
    "newer_chain_after_older_express_revocation": {"first_failure_code": null, "state": "valid"},
    "wrong_revoker_record_verification": {"first_failure_code": "REVOKER_NOT_ISSUER", "state": "invalid"},
    "wrong_revoker_resolver_answer": "unknown",
    "older_chain_with_wrong_revoker_record": {"first_failure_code": "REVOCATION_UNKNOWN", "state": "indeterminate"},
    "external_revoker_issuance_refusal": "authority revocation revoker is not the target delegation issuer (REVOKER_NOT_ISSUER)"

### Why the wrong-revoker record is placed through a raw store primitive

`recordAuthorityRevocation` verifies a candidate against its target and refuses to write
anything that does not verify, which is correct. To reach the state `TPR-A-033-d` is about, the
record has to be inside a store anyway, so this fixture calls
`InMemoryAuthorityRevocationStore.insertVerifiedRevocation` directly. The SDK's own
documentation names that caller as the party asserting the record was verified, and says what
happens next: the resolver re-verifies on the way out and answers `unknown` rather than
`revoked`. That re-verification is the behaviour the vector pins down, and the SDK supplies it.

`harness.ts` implements `AuthorityBoundary` in five configurations. For every evaluation it
answers two things and never derives either from the other: the chain's verdict from the SDK,
and a notice state for one named counterparty at one named time from the notice records and the
register.

## The vectors

Twelve across three cases. `tests` and `differs_from` on each vector in `vectors.json` name
what it exercises and the single change from its nearest control.

| id | case | chain | revocation records | notice records | counterparty | authority | notice |
|---|---|---|---|---|---|---|---|
| `TPR-A-027-a` | LC-A-027 | terminated | none | none | repeat | valid | not established, `no_termination_recorded` |
| `TPR-A-027-b` | LC-A-027 | terminated | its own issuer's | none | repeat | invalid, REVOKED | not established, `no_notice_record` |
| `TPR-A-027-c` | LC-A-027 | terminated | its own issuer's | individual to repeat | repeat | invalid, REVOKED | established, individual |
| `TPR-A-027-d` | LC-A-027 | terminated | its own issuer's | individual from a non-revoker | repeat | invalid, REVOKED | not established, `notice_issuer_without_standing` |
| `TPR-A-028-a` | LC-A-028 | terminated | its own issuer's | publication only | stranger | invalid, REVOKED | established, publication |
| `TPR-A-028-b` | LC-A-028 | terminated | its own issuer's | publication only | repeat | invalid, REVOKED | not established, `individual_notice_required_for_prior_dealing` |
| `TPR-A-028-c` | LC-A-028 | terminated | its own issuer's | publication and individual to repeat | repeat | invalid, REVOKED | established, individual |
| `TPR-A-028-d` | LC-A-028 | terminated | its own issuer's | publication and individual to someone else | repeat | invalid, REVOKED | not established, `individual_notice_required_for_prior_dealing` |
| `TPR-A-033-a` | LC-A-033 | older | none | none | stranger | valid | not established, `no_termination_recorded` |
| `TPR-A-033-b` | LC-A-033 | older | express, naming the older grant | none | stranger | invalid, REVOKED | not established, `no_notice_record` |
| `TPR-A-033-c` | LC-A-033 | newer | express, naming the older grant | none | stranger | valid | not established, `no_termination_recorded` |
| `TPR-A-033-d` | LC-A-033 | older | naming the older grant, wrong revoker | none | stranger | not established, REVOCATION_UNKNOWN | not established, `no_notice_record` |

`TPR-A-033-a`, `-b` and `-d` all hold both the older and the newer grant at once, so the
newest-wins control below has a real target to misfire on in each of them and correctly
misfires in only one.

### The structural check that carries LC-A-027

Both runners assert, over the reference boundary's twelve outcomes, that **neither answer is a
function of the other**. At least one authority verdict has to appear with both notice states,
and at least one notice state with more than one authority verdict, or the two fields are
interchangeable and this family has proved nothing. Verbatim from both runs:

    ok   notice state is not a function of the authority verdict: verdict(s) appearing with both notice states: "invalid"
    ok   authority verdict is not a function of the notice state: notice state(s) appearing with several verdicts: "not established"

`TPR-A-027-b` and `TPR-A-027-c` are the pair that makes the first line true: the same
`invalid` / `REVOKED` chain, one before any notice record exists and one after an individual
record reaches this counterparty.

## Negative controls

**Vector-level.**

- `TPR-A-027-d`. An individual notice naming the right counterparty and the right revocation,
  genuinely signed, from a principal who did not revoke the grant. `mint.ts` asserts that the
  record verifies under its own signer's key and does not verify under the principal's, so the
  rejection is a standing failure and never a signature failure. Notice is **not established**,
  which is not the same as a statement that no notice was given.
- `TPR-A-028-d`. The publication record plus an individual record addressed to a different
  counterparty. Still not established for the listed one. Without this vector, a boundary that
  accepted any individual record as notice to everyone would pass.
- `TPR-A-033-c`. The newer grant under the express revocation of the older one. Valid. The
  revocation reaches the delegation it names and no other.
- `TPR-A-033-d`. A well-formed, correctly signed revocation naming the older grant whose revoker
  is a different principal. The SDK resolver answers `unknown`, chain verification is
  `indeterminate` / `REVOCATION_UNKNOWN`, and the verdict is `not established`. An unestablished
  revocation neither ends the grant nor leaves it valid.

**Boundary-level. Four declared defective boundaries**, each with its failing set declared in
`vectors.json`. Both runners check both directions: every declared id must actually diverge, and
every other id must still match.

**`defective-boundary-publication-covers-everyone` and
`defective-boundary-single-notice-boolean` are the two controls a naive checker passes
wrongly.** Both runners print the fact for every control:

    defective-boundary-single-notice-boolean: 6 declared, diverged on exactly its declared set: true, reaches the reference authority verdict on every vector: true
    defective-boundary-publication-covers-everyone: 2 declared, diverged on exactly its declared set: true, reaches the reference authority verdict on every vector: true
    defective-boundary-notice-without-standing: 1 declared, diverged on exactly its declared set: true, reaches the reference authority verdict on every vector: true
    defective-boundary-newest-wins: 1 declared, diverged on exactly its declared set: true, reaches the reference authority verdict on every vector: false

Three of the four reach the reference boundary's authority verdict and reason on every single
vector, and differ only in what they say about notice. A checker that compares the
authorized-or-not answer passes all three everywhere. That is why `notice_state`,
`notice_basis` and `notice_reason` are compared fields and not log lines.

`defective-boundary-single-notice-boolean` reports notice as established whenever the chain no
longer verifies valid, and keeps the reason string the records actually support, so its own
record contradicts itself in the open: `notice="established"/no_notice_record`. Six declared
failures, and they run in both directions. On `TPR-A-027-b` it claims notice reached a
counterparty nobody wrote to. On `TPR-A-033-d` it claims notice of a revocation it could not
even establish happened.

`defective-boundary-publication-covers-everyone` treats one broadcast record as notice to every
counterparty including the one the signed register lists. Two declared failures.

`defective-boundary-notice-without-standing` verifies every notice record's signature and never
asks whether the signer revoked the grant. One declared failure, `TPR-A-027-d`.

`defective-boundary-newest-wins` treats the existence of a later grant from the same issuer to
the same subject as having revoked the earlier one, with no revocation record anywhere saying
so. One declared failure, `TPR-A-033-a`. It is the only one of the four whose defect shows up in
the authority verdict, which is why it is the only one a naive checker catches.

## Where the proposed text was too vague to test

These are findings, not defects in the fixture. Each one is a place this family had to choose
something the proposed text does not say.

1. **A notice record has no shape.** "That a particular party or enforcement point learned of a
   transition at a particular time" names the concept and defines nothing: no record, no way to
   name a recipient, no way to name the transition. This family invented
   `notice-record-v0`. Any other implementation would invent a different one and the two would
   not interoperate. Nothing here tests interoperability of the record.

2. **Nobody is named as having standing to give notice.** The text separates lifecycle standing
   from issuer standing and never applies either to notice. This family made the rule "only the
   party who revoked the grant can give notice of that revocation", which is the narrowest
   defensible reading and is still an invention. A model where a gateway, a registry or a
   successor may give notice on the principal's behalf is equally consistent with the text, and
   `TPR-A-027-d` would then be a positive rather than a negative control.

3. **"That a particular party learned" is not "a record was published".** The text's notice
   entry is about a party *learning*, which no record establishes. A signed record establishes
   only that its issuer said something at a time. This family reports `established` for what is
   really "a record exists that this fixture's rule counts as notice to this counterparty", and
   the gap between that and actual knowledge is not closeable by any record. It is the same
   shape of gap that makes the reliance question legal rather than technical.

4. **A two-tier notice rule has no basis in the proposed text at all.** The text has one notice
   concept. The two tiers, and the prior-dealing register that makes them decidable, come
   entirely from `CASES.md`'s `LC-A-028` and from this fixture. Which tier a counterparty falls
   into is decided here by a register the principal signs, which means a principal who omits a
   counterparty from its own register escapes the stricter tier. That is a real hole in this
   fixture's model and the honest consequence of the text having no mechanism.

5. **Freshness is named and never defined.** "at what time and with what freshness" puts
   freshness in the observation entry, and nothing defines a staleness bound for a notice record
   or a register. This family compares `issued_at` and the register's `as_of` against a supplied
   `now` and has no freshness rule at all. A verifier reading a register that stopped being
   maintained a year ago answers exactly as one reading a current register. No vector covers
   that, and none could without a field the text does not define.

6. **Withdrawal of notice, and notice of a suspension rather than a revocation, are both
   undefined.** Every notice record here names a `revocation_id`. Whether notice can be given of
   a suspension, a restriction or an expiry, and whether a notice record can itself be
   superseded, are questions the text does not raise and no vector here covers.

7. **What "an express revocation clause" is, in records.** `LC-A-033` turns on whether the newer
   instrument expressly revokes the older. In this family that is a separate
   `AuthorityRevocationV1` naming the older delegation, which is the only mechanism draft-03
   offers. Whether a grant should be able to carry a revocation of another grant inside itself
   is not a question either text asks, and draft-03's closed authority vector has no slot for
   one.

## Running

TypeScript, wired into `npm test` as its last step:

    npm ci --include=dev
    npm run verify:lifecycle-third-party-reliance-notice

Expected final line:

    PASSED: reference-boundary matched every vector, all four defective boundaries diverged on exactly their declared sets

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/lifecycle-third-party-reliance-notice/mint.ts

Python, against the pinned Python SDK, a manual run and not part of `npm test`:

    python3 -m venv /tmp/aac-lc-g3-venv
    /tmp/aac-lc-g3-venv/bin/pip install 'agent-passport-system==4.1.0'
    /tmp/aac-lc-g3-venv/bin/python fixtures/lifecycle-third-party-reliance-notice/verify_python_sdk.py

Expected final line:

    PASSED: reference-boundary matched every vector, all four defective boundaries diverged on exactly their declared sets (python SDK)

## Determinism

Every key is an Ed25519 seed derived from a published label under the prefix
`aps-conformance-suite:lifecycle-third-party-reliance-notice:`, recorded in `chain.json` as
`seed_label_prefix`. No clock is read and no randomness is drawn. Canonical bytes are RFC 8785
JCS throughout, through the SDK's own `canonicalizeJCS` on the TypeScript side and
`canonicalize_jcs` on the Python side. `chain.json` is written with keys sorted at every depth.

Checksums of the committed data files, as generated, and also in `CHECKSUMS.sha256`:

    b4bb99ecc506af1307d9cbd16dd1e5c5d7da678f99c6e4f152502022ca25132b  chain.json
    71676fc81d6729358f2f917bc9a880097730761f344a007ba32daa079b5af2cd  vectors.json

## Results

Both runners were executed locally. `reference-boundary` matched 12/12 vectors under both, and
the six structural checks passed under both. All four defective boundaries diverged on exactly
their declared sets under both runners: 6, 2, 1 and 1 respectively. The two runners agree on all
12 outcomes for all five configurations.

Both records are author-produced, not independent, per `CONTRIBUTING.md`'s admission rules for
run records. See the Verification split below.

## Verification split

One entry per distinct verification claim, in the form
`layer / claim; runner; Mode; authorship; implementation`, per `CONTRIBUTING.md`.

- **Chain state, including temporal, root-trust and revocation validity / claim: all three
  grants verify `valid` with no revocation recorded, the terminated grant verifies
  `invalid`/`REVOKED` after its own issuer's revocation, and the newer grant stays `valid`
  under the older grant's express revocation**; runner: the lab, via
  `fixtures/lifecycle-third-party-reliance-notice/verify.ts`; Mode A; author-produced;
  implementation: `agent-passport-system` 7.1.0 (npm). Authorship relationship preventing an
  independent label: the lab authored the vectors and the claim inputs, and the implementation
  is a reference SDK from the same project.

- **Chain state / same claim, recomputed by the Python reference SDK**; runner: the lab, via
  `fixtures/lifecycle-third-party-reliance-notice/verify_python_sdk.py`; Mode B;
  author-produced; implementation: `agent-passport-system` 4.1.0 (PyPI). Authorship
  relationship: as above. The two SDKs are separate implementations and the Python run supplies
  the substantive recomputation, but both are reference SDKs of the same project and the lab
  authored the vectors, so the record is not independent.

- **Direct revocation by the delegation's own issuer / claim: both supported-path revocations
  verify `valid` against their targets and record into the store**; runner: the lab, via
  `mint.ts` and `verify.ts`; Mode A; author-produced; implementation: `issueAuthorityRevocation`,
  `verifyAuthorityRevocation` and `recordAuthorityRevocation` in `agent-passport-system` 7.1.0
  (npm). Authorship relationship: the lab authored the records being checked.

- **Direct revocation recording / same claim**; runner: the lab, via `verify_python_sdk.py`;
  Mode B; author-produced; implementation: `record_authority_revocation` and
  `verify_authority_revocation` in `agent-passport-system` 4.1.0 (PyPI). Authorship
  relationship: as above.

- **Refusal of a revoker who is not the target's issuer / claim:
  `verifyAuthorityRevocation` returns `invalid`/`REVOKER_NOT_ISSUER` for the wrong-revoker
  record, `issueAuthorityRevocation` refuses to mint the same construction at all, and once the
  record is inside a store the resolver answers `unknown`, which chain verification reports as
  `indeterminate`/`REVOCATION_UNKNOWN`**; runner: the lab, via `mint.ts` with the results
  written into `chain.json`'s `mint_time_sdk_observations` and printed by `verify.ts`; Mode A;
  author-produced; implementation: `agent-passport-system` 7.1.0 (npm). Authorship relationship:
  the lab authored the record being refused.

- **Revocation resolution for a record that does not verify / same claim, recomputed through the
  Python resolver**; runner: the lab, via `verify_python_sdk.py`; Mode B; author-produced;
  implementation: `create_authority_revocation_resolver` over `InMemoryAuthorityRevocationStore`
  in `agent-passport-system` 4.1.0 (PyPI). Authorship relationship: as above.

- **Notice record and prior-dealing register signatures / claim: all four notice records and the
  register verify under the domain-separated JCS rule, and the no-standing record verifies under
  its own signer's key and not under the principal's**; runner: the lab, via `mint.ts` and
  `verify.ts`; Mode A; author-produced; implementation: `verify` and `canonicalizeJCS` in
  `agent-passport-system` 7.1.0 (npm). Authorship relationship: the lab authored the records and
  the signing rule.

- **Notice record signatures / same claim**; runner: the lab, via `verify_python_sdk.py`; Mode B;
  author-produced; implementation: `verify` and `canonicalize_jcs` in `agent-passport-system`
  4.1.0 (PyPI). Authorship relationship: as above.

- **Notice-state decisions, and the independence of the two answers / claim: the reference
  boundary matches all 12 vectors, neither answer is a function of the other across the vector
  set, and the four defective boundaries diverge on exactly their declared sets of 6, 2, 1 and
  1**; runner: the lab, via `verify.ts` and `verify_python_sdk.py`; Mode A and Mode B
  respectively; author-produced; implementation:
  `fixtures/lifecycle-third-party-reliance-notice/harness.ts` and the boundary logic inside
  `verify_python_sdk.py`, both authored by the lab. Authorship relationship: the lab authored
  the vectors, the boundary, the record shapes and both runners. Neither runner is a thin
  harness for this claim: each constructs and interprets the claimed semantic result, so both
  are part of the recomputation implementation.

These records are attributed per layer. Merge of this family is not an end-to-end verification
or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundary:

- a chain's verdict and a notice state for one named counterparty are computed from different
  records and neither is a function of the other across this vector set, verified structurally
  by both runners rather than asserted
- an individually addressed notice record establishes notice for the party it names and for
  nobody else, including when a record addressed to a different party is also present
- a broadcast record naming no recipient establishes notice for a counterparty the signed
  register does not list, and does not for one the register does list
- a genuinely signed notice record from a party that did not revoke the grant leaves notice
  `not established`, which is reported differently from the absence of any record
- a later, broader grant from the same principal to the same agent leaves the earlier grant
  verifying `valid`, and an express revocation naming the earlier grant leaves the later one
  verifying `valid`
- a well-formed, correctly signed revocation record whose revoker is not the target's issuer
  makes the chain `not established` through the SDK's own `indeterminate` /
  `REVOCATION_UNKNOWN`, never `valid` and never `invalid`
- the reference boundary returns only the settled authority verdicts and only `established` or
  `not established` for notice, on both runners

It also establishes that three of the four defective boundaries reach the reference boundary's
authority verdict and reason on every one of the twelve vectors and differ only in what they
record about notice, so an implementation checked on the authorized-or-not answer alone can be
wrong about notice on half the vectors here without anything showing.

## Does not claim

A pass does **not** establish:

- **anything about whether any outside party's reliance is protected, what any party is
  entitled to, or whether any legal doctrine applies to an AI agent.** The word `established`
  in a notice state means one thing here: a record exists that this fixture's rule counts as
  notice to this counterparty at this time. See item 3 under "Where the proposed text was too
  vague to test".
- that the `notice-record-v0` or `prior-dealing-register-v0` shapes here are required,
  recommended or recognised by draft-pidlisnyi-aps-03, or that any other implementation would
  produce interoperable records. They are this fixture's invention.
- that the two-tier notice rule is the right rule, or that the register is the right way to
  decide which tier a counterparty is in. Both come from `CASES.md` and from this fixture, not
  from the proposed text. See item 4.
- that only the revoking party may give notice. That is this family's narrowest defensible
  reading and an invention. See item 2.
- that a notice record establishes that anybody learned anything. It establishes that its
  issuer said something at a time.
- anything about a deployed enforcement gateway, MCP server or agent runtime. No network call is
  made and no protocol is spoken.
- that the reference SDKs are wrong to omit a notice record. Neither claims to have one and no
  published text requires one. The `not_supported` entries are a record of what exists, not a
  defect report.
- anything about freshness, withdrawal of notice, or notice of a suspension rather than a
  revocation. See items 5 and 6.
- real concurrency. Every vector is evaluated synchronously against a fixed record set at a
  pinned time.

## Provenance

`vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`, `verify_python_sdk.py`,
`CHECKSUMS.sha256` and this README are authored for this suite. The minting, key-resolution and
seed-label pattern follows [`fixtures/approval-single-use/mint.ts`](../approval-single-use/mint.ts).
The reference-boundary-plus-declared-defective-control pattern follows
[`fixtures/runtime-authority-denial-continuity/harness.ts`](../runtime-authority-denial-continuity/harness.ts).
The sibling family [`fixtures/lifecycle-legal-regulatory-events/`](../lifecycle-legal-regulatory-events/README.md)
was authored in the same pass and records the same `REVOKER_NOT_ISSUER` finding from the other
side. All code was written in this lab. Neither runner was reviewed by anyone outside it, and no
independent third party has run either of them.
