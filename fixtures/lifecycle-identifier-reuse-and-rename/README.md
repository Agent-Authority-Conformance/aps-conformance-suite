# lifecycle-identifier-reuse-and-rename: the string stayed the same, the party behind it did not

**Status: candidate against proposed text. This is not a draft-03 conformance case.**
Every vector in `vectors.json` carries `status: "candidate_against_proposed"` and names
both the proposed text it tests and the `CASES.md` case id it comes from. `verify.ts` and
`verify.py` both refuse to run if any vector loses that label, names proposed text the
file does not define, or stops carrying its case id in its own vector id.

An authority path can depend on an identifier that no party in the delegation graph
controls: a mail domain a recovery flow delivers to, a package namespace a dependent
reference resolves, a phone number an account was enrolled with. Those identifiers have
their own lifecycle, run by a custodian, and it is not the grant's lifecycle. This family
makes executable what a verifier can say once one of them changes hands with no
delegation-layer event marking the change.

## Which cases this family covers

Three cases from the **Identifier reuse and rename** section of `CASES.md` in
[`aeoess/agent-authority-lifecycle`](https://github.com/aeoess/agent-authority-lifecycle),
at commit `2bf5c7e2d07d41c13611478d6e5e47fcb4d3ceda`:

| case | vectors |
|---|---|
| LC-I-001, re-registering an abandoned identifier hands the new controller everything still addressed to the old one | IRR-01 to IRR-04, IRR-13 |
| LC-I-002, a rename does not travel with the references that still point at the old name | IRR-05 to IRR-08 |
| LC-I-003, a recycled identifier reused for a new subject can still unlock the old subject's authority | IRR-09 to IRR-12 |

That commit is reachable from the public default branch of that repository. The
proposed text the vectors actually test is pinned separately, at an earlier commit on
the same history.

## The real-world shapes behind the three cases

Each source below was fetched while this family was being built, and each quote is
verbatim from it. They are cited as the source of the shape of the question. None of them
is a statement about AI agents, and this family does not treat any of them as one.

**A lapsed mail domain (LC-I-001).** Researchers who re-registered abandoned law firm
domains and stood up mail on them reported receiving, per
[ESET WeLiveSecurity](https://www.welivesecurity.com/2018/09/11/abandoning-domain-name-research-shows/):

> highly sensitive information about the legal practice and its clients, such as
> transcripts of court proceedings and other sensitive legal documents, as well as
> supplier invoices, bank statements, etc.

The same report describes being able to "regain access to the firms' Office 365 and G
Suite accounts by resetting the passwords". The recovery path depended on control of the
domain, and nothing in any account record said so.

**A vacated account name (LC-I-002).** GitHub's own documentation on changing a username,
[docs.github.com](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-personal-account-settings/changing-your-github-username):

> After changing your username, your old username becomes available for anyone else to
> claim.

and, on what a new holder of that name can do to references that still point at it:

> If the new owner of your old username creates a repository with the same name as your
> repository, that will override the redirect entry and your redirect will stop working.

**A recycled number (LC-I-003).** The Princeton study on recycled phone numbers,
[recyclednumbers.cs.princeton.edu](https://recyclednumbers.cs.princeton.edu/):

> 171 of 259 numbers we sampled were vulnerable to account hijackings at six popular
> websites: Amazon, AOL, Facebook, Google, Paypal, and Yahoo.

and, on the scale of the underlying churn:

> 35 million phone numbers are disconnected in the U.S. every year.

The Checkmarx report on GitHub's popular-repository namespace retirement, which `CASES.md`
cites for LC-I-002 and which describes a transfer race around that protection, could not be
fetched while this family was built. The retirement rule, the hundred-clone threshold and
the race are therefore **not** asserted anywhere in this family. IRR-06 to IRR-08 model a
generic custodian retention record instead, and its existence is this family's own
construction rather than a claim about any real host.

## What this tests, and against which text

The proposed text is the **Target binding** concept in
[`AUTHORITY-LIFECYCLE.md`](https://github.com/aeoess/agent-authority-lifecycle), version
0.1.2-draft, at commit `7796e22fb80480d0336ff0967a862c84284c15e4`, section **Lifecycle
concepts are separate > Authority and dependencies**:

> Target binding. Which resource, counterparty or object the authority applies to.
> Continuity of a name does not by itself establish continuity of the thing named.

Vectors also test three neighbouring concepts at the same commit. **Authority path and
dependency**, in the same section:

> Authority path and dependency. Which other authority a grant currently depends on.
> Historical provenance and current dependency are not necessarily the same thing.

**Issuer standing**, in **Parties and standing**:

> Issuer standing. Why the issuer was allowed to create, narrow, suspend, revoke or
> replace authority for the principal. A valid signature establishes who signed. It does
> not by itself establish standing.

**Coverage and completeness**, in **Verification and evidence**:

> Coverage and completeness. What set or interval the available evidence covers. Showing
> that individual records are authentic is weaker than establishing that all relevant
> events were observed.

That document states the status of all four entries itself:

> The grouping and every other entry are **proposed**, added in 0.1.1-draft or
> 0.1.2-draft. No public case tests them yet.

### Why this is not a draft-03 case

[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/) states
no rule about an off-chain identifier a grant depends on. The closest text is section 4.1,
on the `target` field of an action reference:

> target is the exact resource, tool, or endpoint against which the action will be
> dispatched; a profile MUST define its target string construction.

`target` names a resource for one action. It says nothing about an identifier a grant's
recovery or verification path depends on, who currently controls that identifier, or what
a verifier records when control of it moves.

One piece of draft-03 the family does lean on is the scope grammar, section 3.2:

> Scope grants use ASCII colon-separated segments. "\*" covers all grants; a wildcard is
> otherwise permitted only as the terminal segment ":\*".

A dependency and its controller pin are expressed as further colon-separated segments, so
both stay inside the grammar draft-03 already defines rather than inventing a record
field. draft-03 does not define this encoding or any other.

## What this family defines itself

The proposed text names the distinction in two sentences and stops. It does not say how a
grant carries a dependency on something outside the graph, who is entitled to say who
controls it, what a verifier returns when control moves, or what an interval with no
controller at all means. This family supplies all four, because a runnable case cannot
exist without them, and none of them is a reading the proposed text compels:

1. **Dependency and pin encoding.** `extid:<kind>:<identifier>` declares the dependency.
   `extid:<kind>:<identifier>:controller:<did>` pins who holds it. Both are scope grants.
2. **Custodian standing.** Who a binding record has to come from is resolved from the
   identifier kind, never from the `custodian` field the presented record asserts about
   itself. A registrar's signature over a phone-number binding verifies and still does not
   count.
3. **Verdict vocabulary.** `valid`, `not_established`, `invalid`, from the settled
   lifecycle vocabulary. Every identifier failure gives `not_established`, not `invalid`:
   the grant is a fine grant and the chain is valid, and what has not been established is
   that the thing the name points at is the thing the grant was written against. IRR-13 is
   the contrast, where an actual revocation gives `invalid`.
4. **Continuity, not just currency.** Reaching the right holder at the action instant is
   not the whole question. An interval since issuance in which nobody held the identifier
   is an interval in which anybody could have, and the boundary treats it as uncovered
   unless a retention record from the custodian with standing closes it. IRR-06 against
   IRR-07 is that rule made executable, and it is the one a naive implementation cannot
   see at all, because in both of them the holder now is the pinned holder.

Read 1 to 4 as this family's proposal for how the concept would be tested, not as the
concept's meaning. See "Where the proposed text was too vague to test".

## What exists

Neither reference SDK exposes an API that takes an external identifier and an instant and
answers who controls it. The reference boundary is therefore this family's own code, in
`harness.ts`, following the precedent set by
[`fixtures/runtime-authority-denial-continuity/`](../runtime-authority-denial-continuity/)
and [`fixtures/approval-single-use/`](../approval-single-use/). **The identifier-dependency
boundary is implemented by this fixture, not by either APS SDK. The SDKs are used only for
the things they actually decide.**

`harness.ts` calls the TypeScript SDK for three of them:

- `verifyAuthorityDelegationChain` for the grant's structural, temporal, signature and
  revocation state
- `canonicalizeJCS` for the RFC 8785 canonical bytes the custodian records are signed over
- `verify` for the Ed25519 signatures on those records

Everything else, the dependency check, the pin parsing, the standing rule, the interval
arithmetic and the verdict vocabulary, is the family's own.

### SDK findings

Two findings surfaced while building this family. They are recorded here because they
changed how the family is built, not as vectors: no vector tests an SDK's export list.

**1. The TypeScript SDK's namespace-claim layer is compiled but not reachable.**
`agent-passport-system` 7.1.0 ships `createNamespaceClaim` and `verifyNamespaceClaim` in
`dist/src/core/tool-integrity.js` with matching type declarations, and exports neither
from the package root nor from the `./core` subpath, so neither is callable by a consumer
of the published package. `fixtures/capability-binding-drift/sdk-probe.mjs` recorded the
same unreachable module for its own reasons, and
`fixtures/lifecycle-identifier-reuse-and-rename/sdk-probe.mjs` records it again here: 9 of
16 supported. A namespace claim is the nearest thing either SDK has to the question this
family asks, and it is not reachable, so the family models the binding record itself.

**2. The Python SDK has no identity-binding surface at all.** `agent-passport-system`
4.1.0 on PyPI has no `verify_namespace_claim`, no `create_did_document`, no
`public_key_from_did` and no `verify_rotation_log`. It exposes the authority-chain
verifier, `issue_authority_delegation`, the JCS canonicalizer and Ed25519 verify, and
nothing else this family could use. `fixtures/lifecycle-identifier-reuse-and-rename/sdk-probe.py`
records it: 4 of 13 supported. `verify.py` therefore writes the binding resolution, the
standing rule and the interval arithmetic out from `agent_passport.canonicalize_jcs` and
`agent_passport.crypto.verify`. That is a recorded gap, not a claim that the Python SDK
decided any of it.

## What the family does

`mint.ts` mints, with `agent-passport-system` 7.1.0:

- five one-hop `AuthorityDelegationV1` grants, principal to agent, issued at
  `2026-09-19T09:00:00.000Z` and identical except for their nonce and their scope: a mail
  domain declared and pinned, the same recovery authority with the mail domain named
  nowhere, a package namespace declared and pinned, a phone number declared and pinned, and
  the same phone number declared with no controller pin
- eleven custodian-signed binding records over three identifiers of three kinds: a current
  open-ended holding, the same holding allowed to lapse, a re-registration by an unrelated
  party two days later, a rename-vacated namespace claimed by a third party, the same
  namespace resumed by the original publisher after a two-day gap, a routine number
  reassignment with no gap at all, and two open records from one carrier that overlap and
  name different subscribers
- three custodian-signed retention records over the namespace gap: one covering it exactly,
  one stopping one day short, and one covering it from an identity with no standing

`mint.ts` asserts at mint time, and exits without writing `chain.json` if any assertion
fails, that: all five grants verify `valid` at `2026-09-23T12:00:00.000Z` with an active
resolver, the phone reassignment is exactly adjacent so no interval is uncovered, the mail
domain genuinely lapses before the new registration, the full retention record covers the
publisher gap exactly at both ends, and the short one stops before the resumption.

`harness.ts` implements `IdentifierDependencyBoundary` in five ordered steps: the grant
chain, the declared dependency, the controller pin, the holder at the action instant, and
continuity since issuance. `verify.ts` runs both configurations over the thirteen
presentations. `verify.py` is a second implementation of the same five steps written
against the Python SDK's primitives. Both run with no network access.

Each presentation is an independent evaluation against a fresh boundary. Unlike
`fixtures/approval-single-use/`, no state is carried between presentations and
presentation order does not matter.

## Vectors

| id | case | differs by | expected |
|---|---|---|---|
| IRR-01-LC-I-001-a-declared-pinned-and-continuously-bound-control | LC-I-001 | control | `valid`, `identifier_continuity_established` |
| IRR-02-LC-I-001-b-dependency-not-declared-not-established | LC-I-001 | the grant names the identifier nowhere | `not_established`, `identifier_dependency_not_declared` |
| IRR-03-LC-I-001-c-lapsed-then-registered-by-an-unrelated-party-not-established | LC-I-001 | lapse, then a new registrant | `not_established`, `identifier_controller_changed` |
| IRR-04-LC-I-001-d-no-binding-covers-the-action-instant-not-established | LC-I-001 | lapse, and nobody took it | `not_established`, `identifier_binding_lapsed` |
| IRR-05-LC-I-002-a-vacated-name-claimed-by-a-new-controller-not-established | LC-I-002 | a rename vacates the name and another party claims it | `not_established`, `identifier_controller_changed` |
| IRR-06-LC-I-002-b-retained-gap-with-the-pinned-controller-back | LC-I-002 | control: the gap is retained by the custodian | `valid`, `identifier_continuity_established` |
| IRR-07-LC-I-002-c-uncovered-gap-with-the-pinned-controller-back-not-established | LC-I-002 | the retention stops a day short | `not_established`, `identifier_continuity_gap_uncovered` |
| IRR-08-LC-I-002-d-retention-record-from-a-custodian-without-standing-not-established | LC-I-002 | the retention covers the gap and comes from the wrong party | `not_established`, `retention_custodian_without_standing` |
| IRR-09-LC-I-003-a-routine-reassignment-to-a-new-subscriber-not-established | LC-I-003 | adjacent reassignment, no gap at all | `not_established`, `identifier_controller_changed` |
| IRR-10-LC-I-003-b-two-custodian-records-disagree-not-established | LC-I-003 | one custodian, two overlapping records, two holders | `not_established`, `identifier_binding_conflict` |
| IRR-11-LC-I-003-c-declared-dependency-with-no-controller-pin-not-established | LC-I-003 | declared and unpinned, nothing changed | `not_established`, `identifier_controller_not_pinned` |
| IRR-12-LC-I-003-d-still-held-by-the-pinned-subscriber-control | LC-I-003 | control, per kind | `valid`, `identifier_continuity_established` |
| IRR-13-LC-I-001-e-revoked-grant-is-invalid-not-identifier-not-established | LC-I-001 | the discriminator: the resolver answers revoked | `invalid`, chain `invalid`, `REVOKED` |

IRR-11 is the vector most likely to be argued with, and it is deliberate. Nothing about
the number changed, and the verdict is still `not_established`, because a grant that names
an identifier and pins nobody gives the verifier no basis in either direction. The absence
of change is not something the grant establishes. IRR-09 is the second most arguable: the
carrier did nothing wrong, the records show no gap, and the answer is still that continuity
of the thing named was not shown.

IRR-07 against IRR-06 is the pair the family turns on. In both, the holder at the action
instant is the pinned holder and the string never changed. They differ only in whether the
custodian's own records account for the interval in between.

## Negative control

`defective-boundary-the-string-is-the-identifier` is one coherent implementation of "the
address on file has not changed". It runs the identical SDK chain check and removes exactly
four things:

- an undeclared dependency is treated as no dependency
- an absent controller pin is treated as satisfied
- the identifier string matching is the whole check, and no custodian record is ever read
- custodian standing is read from the record's own `custodian` field

Those four removals account for exactly nine vectors. The declared diverging set:

    IRR-02-LC-I-001-b-dependency-not-declared-not-established
    IRR-03-LC-I-001-c-lapsed-then-registered-by-an-unrelated-party-not-established
    IRR-04-LC-I-001-d-no-binding-covers-the-action-instant-not-established
    IRR-05-LC-I-002-a-vacated-name-claimed-by-a-new-controller-not-established
    IRR-07-LC-I-002-c-uncovered-gap-with-the-pinned-controller-back-not-established
    IRR-08-LC-I-002-d-retention-record-from-a-custodian-without-standing-not-established
    IRR-09-LC-I-003-a-routine-reassignment-to-a-new-subscriber-not-established
    IRR-10-LC-I-003-b-two-custodian-records-disagree-not-established
    IRR-11-LC-I-003-c-declared-dependency-with-no-controller-pin-not-established

This is the negative control a naive implementation passes wrongly, and it is not a straw
man. It is what a system looks like when the identifier was never a modelled authority
artifact, only a string other artifacts silently depend on, which is exactly the situation
LC-I-001 describes. On IRR-03, IRR-05 and IRR-09 it returns a confident `valid` for an
identifier a different party now holds, and it reports the pinned controller as the holder
while doing so, because it never asked anyone. It still matches the reference boundary on
IRR-01, IRR-06, IRR-12 and IRR-13, which is why the defect survives. Both `verify.ts` and
`verify.py` check the control in both directions, so an undeclared divergence or a declared
divergence that quietly starts matching is loud in either runner's output.

## Running

TypeScript, wired into `npm test` as a step:

    npm ci --include=dev
    npm run verify:lifecycle-identifier-reuse-and-rename

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/lifecycle-identifier-reuse-and-rename/mint.ts

Python, a manual run and not part of `npm test`, the same convention
`fixtures/approval-single-use/verify.py` and
`fixtures/ancestor-revocation-chain/validate.py` already follow for a Python side kept out
of the hermetic Node-only CI gate. Needs `agent-passport-system` 4.x installed:

    python3 fixtures/lifecycle-identifier-reuse-and-rename/verify.py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set (python)

The two SDK support probes, which print a per-API `supported` or `not_supported` line and
assert nothing:

    node fixtures/lifecycle-identifier-reuse-and-rename/sdk-probe.mjs
    python3 fixtures/lifecycle-identifier-reuse-and-rename/sdk-probe.py

## Determinism

Every Ed25519 key is the SHA-256 of a published label under the seed prefix
`aps-conformance-suite:lifecycle-identifier-reuse-and-rename`, recorded in `chain.json` as
`seed_prefix`. Every delegation, binding and retention nonce is derived the same way. Every
timestamp is pinned: the grants are issued at `2026-09-19T09:00:00.000Z`, the bindings run
from `2026-01-01T00:00:00.000Z` and change hands at `2026-09-20`, `2026-09-21` and
`2026-09-22T00:00:00.000Z`, the retention records cover `2026-09-20` to `2026-09-22` and
`2026-09-20` to `2026-09-21`, and `now` is `2026-09-23T12:00:00.000Z`. Every record digest
is taken over RFC 8785 JCS canonical bytes produced by the SDK's own `canonicalizeJCS`, and
`verify.py` reproduces the same bytes with the Python SDK's `canonicalize_jcs`, which is
what makes the signature checks a cross-language claim. Every interval is half-open,
`[from, until)`, with a null `until` meaning open-ended, so the phone reassignment at
`2026-09-22T00:00:00.000Z` has exactly one holder at that instant and not zero or two. No
secret material is in the file: every public key is published and every private key is
reproducible from its published label, which is exactly why these keys are for test vectors
and nothing else.

SHA-256 over the exact bytes of this family's files, at this commit:

    4d5e5955de4b550232da4ac0dad076df4e432a9e87fca16311eeabb4c865bafa  chain.json
    01d16a0204545a5aaaa15f1d9f121b758f72a9ee11e076afbed5b91f019b82e4  harness.ts
    82b9758aa2ecebc2cfd82201609366074d9280cc737d4d657729421a2fb0436f  mint.ts
    851f6f85c6906ce0a4ff66e6c130f00c9b0e2d2181d73da90481ea009ecaba44  sdk-probe.mjs
    7ae35ff8582ac1ec9feeb929bc4aea6b62b6cb20a10200e76929a3e207fd3065  sdk-probe.py
    7a504f58876d76de25ad4ea6dc1b57cd6acbc13876c07a94399174d5c5d9a0a1  vectors.json
    7e0956dd9fcff90093271250dfa1f3650665433ef7be5139f69de0680ece85a0  verify.py
    5f68381b42487ac76246700e827834ae6d957b17c4871e10592d92ec1e26932c  verify.ts

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

- grant chain state for all five grants at the pinned instant (`valid` under an active resolver, `invalid`/`REVOKED` under a revoked one); runner aeoess; Mode A; author-produced, because this lab authored the vectors and `mint.ts` and the implementation under test is this lab's own `agent-passport-system`; recomputed by `agent_passport.v2.authority_delegation.verify_authority_delegation_chain` in `verify.py` under the same relationship.
- Ed25519 signatures on the eleven binding records and three retention records over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` plus `verify` on one side and the Python SDK's `canonicalize_jcs` plus `agent_passport.crypto.verify` on the other.
- binding and retention record digests over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` on one side and the Python SDK's `canonicalize_jcs` on the other.
- the thirteen identifier-dependency verdicts, the interval arithmetic behind them and the declared defective diverging set; runner aeoess; Mode A; author-produced, because the boundary that decides each verdict is this family's own `harness.ts` and its Python counterpart in `verify.py`, both written in this lab.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Results

Both runners were executed locally against `agent-passport-system` 7.1.0 (npm) and
`agent-passport-system` 4.1.0 (PyPI, in a virtual environment). The `reference-boundary`
matched 13/13 presentations under both runners.
`defective-boundary-the-string-is-the-identifier` diverged on exactly the declared set of 9
under both runners and matched the remaining 4 under both. `npm ci --include=dev` and
`npm test` both exited 0 with this family wired in. These are author-produced records, not
independent ones, per `CONTRIBUTING.md`.

## Where the proposed text was too vague to test

This is a finding, and it matters at least as much as the fixture. The **Target binding**
entry names a real distinction in two sentences and leaves four things undetermined. Each
one had to be decided before a single vector could exist, and a different decision gives
different expected verdicts for the same records:

1. **No place for the dependency.** The text says continuity of a name does not establish
   continuity of the thing named, and does not say where a grant records which names it
   depends on. A scope grant, an authority facet, a field on the action reference, and an
   out-of-band registry the grant points at are all candidates, and they narrow differently
   across a chain. The scope-grant encoding chosen here means a child delegation's
   dependency is checked by draft-03's ordinary scope covering rule, which is not a
   decision the proposed text asked for.
2. **No verdict.** The text does not say what a verifier returns when a name's controller
   changes. `invalid`, `not_established`, `suspended` and "valid, and the dependency is
   flagged" are all readings. This family chose `not_established`, which keeps the grant
   and the chain intact and says only that continuity of the thing named was not shown.
   Nothing in the text compels it.
3. **No rule for an undeclared or unpinned dependency.** LC-I-001's whole point is that the
   dependency was never modelled, so the text's own subject matter includes a grant that
   says nothing. Reading that silence as admitting, as admitting with a recorded caveat, or
   as not established are all defensible. IRR-02 and IRR-11 make the third reading
   executable and would change wholesale under either of the others.
4. **No treatment of an interval with no controller.** The text is written about a moment,
   "continuity of a name", and gives no basis for deciding whether an interval in which
   nobody held the identifier matters once the right party holds it again. IRR-06, IRR-07
   and IRR-08 turn entirely on this family's own rule that such an interval is uncovered
   unless a custodian with standing closes it, and there is nothing in the proposed text
   that either requires or forbids it.

A fifth thing is under-determined rather than undetermined. **Issuer standing** says a
valid signature does not establish standing, which this family applies to custodians by
analogy. The text is about issuers of authority artifacts, and a registrar or a carrier is
not one. Whether the same rule should govern a party whose records a verifier consults but
who grants no authority at all is not something the text addresses, and IRR-08 depends on
reading it that way.

A sixth is outside what any record set can settle, and no vector claims it.
`OPEN-QUESTIONS.md` at the same commit says of notice and relying parties:

> What a relying party that acted on stale but authentic evidence is entitled to, and what
> evidence of notice a principal needs to show, is not defined here.

LC-I-001 raises exactly that: mail keeps arriving at the old address and the sender has no
way to know control of it moved. This family tests only what the receiving verifier can
establish from the records in front of it. It says nothing about what the sender was
entitled to rely on.

Until at least 1 to 4 are settled in the proposed text, no case in this family can move
from `candidate` to `tested` against it, because there is nothing yet to be conformant
with. That is the finding.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundary and its own record shapes:

- an identifier declared as a dependency, pinned to a controller, and continuously bound to
  that controller by a custodian with standing since the grant was issued is established
- an identifier the grant never names establishes nothing, even when the identifier in fact
  has not changed hands, because the boundary has no record to check
- an identifier the grant names without pinning a controller establishes nothing, whether or
  not the identifier changed, rather than admitting
- a re-registration or a claim by a different party after a lapse or a rename is recorded as
  the controller having changed, and the new holder is named in the record
- a routine reassignment with no gap at all is recorded the same way, so the distinction
  between a lapse someone could have prevented and ordinary custodian behaviour does not
  change what the verifier can establish
- an action instant no binding record covers is recorded as the binding having lapsed, which
  is a different answer from a record naming a different holder
- two records from one custodian with standing that cover the same instant and name
  different holders record that the holder is not established, rather than one of them
  winning
- an interval since issuance in which the pinned controller did not hold the identifier is
  uncovered unless a retention record from a custodian with standing closes it, and a
  retention record from an identity without standing does not close it even when its
  signature verifies and its interval fits
- an actual revocation of the grant records `invalid` with `REVOKED`, so an identifier
  changing hands and an authority being revoked are distinguishable from the output alone
- an implementation for which the string is the identifier predictably diverges on exactly
  those nine vectors, and on none of the other four

## Does not claim

A pass does **not** establish:

- anything about draft-pidlisnyi-aps-03 conformance. draft-03 states no rule about an
  off-chain identifier a grant depends on. Every vector is `candidate_against_proposed`, and
  a maintainer who disagrees with any of the four decisions under "What this family defines
  itself" should expect different expected verdicts, not a bug report.
- that this family's dependency encoding, standing rule, verdict vocabulary or continuity
  rule is the right one, or the only defensible one. See "Where the proposed text was too
  vague to test".
- anything about DNS, domain registration, WHOIS, any package host, any carrier, or any
  real number plan. No network call is made and no registry protocol is spoken. The
  custodian records here are generic signed statements authored for this family.
- the GitHub popular-repository namespace retirement rule, its hundred-clone threshold, or
  the transfer race reported against it. That source could not be fetched while this family
  was built, so none of it is asserted anywhere here. The retention record is this family's
  own construction.
- that any legal or regulatory doctrine about domain names, telephone numbering or account
  recovery applies to AI agents. The three sources above are cited for the shape of the
  question, which is what the model document says about agency law too.
- that either reference SDK implements identifier binding. Neither does. The TypeScript
  SDK's namespace-claim pair is compiled and unreachable, and the Python SDK has no
  identity-binding surface at all. See "SDK findings".
- anything about how an identifier dependency should narrow across a delegation chain. Every
  grant here is a one-hop root delegation, so no parent-to-child comparison of a dependency
  or a pin is exercised.
- that anything was delivered to, resolved from, or dialled at any of these identifiers.
  Nothing here executes anything.

## Provenance

`README.md`, `vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`,
`verify.py`, `sdk-probe.mjs` and `sdk-probe.py` are authored for this suite. The minting,
chain verification, canonicalization and signature primitives are
`agent-passport-system` 7.1.0 (npm) and `agent-passport-system` 4.1.0 (PyPI). The case
statements come from `CASES.md` in `aeoess/agent-authority-lifecycle` at commit
`2bf5c7e2d07d41c13611478d6e5e47fcb4d3ceda`, and the proposed text under test comes from
`AUTHORITY-LIFECYCLE.md` in the same repository at commit
`7796e22fb80480d0336ff0967a862c84284c15e4`.
