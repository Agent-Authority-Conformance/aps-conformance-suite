# authority-epoch-rollback

Candidate cases for authority rollback and fencing. A revocation is recorded at
epoch 7. A restored snapshot or a lagging replica presents epoch-6 state in which
the chain is still active. A stale fencing-token holder tries to publish that
epoch-6 state after a higher token was issued. A recorded revocation is later
withdrawn by a correction record.

Every case in `vectors.json` is labelled `candidate_against_proposed`. Nothing
here is a conformance claim, about APS or anything else. Where the verdict a case
expects does follow from published draft-03 text, the case carries a
`draft03_anchor` naming the section and quoting it, and the README says which part
of the case that anchor covers and which part it does not.

## What is proposed, and where

The text under test is the agent-authority-lifecycle work at commit
[`5c1bf09`](https://github.com/aeoess/agent-authority-lifecycle/tree/5c1bf09ee29d517f2f19c9bb9212543a7c44b227)
(full sha `5c1bf09ee29d517f2f19c9bb9212543a7c44b227`), documents
`AUTHORITY-LIFECYCLE.md` and `OPEN-QUESTIONS.md`. That text is the thing being
tested. It is not cited as a source for any factual claim in this README, and a
case that stops matching it after an edit is a stale case, not a finding.

The concepts and invariants each group tests, by section name:

| group | proposed text | section name | status in the source |
|---|---|---|---|
| epoch rollback | Authority epoch, Status observation, L7 | `Lifecycle concepts are separate` (Authority lifecycle state, Verification and evidence), `Invariants` L7 | Authority epoch and Status observation are **proposed**. L7 is **specified** for unavailable or stale results and **candidate** beyond them |
| write fencing | Authority rollback, L11 | `Authority rollback` in OPEN-QUESTIONS.md, `Invariants` L11 | **open** and **proposed** |
| revocation correction | L3, Lifecycle standing | `Invariants` L3, `Lifecycle concepts are separate` (Parties and standing) | L3 is **specified in part**. The withdrawal half is **proposed** with nothing testing it |

The `Authority rollback` open question states the gap this family exists for:

> An authority epoch, or an append-only record of revocations that a restore must
> replay, would stop a restore from reviving revoked authority.

and, two sentences later, that neither has been specified or tested.

## What draft-03 does and does not state

Three verdicts in this family follow from published draft-03 text, and the rest do
not. Keeping those apart is the point of the `draft03_anchor` field.

Draft-03 ([draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/)),
Section 3.3, "Chain Verification":

> An unavailable or stale revocation result is indeterminate.

and, in the same paragraph, "A caller MUST NOT collapse indeterminate or
unsupported into valid." Section 3.5, "Cascade Revocation":

> Revocation is irreversible.

Section 3.6 carries the same rule as INV-5, Revocation Irreversibility. Section
3.5.1 separates the two questions this family is built on: "whether a delegation is
currently valid, answerable from state, and whether and why a revocation occurred,
verifiable from signed records", which it says MUST NOT collapse into one mutable
lookup.

So draft-03 fixes what a verifier returns **once** it has established that the
answer in front of it is stale, and that a revocation cannot be undone. What
draft-03 does not contain, anywhere, is the word epoch, a fencing token, a
snapshot, a replica, or a restore. It has no mechanism for deciding that a state
source is behind, and no record for withdrawing a revocation. Those are the
candidate parts, and they are this fixture's own model.

## External sources

Two claims here rest on published work outside this project.

**Fencing tokens.** Martin Kleppmann, "How to do distributed locking", 8 February
2016, https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html

> a fencing token is simply a number that increases (e.g. incremented by the lock
> service) every time a client acquires the lock

> Note this requires the storage server to take an active role in checking tokens,
> and rejecting any writes on which the token has gone backwards.

That second sentence is the exact rule the write-fencing gate implements, including
why an equal token is accepted: an equal token has not gone backwards.

**A withdrawal is its own record, not a deletion.** RFC 5280, section 5.3.1,
https://www.rfc-editor.org/rfc/rfc5280.txt

> The removeFromCRL (8) reasonCode value may only appear in delta CRLs and
> indicates that a certificate is to be removed from a CRL because either the
> certificate expired or was removed from hold.

> All other reason codes may appear in any CRL and indicate that the specified
> certificate should be considered revoked.

A deployed revocation system therefore represents a withdrawal as an explicitly
coded record of its own, and confines it to release from hold and expiry rather
than to reversing a permanent revocation. RFC 5280 is about certificates. The
translation into agent-authority terms is this fixture's, and nothing here claims
RFC 5280 or any legal doctrine governs AI agents.

## What the SDKs do and do not support

Both reference SDKs were installed and probed. Neither has an API for any of this
family's three concepts, and the probes are committed so the absence is
reproducible rather than asserted:

    node fixtures/authority-epoch-rollback/sdk-support-probe.mjs
    python3 fixtures/authority-epoch-rollback/sdk_support_probe.py

| concept | npm `agent-passport-system` 7.1.0 | PyPI `agent-passport-system` 4.1.0 |
|---|---|---|
| authority epoch on a delegation, a revocation or store state | `not_supported` | `not_supported` |
| fencing token on an authority-mutating write | `not_supported` | `not_supported` |
| withdrawal or correction of a recorded revocation | `not_supported` | `not_supported` |
| removal of a revocation from a store | `not_supported`, the store exposes `track`, `tracks`, `get`, `insertVerifiedRevocation` and nothing else | `not_supported`, same four methods |

`not_supported` here means the named surface does not exist. It is not a defect
report: nothing in draft-03 asks either SDK for any of these.

The absence of a removal method is worth stating on its own. In both SDKs a
revocation cannot be taken out of a store once recorded, and
`insertVerifiedRevocation` is documented as first-verified-revocation-wins. Inside
one store, irreversibility is structural. Rollback in this SDK can therefore only
arrive by *replacing the store*, which is exactly what a restore, a snapshot mount
or a lagging replica does, and is why this family models state as a set of
epoch-tagged stores rather than as mutations of one.

## What the SDKs do contribute

Every verdict this family reports comes from the SDK's own chain verifier, in both
languages. Per case, the SDK supplies:

- the two `AuthorityDelegationV1` records and their signatures, minted by
  `issue_authority_delegation` and `issue_sub_authority_delegation`
- the draft-03 section 3.5.1 revocation record, minted by
  `issue_authority_revocation`, whose `revoker` the SDK checks against the target's
  own `issuer`
- the store write path, `record_authority_revocation`, which verifies a candidate
  revocation against its target before it is written, so a `revoked` answer in this
  family is earned and not asserted
- the resolver, `create_authority_revocation_resolver`, and its three answers
- the verdict, `verify_authority_delegation_chain`, including `REVOKED` at the
  root's own index and `REVOCATION_UNKNOWN` for an `unknown` answer
- RFC 8785 JCS canonicalization, used for every digest in `chains.json`

The fixture supplies the three gates: the epoch comparison, the fencing-token
check on publication writes, and the withdrawal check. Those decide what answer
the resolver gives the SDK. They never decide the verdict.

## Files

| file | what it is |
|---|---|
| `mint.py` | deterministic generator. Ed25519 seeds are SHA-256 over published labels, nonces are supplied, no clock is read |
| `chains.json` | generated. Two-member chain, one revocation, two withdrawal records, five epoch-tagged views, and a JCS digest per record |
| `vectors.json` | twelve cases, hand-authored, with the proposed text and the draft-03 anchor named per case |
| `harness.ts` | the three gates and the view materializer, TypeScript |
| `verify.ts` | TypeScript runner, wired into `npm test` |
| `validate.py` | Python runner, written from the README and the vectors rather than ported from `harness.ts` |
| `sdk-support-probe.mjs`, `sdk_support_probe.py` | the `not_supported` table above, reproducible |
| `CHECKSUMS.sha256` | pins `chains.json` only, see Determinism |

## Principals, chain and views

Three identities, minted from the published seed labels in `mint.py`:

- `did:aps:example:aer-principal`, the root issuer and the only party that can
  revoke the root delegation, because draft-03 section 3.5 says "Any delegation MAY
  be revoked by its issuer"
- `did:aps:example:aer-agent-a`, the root's subject and the child's issuer
- `did:aps:example:aer-agent-b`, the child's subject

One two-hop chain: `aer-principal -> aer-agent-a` at index 0, then
`aer-agent-a -> aer-agent-b` at index 1. One revocation, of the root, at
`2026-09-20T11:30:00.000Z`. All verification happens at one fixed
`now`, `2026-09-20T13:00:00.000Z`.

Five named views. A view is a complete epoch-tagged state of a revocation store,
materialized at run time into a real `InMemoryAuthorityRevocationStore`:

| view | epoch | holds |
|---|---|---|
| `epoch-6` | 6 | both delegations tracked, no revocation |
| `epoch-7` | 7 | the root revocation |
| `epoch-8` | 8 | the root revocation, nothing new, used to show a forward move is not fenced |
| `epoch-8-corrected` | 8 | the root revocation plus a withdrawal signed by the revoker |
| `epoch-8-unauthorized-correction` | 8 | the root revocation plus a withdrawal signed by the root's subject, who is not the revoker |

Tracked delegations are registered explicitly. In both SDKs absence from a store
answers `unknown`, never `active`, so an `active` answer in this family always
comes from a store that says it covers the delegation and holds no revocation for
it.

## The withdrawal record is fixture-local

Neither draft-03 nor the proposed text at `5c1bf09` defines a record for
withdrawing a recorded revocation, or says what a verifier should do with one. The
shape used here,

    fixture:authority-epoch-rollback:revocation-withdrawal:v0

is fixture-local, exists so the case is runnable, and is **not proposed as APS
vocabulary**. Record fields and failure-class names are conformance vocabulary
decided by the maintainer, per `CONTRIBUTING.md`, and this fixture is deliberately
not minting any. That the vocabulary does not exist is one of this family's
findings, not a gap this fixture fills.

The record references the revocation by `revocation_id` and never modifies it. Its
signature covers a domain-separated RFC 8785 JCS preimage of its own body, the same
separation pattern the SDK uses for its own records. Three things have to hold for
the fixture to accept one, and they are kept as three separate questions: it names
a revocation the view actually holds, its signature verifies, and its signer is the
party the revocation itself names as revoker. A genuine signature from a party
without standing fails the third.

## The three gates

**The epoch gate.** A view whose epoch is lower than the verifier's high-water mark
is stale. The gate then has two outcomes and they are not the same:

- the verifier retained the records it observed at its high-water mark, one of them
  verifies as a revocation of this delegation, and the answer is `revoked`
- the verifier retained only the epoch number, cannot establish a revocation from
  records, and the answer is `unknown`, which the SDK's verifier turns into
  `indeterminate` with `REVOCATION_UNKNOWN`

A stale view never answers `active`. The second outcome is "not established", not
"no revocation happened", which is the distinction L7 draws and which draft-03
section 3.3 fixes the verdict for once staleness is established.

**The publication store.** Authority state is published by whoever holds the
current fencing token. A write whose token is lower than the highest token already
seen is refused with `stale_fencing_token`. An equal or higher token is accepted.

**The withdrawal check.** Described above. An accepted withdrawal is a record, not
a deletion: the revocation stays in the store, still verifies byte for byte, and
the chain verdict does not change.

## Cases

Twelve cases in `vectors.json`, in three groups.

| case | group | role | expected |
|---|---|---|---|
| `AER-01-epoch7-current-control` | epoch rollback | positive control | `invalid`, `REVOKED`, index 0 |
| `AER-02-epoch6-before-revocation-control` | epoch rollback | positive control | `valid` |
| `AER-03-restored-snapshot-with-retained-record` | epoch rollback | negative | `invalid`, `REVOKED`, index 0 |
| `AER-04-lagging-replica-epoch-only` | epoch rollback | negative | `indeterminate`, `REVOCATION_UNKNOWN`, index 0 |
| `AER-05-forward-move-is-not-fenced` | epoch rollback | positive | `invalid`, `REVOKED`, index 0, high-water mark advances to 8 |
| `AER-06-first-contact-no-prior-observation` | epoch rollback | boundary, not determined by the source | `valid`, declared, excluded from the tally |
| `AER-07-current-token-write-accepted` | write fencing | positive control | write accepted, `invalid`, `REVOKED`, index 0 |
| `AER-08-stale-token-write-refused` | write fencing | negative | second write refused `stale_fencing_token`, published epoch stays 7, `invalid`, `REVOKED`, index 0 |
| `AER-09-higher-token-write-accepted` | write fencing | positive | both writes accepted, published epoch 8 |
| `AER-10-equal-token-retry-accepted` | write fencing | positive | equal token accepted and idempotent |
| `AER-11-withdrawal-does-not-restore-the-chain` | revocation correction | negative | withdrawal accepted, revocation still held and still verifies, `invalid`, `REVOKED`, index 0 |
| `AER-12-withdrawal-without-standing-is-not-a-correction` | revocation correction | negative | withdrawal refused `withdrawal_signer_is_not_the_revoker`, `invalid`, `REVOKED`, index 0 |

`AER-02` and `AER-03` are the pair that carries the family. They present the same
epoch-6 state to two verifiers and expect opposite results, because epoch-6 state
is not defective in itself. It is stale only relative to a verifier that has
already observed epoch 7.

Every case in the write-fencing group gives the verifier no observed epoch on
purpose, so the write-side gate is the only thing that can refuse the stale state.
Letting the epoch gate also catch it would mean a fencing defect could be masked by
the epoch comparison, and the fixture would stop attributing a failure to one axis.

### Where the source does not determine an outcome

`AER-06` presents epoch-6 state to a verifier that has never observed any epoch.
It has nothing to compare against. This fixture reads the view as current and the
chain verifies `valid`. A fail-closed deployment could as well refuse any state
source it cannot place against a known epoch and return `indeterminate`. Neither
the proposed text nor draft-03 chooses between those, so the case carries
`unconstrained_by_source: true`, the runner asserts the declared choice, and both
runners print the case as excluded from the property count. Four of twelve cases
discriminate a fenced implementation from an unfenced one, and the rest are controls.

## Negative controls

Three defective policies are run on purpose. Each removes exactly one gate and is
run only against the group whose gate it removes, and against every case in that
group rather than only the ones predicted to fail, so an undeclared failure and a
declared failure that quietly starts passing are both loud.

| policy | gate removed | group | declared failures | what it returns there |
|---|---|---|---|---|
| `latest-read` | epoch comparison | epoch rollback | `AER-03`, `AER-04` | `valid` |
| `unfenced-writer` | fencing-token check | write fencing | `AER-08` | `valid` |
| `correction-as-deletion` | withdrawal is not a deletion | revocation correction | `AER-11` | `valid` |

All three failures are in the dangerous direction. A naive implementation returns
`valid` on a chain whose root was revoked at epoch 7, and it does so while every
signature, every identifier and every canonical byte in front of it checks out.
That is what these controls exist to make visible: the defect is not in the
records, it is in which records the verifier was willing to read as current.

`AER-11` also names what the deletion control returns, and `AER-08` names what the
unfenced writer publishes and returns, and both runners assert those values against
the control runs rather than leaving them as prose.

## Determinism

- Ed25519 seeds are SHA-256 over the published labels listed in `mint.py` and in
  `chains.json`'s `seed_labels`. No secret material ships.
- Nonces are supplied, never generated. No clock, network or random source is read
  by the generator or by either runner.
- `chains.json` records a SHA-256 over the RFC 8785 JCS canonical bytes of every
  chain member and every record, computed with the SDK's own canonicalizer. Both
  runners recompute all five digests before any case runs and exit 2 on a mismatch:
  a vector result over bytes that drifted would be a statement about the wrong
  bytes. Both runners agreeing on those digests is also byte parity between the two
  canonicalizers.
- Regenerating is the reproduction:

      python3 fixtures/authority-epoch-rollback/mint.py

  `git diff` on `chains.json` is then empty. This was checked while authoring by
  re-running `mint.py` and comparing the SHA-256 of the file before and after.
- `CHECKSUMS.sha256` pins `chains.json` and is checked by
  `npm run test:digest-integrity`. It deliberately covers only that file.
  `chains.json` is generated and must never be hand-edited, so pinning it is free.
  `vectors.json` and the runners are not covered, because their expected outcomes
  and prose are exactly what review changes, and a digest set makes the files it
  covers immutable under `CONTRIBUTING.md`.

## Running

TypeScript, from the repository root:

    npm ci --include=dev
    npm run verify:authority-epoch-rollback

It also runs as part of `npm test`. Expected final line:

    PASSED: reference matched every case, latest-read, unfenced-writer and correction-as-deletion each failed exactly their declared set

Python, against the published PyPI package in a clean virtual environment:

    python3 -m venv /tmp/aer-venv
    /tmp/aer-venv/bin/pip install agent-passport-system
    /tmp/aer-venv/bin/python fixtures/authority-epoch-rollback/validate.py

This is a manual run and is not part of `npm test`, which stays Node only so the
hermetic gate keeps running on the Windows job. It prints the same final line,
with `Python` in place of `TypeScript` on the tally line.

Both runners were executed and matched on all twelve cases, on every field each
case declares, and on all five JCS digests.

## Verification split

One entry per distinct verification claim, using the single definition in
`CONTRIBUTING.md`.

- Record bytes and digests / that every chain member and record in `chains.json`
  matches its declared SHA-256 over RFC 8785 JCS canonical bytes; runner: the
  author; Mode B; author-produced; implementations: npm `agent-passport-system`
  7.1.0 `canonicalizeJCS` and PyPI `agent-passport-system` 4.1.0
  `canonicalize_jcs`. Authorship relationship preventing an independent label: the
  author of this fixture also ran both runners, and the two canonicalizers are
  the reference SDKs of the same project that publishes this suite.
- Chain verdict per case / that the state, failure code and failure index each case
  declares are what the SDK's chain verifier returns for the resolver answer the
  gate supplies; runner: the author; Mode A; author-produced; implementations: npm
  `agent-passport-system` 7.1.0 `verifyAuthorityDelegationChain` and PyPI
  `agent-passport-system` 4.1.0 `verify_authority_delegation_chain`. Authorship
  relationship: same author for the vectors, the gates and the run.
- Revocation record validity / that the epoch-7 revocation verifies against the
  root delegation, before it is written to any store and again after a withdrawal
  is accepted; runner: the author; Mode A; author-produced; implementations: the
  same two SDKs, `recordAuthorityRevocation` and `verifyAuthorityRevocation`.
  Authorship relationship: same author for the vectors and the run.
- Gate behaviour / that the epoch gate, the fencing-token gate and the withdrawal
  check produce the answers, write outcomes and withdrawal outcomes each case
  declares; runner: the author; Mode B; author-produced; implementations:
  `harness.ts` and `validate.py`, both authored in this lab. Authorship
  relationship: the harness decides the claimed semantic result, so it is part of
  the recomputation implementation, not a thin harness, and the author wrote both
  of them and the vectors.
- SDK surface absence / that neither SDK exports an authority epoch, a fencing
  token, a revocation withdrawal or a store removal method; runner: the author;
  Mode B; author-produced; implementations: `sdk-support-probe.mjs` and
  `sdk_support_probe.py` reading the installed packages. Authorship relationship:
  the author wrote the probes.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Where the proposed text was too vague to test

These are findings, not complaints, and they matter as much as the vectors.

1. **Nothing says what a verifier returns after a restore.** The `Authority
   rollback` open question says so in as many words. This fixture had to choose,
   and it chose two different answers for two different verifiers: `invalid` when
   the verifier retained the revocation record, `indeterminate` when it retained
   only the epoch number. The text does not distinguish those cases at all, and
   the distinction turns out to be the whole substance of the rollback question.
2. **No rule for a verifier with no prior observation.** `AER-06`. A high-water
   mark has to start somewhere, and nothing says whether a first read is trusted or
   refused. Both are defensible and the outcomes differ.
3. **An epoch has no owner, no scope and no issuance rule.** The proposed text
   says an authority epoch is "where a system uses generations" and stops. It does
   not say who advances one, whether it is global or per delegation, per principal
   or per store, whether it is signed, or what evidence carries it. This fixture
   made it a global integer on a state view because that is the smallest thing that
   makes the case runnable, and that choice is not read from the text.
4. **Fencing is not in the proposed text at all.** The word does not appear. The
   write-fencing group is an extrapolation from the `Authority rollback` open
   question by way of the Kleppmann source, and the case for including it is that a
   partition resolving the wrong way rolls authority back with no restore involved.
   If the proposed text takes a different route, for example the append-only
   revocation log it mentions in the same sentence, this group needs rewriting
   against that instead.
5. **No vocabulary for a withdrawal, and no standing rule for one.** L3 says
   revocation is never reversed, which settles the chain verdict, and draft-03
   section 3.5 names the issuer as the party who may revoke. Nothing says who may
   withdraw a revocation, what such a record contains, or how a verifier should
   report a record set that holds both a revocation and an authorized withdrawal of
   it. This fixture requires the withdrawal's signer to be the revocation's
   revoker. That is a choice.
6. **"Later findings never rewrite earlier receipts" has no representation here.**
   The withdrawal references the revocation and leaves it intact, which is the
   shape the source implies. But a verifier that must report "revoked, and the
   revoker later said this was recorded in error" has no field to put that in,
   in either SDK or in the proposed text, so `AER-11` can only assert that the
   verdict did not change and the record is still there. What a relying party
   should be told is untested because there is nothing to test it against.

## What a pass establishes

For these two SDK revisions, on one machine, a pass establishes that:

- a chain whose root revocation is recorded in the state a verifier reads fails at
  the root's own index, in both SDKs
- state that is behind what a verifier has already observed can be made to produce
  `invalid` when the verifier retained the records, and `indeterminate` when it did
  not, without either SDK having any notion of an epoch
- an implementation that reads whatever state is presented returns `valid` on the
  same bytes, and this family names exactly which two cases catch it
- refusing an authority-state write whose fencing token went backwards is what
  keeps pre-revocation state from being republished, and an implementation without
  that check republishes it and then verifies the revoked chain as `valid`
- an accepted withdrawal of a revocation, modelled as a separate record, leaves the
  revocation held and verifying and leaves the chain invalid, while an
  implementation that treats the withdrawal as a deletion returns `valid`
- a withdrawal signed by a party without standing is refused with a named reason
  rather than ignored

## Does not claim

- **It does not establish that the epoch model here is the right one.** A global
  integer on a state view is the smallest model that makes the cases runnable. The
  proposed text does not specify one, and the alternative it names in the same
  sentence, an append-only revocation log a restore must replay, is not modelled
  here at all.
- **It is not a conformance result for either SDK.** Neither SDK has an API for
  any of the three concepts, so no SDK passed or failed anything about them. What
  the SDKs did was verify records and chains, which they do correctly here.
- **It does not test a real restore, replica, backup or lock service.** No process
  is checkpointed, no database is restored, no lock is acquired, no network call is
  made, and no clock is read. A view is a store built in memory from committed
  bytes.
- **It does not test work in flight.** Nothing here models an action that was
  authorized under epoch 6 and executes after epoch 7 is recorded. The proposed
  text lists that as a separate open question and this family does not touch it.
- **It does not test cascade completeness.** The revocation names the root only.
  Whether every descendant was reached, and what a completion record would prove,
  is a different family and a different open question.
- **It does not establish that the two runners are independent implementations of
  the SDK.** They are two harnesses over the same project's two SDKs, written by
  the same author. Their agreement is agreement between two gate implementations,
  not independent corroboration of a verdict.
- **It says nothing about any legal doctrine.** RFC 5280 is cited as evidence about
  how a deployed revocation system represents a withdrawal, nothing more. No claim
  is made or implied that agency law, or any other body of law, applies to AI
  agents.
