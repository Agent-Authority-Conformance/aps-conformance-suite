# activation-not-established: two different negative answers about an unmet activation condition

A grant is issued with an activation condition. This family asks what a verifier should
return before the condition is met, after it is met, and in the cases where the verifier
cannot tell. Its central claim is that those are not one answer but two, and that a
verifier which reports them as one throws away information it already had.

- **not yet effective.** The verifier establishes, from evidence the authority model
  accepts, that the condition had not been met at the action instant. That is a positive
  finding with a clear remedy: wait.
- **not established.** The verifier cannot tell whether the condition was met. Nothing
  usable was presented, or the only evidence comes from a source the model does not accept
  for this condition, or two acceptable records disagree. The remedy is a better source.

Neither is `invalid` and neither is `exercisable`. A revoked grant is `invalid`, which is a
third thing, and the family holds an acceptable attestation while reaching it so the
difference cannot be an artefact of missing evidence.

Six claims, in the order the vectors exercise them:

1. an acceptable record from the required source that the condition was met at or before
   the action instant makes an already valid grant **exercisable**
2. an acceptable record establishing the condition was not met by that instant, or that it
   was first met after it, leaves the action **not yet effective**
3. nothing presented, unusable evidence, evidence from a source the model does not accept,
   and two acceptable records that disagree all leave activation **not established**
4. a date condition needs no evidence at all. The verifier reads the date, so an unreached
   date is always a known negative and never an unknown one
5. the instant an attestation was written never decides a verdict. A record written after
   an action can establish a condition that obtained before it
6. a condition first met after an action does not reach back to that action, and the same
   record establishes the condition for any later one

## This is v2

v1 of this family asserted a single negative verdict, `not_established`, for every unmet
activation condition, and built its no-retroactive-activation case on `attested_at`, the
instant the attestation was written. Both were wrong, in ways worth recording because the
fixture would have certified them.

**The collapsed verdict.** A grant whose activation date is next Tuesday returns a clean,
decidable, positive answer today. Reporting that as "not established" says the verifier
could not reach a conclusion, when in fact it reached one. The two states have different
remedies and they should not share a label.

**The wrong timestamp.** Keying retroactivity on the attestation date conflates the date
of the evidence with the date of the condition. Learning on Thursday that a condition was
met on Monday is the normal case, not a defect, and a rule that rejects it would make any
model built around an after-the-fact determination unusable. What the rule is reaching for
is real and is kept: a condition first met after an action does not reach back to it. That
is a statement about the condition's own instant, not about when someone wrote it down.

v2 splits the verdict and rebuilds the retroactivity vectors on the occurrence instant.
`AX-07` and `AX-09` are the pair that pins the difference, and gate `N2-keys-on-attestation-date`
is v1's rule run as a declared-wrong implementation. Gate
`N4-collapses-not-yet-effective-into-not-established` is v1's verdict, likewise.

Both v1 vectors and their expectations are gone from `vectors.json` rather than marked
superseded in place. The v1 result stands as what was recorded at the time under the rule
then written, and nothing here rewrites it. This is a new set of records against a revised
reading, not a correction applied to the old ones.

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`, and the
runners refuse to run if any vector loses that label.

The proposed text is `AUTHORITY-LIFECYCLE.md` in `aeoess/agent-authority-lifecycle` at
commit `5c1bf09ee29d517f2f19c9bb9212543a7c44b227`, in two places.

Section **Lifecycle concepts are separate**, subsection **Authority and dependencies**,
entry **Activation condition**, quoted in full:

> **Activation condition.** When already issued authority becomes exercisable. A grant can
> be validly issued and still wait on a date or a recorded event.

That document marks the whole grouping, including this entry, **proposed**, and says no
public case tests it. Section **Invariants**, invariant **L7. Unknown revocation state is
not active**, supplies one half of the verdict distinction the family is built around:

> A revocation answer that is unavailable or stale is indeterminate. It does not become
> active, and the evidence does not claim a revocation that never happened.

L7 is about a revocation answer reaching a verifier. This family is the mirror case at
issuance: an activation answer that has not reached a verifier, and separately an
activation answer that has reached one and says not yet. The proposed document names the
first as its own gap. The second is this family's construction, and the proposed text does
not have a verdict word for it.

### This is not a draft-03 conformance case

`draft-pidlisnyi-aps-03` states no activation-condition rule, no attestor role, and no
attestation-acceptance rule. Searching the published plain text
(<https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt>, fetched 2026-09-23) for
`activation`, `attestor` and `contingen` returns nothing, and `not_before` appears only in
the time facet at lines 469 and 535-536.

Three vectors do touch draft-03, and each names that surface in its own
`draft_03_surface` member. What they touch is Section 3.3 chain verification, quoted at
lines 578-592 of the published plain text:

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

`AX-17` uses "revocation state for every member". `AX-18` uses "An unavailable or stale
revocation result is indeterminate". `AX-19` sits against "current validity", which that
paragraph lists without saying which of the four results a not-yet-reached `not_before`
produces. Even in those three cases the chain result is draft-03 and the mapping onto this
family's verdict names is not.

### The verdict names are not suite vocabulary

`exercisable`, `not_yet_effective`, `not_established` and `invalid`, and the `activation_*`
and `condition_*` codes, are this family's own local labels. `CONTRIBUTING.md` reserves
failure-class names, record fields and verifier semantics to the maintainer as schema
owner, and says a pull request is not the vehicle for minting them. This branch is a
candidate for discussion, so the names are a proposal to be decided or replaced, not a
taxonomy anyone should bind to. That applies with extra force to `not_yet_effective`, which
v2 adds.

## What the SDKs supply, and what this fixture supplies

Neither reference SDK has an API for an activation condition. `sdk-support.ts` and
`sdk_support.py` print, per vector, what each SDK decided and what it declined, and their
output is the evidence for this table.

| concept | npm `agent-passport-system` 7.1.0 | PyPI `agent-passport-system` 4.1.0 |
|---|---|---|
| grant chain state at an instant | supported, `verifyAuthorityDelegationChain` | supported, `verify_authority_delegation_chain` |
| RFC 8785 canonical bytes of an attestation body | supported, `canonicalizeJCS` | supported, `canonicalize_jcs` |
| Ed25519 signature over those bytes | supported, `verify` | supported, `verify` |
| activation condition attached to a grant, by date or by recorded event | `not_supported`: no field in the closed seven-facet `AuthorityVectorV1`, no other API | `not_supported`: same |
| attestor-role registry or role lookup | `not_supported`: no role-resolution API on the authority-delegation surface | `not_supported`: same |
| attestation acceptance against an activation condition | `not_supported`: no such function | `not_supported`: same |
| a `not_yet_effective` verdict | `not_supported`: `AuthorityValidationState` has no value for a condition established as not yet met | `not_supported`: same |
| a `not_established` verdict distinct from `invalid` | `not_supported`: `AuthorityValidationState` is `valid`, `invalid`, `indeterminate`, `unsupported` | `not_supported`: same |

So the gate in `harness.ts` calls the real SDK for the grant's chain state and for each
attestation's signature over canonical bytes, and **implements the activation conditions,
the role registry, the condition binding, the occurrence comparison and the verdict names
itself**. A pass is a result about this gate. It is not a conformance result about either
SDK, and neither SDK fails anything here by not having an API the protocol does not define.

### Two SDK findings this family's own testing surfaced

Recorded as findings, not as vectors. Neither changes anything the family tests.

**`canonicalizeJCSForWrite` is documented for signing but not exported from the npm
package root.** `node_modules/agent-passport-system/dist/src/core/canonical-jcs.d.ts`
declares it and says "Use this at signing and new-write boundaries only."
`dist/src/index.d.ts` line 21 re-exports only `canonicalizeJCS`, `detectCanonicalVariant`
and `getTestVectors` from that module, and at runtime
`import { canonicalizeJCSForWrite } from 'agent-passport-system'` resolves to
`undefined`. This is the same class of gap `fixtures/approval-single-use/` recorded for
`verifyAuthorityDelegation` in 7.0.0. `mint.ts` signs with `canonicalizeJCS` instead,
which the same file documents as byte-identical for every value the write variant
accepts, and which is also the only variant the PyPI SDK exposes, so using it keeps the
two runners on one preimage.

**The npm package's `exports` map does not expose `./package.json`.**
`require('agent-passport-system/package.json')` throws
`ERR_PACKAGE_PATH_NOT_EXPORTED`, so `sdk-support.ts` reads the installed file by path to
report the version.

## Records

`chain.json` is minted by `mint.ts`, deterministically, from published seed labels:

    seed = SHA-256("aps-conformance-suite:acx:" + label)

which is the convention `docs/fixture-format.md` records for this suite. No secret
material is in the file: every private key regenerates from a label printed in
`chain.json` under `seed_labels`. `mint.ts` runs 32 mint-time assertions and refuses to
write `chain.json` if any fails.

Four identities: `acx-principal`, `acx-agent`, `acx-monitor-a` (registry role
`outage-monitor`), `acx-auditor-b` (registry role `billing-auditor`).

Three one-hop `AuthorityDelegationV1` chains, all `principal -> agent`:

- **`GRANT`**, time facet open over every action instant in `vectors.json`. Carries the
  recorded-event activation condition.
- **`GRANT_DATED`**, same window, carrying a date activation condition whose
  `activation_date` falls between `T_ACTION` and `T_LATER_ACTION`. Mint asserts the chain
  is valid at both instants, so the verdict difference between them comes from the
  condition and not from the chain.
- **`GRANT_FUTURE_WINDOW`**, no activation condition, whose time facet `not_before` is the
  same instant as `GRANT_DATED`'s `activation_date`. `AX-19` presents it.

Two activation conditions:

```json
{
  "condition_id": "acx-cond-outage-1",
  "condition_type": "recorded_event",
  "event_type": "service_outage_declared",
  "event_id": "acx-outage-2026-09-20",
  "required_attestor_role": "outage-monitor"
}
```

```json
{
  "condition_id": "acx-cond-date-1",
  "condition_type": "date",
  "activation_date": "2026-09-20T11:30:00.000Z"
}
```

Ten attestations, `record_type` `fixture:activation-attestation:v0`. **That is not an APS
record type and no SDK claims it.** Each is canonicalized under RFC 8785 by the SDK's own
canonicalizer over a body carrying no `attestation_id` and no `signature` member, its
`attestation_id` is SHA-256 over those bytes, and its `signature` is Ed25519 over the
same bytes.

Each attestation carries an `assertion` member. `condition_occurred` names the instant the
event occurred, in `occurred_at`. `condition_not_occurred_through` names the instant
through which the attestor states the event had not occurred, in `not_occurred_through`.
`attested_at`, when the record itself was written, is separate from both and the reference
gate never compares it with the action instant.

| attestation | signer | registry role | `attestor_role` claim | assertion | condition instant | `attested_at` |
|---|---|---|---|---|---|---|
| `ATT_MONITOR_OCCURRED_ON_TIME` | monitor-a | outage-monitor | outage-monitor | occurred | `T_EVENT`, before the action | before the action |
| `ATT_MONITOR_OCCURRED_ATTESTED_LATE` | monitor-a | outage-monitor | outage-monitor | occurred | `T_EVENT`, before the action | **after the action** |
| `ATT_MONITOR_OCCURRED_AFTER_ACTION` | monitor-a | outage-monitor | outage-monitor | occurred | **`T_LATE_EVENT`, after the action** | after the action |
| `ATT_AUDITOR_HONEST_ROLE` | auditor-b | billing-auditor | billing-auditor | occurred | before the action | before the action |
| `ATT_AUDITOR_CLAIMS_MONITOR_ROLE` | auditor-b | billing-auditor | **outage-monitor** | occurred | before the action | before the action |
| `ATT_MONITOR_WRONG_EVENT` | monitor-a | outage-monitor | outage-monitor | occurred, **another event id** | before the action | before the action |
| `ATT_MONITOR_FORGED_SIGNATURE` | **auditor-b's key, body names monitor-a** | outage-monitor | outage-monitor | occurred | before the action | before the action |
| `ATT_MONITOR_NOT_OCCURRED_THROUGH_ACTION` | monitor-a | outage-monitor | outage-monitor | **not occurred** through `T_ACTION` | covers the action | after the action |
| `ATT_MONITOR_NOT_OCCURRED_STALE` | monitor-a | outage-monitor | outage-monitor | **not occurred** through `T_STALE_THROUGH` | **stops before the action** | before the action |
| `ATT_AUDITOR_NOT_OCCURRED_THROUGH_ACTION` | auditor-b | billing-auditor | billing-auditor | **not occurred** through `T_ACTION` | covers the action | after the action |

The attestor-role registry in `chain.json` is what the reference gate treats as
authoritative about a role. An attestation's `attestor_role` member is the attestor's
claim about itself, which is what `AX-04` turns on.

One clock, in `chain.json` under `clock`. Every action instant and every attestation
timestamp is one of its entries, and every vector names its instant by label.

## The gate

`harness.ts`, in two stages.

**Stage one, the SDK.** `verifyAuthorityDelegationChain` at the vector's action instant,
with the vector's revocation answer. `invalid` stays `invalid`. `indeterminate` and
`unsupported` become `not_established`, on the reading that a verifier which could not
establish current authority has not made a claim against the grant and is not waiting on
anything either. The activation question is never reached when stage one does not return
`valid`.

**Stage two, this fixture.** A date condition is answered without evidence: the gate
compares the action instant with `activation_date` and returns `exercisable` or
`not_yet_effective` with code `condition_date_not_reached`.

For a recorded-event condition, each presented attestation is checked in this order, and
the first failing check is its reason:

1. signature verifies under the key its `verification_method` points at, over the SDK's
   RFC 8785 bytes, else `attestation_signature_unverified`
2. `verification_method` belongs to the `attestor` the body names, else
   `attestation_attestor_binding_mismatch`
3. the registry's role for that attestor agrees with the body's own `attestor_role`, else
   `attestation_role_claim_conflict`
4. the registry's role is the role the condition requires, else
   `attestation_attestor_role_mismatch`
5. `condition_id`, `event_type` and `event_id` match the condition, else
   `attestation_condition_mismatch`
6. the assertion is one of the two the family defines, else
   `attestation_unknown_assertion`
7. a `condition_not_occurred_through` record reaches the action instant, else
   `attestation_does_not_reach_action`

A record that fails any of these is not evidence in either direction. This matters most at
checks 3 and 4: a source the model does not accept for this condition cannot establish the
condition, and it equally cannot establish that the condition was unmet. `AX-11` is that
case and it lands on `not_established`, not on `not_yet_effective`.

Each accepted record then yields one finding, measured on the condition's own instants:

- `occurred_by_action`, from a `condition_occurred` record whose `occurred_at` is at or
  before the action instant
- `occurred_after_action`, from a `condition_occurred` record whose `occurred_at` is after
  it
- `not_occurred_through_action`, from a `condition_not_occurred_through` record that
  reaches it

The verdict follows, in this order:

| findings present | verdict | code |
|---|---|---|
| `occurred_by_action` **and** `not_occurred_through_action` | `not_established` | `condition_evidence_conflict` |
| `occurred_by_action` | `exercisable` | `activation_established` |
| `not_occurred_through_action` | `not_yet_effective` | `condition_established_not_yet_occurred` |
| `occurred_after_action` | `not_yet_effective` | `condition_first_occurred_after_action` |
| none | `not_established` | the furthest rejection reason, or `no_attestation_presented` |

With no accepted finding, the reported code is the reason of the attestation that got
**furthest** through the checks, ties broken by `attestation_id` ascending, so the code
names the closest thing to usable evidence presented and does not depend on presentation
order.

Contradiction sits above acceptance on purpose. Two acceptable records that disagree leave
the verifier unable to tell which holds, and neither is discarded in favour of the other.
That is different from `AX-14`, where two unaccepted records sit alongside an acceptable
one and change nothing, because they were never evidence.

## Vectors

Nineteen cases in `vectors.json`. Each names its grant, its action instant by clock label,
its revocation answer, and the attestations presented.

| id | polarity | presents | expected |
|---|---|---|---|
| `AX-01-occurrence-before-action-exercisable` | positive | `ATT_MONITOR_OCCURRED_ON_TIME` | `exercisable` / activation / `activation_established` |
| `AX-02-no-attestation-not-established` | negative | nothing | `not_established` / activation / `no_attestation_presented` |
| `AX-03-honest-wrong-role-not-established` | negative | `ATT_AUDITOR_HONEST_ROLE` | `not_established` / activation / `attestation_attestor_role_mismatch` |
| `AX-04-self-declared-role-not-established` | negative, **control** | `ATT_AUDITOR_CLAIMS_MONITOR_ROLE` | `not_established` / activation / `attestation_role_claim_conflict` |
| `AX-05-wrong-event-not-established` | negative | `ATT_MONITOR_WRONG_EVENT` | `not_established` / activation / `attestation_condition_mismatch` |
| `AX-06-unverifiable-signature-not-established` | negative | `ATT_MONITOR_FORGED_SIGNATURE` | `not_established` / activation / `attestation_signature_unverified` |
| `AX-07-occurrence-after-action-not-yet-effective` | negative | `ATT_MONITOR_OCCURRED_AFTER_ACTION` at `T_ACTION` | `not_yet_effective` / activation / `condition_first_occurred_after_action` |
| `AX-08-same-attestation-later-action-exercisable` | positive | `ATT_MONITOR_OCCURRED_AFTER_ACTION` at `T_LATER_ACTION` | `exercisable` / activation / `activation_established` |
| `AX-09-attested-after-action-about-earlier-occurrence-exercisable` | positive | `ATT_MONITOR_OCCURRED_ATTESTED_LATE` | `exercisable` / activation / `activation_established` |
| `AX-10-accepted-negative-attestation-not-yet-effective` | negative | `ATT_MONITOR_NOT_OCCURRED_THROUGH_ACTION` | `not_yet_effective` / activation / `condition_established_not_yet_occurred` |
| `AX-11-negative-from-unaccepted-source-not-established` | negative | `ATT_AUDITOR_NOT_OCCURRED_THROUGH_ACTION` | `not_established` / activation / `attestation_attestor_role_mismatch` |
| `AX-12-negative-stopping-short-of-action-not-established` | negative | `ATT_MONITOR_NOT_OCCURRED_STALE` | `not_established` / activation / `attestation_does_not_reach_action` |
| `AX-13-conflicting-accepted-evidence-not-established` | negative | `ATT_MONITOR_OCCURRED_ON_TIME` and `ATT_MONITOR_NOT_OCCURRED_THROUGH_ACTION` | `not_established` / activation / `condition_evidence_conflict` |
| `AX-14-right-role-alongside-wrong-role-exercisable` | positive | both auditor records and `ATT_MONITOR_OCCURRED_ON_TIME` | `exercisable` / activation / `activation_established` |
| `AX-15-date-condition-not-reached-not-yet-effective` | negative | nothing, `GRANT_DATED` at `T_ACTION` | `not_yet_effective` / activation / `condition_date_not_reached` |
| `AX-16-date-condition-reached-exercisable` | positive | nothing, `GRANT_DATED` at `T_LATER_ACTION` | `exercisable` / activation / `activation_established` |
| `AX-17-revoked-grant-is-invalid` | negative | `ATT_MONITOR_OCCURRED_ON_TIME`, resolver `revoked` | `invalid` / chain / `REVOKED` at index 0 |
| `AX-18-unknown-revocation-is-not-established` | negative | `ATT_MONITOR_OCCURRED_ON_TIME`, resolver `unknown` | `not_established` / chain / `REVOCATION_UNKNOWN` at index 0 |
| `AX-19-grant-time-facet-not-yet-reached-is-invalid-in-both-sdks` | negative | `GRANT_FUTURE_WINDOW` | `invalid` / chain / `NOT_YET_VALID` at index 0 |

Nothing in this family is stateful across vectors: there is no ledger, no consumption and
no ordering between cases. `AX-07` and `AX-08` are two independent evaluations over the
same records at two action instants, not a sequence, and `AX-08` does not revise `AX-07`.

### The four pairs that carry the family

**`AX-02` against `AX-10`.** Nothing presented, against an acceptable record from the
required role saying the event had not occurred through the action instant. v1 gave these
the same answer. They are not the same answer: one verifier is ignorant and one has a
finding.

**`AX-07` against `AX-09`.** One record reports an occurrence after the action and is
written after it. The other reports an occurrence before the action and is also written
after it. The reference gate separates them on the occurrence instant, which is the only
instant that bears on whether the condition held when the action was taken. A gate that
keys on the attestation date gives both the same answer, and that gate is `N2`.

**`AX-11` against `AX-10`.** The same negative statement, covering the same instant, from
a source the model accepts and from one it does not. A source that cannot establish the
condition also cannot establish that the condition was unmet, so the unaccepted one falls
back to `not_established`. Without this pair, "not yet effective" could be read as
anything that looks like a denial.

**`AX-15` against `AX-19`.** One instant, two mechanisms carrying the wait, two deciders,
two answers. `GRANT_DATED`'s `activation_date` and `GRANT_FUTURE_WINDOW`'s `not_before` are
the same instant, asserted equal at mint time, and both are evaluated at `T_ACTION`. The
SDK chain verifier answers `invalid` with `NOT_YET_VALID` for the time facet. This
family's gate answers `not_yet_effective` for the activation condition. That gap is a
finding about the proposed text, recorded below, not a claim that either answer is right.

### The negative control

`AX-04` is the vector a naive implementation passes wrongly. `ATT_AUDITOR_CLAIMS_MONITOR_ROLE`
is a genuine, correctly signed record from a real attestor, naming the condition's own
event, timestamped before the action, whose `attestor_role` member reads
`outage-monitor`. Every check an implementation can run against the record alone succeeds.
Only an attestor-role registry outside the record catches it. An implementation that reads
the role off the attestation body admits the action.

`N1-trusts-self-declared-role` is that implementation, run against all nineteen cases, and
it fails exactly `AX-04`.

## Negative control gates

Five gate configurations, all run against all nineteen cases, each with a declared failing
set checked in both directions: a declared failure that quietly starts passing fails the
run just as loudly as an undeclared failure.

| gate | flaw | declared failing set |
|---|---|---|
| `reference-gate` | none | empty |
| `N1-trusts-self-declared-role` | reads the role from the attestation body, not the registry | `AX-04` |
| `N2-keys-on-attestation-date` | treats the instant an attestation was written as the instant the condition occurred, which is v1's rule | `AX-07`, `AX-09` |
| `N3-collapses-not-established-into-invalid` | reports `invalid` wherever the reference gate reports `not_established` at the activation stage | `AX-02`, `AX-03`, `AX-04`, `AX-05`, `AX-06`, `AX-11`, `AX-12`, `AX-13` |
| `N4-collapses-not-yet-effective-into-not-established` | reports `not_established` wherever the reference gate reports `not_yet_effective`, which is v1's verdict | `AX-07`, `AX-10`, `AX-15` |

`N3` exists because the distinction between false and not established is half the point of
the family. `N4` exists because the distinction between not established and not yet
effective is the other half, and it is the one v1 got wrong. An implementation that answers
`not_established` for a condition it has established as unmet is wrong in exactly three of
these nineteen cases, and `N4` pins which three.

`N2` and `N4` overlap on `AX-07` and diverge everywhere else, which is itself the point:
the wrong timestamp and the collapsed verdict are two separate defects that happened to
appear in one sentence of the candidate text.

## Running

Both runners are hermetic: they read `chain.json` and `vectors.json` from this directory
and make no network call.

TypeScript, against the pinned npm SDK, wired into `npm test`:

    npm ci --include=dev
    npm run verify:activation-not-established

Expected final line:

    PASSED: reference-gate matched every case, N1, N2, N3 and N4 each failed exactly their declared set

Python, against the PyPI SDK, a manual run and not part of `npm test`, following the
convention `fixtures/sponsor-handover/validate.py` and
`fixtures/runtime-authority-denial-continuity/verify.py` already set for a Python side
kept out of the Node-only hermetic gate:

    python3 -m venv /tmp/aac-venv-activation
    /tmp/aac-venv-activation/bin/pip install agent-passport-system
    /tmp/aac-venv-activation/bin/python fixtures/activation-not-established/validate.py

Expected final line:

    PASSED: reference-gate matched every case, N1, N2, N3 and N4 each failed exactly their declared set (python)

The per-SDK support records:

    npx tsx fixtures/activation-not-established/sdk-support.ts
    /tmp/aac-venv-activation/bin/python fixtures/activation-not-established/sdk_support.py

Regenerating the records gives the same bytes:

    npx tsx fixtures/activation-not-established/mint.ts

`CHECKSUMS.sha256` pins every file in this directory except itself, and
`tests/digest-integrity.test.mjs` recomputes it inside `npm test`.

## Results

Both runners were executed locally, on one machine, on 2026-09-23. `reference-gate`
matched all 19/19 cases under both runners. `N1`, `N2`, `N3` and `N4` each failed exactly
their declared set under both runners and matched every other case under both. The
per-vector SDK records from `sdk-support.ts` and `sdk_support.py` agree on all nineteen
vectors, for both the chain state and the attestation signature results, after normalizing
API names and boolean spelling.

## Verification split

One entry per distinct verification claim, in the form `layer / claim; runner; Mode;
authorship; implementation`, per `CONTRIBUTING.md`. This family is lab-authored rather
than ingested from an external system, so no entry here could be `independent`, and each
one states the authorship relationship that prevents it.

- **Record minting / `chain.json` regenerates byte for byte from its published seed
  labels; Tymofii Pidlisnyi; Mode A; author-produced; npm `agent-passport-system` 7.1.0
  via `mint.ts`.** Authorship relationship: the runner authored `mint.ts`, the seed labels
  and the records it checks.
- **Grant chain state / each vector's chain result at its action instant; Tymofii
  Pidlisnyi; Mode A; author-produced; npm `agent-passport-system` 7.1.0 via `verify.ts`
  and `sdk-support.ts`.** Authorship relationship: the runner authored the vectors and the
  harness whose expectations the SDK result is compared against, though not the SDK.
- **Grant chain state / the same claim recomputed by the other reference SDK; Tymofii
  Pidlisnyi; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0 via
  `validate.py` and `sdk_support.py`.** Authorship relationship: same runner and same
  vector author as the Mode A entry above.
- **Attestation signature / each presented attestation's Ed25519 signature over its RFC
  8785 canonical bytes; Tymofii Pidlisnyi; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.** Authorship relationship: the runner minted the
  attestations being checked.
- **Attestation signature / the same claim recomputed by the other reference SDK;
  Tymofii Pidlisnyi; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.**
  Authorship relationship: same runner, and the records were minted by the npm SDK under
  the same author.
- **Activation verdict / each vector's `exercisable`, `not_yet_effective`,
  `not_established` or `invalid` result and its code; Tymofii Pidlisnyi; Mode A;
  author-produced; this family's own `harness.ts`, with `validate.py` as a second
  implementation of the same rules.** Authorship relationship: the claimed semantic result
  is constructed by `harness.ts` and `validate.py`, both of which the runner wrote, so both
  are part of the recomputation implementation and not a thin harness. Neither reference
  SDK supplies this claim at all.
- **Negative-control isolation / `N1`, `N2`, `N3` and `N4` each diverge on exactly their
  declared set; Tymofii Pidlisnyi; Mode A; author-produced; `harness.ts` and
  `validate.py`.** Authorship relationship: the runner authored the gates, their declared
  sets and the cases.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Where the proposed text was too vague to test

This is a finding of the family, not a defect in it.

**A date and a recorded event are grouped in one sentence and answered by different
deciders.** The Activation condition entry says a grant "can be validly issued and still
wait on a date or a recorded event," as if the two waits were the same kind of wait.
`AX-15` and `AX-19` put that to a test at one instant. A date carried by the grant's own
time facet is answered by shipped code, and both reference SDKs return `invalid` with
`NOT_YET_VALID`. A date carried by an activation condition has no answer in shipped code
at all, and this family answers `not_yet_effective`. A recorded event has no answer in
shipped code either. So one sentence covers a case the SDKs call invalid and two cases
they cannot express, and the text does not say whether a waiting grant should be invalid,
not yet effective, or something else. `AX-19` pins what the SDKs do. It does not assert
that answer is right.

**The text has no word for the known negative.** The proposed entry says when authority
becomes exercisable and says nothing about what a verifier returns before that. The corpus
vocabulary has `not yet effective` for exactly this state, and the candidate text this
family is built against did not use it. v2 uses it, and `N4` is the control that makes the
difference observable, but until the proposed document adopts a word for the state, the
verdict name here is this family's own.

**"When already issued authority becomes exercisable" does not say who decides.** The
entry names no attestor, no role, no registry and no acceptance rule. That an activation
condition names a role, that some registry outside the attestation is authoritative about
who holds it, and that a self-declared role is not enough, are all this family's
construction. The related case `LC-A-003` in the same repository says the mirror problem
"needs a defined verifier role, not just any evidence," which identifies the gap without
closing it. Until the text names where role authority comes from, `AX-04` tests a rule the
document does not state.

**Nothing says which instant the condition is measured from.** v2 measures it from the
condition's own instants and never from `attested_at`, and the README says why. The
proposed text distinguishes a transition from its observation elsewhere, under `Status
observation` and `Notice`, but the Activation condition entry itself says nothing about
which instant an activation is measured from. The answer here is a reading, and it is the
reading `N2` exists to contrast with the other one.

**Nothing says what to do with contradiction.** `AX-13` presents two acceptable records
that disagree and this family answers `not_established`. The proposed text has no rule for
a conflict between two records from sources it accepts, no precedence rule and no quorum.
A model that preferred the later record, or the negative one, or required agreement, would
all be defensible and would all give a different answer here.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that for this family's
own gate:

- a grant carrying an activation condition, with no usable evidence presented, is neither
  exercisable nor invalid, and the verdict names ignorance rather than a finding
- an acceptable record that the condition was not met at the action instant, or was first
  met after it, gives a different verdict from an absence of evidence, under distinct codes
- a date condition that has not been reached is a known negative, decided without evidence
- an attestation from an attestor whose registered role is not the required role does not
  establish activation, does not establish that activation was unmet, and does not
  invalidate the grant
- a correctly signed attestation that claims the required role, from an attestor the
  registry places elsewhere, does not establish activation, and an implementation reading
  the role off the record admits it
- an acceptable record that the condition was met at or before the action instant makes an
  already valid grant exercisable, whether it was written before or after that instant
- a condition first met after an action does not make that action exercisable, and the
  same record does make a later action exercisable
- two acceptable records that disagree about the action instant leave the verdict at not
  established, and neither defeats the other
- a revoked grant is invalid and an unresolvable revocation answer is not established,
  under distinct codes, with an acceptable attestation present in both cases
- both reference SDKs return `invalid` / `NOT_YET_VALID` for a grant time facet whose
  `not_before` has not been reached, at the same instant where this family's gate returns
  not yet effective for an activation condition

## Does not claim

A pass does **not** establish:

- that any of this is specified. draft-03 states no activation-condition rule, and the
  proposed text marks its own entry `proposed`
- that `not_yet_effective` is the right name, or that four verdicts are the right number.
  Both are this family's proposal
- anything about a deployed gateway, MCP server or agent runtime. No protocol is spoken
  and no network call is made
- that either reference SDK conforms to or violates anything here. Both lack an API for
  the concept, which is `not_supported`, not a failure
- that `fixture:activation-attestation:v0` is, or should be, an APS record type. It is a
  fixture-local shape with no standing
- that an attestor-role registry is the right mechanism for role authority, or that a
  registry lookup is where a real deployment would get one. The registry is this family's
  modeling choice and `AX-04` depends on it entirely
- that one acceptable attestation is the right threshold. No vector exercises a quorum, an
  `n`-of-`m` rule, or a precedence rule for the conflict `AX-13` presents
- that an activation condition, once met, stays met. No vector models a deactivation, an
  attestation being withdrawn, or an event being re-declared
- anything about a condition whose trigger is the absence of an event rather than its
  occurrence. `condition_not_occurred_through` is evidence about a condition, not a
  condition that fires on absence, and no vector models the second
- anything about the grant's own suspension, expiry or exhaustion. `GRANT` and
  `GRANT_DATED` have time facets open over every action instant in the family, and `AX-19`
  is the only vector that turns on a time facet at all
- anything about work in flight across an activation boundary. Every vector is one
  evaluation at one instant
- that the verdict names or codes here will survive review as suite vocabulary. See
  "The verdict names are not suite vocabulary"
- that agreement between the two runners is independent corroboration. Both were written
  in this lab by the same author, and the Verification split says so per layer
- anything about legal doctrine. Human agency law has related distinctions, the proposed
  document says it does not assume they apply to AI agents, and neither does this fixture
