# arap-binding

Candidate cases against the AuthZEN Access Request Approval Profile (ARAP), a
profile of the AuthZEN Access Request Extension, proposed in a pull request
that has not merged.

Every case here is a candidate against that text. None of them is a
conformance claim, about any AuthZEN implementation or about the Agent
Passport System, and if the proposal changes or is closed the cases go with
it.

## Source

| field | value |
|---|---|
| repository | `openid/authzen` |
| pull request | #658 (open, author mcguinness) |
| head SHA read | `2e9412c943d77c3a1ec82de59f8903b45c5bec14` |
| file | `profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md` |
| status | **proposed, not merged** |

The file was fetched at the head SHA above and its digest recorded:

    curl -sSL https://raw.githubusercontent.com/openid/authzen/2e9412c943d77c3a1ec82de59f8903b45c5bec14/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md | shasum -a 256

Anchors are cited by name and by line number at that head. The text is
paraphrased throughout this family rather than quoted at length. A case that
stops matching the source after an edit to the pull request is a stale case,
not a finding.

Bulk submission, the callback completion mode, actor delegation, and the
catalog companion profile are out of scope for this family.

## What this tests

Three small reference components, each a minimal model of one rule set in the
profile, so the proposed checks have something executable to run against.
None of them is an AuthZEN implementation, a PDP, an Access Request Service,
or a PEP.

1. **An Access Request Service (ARS) denial-binding verifier**, implementing
   the five steps of `{{verifying-denial-binding}}` (1205-1220) for both the
   inline and hashed binding forms defined in `{{denial-request-binding}}`
   (1177-1184) and `{{denial-binding-hash}}` (1186-1203).
2. **A PDP approval verifier at re-evaluation**, implementing
   `{{approval-verification}}` (936-954), `{{approval-current-status}}`
   (960-962), and `{{approval-scope}}` (964-972) against a trusted-state
   ledger and a JWS `approval.state` per `{{approval-state}}` (1230-1246).
3. **A PEP next-action resolver**, a pure function over the fallback table in
   `{{pep-reevaluation-handling}}` (824-843).

Both binding artifacts are carried as compact-serialization JWS signed with a
deterministic Ed25519 key, following `{{interoperability-baseline}}`
(1112-1116). The suite has no JWS library dependency (checked: no `jose` in
`package.json`, no `jose` in `node_modules`, no existing compact-JWS code
elsewhere in the tree), so `harness.ts` hand-rolls a minimal Ed25519 JWS and a
minimal RFC 8785 JSON Canonicalization Scheme (JCS) serializer, small because
the inputs are small. Every key is an Ed25519 seed derived from a published
label by SHA-256, so the file carries no secret material. Nothing in the
harness reads wall time or draws randomness. "Now" is always a value the
caller passes in.

## Part D: denial binding (ARS)

Twelve cases against `{{structural-comparison}}` (712-733),
`{{denial-request-binding}}` (1177-1184), `{{denial-binding-hash}}`
(1186-1203), and `{{verifying-denial-binding}}` (1205-1220). D1 is the
positive control: submission and binding artifact match exactly. Each reject
case changes exactly one thing from D1, stated in the table.

| case | form | change from D1 | expected outcome |
|---|---|---|---|
| D1 | hashed | none (control) | `accepted` |
| D2 | hashed | `resource.id` changed | `invalid_denial_binding` |
| D3 | hashed | `action.name` changed | `invalid_denial_binding` |
| D4 | hashed | only `subject.properties.act` changed | `accepted` |
| D5 | hashed | a bound context member (`region`) changed | `invalid_denial_binding` |
| D6 | hashed | an unbound context member (`time`) changed | `accepted` |
| D7 | hashed | a bound member is `null` in one, absent in the other | `invalid_denial_binding` |
| D8 | hashed | now is past `exp`, before the echoed `denial.expires_at` | `expired_denial` |
| D9 | hashed | no `denial_expires_at` claim, `exp` later than the echoed value | `invalid_denial_binding` |
| D10 | hashed | `aud` omitted from the claims | `invalid_audience` (see note) |
| D11a | inline | same change as D2 | `invalid_denial_binding` |
| D11b | inline | same change as D4 | `accepted` |

D4 and D11b exercise the `subject.properties.act` exclusion at line 724: two
core implementations that disagree on whether the PEP normalized the actor to
`client.actor` must still compare identically. D7 exercises the
absent-is-distinct-from-null rule at line 720. D8 and D9 exercise the
freshness rules at lines 1215-1220, including the case where the binding
material cannot prove a freshness window at all and the submission is
rejected rather than trusted.

D10's outcome note: the profile's Error Responses section defines a problem
type for a step-4 binding mismatch (`invalid_denial_binding`) and a step-5
freshness failure (`expired_denial`), but assigns none specifically to a
step-2 `aud` failure. The harness keeps a distinct internal outcome,
`invalid_audience`, so the case is traceable. This is not a claim that the
profile defines an `invalid_audience` wire error, only that its Error
Responses section (667-706) does not name one for this step.

### D12: finding, binding_context_members absent

`{{denial-request-binding}}` line 1179 says the claim "binds only Subject,
Resource, and Action" when `binding_context_members` is absent, which reads
naturally as no `context` key in the hash object at all. The object literal
shown at lines 1190-1197 always includes a literal `"context"` key. The
family computes both readings of the hash, with `binding_context_members`
absent, over the same subject, resource, and action:

- reading A: the `context` key omitted from the hashed object
- reading B: the `context` key present with an empty object

`verify.ts` asserts the two digests differ, which they do, and prints both.
The vector is marked `indeterminate` and excluded from both tallies below.
Neither reading is picked as correct. A PDP and an independently implemented
Access Request Service that each picked a different reading here would
compute different `binding_hash` values for the same evaluation and would
never agree on a submission's binding, which is exactly the interoperability
`{{denial-binding-hash}}` line 1201 says this construction exists to provide.

## Part A: approval verification (PDP)

Ten cases against `{{approval-verification}}` (936-954),
`{{approval-current-status}}` (960-962), `{{approval-scope}}` (964-972), and
`{{approval-reuse}}` (851-859).

| case | change | expected outcome | next_action |
|---|---|---|---|
| A1 | exact-match evaluation, before `approved_until`, status active | `approval_applies` | (none) |
| A2 | known `approval.id`, evaluation names a different resource | `out_of_scope` | `request` |
| A3 | approval revoked before `approved_until` | `approval_expired` | `request` |
| A4 | now is past `approved_until` | `approval_expired` | `request` |
| A5 | `approval.id` and the id inside `approval.state` differ | `approval_unverifiable` | `none` |
| A6 | `approval.state` `aud` names a different PDP | `approval_unverifiable` | `none` |
| A7 | mandatory policy now denies (subject disabled) | `policy_denied` | `none` |
| A8 | the same exact-match evaluation, run twice | `approval_applies` (both times) | (none) |
| A9 | only `context.time` differs from the bound value | `approval_applies` | (none) |
| A10 | finding, see below | `out_of_scope` | `request` |

A5 and A6 exercise the identifier-consistency and audience checks at line
942 and in `{{approval-state}}` (1230-1246): an `approval.state` cannot be
replayed to a PDP other than the one its `aud` names, even when that PDP
trusts the same signer's key. A7 exercises the mandatory-policy gate that
`{{decision-and-binding-integrity}}` (735-743) and the `policy_denied`
reason (618) both require to remain effective even when the approval itself
is otherwise valid, in scope, and unexpired.

A8 states plainly, against this profile's own text and not against any other
protocol, that ARAP permits reuse of an approval within its scope
(`{{approval-reuse}}`, 851-859): the same exact-match evaluation, verified
twice, applies both times. It is not a single-use token.

### A10: finding, the round-trip gap in openid/authzen#663

A1's approval and its originating denial carry an authorization-relevant
context member, `region`. The profile's own non-normative worked example at
`{{lookup-reevaluation-example}}` (623-666) sends only `context.approval` and
`context.time` at re-evaluation, nothing else. A PEP that follows that
example when the original evaluation had any authorization-relevant context
loses that context on the round trip, and this profile's own exact-match
scope rule (964-972) then denies it `out_of_scope`, because the bound
`region` no longer matches the evaluation's (absent) `region`.

This is issue #663, opened by the same author against the same pull request.
It reports that a PEP following the examples is denied `out_of_scope`
whenever the original evaluation carried authorization-relevant context, and
calls this a case where two conformant implementations fail on their first
re-evaluation. A10 reproduces exactly that shape: bind on `region`,
re-evaluate with only `time` and `approval`, and
confirm the reference PDP verifier denies it `out_of_scope`. This is a
finding about the text, specifically about its own worked example
contradicting its own normative rule, not a defect in any implementation.

## Part P: PEP next-action fallback

Five cases against the fallback table in `{{pep-reevaluation-handling}}`
(824-843), no negative control declared, a pure function with no state, no
clock, and no I/O.

| case | inputs | expected |
|---|---|---|
| P1 | recognized `next_action` ("retry"), `reason` with a different default ("policy_denied" defaults to "none") | `retry` |
| P2 | no `next_action`, recognized `reason` ("grant_pending") | `retry` |
| P3 | neither recognized, `access_request` present | `request` |
| P4 | neither recognized, `access_request` absent | `none` |
| P5 | `next_action: "request"`, `access_request` absent | `none` |

P1 shows a recognized `next_action` overriding even a reason code whose
registered default disagrees (line 828, table row 841). P5 shows the gate at
line 829: a recognized `next_action` of `request` still falls back to `none`
without `context.access_request`, the one case where a recognized
`next_action` does not simply win outright.

## Which ARAP issue each vector bears on

Every vector in `vectors.json` carries an `arap_issue` field. It names the open
issue against the same pull request that the vector bears on, or is null when no
filed issue covers it. The vectors are grouped by issue so that results are read
issue by issue, not as one pass count for the profile.

| issue | vectors |
|---|---|
| openid/authzen#660, the denial-binding form and the expiry claims | D8, D9, D11a, D11b |
| openid/authzen#659, signed approval state | A5, A6 |
| openid/authzen#663, the re-evaluation round trip | A10 |
| none filed | D1 to D7, D10, D12, A1 to A4, A7 to A9, P1 to P5 |

D12 records an ambiguity in the hash construction that no filed issue covers yet.
A pass on the other vectors says the reference harness agrees with the proposed
text as written at the pinned head. It says nothing about which reading the
editor intends where an issue is open.

## Negative controls

Failing sets are declared here and checked in both directions by
`verify.ts`. An undeclared failure appearing, and a declared failure quietly
starting to pass, are both loud.

**`byte-compare-ars`** compares submission bytes directly (`JSON.stringify`
equality, or a hash recomputed over the raw submission) instead of applying
`{{structural-comparison}}`. It never removes `subject.properties.act`
before comparing or hashing. Declared to fail exactly:

    D4  D11b

Every other Part D case gives `byte-compare-ars` the same verdict as the
reference verifier, including D7, where whole-value JSON comparison happens
to still catch the absent-versus-null mismatch, and D9 and D10, where the
freshness and audience checks run before either implementation's comparison
logic is reached.

**`trusting-pdp`** applies any `approval.id` it recognizes in its ledger,
with no scope check, no current-status check, and no `aud` check on
`approval.state`. It still enforces the mandatory policy gate, a separate
check this defect does not claim to bypass. Declared to fail exactly:

    A2  A3  A4  A5  A6  A10

A1, A7, A8, and A9 pass under `trusting-pdp` for two different reasons: A1,
A8, and A9 are in-scope, active, unexpired approvals that a correct verifier
also applies, so an unconditional "apply it" defect happens to agree, and A7
still gets `policy_denied` because that check is implemented deliberately.
None of the four discriminate the defect from a correct implementation, and
none is claimed to.

## Provenance

The vectors and the harness were both authored in this lab. Neither came
from the author of pull request #658, and nothing here was reviewed or
endorsed by them. The cases are one reading of proposed text by a party that
did not write it.

The harness is a reference model, not a tested AuthZEN implementation. It
implements a synthetic ARS denial-binding verifier, a synthetic PDP approval
verifier, and a synthetic PEP resolver, so the proposed checks can be
executed against something. The runs record its behavior and no one else's.

The vectors are hand-authored, fully deterministic, and generated by no
external process. The clock is synthetic: nothing reads wall time, touches
the network, or uses randomness, so replaying the runner is the
reproduction.

## Running

From the repository root:

    npm ci --include=dev
    npm run verify:arap-binding

It also runs as a step of `npm test`.

Expected final line:

    PASSED: correct matched every non-indeterminate vector, each control failed exactly its declared set

## Does not claim

A run of this family does not establish:

- anything about any AuthZEN implementation, about interoperability between
  two real implementations, or about the Agent Passport System.
- that pull request #658 will merge in this form, or at all.
- anything about bulk submission, the callback completion mode, actor
  delegation, or the catalog companion profile. All four are out of scope.
- that D12 or A10's outcome is a defect in anyone's software. Both are
  findings about the proposed text: D12 about an ambiguity in the hash
  construction, A10 about a worked example that contradicts the profile's
  own normative scope rule, reported upstream as issue #663 by the profile's
  own author.
- that the declared failing sets for `byte-compare-ars` or `trusting-pdp` are
  exhaustive descriptions of those defects in general. They are the sets
  these twenty-two accept and reject vectors happen to discriminate.
- that any particular key format, seed derivation, or JWS library choice
  reflects a deployment recommendation. The hand-rolled JWS and JCS code in
  `harness.ts` exists because the vectors are small and the suite has no JWS
  dependency to reuse, not because either is the right choice for a real
  PDP or Access Request Service.
