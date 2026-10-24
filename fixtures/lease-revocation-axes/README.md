# lease-revocation-axes

Revision 2 candidate, lab-authored timelines for original-evidence lease,
scoped authority validity and an explicitly selected action policy. A separate
composite result reports verification acceptance. This is a reference model and
an attributed SDK primitive run, not a protocol conformance verdict.

## Source and authority

The source is the public-agentprotocol W3C discussion of 21 October 2026.
Larry Lewis proposed evidence at T=0, revocation at T=10 seconds, calls at
T=30/60/119, temporary revocation-service unavailability and three separate axes.
ShaoBao Li (Lee) described cached lease and live standing-read expectations and
did not claim action-time authorization. Tymofii Pidlisnyi offered to host cases
and run APS first. These are proposals, not an approved W3C specification. No
ATP or RTTP/IQA run or participant endorsement of these vectors is supplied.

Boundary rules, atomic timing, P1, extra controls, expected values and the grant
binding prerequisite are lab choices. The source does not define these as a
shared contract. Real adapters require separately declared timing, observation,
authority and action-policy mappings. Model choices cannot establish another
participant's behavior.

## Profiles and inputs

Original evidence e1 and e2 refers to distinct grants for the same subject. Both
are issued at zero, expire at 120000 synthetic milliseconds and permit read.
No use, retrieval or new status observation changes that original expiry.
There is no renewal event.

- cached_lease uses the original active observation while evidence is unexpired.
  Its verification path makes no source reads. A later diagnostic after rejection
  is permitted, but cannot renew evidence or repair a grant mismatch.
- live_standing_read attempts one instrumented source read for every unexpired,
  correctly bound call. An unavailable source returns no observation, but the
  attempt is still recorded. The synthetic source answers atomically at call
  time. This is not a network freshness guarantee.
- exclusive expires at T >= 120000. inclusive expires at T > 120000. Both are
  declared alternatives because the discussion does not select one.

The runner supplies each worker with its own Verifier instance and private
history maps. Workers share the authoritative source and an independently
instrumented downstream double. No expected block or ledger truth enters the
verifier. Hostile getters check that input boundary. The runner retains call,
worker, grant, time and returned observation for each source read, and checks
read count, grant, time and observation against the declared mode.

Known deterministic cases can be hardcoded. The fabricated-live-read control
returns matching canned semantic answers but still fails the source-read audit.
This establishes that this runner detects the selected bypass, not resistance
to every malicious adapter or proof of source authenticity.

## Three axes, prerequisites and composite outcome

Evidence freshness measures the original evidence lease only. It does not
measure every general meaning of evidence freshness.

Authority validity records the observation, scoped answer and current validity.
A cached valid answer at T=119 after revocation matches its bounded-observation
contract, while current validity is not_established. The runner separately
records ledger truth and the disagreement. Bounded acceptance is not current
unrevoked authority. The bounded scope has an explicit issuance anchor and
numeric maximum age, rather than a bounded:<ms> mini-language.

After expiry, rejection remains mandatory, but a diagnostic status read is
permitted. Its observation must be backed by the instrumented source. An actual
revoked diagnostic can establish current revocation while evidence remains
expired, verification remains rejected and dispatch remains denied. The default
reference path makes no diagnostic read. Twenty additional positive profile runs
exercise permissible diagnostics, including outages and both expiry endpoints.

Evidence-to-grant binding is a separately checked prerequisite. Verification
acceptance is a separately graded composite of binding, lease and observed
validity. It is not counted inside the authority axis. Dependencies between
these properties are explicit and are not independent demonstrations.

The selected P1-current-observation policy additionally requires an observation
at the exact call instant and an in-scope operation. The action answer and the
downstream double are checked separately. A deny returned after dispatch fails.

P1 has zero observation-age tolerance. All cached calls after T=0 deny even with
no revocation. Cached positive action controls exist only at T=0. Consequently,
this policy provides limited cached-mode action discrimination and cannot rank
cached and live designs as competing security products. A bounded-lease action
policy would be a separate future profile, not a reinterpretation of P1 or Lee's
unclaimed action axis.

## Coverage declarations

Mode, endpoint, claimed axes and policy are declared before replay. The runner
freezes supported, not_supported and not_claimed mappings before constructing
any verifier. An unsupported policy makes the entire action axis unmapped.
A supported axis cannot avoid scoring by returning not_supported on a hard call.
Unsupported or unclaimed action mappings receive no dispatch coverage.

Each run has an explicit status. matched means its scored checks matched,
partial_coverage means at least one claimed axis is unmapped, no_scored_coverage
means no axes were scored, and failed records a failed check. An empty failure
list alone does not make a zero-coverage run successful.

## Frozen timelines and controls

| Case | Concern |
|---|---|
| LRA-01 | No-revocation positive control and T=0 permit |
| LRA-02 | Revocation versus retained original observation |
| LRA-03 | Source outage with revocation |
| LRA-04 | Expiry with reachable and unreachable revoked source |
| LRA-05 | Just before, at and after each expiry endpoint |
| LRA-06 | Independent grant for the same subject |
| LRA-07 | Source outage without revocation |
| LRA-08 | Two distinct verifier instances with worker-local histories |
| LRA-09 | Valid read authority does not authorize write |
| LRA-10 | Repeated use does not slide expiry |
| LRA-11 | Outage recovery with active and revoked grants |
| LRA-12 | Presenting g1 evidence for a g2 request, then a valid g2 control |

Revision 2 has 44 calls per profile, 48 baseline case runs and 176 calls over
four mode/endpoint profiles. It scores 528 axis comparisons and separately
176 composite verification comparisons. These are author-produced comparisons,
not independent cases or implementations.

Twelve defective variants have exact declared failure sets. Four new variants
retain stale state only on w2, fabricate live answers without reading, selectively
return not_supported, and ignore evidence-to-grant binding. The w2 variant must
fail only w2 calls, with w1 unaffected. The other variants cover ignored or sliding
expiry, fail-open status, sticky outage, retrieval as renewal, deny after dispatch,
blanket denial and first-read-only behavior. Each mutant uses one declared profile.
Overlapping failure sets and twelve killed mutants are not a completeness claim.

The rule each variant applies, as `harness.ts` implements it. Each worker has its own verifier, so remembered state belongs to one worker. The lease length is `expires_at_ms - issued_at_ms`. "Fresh, matched" means the evidence passed the freshness check and names the call's grant.

- `lease-ignores-expiry`: in either mode, evidence counts as fresh at every call, whatever its expiry.
- `sliding-lease`: in either mode, the first call with an evidence id uses its original expiry. Every later call with that id on the same worker uses the previous call's time plus the lease length, whatever the previous call's result.
- `live-fail-open`: in live mode, for fresh, matched evidence, a source read that gets no answer becomes an `active` observation dated at the call time.
- `sticky-unavailable`: in live mode, once a source read on a worker gets no answer, that worker stops reading the source and gives no observation for every later fresh, matched call, for every grant.
- `retrieval-renews-evidence`: in live mode, for matched evidence, the verifier reads the source before judging freshness, even when the original evidence has expired. If the read answers, freshness becomes `at_ms < retrieved_at_ms + lease length`, whatever the declared boundary. If it gets no answer, the original freshness result stands and there is no observation.
- `deny-but-dispatch`: in either mode, a deny decision still sends the call to the downstream executor.
- `deny-everything`: in either mode, every permit becomes deny.
- `live-first-read-only`: in live mode, for fresh, matched evidence, each worker keeps its first source result for each grant, including no answer, and reuses it with its original timestamps instead of reading again.
- `second-worker-stale`: the same reuse as `live-first-read-only`, on worker w2 only.
- `fabricated-live-read`: in live mode, for fresh, matched evidence, the verifier never reads the source. Rules hardcoded from the call id, grant and time give either no observation or an `active` or `revoked` one.
- `selective-not-supported`: in either mode, every deny becomes `not_supported`.
- `ignore-evidence-binding`: in either mode, evidence counts as matching the call's grant even when it names another grant. The freshness, observation and action checks still apply.

A reused observation keeps its old `as_of_ms`, so it can still give `authority_answer: valid` while `current_validity` is `not_established`.

Six further tests mutate disposable corpus copies and require the intended
failure diagnostic. The original corpus bytes remain unchanged. Positive checks
also cover optional diagnostics, unclaimed axes, unsupported policies, zero
coverage, hostile getters and twelve hand-reasoned checkpoints in ORACLE.md.

The generator and model are separate author-produced implementations of the
same candidate contract. Agreement does not independently validate that contract.
The literal oracle-checkpoints.json is not generated from their formulas. Its
reasoned table surfaces selected semantic choices for review, not independent
semantic validation.

## SDK primitives and provenance

The bridge uses timeline events to supply revocation answers. Its expiry
assertions compare SDK output with frozen expected freshness values. It invokes
the installed package's freshness API and fixed signed-chain verifier. The chain
is reused from conflicting-status-sources/chain.json. It does not map each fixture
grant to an independently signed chain or test evidence-to-grant binding.

Supplied active/revoked/unknown resolver states test the chain verifier. They do
not establish SDK status retrieval, complete cached/live modes, observation
provenance, worker synchronization, P1 dispatch, or inclusive endpoint support.
These six mappings remain not_supported by this bridge. That is not a claim that
all SDK APIs lack those capabilities. No missing full-mode capability is simulated
into a passing result. Primitive results cannot be reported as APS passing the
family or enforcing an action at its real boundary.

The original revision 1 vectors and three records remain unchanged under their
original SHA256SUMS.txt. Current vectors and records are in revision-2, with a
separate manifest. CLARIFICATIONS.md distinguishes the original limitations and
SDK-RUNS.md retains the historical account and appends the current run details.
Digest gates enforce comparison with the pinned manifest. Record immutability is
repository policy, not protection against rewriting both artifact and digest.

## Verification split

| Layer / claim | Runner | Mode | Relationship | Implementation |
|---|---|---|---|---|
| Revision 2 model, source audit and controls | aeoess, Codex under Tima's direction | Mode A | author-produced | harness.ts and verify.ts |
| SDK expiry and supplied-answer chain primitives | aeoess, Codex under Tima's direction | Mode A | author-produced | pinned npm SDK and sdk-bridge.mjs |

The runner authored vectors and bridge. The model and checkpoint table are also
runner-authored. These records are attributed per layer. Merge of this family
is not an end-to-end verification or a family-level verdict.

## Run

From the repository root:

    npm ci --include=dev
    npm run verify:lease-revocation-axes
    npm run test:lease-revocation-axes
    npm run verify:lease-revocation-axes:sdk

These checks run in npm test. The model has its own strict TypeScript check.
For full per-call records, run node --import tsx
fixtures/lease-revocation-axes/verify.ts --json. Set APS_SDK_ROOT to an isolated,
pinned agent-passport-system package directory for an additional primitive run.
Use sdk-bridge.mjs --vectors fixtures/lease-revocation-axes/vectors.json to
reproduce the historical primitive observations against the unchanged v1 corpus.
No credentials or live authority services are used.

## Limits and follow-up

There is no real protocol, network delay, clock skew, signed lease, source
authenticity, renewal, ongoing-action cancellation, payment, receipt binding or
real execution-boundary verification here. The downstream double observes only
its instrumented path. Real adapters need justified mappings and independent
observations at their actual enforcement boundaries. Distinct in-process worker
instances do not establish distributed cache synchronization.

The hand-reasoned oracle remains open to independent semantic challenge. The
repaired candidate needs review before public clearance. Opening a PR and posting
to W3C require Tima's separate authorization.
