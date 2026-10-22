# lease-revocation-axes

Candidate, lab-authored timelines for three distinct questions: whether the original
evidence is within its lease, what authority state a verifier can establish, and
whether a specified action policy permits dispatch. This is a reference model and
an attributed SDK primitive run. It is not a protocol conformance verdict.

## Source and authority

The source is the public-agentprotocol W3C mailing-list discussion of 21 October
2026. Larry Lewis proposed evidence at T=0, revocation at T=10 seconds, calls at
T=30, T=60 and T=119, temporary revocation-service unavailability, and separate
freshness, authority-validity and action-authorization results. ShaoBao Li (Lee)
described a 120-second cached lease and live standing reads, and explicitly did
not claim action-time authorization. Tymofii Pidlisnyi offered to host cases and
run APS first. These are discussion proposals, not an approved W3C specification.
The source identities and dates are recorded in vectors.json. No participant has
reviewed or endorsed these vectors. No result for ATP or RTTP/IQA is supplied.

Only the named times and cached/live verification expectations come from that
discussion. The boundary rules, atomic clock, P1 policy, controls, observation
format and expected matrix are this lab's candidate profile choices. This does
not define the standing-state mapping of another implementation.

## Fixed candidate profiles

The clock is synthetic milliseconds. Evidence e1 and e2 are issued at zero and
expire at 120000. They refer to different delegations for the same subject and
permit only `read`. There is no renewal event. Neither using nor retrieving an
item changes its issuance or expiry. A later authority status observation is
not replacement evidence and cannot renew the original lease.

Every timeline is run under both modes and both declared endpoint rules:

- `cached_lease` uses the original observation for the original lease. It performs
  no authority read. Its assessed authority property is acceptance of an observation
  bounded by that fixed lease, anchored at original evidence issuance.
- `live_standing_read` reads the source at each call while the original evidence is
  unexpired. The model source answers atomically as of the synthetic call time.
  An unreachable source supplies no observation. This is a declared zero-latency
  model, not a network freshness guarantee.
- `exclusive` expires at T >= 120000. `inclusive` expires at T > 120000.
  The discussion does not select either endpoint. Matching a declared endpoint
  tests internal consistency and is not agreement by a participant on that rule.

Once original evidence expires, this reference model rejects locally and performs
no read in either mode. The cases do not require every real implementation to
avoid such reads. A real implementation may inspect status after rejection, but
that cannot extend this evidence's lease.

## Observable answers and oracle truth

The tested verifier receives only the call, original evidence and a source-read
interface. It receives neither expected answers nor the ledger truth. The runner
owns the ledger, grades the answers and adds truth-comparison labels separately.
The constructor declaration fixes mode, endpoint, claimed axes and policy before
any timeline runs.

Every call record carries original evidence identity and expiry, the observation's
status, `as_of_ms` and `retrieved_at_ms`, observation age, verifier answer, current
validity, verification acceptance and separately observed downstream reach. The
runner adds `truth` and `observation_differs_from_truth` from the ledger.

`authority_answer` describes the observation under the declared mode. A cached
`valid` answer at T=119 after revocation at T=10 matches the bounded-observation
contract, but `current_validity` is `not_established`, the ledger truth is
`revoked`, and the disagreement is visible. That match is not evidence that
current authority remains unrevoked. A live revoked observation can be freshly
obtained while authority is revoked. Freshness concerns the original evidence
lease, not a new issuance caused by a network read.

The report calls the bounded scope `bounded_observation` with a numeric
`max_observation_age_ms` and an explicit anchor. It does not introduce a
`bounded:<ms>` string syntax or reinterpret a participant's claims automatically.
Any future participant mapping needs to state what its own claim means.

## P1 action policy

`P1-current-observation` requires unexpired original evidence, an active authority
observation as of this exact synthetic call time, and an operation in the grant.
Unavailable or older observations do not establish current authority, so P1 denies.
The caller's action decision and the downstream double's recorded dispatch are
checked separately. A late `deny` cannot hide a dispatch.

P1 deliberately has no nonzero observation-age tolerance. A cached observation
at T=0 cannot establish current authority at T=30, even if the oracle knows the
grant was never revoked. It therefore does not authorize that later call under
P1. A cached call at T=0 does exercise a positive authorization control. A live
active call has a current observation and permits `read`. Fresh active evidence
still denies `write` in LRA-09. The implementation never borrows the oracle's
hidden state to answer these questions.

P1 is one candidate policy, not a universal rule for systems claiming action
authorization. A deployment that authorizes use of an unexpired lease despite
unseen revocation uses a different policy. Such a mapping is `not_supported`
with a policy-mismatch reason, rather than a failed P1 implementation. A mechanism
that does not claim action authorization reports `not_claimed`; no action verdict
or enforcement coverage is credited to it. Lee's verification refusal is never
reported as his system denying an action.

## Frozen timelines

| Case | Discriminating concern |
|---|---|
| LRA-01 | No-revocation positive control, including a T=0 action permit |
| LRA-02 | Shared timeline, retained first observation and later revocation |
| LRA-03 | Source unreachable before revocation |
| LRA-04 | Original evidence expired, first source reachable then unreachable |
| LRA-05 | 119999, 120000 and 120001 under each declared endpoint |
| LRA-06 | Revoking one delegation leaves a second for the same subject active |
| LRA-07 | Unreachable source without revocation, including expired evidence |
| LRA-08 | Two workers receive identical evidence before and after revocation |
| LRA-09 | Valid authority is not permission for a different operation |
| LRA-10 | Repeated use does not slide the original expiry |
| LRA-11 | Temporary outage recovers, for both revoked and active grants |

There are 41 calls per profile, 44 model case runs and 164 calls across four
profiles. Each baseline scores three axes for 492 axis comparisons. These are
model comparisons, not independent cases or independent implementations. Endpoint
choices are model profiles, not additional source requirements.

Each worker must meet its declared contract with its own observation history.
Identical evidence under the model's identical observations produces identical
answers here. Real workers holding differently dated observations are not required
to answer identically solely because they are workers in one system.

`generate.py` is the deterministic authoring procedure for vectors.json. Its
expected-value construction is separate from harness.ts. It is run only when
authoring the corpus, never before grading. The frozen JSON holds per-call,
per-mode and per-endpoint expectations. A hand-reviewed table is still an oracle
choice, not an independent implementation. Changing it requires reviewing the
semantics, not making the current implementation pass.

## Negative controls and integrity

Eight defective model variants are run deliberately. Their exact failed-case
sets are authored in vectors.json and checked in both directions. They cover
ignoring expiry, resetting expiry on use, fail-open reads, sticky outage state,
renewing evidence on retrieval, denial followed by dispatch, blanket denial and
performing a live read only on first use. Metadata such as source observation
time is compared, so stale live answers also fail in no-revocation controls.
The expiry-reset variants have overlapping failure sets but different causes.

Four additional tests mutate disposable corpus copies: claiming cached knowledge
as current validity, hiding dispatch behind denial, dropping a call and extending
original expiry. Each must fail with the corresponding diagnostic. Original
expected bytes must remain unchanged. Tests also exercise zero claimed axes,
statement-only scoring, unsupported policy and hostile oracle-property getters.
No scored coverage is reported as `no scored coverage`, never as a successful run.

## SDK support and provenance

The SDK bridge does not import the model. It gets revocation inputs from timeline
events, never from expected verdicts. It calls the package's freshness functions
with explicit dates and verifies a fixed signed chain using supplied
active/revoked/unknown resolver answers. The signed-chain fixture is reused from
conflicting-status-sources and its path is explicit in the bridge.

These are primitive checks. The bridge does not implement a complete cached lease
or live standing-read transport, establish observation provenance, synchronize
workers, or invoke a protected resource. It cannot claim P1 action enforcement.
Those full-mode mappings are reported `not_supported` with reasons. This means
no mapping was established by this bridge, not that no other SDK API could support
one. A successful primitive invocation must not be presented as a complete mode
run. The inclusive endpoint is also unmapped for the selected exclusive freshness
API. Other lease lengths and subsecond expiry times were not assessed.

See SDK-RUNS.md for pins, exact commands, exits and the scope of the retained
package runs. Network is unnecessary after dependency installation.

## Verification split

| Layer / claim | Runner | Mode | Relationship | Implementation |
|---|---|---|---|---|
| Timeline model, scoring and negative controls | aeoess, Codex under Tima's direction | Mode A | author-produced | this family's harness.ts and verify.ts |
| SDK expiry and chain primitives | aeoess, Codex under Tima's direction | Mode A | author-produced | pinned npm SDK plus sdk-bridge.mjs |

The runner authored the vectors and the bridge. The model is also runner-authored.
None of these records is independent. No external implementation record exists.
These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Run

From the repository root:

    npm ci --include=dev
    npm run verify:lease-revocation-axes
    npm run test:lease-revocation-axes
    npm run verify:lease-revocation-axes:sdk

These checks also run in npm test. The model has a dedicated strict TypeScript
check because the root configuration does not include every standalone family.
For a machine-readable model record:

    node --import tsx fixtures/lease-revocation-axes/verify.ts --json

For an independently installed, pinned npm package, set APS_SDK_ROOT to its
agent-passport-system package directory and run sdk-bridge.mjs. The package
version, entry digest, vector digest and unsupported claims are emitted with
each JSON record. No credentials or live services are used.

## Limits and follow-up

No real protocol, network revocation service, clock skew, credential signature
model, push invalidation, renewal, ongoing-action cancellation, payment, receipt
binding or deployment risk taxonomy is exercised by the reference model. Known
deterministic vectors can be hardcoded, so passing them is agreement with these
cases, not security certification. The model's downstream double observes only
the path it instruments. A future real adapter must observe its real execution
boundary and justify its claim mappings separately.

The proposal's exact endpoint remains open. Candidate profile choices and reports
remain inspectable. Required next steps before public claims are review of the
implemented oracle and any participant-specific mapping. Opening a PR and posting
to W3C require their own authorization.
