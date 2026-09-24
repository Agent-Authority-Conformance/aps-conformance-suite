# lifecycle-time-and-scheduling

Sixty-one candidate vectors for fourteen time and scheduling lifecycle cases: what an
authorization boundary can establish about an agent's authority when a handover is
half-done, a rotation is on a schedule, a workflow is mid-replay, a scheduled series
outlives its owner, a workload is winding down, a queued action fires later than anyone
planned, and two honest clocks disagree.

Every vector here is **candidate against proposed text**. None of them is a conformance
claim about draft-pidlisnyi-aps-03, about the Agent Passport System SDKs, or about
anything else. If the proposed text changes or is dropped, these vectors go with it.

## What this tests

| field | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| model document | `AUTHORITY-LIFECYCLE.md`, version 0.1.2-draft, commit `7796e22` or later |
| case document | `CASES.md`, commit `2bf5c7e`, section **Time and scheduling** |
| cases | LC-C-008, LC-C-014, LC-C-015, LC-C-017, LC-C-025, LC-E-008, LC-E-014, LC-E-018, LC-E-019, LC-E-020, LC-E-034, LC-G-007, LC-G-008, LC-G-009 |
| status of that text | **proposed**. No public specification states any of the fourteen rules |
| label on every vector | `candidate_against_proposed` |

The concepts and invariants each vector is written against are listed in
`vectors.json` under `proposed_text.concepts_and_invariants`, and every vector carries its
CASES.md case id in its own id (for example `LC-E-034-b-suspension-still-active-at-fire`).

## Verdict vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended`, `restricted`.

Three wording rules are load-bearing here and are enforced by the vectors rather than
stated in prose:

- A **missing** record gives `not_established`, never `invalid`. Twenty-two vectors turn
  on that distinction.
- A bound that has **not been reached yet** gives `not_yet_effective`, never `invalid`.
- A later record never rewrites an earlier one.

Nothing in this family says that a legal doctrine applies to AI agents. The cases in
CASES.md take their situations from statutes, regulators, standards and product
documentation. The translation into agent terms is ours, and the source is a source of
cases, not a claim about what any law requires of software.

## Layout

```
mint.ts                 builds chain.json, byte for byte, from published seed labels
chain.json              13 grants, 59 signed lifecycle records, 14 action references
harness.ts              the reference boundary and its five declared defective controls
vectors.json            61 vectors, their expected outcomes and the declared fail sets
verify.ts               the TypeScript run, wired into `npm test`
verify_python_sdk.py    the Python run, manual, not in the Node-only CI gate
CHECKSUMS.sha256        digests of every file above
```

## Determinism

Every Ed25519 key is derived from a published seed label,
`aps-conformance-suite:lifecycle-time-and-scheduling:<label>`, hashed with SHA-256. No
secret material is in the tree and anyone can regenerate every byte. Timestamps, nonces
and payloads are pinned constants. No wall clock is read anywhere: every instant compared
in `harness.ts` comes from `vectors.json` or from a signed clock attestation in
`chain.json`. Canonical bytes are RFC 8785 JCS, produced by the SDK's own
`canonicalizeJCS`.

```
npx tsx fixtures/lifecycle-time-and-scheduling/mint.ts
git diff --exit-code fixtures/lifecycle-time-and-scheduling/chain.json
```

must produce no diff. Each vector is presented to a **freshly constructed** boundary, so
no vector's result depends on where it sits in the list.

## What the SDK decides and what this fixture decides

This is the point of the family. On every vector where a lifecycle bound decides the
answer, the SDK's own chain verification still returns `valid`.

| step | decided by | how |
|---|---|---|
| chain shape, signatures, the time facet, revocation state | the SDK | `verifyAuthorityDelegationChain` / `verify_authority_delegation_chain` |
| scope membership | the TypeScript SDK | `isPurposePermitted`. The Python SDK has no equivalent, so the Python runner applies the documented rule and records `not_supported` |
| each signed lifecycle record's issuer signature | the SDK | `verify` over `canonicalizeJCS` / `canonicalize_jcs` |
| all fourteen lifecycle rules | **this fixture** | `harness.ts`, and `verify_python_sdk.py` on the Python side |

`vectors.json` carries the SDK chain answer beside every lifecycle verdict, not inside
it. Each vector has an `expected` block holding `verdict`, `reason` and `detail`, and a
sibling `sdk_cross_check` block holding `chain_state` and `failure_code`. Both are
checked on every vector by both runners and a vector passes only when both match. The two
blocks are never merged, which is why they sit apart: the lifecycle verdict is decided by
this fixture's rules and the chain answer is the SDK's, and on three vectors they
disagree on purpose. Keeping them apart also means a verifier with a different authority
model can be driven by these inputs and compared on the `expected` block alone.

Three places where they disagree on purpose:

- `LC-G-007-c`: lifecycle verdict `not_yet_effective`, SDK `chain_state: invalid` with
  `failure_code: NOT_YET_VALID`.
- `LC-E-019-b`: lifecycle verdict `invalid` (the wind-down grace elapsed), SDK `valid`
  (the grant itself is untouched).
- `LC-E-034-b`: lifecycle verdict `suspended`, SDK `valid`. The resolver has no answer for
  suspension at all.

## The five negative controls

Each is a boundary that is wrong in one named way, with a declared set of vectors it must
diverge on. `verify.ts` fails if a control diverges anywhere else, and fails if a declared
divergence does not reproduce.

| control | its defect | declared fail set |
|---|---|---|
| `defective-boundary-queue-time-only` | checks authority state when work is queued and never again | 3 vectors |
| `defective-boundary-current-version-only` | always evaluates against whatever version is deployed now | 5 vectors |
| `defective-boundary-instant-transfer` | models every transfer as one timestamped event | 9 vectors |
| `defective-boundary-issuer-clock` | reads the time the issuer's own action reference claims | 3 vectors |
| `defective-boundary-single-clock-trusted` | trusts one external source and reads any mismatch as a fault | 6 vectors |

**The negative control a naive implementation passes wrongly** is
`LC-E-034-a-suspension-lifted-before-fire`. The suspension was lifted before the queued
action fired, so admitting it is the correct answer, and
`defective-boundary-queue-time-only` returns exactly the same verdict, the same reason and
the same SDK state as the reference boundary. It reached that answer having checked
nothing at fire time, and its record claims `live_state_clear_at_fire_time`, which it did
not establish. Change nothing about the boundary and only change the timeline
(`LC-E-034-b`) and it admits an action that should have been paused.

`LC-C-008-d`, `LC-C-014-e`, `LC-C-025-e`, `LC-E-034-a` and `LC-G-009-b` are the other
vectors written specifically so that a checker looking only at the admit bit, or only at a
signature, reaches the wrong conclusion.

## Sources

Each case in CASES.md rests on an external source. The quotes below are the ones fetched
while building this fixture and they are what the vector design actually leans on. The
rest of each case's reasoning is in CASES.md, not here.

- **LC-C-008.** [US GAO, GAO-02-272R](https://www.gao.gov/products/gao-02-272r): "the
  first assistant to the office of such officer shall perform the functions and duties of
  the office temporarily in an acting capacity subject to the time limitations". The
  fixture takes from this only the shape of a *declared default with its own eligibility
  gate*, not any claim about what the statute requires.
- **LC-C-014.** [SKYbrary](https://skybrary.aero/articles/hand-overtake-over-operational-positions):
  "The taking-over controller ... should accept responsibility only after he/she is
  completely satisfied that he/she has a total awareness of the situation."
- **LC-C-015.** [CFI Notebook](https://www.cfinotebook.net/notebook/remotely-piloted-aircraft/lost-link):
  "The lost link algorithm provides a safe manner of operation and retrieval of the
  aircraft when operator control is lost".
- **LC-C-017.** [14 CFR 117.25, via Cornell LII](https://www.law.cornell.edu/cfr/text/14/117.25):
  "No certificate holder may assign and no flightcrew member may accept assignment to any
  reserve or duty with the certificate holder during any required rest period."
- **LC-C-025.** The NRC document CASES.md cites (ADAMS ML072831246) returned HTTP 403 when
  fetched for this fixture, so **no claim about it is restated here**. The vectors are
  written against the proposed text alone: a governing record that requires the departure
  and the designation to be one operation, and what a verifier returns inside a gap when
  it is not.
- **LC-E-008.** [Temporal docs](https://docs.temporal.io/workflows): "It has to make the
  same decisions when given the same history." And: "It shouldn't depend on any values
  *not* recorded in the history which would be different between runs."
- **LC-E-014.** [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1098768/recurring-meeting-after-the-owner-mailbox-deleted),
  an answer by a Microsoft support engineer, not normative product documentation: "For
  recurring meetings, it is not automatically deleted and will left as an orphaned
  meeting." [sic]
- **LC-E-018.** [Kubernetes CronJob docs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/),
  under schedule suspension: "This setting does *not* affect Jobs that the CronJob has
  already started." The quote fetched covers the `.spec.suspend` field specifically. The
  broader template-versus-instance point is the case's inference, and this fixture's
  vectors test the inference, not the quote.
- **LC-E-019.** [Kubernetes pod lifecycle docs](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/):
  "Once the grace period has expired, the KILL signal is sent to any remaining processes,
  and the Pod is then deleted from the API Server." That a pod's assigned identity stays
  valid throughout that window is the case's inference, not a line on that page.
- **LC-E-020.** [pg_cron README](https://github.com/citusdata/pg_cron): "For security, jobs
  are executed in the database in which the `cron.schedule` function is called with the
  same permissions as the current user." The project's documentation does not say what
  happens once that role is gone or downgraded, which is the case.
- **LC-E-034.** No external source. CASES.md labels it hypothetical and reasons from
  AUTHORITY-LIFECYCLE.md's own L8.
- **LC-G-007.** [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) section 6.1.3:
  "the certificate validity period includes the current time". Section 6 defines path
  validation as something the validating party performs, which is the whole of the case.
- **LC-G-008.** [Wikipedia, GPS week number rollover](https://en.wikipedia.org/wiki/GPS_week_number_rollover):
  "The GPS week number rollover is a phenomenon that happens every 1,024 weeks, or about
  19.6 years." The fixture's wrapped reading is computed from that period rather than
  written by hand, and `chain.json` records both the period and the result.
- **LC-G-009.** [Google, Leap Smear](https://developers.google.com/time/smear): "At the
  beginning of the leap second, smeared time is just under 0.5 s behind UTC." The
  five-hundred-millisecond bound in the fixture's smear policy comes from that figure.

## Verification split

One entry per distinct verification claim. Labels are `Mode A` / `Mode B` and
`author-produced` / `independent`, and nothing else stands in for them.

- reference boundary behaviour over all 61 vectors / the lifecycle verdicts; `npm run
  verify:lifecycle-time-and-scheduling`; Mode A; author-produced; `harness.ts` in this
  repository. Author-produced because the same author wrote the vectors, the expected
  outcomes and the boundary whose behaviour is being checked.
- chain state, the time facet and revocation state on every vector; `npm run
  verify:lifecycle-time-and-scheduling`; Mode A; author-produced; `agent-passport-system`
   7.1.0 (npm). Author-produced because the vectors and the SDK share an author, even
  though the harness only transports inputs into the SDK and compares its output.
- scope membership on every vector; `npm run verify:lifecycle-time-and-scheduling`; Mode
  A; author-produced; `agent-passport-system` 7.1.0 `isPurposePermitted`. Same authorship
  relationship as the entry above.
- chain state, the time facet and revocation state recomputed in a second language;
  `python fixtures/lifecycle-time-and-scheduling/verify_python_sdk.py`; Mode B;
  author-produced; `agent-passport-system` 4.1.0 (PyPI). Author-produced because the
  Python SDK shares an author with the vectors.
- the lifecycle verdicts recomputed against a separately written port; `python
  fixtures/lifecycle-time-and-scheduling/verify_python_sdk.py`; Mode B; author-produced;
  the rule port in `verify_python_sdk.py`. Author-produced because the port and
  `harness.ts` were written by the same author in the same session, so agreement between
  them is weaker evidence than agreement between independently written implementations.
- determinism of `chain.json`; `npx tsx fixtures/lifecycle-time-and-scheduling/mint.ts &&
  git diff --exit-code`; Mode A; author-produced; `mint.ts` in this repository. Same
  authorship relationship.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## What a pass establishes

That this fixture's reference boundary, run over records the pinned SDKs verify, returns
the recorded lifecycle verdict on each of the sixty-one timelines, that five named
defective boundaries diverge on exactly the vectors declared for them and nowhere else,
and that a second implementation in a second language reaches the same answers.

## Does not claim

- That any of the fourteen rules is correct, required, or the only reasonable answer.
- That draft-pidlisnyi-aps-03 or any published specification states any of them. It does
  not, and the SDK support table printed by every run says which steps came from an SDK.
- That either SDK is non-conformant. Every step this family supplies itself is a step the
  SDKs do not claim to implement.
- Anything about what a law, regulation or standard requires of AI agents.

## Where the proposed text was too vague to test

Eleven places where a vector had to be built on an invention rather than on the text.

1. **No wire shape for any of the fourteen bounds.** draft-03 section 3.2's authority
   vector is a closed set of seven facets (scope, spend, depth, time, reputation, values,
   reversibility). It has no facet for a handover acknowledgment, a rotation schedule, a
   pre-authorized fallback scope, a pinned policy version, an occurrence template, a
   wind-down bound, a queue entry or a clock attestation. Every one of them is minted here
   as a separate principal-signed record in a fixture-local profile. Where that state
   should live is undecided.
2. **`not_yet_effective` exists in the settled vocabulary and in neither SDK.** Both
   pinned SDKs answer `invalid` with `NOT_YET_VALID` for a grant before its `not_before`.
   The distinction the vocabulary draws has no representation on the wire, so the fixture
   has to carry it alongside the SDK's answer rather than inside it.
3. **`restricted` is named and never defined.** Nothing says what narrows, by how much, or
   who may declare the narrowing. LC-C-015's `fallback_scope` is this fixture's guess at
   what a restricted state carries.
4. **`suspended` is not a resolver answer.** The revocation resolver recognizes `active`
   and `revoked`, and anything else is `REVOCATION_UNKNOWN` (the
   `revocation-resolution-forward-compat` family already pins that). Suspension therefore
   cannot live in the chain at all, so LC-E-034 has to model it entirely outside.
5. **Who may declare a default successor is undefined.** AUTHORITY-LIFECYCLE.md leaves
   office vacancy and succession open, and says so. LC-C-008's vectors test only what one
   recorded instrument declares, and make no claim that office-based authority continues
   in general.
6. **Transfer is modelled as instantaneous.** Nothing in L1 to L12 has a two-step,
   acknowledgment-gated transfer or an atomic departure-plus-designation, and nothing says
   what a verifier returns inside a gap. `not_established` for the gap is this fixture's
   choice, not a reading of the text.
7. **Termination in progress is a state L8 does not name.** L8 has suspension and
   revocation. This fixture models wind-down as time-bounded `valid`. Modelling it as a
   `restricted` state that narrows to finishing in-flight work would be equally consistent
   with the text and would give different answers.
8. **Which occurrence properties are pinned and which are live is undecided.** LC-E-018
   wants the template pinned at creation and LC-E-020 wants the creator's authority
   evaluated now. The text does not distinguish them. This fixture pins the declared scope
   and evaluates the grant live, and both vectors are built on that split.
9. **No text says whose clock a validity check runs against.** RFC 5280 says "the
   certificate validity period includes the current time" and defines path validation as
   the validating party's procedure, and draft-03 inherits the phrasing without naming the
   party. LC-G-007 exists because the answer is obvious and unwritten.
10. **No concept of a time-source attestation or a declared tolerance window exists.** The
    whole `clock_attestation` record, its `cross_check` and its `smear_policy` are
    invented here. Whether a decision record should carry which clock it used, and what a
    reviewer may conclude when it does not, is unaddressed.
11. **L8's scope over dormant work is undecided.** L8 says suspension "stops the use of
    authority and of everything that depends on it". A queued action is not in use, so
    whether it depends on the suspended authority in L8's sense is exactly what the text
    does not say, and therefore whether the reference behaviour on LC-E-034 is required or
    merely sensible is undecided.

## Related fixtures in this repository

Adjacent, and not duplicated here: `revocation-resolution-forward-compat` (what an
unrecognized resolver answer does), `key-rotation-historical` (which key version applies
at `issued_at`), `cached-authorization-revocation` (revocation enforcement against a warm
cache), `ancestor-revocation-chain` and `sponsor-handover`.

## Running it

```
npm ci --include=dev
npm run verify:lifecycle-time-and-scheduling

python3 -m venv /tmp/pyenv
/tmp/pyenv/bin/pip install agent-passport-system==4.1.0
/tmp/pyenv/bin/python fixtures/lifecycle-time-and-scheduling/verify_python_sdk.py
```

Both exit 0 on success. Neither touches the network.
