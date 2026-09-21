# action-result-binding

A pinned input for independent evidence consumers of `aps:action-result:v1`.

One deterministic chain under draft-pidlisnyi-aps-03 section 5.3, plus six
action-result records that differ from the accepted one by exactly one named defect.
For each case the family records four separate sources of expectation and never
merges them.

## What the family is

`chain.json` carries one three-stage chain:

1. an action-intent record (section 5.3.1), issued and signed by the acting agent
2. a policy-decision permit (section 5.3.2), issued by the enforcement boundary, whose
   `prev` is the intent's `receipt_id` and whose `valid_until` is later than its own
   `issued_at`
3. an action-result record (section 5.3.3), issued by the enforcement boundary, whose
   `prev` is the decision's `receipt_id`, whose `decision_ref` equals that decision's
   `decision_ref`, and whose `effect_ref` is computed with the `APS-ACTION-EFFECT-V1`
   formula over a small fixed effect object

A second policy-decision for the same intent, verdict `deny`, is also minted. It exists
for one reason: case 4 needs a real, well-formed `decision_ref` that is not the permit's
to put on an action-result record. It is never consumed as an approval, which line 1098
forbids for a deny record in any case.

The deny's evidence reuses the permit's `authority_state` and `policy_input` byte for
byte. Its only input of its own is `decision_context.evaluated_at`, half a second later,
which is its own `issued_at` just as the permit's is. Nothing in this family tracks a
delegation's status changing between the two decisions, and no case turns on any such
change. The deny is not a worked example of why a boundary would deny, and nothing here
reads it as one.

`chain.json` also carries the `DecisionEvidenceV1` material the composite verifier
needs (`authority_state`, `policy_input`, `decision_context`, `decision_output`), so a
third party can run the composite check from the committed files alone.

`verification_keys` carries only the keys that sign something here, the acting agent's
and the enforcement boundary's. The second agent DID is named by case 6 as a
`subject_agent` and signs nothing, so no verification key is published for it.

Both runners validate the three chain receipts as well as the six cases: `receipt_id`
recomputed from the record, every signature verified over the section 5.2 signature
payload, and the section 5.3 stage rules applied, each held to what `vectors.json`
records under `chain_receipts`.

Every key is an Ed25519 seed derived from a published label of the form
`aps-conformance-suite:action-result-binding:<label>`, the same pattern C19 uses. The
files carry no secret material. Timestamps, nonces and payloads are pinned constants.
No clock is read and no randomness is drawn.

## The four blocks

`vectors.json` gives each case four blocks. They are never merged into one expected
field.

**`draft03`** is the expectation derived from the published draft text, with the section
and line. It is authored from the text, not from any implementation, and no runner
asserts an SDK result against it.

**`sdk_ts`** is what `agent-passport-system` 7.0.0 actually returns, recorded from real
runs, on two separate entrypoints:

- `validateReceiptStageV1(record, { boundaryIdentity })`, the section 5.3 stage rules
  for one record on its own
- `verifyReceiptWithDecisionV1(record, evidence, resolveKey, { boundaryIdentity })`, the
  section 5.6 composite check of a receipt together with the decision it references

A case may be stage-valid and composite-invalid. Cases 4 and 5 are exactly that. The
distinction survives into `vectors.json`, into this README and into the runner output,
on separate lines, because collapsing several verification surfaces into one valid or
invalid outcome is the failure this family exists to prevent.

**`sdk_py`** is what `agent-passport-system` 4.0.0 for Python actually returns from
`validate_receipt_stage_v1`, recorded from real runs, plus an entry stating that the
pinned release has no counterpart to `verifyReceiptWithDecisionV1`. That absence is
checked executably by `validate.py` rather than asserted in prose. The probe imports
every module in the installed `agent_passport` package and looks for any callable whose
name contains both `receipt` and `decision` together with `verify` or `check`. A future
release that adds a composite verifier under a name of that shape makes the runner fail
instead of leaving a stale record on disk. A release that adds one under a name outside
that shape is not covered, and the probe claims no more than that.

**`replay_policy`** holds two kinds of value, kept apart by a `status` member, and this
suite did not run Agent Replay for either of them.

`status: derived` is what Agent Replay's binding rules, as stated by its author, imply
for the record. This suite derived each of those values by applying those stated rules.
The stated rules are quoted in `vectors.json` under `replay_policy_stated_rules`, cited
to the Agent Replay author at revision `08b3146097977db565a202c7a8f34d350da00fd0` in
`Agent-Authority-Conformance/aps-conformance-suite#99`. Each derived value names the
stated rule that determines it. Cases 1, 3, 4 and 5.

`status: reported` is an outcome the Agent Replay author obtained from a run and
reported. Cases 2 and 6, the two the stated rules did not settle. Their earlier
`unresolved_until_run` explanation is kept under `stated_rules_did_not_settle` as
history, and it is the reported outcome, not that explanation, that the `outcome` member
now carries.

The author ran the fixture pinned at this suite's commit
`b64cc8dfa889b493bbf285fbb115a988ac54566b` and this path, against Agent Replay at
revision `1f4db7a12e8ddf8853c2533f08f8252f7efbe326`, and reported all six outcomes in
`Agent-Authority-Conformance/aps-conformance-suite#99` comment `5767384166`. Every case
records the author's exact Replay status string and cites that revision and comment.
Cases 1, 3, 4 and 5 carry it under `author_run_confirmation`: the author's run reported
the outcome this suite had already derived. Cases 2 and 6 take their outcome from it.

This suite did not run Agent Replay, did not submit these records to it, and is not
reporting a result of its own for any case. What is recorded is a third party's report,
attributed to that third party, at a pinned revision.

For case 2 the author states that Agent Replay marks APS `ReceiptV1` schema validation
`NOT_PERFORMED`. That statement is recorded inside `replay_policy` only, under
`aps_schema_validation_note`, as the author's statement about Agent Replay. It does not
replace or soften case 2's own APS result: the record is schema-invalid, the `draft03`,
`sdk_ts` and `sdk_py` blocks say so, and none of them changed.

## The three classifications

**`aps_conformance`** means the SDK outcome matches the `draft03` block. Cases 1, 2, 4
and 5. For cases 4 and 5 the surface the case turns on is the TypeScript composite one,
which Python has no counterpart to, so only the `composite_decision_verifier` sub-block
of `sdk_py` is marked `not_implemented`. The Python stage result for those two cases is
recorded as what it is, `valid`, which is not the `draft03` outcome and is not presented
as one: the stage surface does not recompute `decision_ref` or `action_ref`, and its own
docstring says so.

**`draft03_stated_relation_not_enforced`** means draft-03 states a relation between two
members and lists the check among its verifier steps, without a BCP 14 keyword on either
statement, and the current reference SDKs do not enforce that relation. Case 3 only.

**`draft03_semantic_relation_not_explicitly_enforced`** means two draft-03 definitions
describe the same role, the record makes them disagree, and the draft states no explicit
equality relation and names no verifier step that compares them. Case 6 only.

## Cases

The `replay` column is not a result this suite obtained. `derived` is this suite's
reading of the author's stated rules; `reported` is the author's own run at
`1f4db7a12e8ddf8853c2533f08f8252f7efbe326`, reported in issue #99 comment `5767384166`.
Where the column says `derived, confirmed`, the author's run reported the same outcome
this suite had derived. The Replay status string in the column is the author's. See the
`replay_policy` block above.

| id | defect | draft03 | sdk_ts stage | sdk_ts composite | sdk_py stage | replay (not run here) | classification |
|---|---|---|---|---|---|---|---|
| ARB-01-positive | none | satisfies | valid | valid | valid | derived, confirmed: fully bound, `EXECUTION_EVIDENCE_BOUND_TO_ACTION` | `aps_conformance` |
| ARB-02-subject-agent-absent | `subject_agent` removed | invalid | invalid, `SCHEMA_INVALID` | invalid, `receipt_invalid` | invalid, `SCHEMA_INVALID` | reported: partially bound, `EXECUTION_EVIDENCE_PARTIALLY_BOUND` | `aps_conformance` |
| ARB-03-prev-not-the-decision | `prev` set to the intent's `receipt_id` | stated_relation_not_met | valid | valid | valid | derived, confirmed: partially bound, `EXECUTION_EVIDENCE_PARTIALLY_BOUND` | `draft03_stated_relation_not_enforced` |
| ARB-04-decision-ref-mismatch | `decision_ref` set to the deny decision's | invalid | valid | invalid, `decision_ref_mismatch` | valid | derived, confirmed: partially bound, `EXECUTION_EVIDENCE_PARTIALLY_BOUND` | `aps_conformance` |
| ARB-05-action-ref-mismatch | `action_ref` set to a different action's | invalid | valid | invalid, `decision_ref_mismatch` | valid | derived, confirmed: unbound, `EXECUTION_EVIDENCE_UNBOUND` | `aps_conformance` |
| ARB-06-subject-agent-changed | `subject_agent` set to a second agent DID | semantic conflict, no explicit rule | valid | valid | valid | reported: unbound, `EXECUTION_EVIDENCE_UNBOUND` | `draft03_semantic_relation_not_explicitly_enforced` |

Every mutated record is re-derived so the named defect is the only defect it carries.
The `receipt_id` is recomputed and the boundary signature is redone over the mutated
body. The case 5 action keeps the same `agent_id`, the same `action_type` and the same
`scope_required`, and changes only the `target`, so case 5 does not also carry the case
6 actor conflict and does not ask for a scope its own operation fails to describe.

### Which decision each case was checked against

`vectors.json` pins, per case, the `decision_ref` recomputed from the supplied decision
evidence and that record's own `action_ref`. That is the value the composite verifier
compares with `decision_ref`. The composite result alone does not always identify the
evidence: in case 5 both decisions mismatch and the composite returns the same field
values either way, so without this assertion the case would still report agreement with
the permit evidence replaced by the deny evidence. The pinned digest differs for every
case under that substitution, so a runner exits nonzero when the evidence is swapped.

Both runners assert it, each through its own SDK's digest builder: `verify.ts` through
`buildDecisionRefV1`, `validate.py` through `build_decision_ref_v1`. The two agree on
every case, so the pinned digests are not the statement of one implementation alone.

This is **harness evidence on both sides, not an SDK verdict**, and on the Python side
specifically it is not a composite verifier result. The pinned Python release exposes no
counterpart to `verifyReceiptWithDecisionV1`; the `composite_decision_verifier` sub-block
of `sdk_py` still records `not_implemented`, and `validate.py` still checks that absence
executably. What `validate.py` adds is the digest builder run directly on the same
inputs. `validate.py` prints it on a line labelled
`decision_ref binding (harness, not SDK verdict)`.

### How case 2 is sealed

`createReceiptV1` validates the body before it computes anything, so it refuses a body
with no `subject_agent`, which is the whole defect of case 2. `mint.ts` therefore seals
that one record through the section 5.2 formulas written out against the SDK's own
primitives, `computeReceiptIdV1`, `receiptSignaturePayloadV1` and `sign`, which are the
same three calls `createReceiptV1` makes after its validation step. `mint.ts` asserts at
mint time that this path reproduces `createReceiptV1` byte for byte on a body both paths
accept, and that `createReceiptV1` really does refuse the case 2 body. Case 2 is
therefore a re-derived record, not a hand-edited one.

Both SDK entrypoints fail case 2 on its schema before any signature is verified, so the
one thing that sealing path exists to produce would otherwise go unexercised. Both
runners therefore recompute case 2's `receipt_id` and verify its boundary signature over
the section 5.2 signature payload directly, with the SDK primitives, and hold both to
what `vectors.json` records under `sealed_signature_check`.

### Case 3, stated plainly

draft-03 section 5.3.3 lines 1104 to 1105 state that the action-result `prev` is the
consumed decision's `receipt_id`, and section 5.6 line 1219 lists validating `prev` and
stage transitions among the verifier steps. Neither statement carries a BCP 14 keyword.
Section 1.1 lines 175 to 179 confine BCP 14 force to keywords that appear in all
capitals, and the `MUST` in the same sentence at line 1105 governs `decision_ref`, not
`prev`.

The current reference SDKs do not resolve `prev`. Both say so in their own
documentation: the TypeScript stage validator's doc comment says it "does not resolve
prev against the receipt it names", and the Python module docstring says "no resolution
of prev against the record it names". Both therefore accept this record.

So the relation draft-03 states is not enforced by the current reference SDKs. That is
neither a lab pass nor a normative conformance failure, and it is not a defect in the
draft.

`verify.ts` prints one line for case 3 labelled `draft03 text check (harness, not SDK)`.
That line is this family's own reading of lines 1104 to 1105, computed by the runner,
kept visibly apart from every SDK result, and never recorded in an `sdk_ts` or `sdk_py`
block. The runner does not implement the `prev` comparison anywhere else and never
reports it as SDK behaviour.

### Case 6, stated plainly

`aps-action-ref-v2` commits to `agent_id`, which draft-03 defines at section 4.1 line 789
as the acting agent's identifier. `ReceiptV1` defines `subject_agent` at section 5.1
line 981 as the acting agent. In case 6 the `action_ref` is unchanged and `subject_agent`
names a different DID, so one record names two different acting agents. That is
semantically inconsistent.

draft-03 states no explicit equality relation between the two, and section 5.6 lines
1213 to 1221 name no verifier step that compares them. The reference SDKs accept the
record on every surface, including the composite one, because the decision reference
still binds.

Agent Replay's stated rules require an explicit matching actor for full binding, and
name a missing actor among the conditions that leave a result partially bound. This
record's actor is present and mismatched, which is neither, so those stated rules did not
settle it and this suite derived no outcome from them. The author has since run the
pinned record and reported `EXECUTION_EVIDENCE_UNBOUND`, so the `replay_policy` block
carries `status: reported` and `unbound`, attributed to that run, with the earlier
explanation kept as history.

The case is not an APS negative vector and not evidence of an APS violation. It marks a
relation the draft leaves implicit.

## What the family does not establish

It does not establish that an external effect occurred or settled. Section 5.3.3 line
1131 to 1133 is explicit that an action-result record attests to what the enforcement
boundary observed after dispatch and that external occurrence or settlement requires
separately resolved evidence.

It does not establish single-use consumption or freshness at dispatch. Lines 1093 to
1099 put those obligations on the enforcement boundary, and no record in this family can
carry them.

It does not establish anything about Agent Replay on this suite's own authority. The
`replay_policy` values are either this suite's derivation from rules the Agent Replay
author stated at the cited revision, or outcomes that author reported from a run at the
cited revision and comment. This suite did not run Agent Replay and did not submit these
records to it. Nothing here is independent verification of Agent Replay by this suite,
and the reported outcomes are held as a third party's report, not reproduced here.

It does not establish independent verification of any kind. The `sdk_ts` and `sdk_py`
blocks are two implementations of the same protocol by the same author, run here at two
pinned versions.

It does not establish that `delegation_ref` resolves to a real delegation leaf. The
value carries the correct `sha256:<64 hex>` structural form and nothing binds it to a
chain, which matches what both stage validators check.

## Regenerating

From the suite root, with the pinned `agent-passport-system` 7.0.0 installed:

    npm ci --include=dev
    npx tsx fixtures/action-result-binding/mint.ts

Regeneration is byte for byte. After a second run, `git diff` on `chain.json` is empty.
Minting is in TypeScript rather than Python because `verifyReceiptWithDecisionV1`, the
composite surface this family records, exists only in the TypeScript SDK.

## Running the runners

TypeScript, wired into `npm test` as its last step:

    npm run verify:action-result-binding

Expected final line:

    action-result-binding TypeScript: 9/9 matched

The nine are the six cases and the three chain receipts. `MATCH` means the observed SDK
behaviour equals the recorded expectation. It is not a conformance verdict, and both
runners say so on their first line of output.

The runner refuses to report at all unless the resolved `agent-passport-system` is
exactly 7.0.0, read from the installed package's own `package.json` by absolute path.
`package.json` pins the dependency, but a local override or a changed resolution would
otherwise redefine what `sdk_ts` means while the runner still printed a match. This
mirrors `validate.py`'s guard on the Python side and exists for the same reason.

Python is a manual run and is deliberately not part of `npm test`, for the same reason
C19's `validate.py` is not: the Python CI job keeps SDK dependencies out. Run it against
an interpreter that has the released `agent-passport-system` 4.0.0 installed, which in
practice means a dedicated virtualenv rather than a system `python3` that may carry an
editable install of an unreleased checkout:

    PY=/path/to/venv-aps-py-4.0.0/bin/python
    "$PY" fixtures/action-result-binding/validate.py

Confirm the interpreter before trusting its output:

    "$PY" -c "import importlib.metadata as m; print(m.version('agent-passport-system'))"

Expected final line:

    action-result-binding Python: 10/10 matched

The ten are the six cases, the three chain receipts, and the executable check that this
Python release exposes no composite receipt and decision verifier.

Either runner exits nonzero when a recorded SDK result disagrees with what the pinned
SDK actually returns, when a case named in `vectors.json` is missing from `chain.json`,
when a chain receipt fails to recompute its `receipt_id`, fails a signature or returns a
stage result other than the recorded one, or when case 2's own `receipt_id` or boundary
signature does not check out.

Either runner also exits nonzero when a case names decision evidence `chain.json` does
not carry, or when the `decision_ref` it recomputes for a case does not match the digest
`vectors.json` pins for it.

`verify.ts` additionally exits nonzero when the resolved SDK is not 7.0.0 and, for case
3, when the harness reading of `prev` disagrees with what is recorded. The `prev`
comparison is implemented in `verify.ts` only. `validate.py` does not implement it, and
its own docstring says so.

## Relation to fixtures/receipt-decision-relation

The two families do not overlap, and neither duplicates the other.

`receipt-decision-relation` is about the cross-document relation between one receipt and
one decision: substitution of an unrelated decision, and the strict temporal relation
`valid_until > issued_at`. Its runner imports nothing from the SDK. It reimplements
`decision_ref` from RFC 8785 and Node's stdlib crypto, so agreement with the pinned
digests is evidence about the construction rather than an artifact of shared code. Each
of its vectors carries one relation verdict.

`action-result-binding` is about the section 5.3 stage chain and the binding surfaces
specific to an `aps:action-result:v1` record: `subject_agent` presence, `prev` as the
consumed decision, `decision_ref` equality with that decision, `action_ref` binding, and
the implicit relation between `subject_agent` and the `action_ref` `agent_id`. Its
runners call the pinned SDKs directly and report what those SDKs return on named
entrypoints. Where they recompute anything, `receipt_id`, a signature payload or a
`decision_ref`, they do it through the SDK's own primitives rather than through a second
implementation, so agreement there is a statement about the records and not evidence
about the construction. Each case carries four separate blocks, not one verdict.

Case 4 is the nearest point of contact and is still a different construction.
`receipt-decision-relation`'s substitution vector supplies a decision built for a
different receipt. Case 4 here keeps one intent and mints a second decision for that
same intent with a different verdict, then puts that decision's reference on an
action-result record whose `prev` still names the first decision.
