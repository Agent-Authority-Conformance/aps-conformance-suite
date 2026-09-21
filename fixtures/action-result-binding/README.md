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
only to supply a well-formed real `decision_ref` for case 4. It is never consumed as an
approval, which line 1098 forbids for a deny record in any case.

`chain.json` also carries the `DecisionEvidenceV1` material the composite verifier
needs (`authority_state`, `policy_input`, `decision_context`, `decision_output`), so a
third party can run the composite check from the committed files alone.

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
checked executably by `validate.py` rather than asserted in prose, so a future Python
release that adds a composite verifier makes the runner fail instead of leaving a stale
record on disk.

**`replay_policy`** is Agent Replay's stated outcome for the case, cited in every case as
reported by the Agent Replay author at revision
`08b3146097977db565a202c7a8f34d350da00fd0` in
`Agent-Authority-Conformance/aps-conformance-suite#99`, not run by this suite.

## The three classifications

**`aps_conformance`** means the SDK outcome matches the `draft03` block. Cases 1, 2, 4
and 5. Where Python cannot exercise the surface a case turns on, the case stays
`aps_conformance` and `sdk_py` is marked `not_implemented`.

**`aps_draft_requirement_not_enforced`** means the draft states a requirement and neither
reference SDK enforces it today. Case 3 only.

**`draft03_semantic_relation_not_explicitly_enforced`** means two draft-03 definitions
describe the same role, the record makes them disagree, and the draft states no explicit
equality requirement and names no verifier step that compares them. Case 6 only.

## Cases

| id | defect | draft03 | sdk_ts stage | sdk_ts composite | sdk_py stage | replay | classification |
|---|---|---|---|---|---|---|---|
| ARB-01-positive | none | satisfies | valid | valid | valid | fully bound | `aps_conformance` |
| ARB-02-subject-agent-absent | `subject_agent` removed | invalid | invalid, `SCHEMA_INVALID` | invalid, `receipt_invalid` | invalid, `SCHEMA_INVALID` | partially bound | `aps_conformance` |
| ARB-03-prev-not-the-decision | `prev` set to the intent's `receipt_id` | invalid | valid | valid | valid | partially bound | `aps_draft_requirement_not_enforced` |
| ARB-04-decision-ref-mismatch | `decision_ref` set to the deny decision's | invalid | valid | invalid, `decision_ref_mismatch` | valid | partially bound | `aps_conformance` |
| ARB-05-action-ref-mismatch | `action_ref` set to a different action's | invalid | valid | invalid, `decision_ref_mismatch` | valid | unbound | `aps_conformance` |
| ARB-06-subject-agent-changed | `subject_agent` set to a second agent DID | semantic conflict, no explicit rule | valid | valid | valid | partially bound (actor does not match) | `draft03_semantic_relation_not_explicitly_enforced` |

Every mutated record is re-derived so the named defect is the only defect it carries.
The `receipt_id` is recomputed and the boundary signature is redone over the mutated
body. The case 5 action keeps the same `agent_id` and changes only the operation, so
case 5 does not also carry the case 6 actor conflict.

### How case 2 is sealed

`createReceiptV1` validates the body before it computes anything, so it refuses a body
with no `subject_agent`, which is the whole defect of case 2. `mint.ts` therefore seals
that one record through the section 5.2 formulas written out against the SDK's own
primitives, `computeReceiptIdV1`, `receiptSignaturePayloadV1` and `sign`, which are the
same three calls `createReceiptV1` makes after its validation step. `mint.ts` asserts at
mint time that this path reproduces `createReceiptV1` byte for byte on a body both paths
accept, and that `createReceiptV1` really does refuse the case 2 body. Case 2 is
therefore a re-derived record, not a hand-edited one.

### Case 3, stated plainly

draft-03 section 5.3.3 line 1104 requires the action-result `prev` to be the consumed
decision's `receipt_id`, and section 5.6 line 1219 has a verifier validate `prev` and
stage transitions. The current reference SDKs do not resolve `prev`. Both say so in
their own documentation: the TypeScript stage validator's doc comment says it "does not
resolve prev against the receipt it names", and the Python module docstring says "no
resolution of prev against the record it names". Both therefore accept this record.

This is an open SDK gap against section 5.6. It is not a lab pass, and it is not a
defect in the draft.

`verify.ts` prints one line for case 3 labelled `draft03 text check (harness, not SDK)`.
That line is this family's own reading of line 1104, computed by the runner, kept
visibly apart from every SDK result, and never recorded in an `sdk_ts` or `sdk_py`
block. The runner does not implement the `prev` comparison anywhere else and never
reports it as SDK behaviour.

### Case 6, stated plainly

`aps-action-ref-v2` commits to `agent_id`, which draft-03 defines at section 4.1 line 789
as the acting agent's identifier. `ReceiptV1` defines `subject_agent` at section 5.1
line 981 as the acting agent. In case 6 the `action_ref` is unchanged and `subject_agent`
names a different DID, so one record names two different acting agents. That is
semantically inconsistent.

draft-03 states no explicit equality requirement between the two, and section 5.6 lines
1213 to 1221 name no verifier step that compares them. The reference SDKs accept the
record on every surface, including the composite one, because the decision reference
still binds. Agent Replay enforces that correlation explicitly and its author reports
the case as partially bound, actor does not match.

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

It does not establish anything about Agent Replay beyond what its author reported at the
cited revision. This suite did not run Agent Replay.

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

    action-result-binding TypeScript: 6/6 passed

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

    action-result-binding Python: 7/7 passed

The seventh is the executable check that this Python release exposes no composite
receipt and decision verifier.

Either runner exits nonzero when a recorded SDK result disagrees with what the pinned
SDK actually returns, when a case named in `vectors.json` is missing from `chain.json`,
or, for case 3, when the harness reading of `prev` disagrees with what is recorded.

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
entrypoints, rather than recomputing the protocol independently. Each case carries four
separate blocks, not one verdict.

Case 4 is the nearest point of contact and is still a different construction.
`receipt-decision-relation`'s substitution vector supplies a decision built for a
different receipt. Case 4 here keeps one intent and mints a second decision for that
same intent with a different verdict, then puts that decision's reference on an
action-result record whose `prev` still names the first decision.
