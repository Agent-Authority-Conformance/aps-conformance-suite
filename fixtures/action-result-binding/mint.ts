// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the action-result-binding family, byte for byte.
//
// One three-stage chain under draft-pidlisnyi-aps-03 section 5.3: an action-intent
// record (5.3.1), a policy-decision permit (5.3.2) whose prev is the intent, and an
// action-result record (5.3.3) whose prev is the decision and whose decision_ref is
// that decision's. A second policy-decision for the same intent, verdict deny, exists
// only to supply a well-formed real decision_ref for case 4; it is never consumed as an
// approval (line 1098 makes a deny terminal).
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are
// pinned constants: no clock is read and no randomness is drawn.
//
// Minted in TypeScript rather than Python because verifyReceiptWithDecisionV1, the
// composite surface this family records, exists only in the TypeScript SDK.
//
// Run from the suite root:
//
//     npx tsx fixtures/action-result-binding/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildDecisionRefV1,
  canonicalizeJCS,
  computeActionRefV2,
  computePayloadRefV1,
  computeReceiptIdV1,
  createActionReferenceInputV2,
  createReceiptV1,
  publicKeyFromPrivate,
  receiptSignaturePayloadV1,
  sign,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:action-result-binding:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

const ACTING_AGENT = 'did:aps:example:arb-acting-agent'
const BOUNDARY = 'did:aps:example:arb-enforcement-boundary'
const SECOND_AGENT = 'did:aps:example:arb-second-agent'

const ACTING_AGENT_KEY_ID = `${ACTING_AGENT}#key-1`
const BOUNDARY_KEY_ID = `${BOUNDARY}#key-1`

const actingAgentPrivate = seed('acting-agent:v1')
const boundaryPrivate = seed('boundary:v1')

// The "sha256:<64 hex>" form of delegation_ref is the one the section 5.1 envelope example
// shows at line 964; lines 982-983 say what the value identifies, not what shape it takes.
// This family never binds it to a chain, so a pinned digest of a published label is the
// honest stand-in: the structural form is real, the leaf resolution is out of scope.
const DELEGATION_REF = `sha256:${seed('delegation-ref:v1')}`
const EFFECTIVE_AUTHORITY_REF = seed('effective-authority-ref:v1')

// ---------------------------------------------------------------------------
// Fixed instants. The decision's valid_until is later than its own issued_at
// (line 1091) and the result is issued after the decision and inside the window.
// ---------------------------------------------------------------------------

const ACTION_ISSUED_AT = '2026-09-21T11:59:59.500Z'
const INTENT_ISSUED_AT = '2026-09-21T12:00:00.000Z'
const DECISION_ISSUED_AT = '2026-09-21T12:00:01.000Z'
const DECISION_VALID_UNTIL = '2026-09-21T12:00:31.000Z'
const DENY_DECISION_ISSUED_AT = '2026-09-21T12:00:01.500Z'
const RESULT_ISSUED_AT = '2026-09-21T12:00:05.000Z'

// ---------------------------------------------------------------------------
// The two actions. The alternate keeps the same agent_id, the same action_type and
// the same scope_required, and changes only the target, so case 5 carries an
// action_ref mismatch and nothing else. Changing agent_id here would have folded the
// case 6 actor conflict into case 5, and changing action_type would have left the
// alternate asking for a scope its own operation does not describe.
// ---------------------------------------------------------------------------

const PAYLOAD = {
  event_id: 'evt-2026-09-21-0001',
  title: 'Quarterly review',
}

const payloadRef = computePayloadRefV1(PAYLOAD)

const primaryActionInput = createActionReferenceInputV2({
  agent_id: ACTING_AGENT,
  action_type: 'calendar.write',
  target: 'https://calendar.example/api/v1/events',
  payload_ref: payloadRef,
  scope_required: ['calendar:write'],
  issued_at: ACTION_ISSUED_AT,
  nonce: seed('action-nonce:v1').slice(0, 32),
})

const alternateActionInput = createActionReferenceInputV2({
  ...primaryActionInput,
  target: 'https://calendar.example/api/v1/archive/events',
})

const primaryActionRef = computeActionRefV2(primaryActionInput)
const alternateActionRef = computeActionRefV2(alternateActionInput)

// ---------------------------------------------------------------------------
// The observed effect and its reference.
//
// Section 5.3.3 lines 1129-1130:
//   effect_ref = lowercase-hex(SHA-256(
//       ASCII("APS-ACTION-EFFECT-V1") || 0x00 || JCS(effect)))
//
// The pinned SDK exposes no helper for this tag (grep for APS-ACTION-EFFECT-V1 over
// the published 7.1.0 package returns nothing), so the formula is written out here
// against the SDK's own RFC 8785 canonicalizer rather than a second JCS implementation.
// ---------------------------------------------------------------------------

const EFFECT = {
  profile: 'aps-conformance-suite:action-result-binding:effect-v0',
  event_id: 'evt-2026-09-21-0001',
  outcome: 'created',
  resource: 'https://calendar.example/api/v1/events/evt-2026-09-21-0001',
}

const EFFECT_TAG = 'APS-ACTION-EFFECT-V1'

function computeEffectRef(effect: unknown): string {
  const preimage = Buffer.concat([
    Buffer.from(EFFECT_TAG, 'ascii'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(effect), 'utf8'),
  ])
  return createHash('sha256').update(preimage).digest('hex')
}

const effectRef = computeEffectRef(EFFECT)

// ---------------------------------------------------------------------------
// Decision evidence. This is exactly the DecisionEvidenceV1 material
// verifyReceiptWithDecisionV1 requires, committed so a third party can run the
// composite check from the files alone.
// ---------------------------------------------------------------------------

// One authority state, shared by both decisions. This family is about the action-result
// binding surfaces, so the authority state carries no lifecycle of its own: nothing here
// tracks a delegation's status changing between the two decisions, and no case turns on
// any such change.
const AUTHORITY_STATE = {
  profile: 'aps-conformance-suite:action-result-binding:authority-state-v0',
  selected_chain: [DELEGATION_REF],
  authority_basis: 'delegation',
  spend_state: { mode: 'unbounded' },
}

// The same policy evaluated the same request in both decisions, so the policy input is
// shared too. The deny exists for one reason only: case 4 needs a real, well-formed
// decision_ref that is not the permit's to put on an action-result record. It is not a
// worked example of why a boundary would deny, and nothing in this family reads it as
// one.
const POLICY_INPUT = {
  policy_id: 'calendar-write-v1',
  policy_version: '1.0.0',
  requested_scope: ['calendar:write'],
  target: 'https://calendar.example/api/v1/events',
}

// Each decision's evaluated_at is its own issued_at, the same relation on both. The deny's
// evaluated_at is the one input it does not share with the permit.
const PERMIT_DECISION_CONTEXT = {
  enforcement_boundary: BOUNDARY,
  evaluated_at: DECISION_ISSUED_AT,
}

const DENY_DECISION_CONTEXT = {
  enforcement_boundary: BOUNDARY,
  evaluated_at: DENY_DECISION_ISSUED_AT,
}

const PERMIT_OUTPUT = {
  profile: 'aps-core-decision-output-v1' as const,
  verdict: 'permit' as const,
  effective_authority_ref: EFFECTIVE_AUTHORITY_REF,
  constraints: [] as string[],
  valid_until: DECISION_VALID_UNTIL,
}

const DENY_OUTPUT = {
  profile: 'aps-core-decision-output-v1' as const,
  verdict: 'deny' as const,
  effective_authority_ref: null,
  constraints: [] as string[],
  valid_until: null,
}

const permitEvidence = {
  authority_state: AUTHORITY_STATE,
  policy_input: POLICY_INPUT,
  decision_context: PERMIT_DECISION_CONTEXT,
  decision_output: PERMIT_OUTPUT,
}

const denyEvidence = {
  authority_state: AUTHORITY_STATE,
  policy_input: POLICY_INPUT,
  decision_context: DENY_DECISION_CONTEXT,
  decision_output: DENY_OUTPUT,
}

// action_ref comes from the receipt in the composite verifier, so both decision
// references are built over the primary action_ref, which is the one the chain names.
const permitDecisionRef = buildDecisionRefV1({ action_ref: primaryActionRef, ...permitEvidence }).decision_ref
const denyDecisionRef = buildDecisionRefV1({ action_ref: primaryActionRef, ...denyEvidence }).decision_ref

// ---------------------------------------------------------------------------
// Sealing.
//
// sealUnvalidated writes the receipt_id and the signature by the section 5.2 formulas
// through the SDK's own primitives (computeReceiptIdV1, receiptSignaturePayloadV1,
// sign). It exists because createReceiptV1 validates the body first and therefore
// refuses case 2, whose whole defect is a missing subject_agent. It is the same
// computation createReceiptV1 performs, which is asserted below on a body that both
// paths accept, so case 2 is a re-derived record and not a hand-edited one.
// ---------------------------------------------------------------------------

type Signer = { signer: string; key_id: string; private_key: string }

const compareUtf8 = (a: string, b: string): number =>
  Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))

function sealUnvalidated(fields: Record<string, unknown>, signers: Signer[]): Record<string, unknown> {
  const descriptors = [...signers].sort(
    (a, b) => compareUtf8(a.signer, b.signer) || compareUtf8(a.key_id, b.key_id),
  )
  const draft: Record<string, unknown> = { ...fields, receipt_id: '0'.repeat(64), signatures: [] }
  draft.receipt_id = computeReceiptIdV1(draft as never)
  draft.signatures = descriptors.map(item => {
    const descriptor = { signer: item.signer, key_id: item.key_id, alg: 'Ed25519' as const }
    return {
      ...descriptor,
      value: sign(receiptSignaturePayloadV1(draft as never, descriptor), item.private_key),
    }
  })
  return draft
}

function seal(fields: Record<string, unknown>, signers: Signer[]): Record<string, unknown> {
  return createReceiptV1(fields as never, signers) as unknown as Record<string, unknown>
}

const agentSigner: Signer = {
  signer: ACTING_AGENT,
  key_id: ACTING_AGENT_KEY_ID,
  private_key: actingAgentPrivate,
}
const boundarySigner: Signer = {
  signer: BOUNDARY,
  key_id: BOUNDARY_KEY_ID,
  private_key: boundaryPrivate,
}

// ---------------------------------------------------------------------------
// The chain.
// ---------------------------------------------------------------------------

const intent = seal(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action-intent:v1',
    issuer: ACTING_AGENT,
    subject_agent: ACTING_AGENT,
    action_ref: primaryActionRef,
    delegation_ref: DELEGATION_REF,
    issued_at: INTENT_ISSUED_AT,
    evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  },
  [agentSigner],
)

const decisionPermit = seal(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:policy-decision:v1',
    issuer: BOUNDARY,
    subject_agent: ACTING_AGENT,
    action_ref: primaryActionRef,
    delegation_ref: DELEGATION_REF,
    decision_ref: permitDecisionRef,
    issued_at: DECISION_ISSUED_AT,
    evidence_refs: [],
    result: PERMIT_OUTPUT,
    prev: intent.receipt_id,
  },
  [boundarySigner],
)

const decisionDeny = seal(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:policy-decision:v1',
    issuer: BOUNDARY,
    subject_agent: ACTING_AGENT,
    action_ref: primaryActionRef,
    delegation_ref: DELEGATION_REF,
    decision_ref: denyDecisionRef,
    issued_at: DENY_DECISION_ISSUED_AT,
    evidence_refs: [],
    result: DENY_OUTPUT,
    prev: intent.receipt_id,
  },
  [boundarySigner],
)

const resultFields: Record<string, unknown> = {
  profile: 'aps-receipt-v1',
  receipt_type: 'aps:action-result:v1',
  issuer: BOUNDARY,
  subject_agent: ACTING_AGENT,
  action_ref: primaryActionRef,
  delegation_ref: DELEGATION_REF,
  decision_ref: permitDecisionRef,
  issued_at: RESULT_ISSUED_AT,
  evidence_refs: [],
  result: {
    profile: 'aps-action-result-v1',
    status: 'succeeded',
    effect_ref: effectRef,
    error_code: null,
  },
  prev: decisionPermit.receipt_id,
}

// Every mutated record is re-derived from the mutated fields: receipt_id recomputed and
// the boundary signature redone over the mutated body, so the named defect is the only
// defect each record carries.
const withoutSubjectAgent = { ...resultFields }
delete withoutSubjectAgent.subject_agent

const cases: Record<string, Record<string, unknown>> = {
  positive: seal(resultFields, [boundarySigner]),
  'subject-agent-absent': sealUnvalidated(withoutSubjectAgent, [boundarySigner]),
  'prev-not-the-decision': seal({ ...resultFields, prev: intent.receipt_id }, [boundarySigner]),
  'decision-ref-mismatch': seal({ ...resultFields, decision_ref: denyDecisionRef }, [boundarySigner]),
  'action-ref-mismatch': seal({ ...resultFields, action_ref: alternateActionRef }, [boundarySigner]),
  'subject-agent-changed': seal({ ...resultFields, subject_agent: SECOND_AGENT }, [boundarySigner]),
}

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

// The unvalidated sealer is the same computation createReceiptV1 performs. Asserting it
// on a body both paths accept is what makes case 2 a re-derived record.
assert(
  canonicalizeJCS(sealUnvalidated(resultFields, [boundarySigner])) === canonicalizeJCS(cases.positive),
  'sealUnvalidated does not reproduce createReceiptV1 on a body both accept',
)

// createReceiptV1 really does refuse the case 2 body, which is why case 2 needs the
// other path at all. If a later SDK accepts it, this assertion says so out loud.
let createRefusedCase2 = false
try {
  seal(withoutSubjectAgent, [boundarySigner])
} catch {
  createRefusedCase2 = true
}
assert(createRefusedCase2, 'createReceiptV1 accepted a body with no subject_agent; revisit case 2')

assert(primaryActionRef !== alternateActionRef, 'the two actions share an action_ref')
assert(permitDecisionRef !== denyDecisionRef, 'the two decisions share a decision_ref')
assert(
  primaryActionInput.agent_id === alternateActionInput.agent_id,
  'the alternate action changed agent_id, which would fold case 6 into case 5',
)

// The alternate action differs from the accepted one in target and in nothing else.
assert(
  primaryActionInput.action_type === alternateActionInput.action_type &&
    canonicalizeJCS(primaryActionInput.scope_required) ===
      canonicalizeJCS(alternateActionInput.scope_required),
  'the alternate action changed more than its target',
)
assert(
  primaryActionInput.target !== alternateActionInput.target,
  'the alternate action did not change its target',
)

// The deny reuses the permit's authority state and policy input byte for byte. Its only
// input of its own is decision_context.evaluated_at, which sits against its own issued_at
// the way the permit's does. Anything else differing here would be a second story this
// family does not tell.
assert(
  canonicalizeJCS(denyEvidence.authority_state) === canonicalizeJCS(permitEvidence.authority_state) &&
    canonicalizeJCS(denyEvidence.policy_input) === canonicalizeJCS(permitEvidence.policy_input),
  'the deny evidence does not reuse the permit authority state and policy input',
)
assert(
  DENY_DECISION_CONTEXT.enforcement_boundary === PERMIT_DECISION_CONTEXT.enforcement_boundary &&
    DENY_DECISION_CONTEXT.evaluated_at !== PERMIT_DECISION_CONTEXT.evaluated_at,
  'the deny decision_context differs from the permit in something other than evaluated_at',
)
assert(
  PERMIT_DECISION_CONTEXT.evaluated_at === DECISION_ISSUED_AT &&
    DENY_DECISION_CONTEXT.evaluated_at === DENY_DECISION_ISSUED_AT,
  'a decision names an evaluated_at that is not its own issued_at',
)
assert(
  intent.receipt_id !== decisionPermit.receipt_id,
  'the intent and the decision share a receipt_id',
)

// ---------------------------------------------------------------------------
// Write. Keys are sorted at every depth so the file is a function of its content.
// ---------------------------------------------------------------------------

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

const chain = {
  profile: 'aps-action-result-binding-v0',
  description:
    'One draft-03 section 5.3 chain (action-intent, policy-decision permit, action-result) ' +
    'plus the decision evidence a composite verifier needs, and six action-result records ' +
    'differing from the positive one by exactly one named defect.',
  minted_by: 'fixtures/action-result-binding/mint.ts',
  seed_label_prefix: SEED_PREFIX,
  identities: {
    acting_agent: ACTING_AGENT,
    enforcement_boundary: BOUNDARY,
    second_agent: SECOND_AGENT,
  },
  // Only the keys that sign something in this chain. The second agent is named by case 6
  // as a subject_agent and signs nothing, so publishing a verification key for it would
  // be material no runner resolves and no record needs.
  verification_keys: {
    [ACTING_AGENT_KEY_ID]: publicKeyFromPrivate(actingAgentPrivate),
    [BOUNDARY_KEY_ID]: publicKeyFromPrivate(boundaryPrivate),
  },
  actions: {
    primary: { input: primaryActionInput, action_ref: primaryActionRef },
    alternate: { input: alternateActionInput, action_ref: alternateActionRef },
    payload: PAYLOAD,
    payload_ref: payloadRef,
  },
  effect: {
    tag: EFFECT_TAG,
    value: EFFECT,
    effect_ref: effectRef,
  },
  decision_evidence: {
    permit: permitEvidence,
    deny: denyEvidence,
  },
  decision_refs: {
    permit: permitDecisionRef,
    deny: denyDecisionRef,
  },
  receipts: {
    intent,
    decision_permit: decisionPermit,
    decision_deny: decisionDeny,
  },
  consumed_decision_receipt_id: decisionPermit.receipt_id,
  cases,
}

fs.writeFileSync(
  path.join(here, 'chain.json'),
  JSON.stringify(sortKeys(chain), null, 2) + '\n',
  'utf8',
)

console.log('action-result-binding: chain.json minted')
