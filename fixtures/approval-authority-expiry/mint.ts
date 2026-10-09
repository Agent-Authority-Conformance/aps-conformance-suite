// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the approval-authority-expiry family, byte for byte.
//
// draft-pidlisnyi-aps-03 section 4.3 lines 914-918: at consumption the boundary MUST
// re-validate what can have changed since issuance, including revocation status and
// temporal validity, as required by Section 3.5. An approval that has expired, has
// already been consumed, or fails re-validation MUST NOT admit execution.
//
// This family's case is the one fixtures/approval-single-use does not present: an
// approval issued while its authority was valid, still unexpired itself at consumption,
// whose backing authority has passed its not_after by the time it is consumed. This
// script mints, with the pinned TypeScript SDK, agent-passport-system 7.1.0: two one-hop
// AuthorityDelegationV1 records sharing one validity window, one action-intent, and four
// permit policy-decision receipts bound to that action. The family's own harness.ts, not
// the SDK, supplies the consumption boundary.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are pinned
// constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/approval-authority-expiry/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildDecisionRefV1,
  computeActionRefV2,
  computeAuthorityDelegationId,
  computePayloadRefV1,
  createActionReferenceInputV2,
  createReceiptV1,
  publicKeyFromPrivate,
  signAuthorityDelegation,
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:approval-authority-expiry:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

const PRINCIPAL = 'did:aps:example:aex-principal'
const ACTING_AGENT = 'did:aps:example:aex-acting-agent'
const BOUNDARY = 'did:aps:example:aex-enforcement-boundary'

const PRINCIPAL_KEY_ID = `${PRINCIPAL}#key-1`
const ACTING_AGENT_KEY_ID = `${ACTING_AGENT}#key-1`
const BOUNDARY_KEY_ID = `${BOUNDARY}#key-1`

const principalPrivate = seed('principal:v1')
const actingAgentPrivate = seed('acting-agent:v1')
const boundaryPrivate = seed('boundary:v1')

const principalPublic = publicKeyFromPrivate(principalPrivate)
const actingAgentPublic = publicKeyFromPrivate(actingAgentPrivate)
const boundaryPublic = publicKeyFromPrivate(boundaryPrivate)

// ---------------------------------------------------------------------------
// The timeline. One authority window, half-open [AUTHORITY_NOT_BEFORE,
// AUTHORITY_NOT_AFTER). Every decision is issued inside it, and every permit except
// decisionPermitApprovalExpired carries a valid_until later than AUTHORITY_NOT_AFTER, so
// the approval outlives the authority it was issued under. AEX-04 is consumed in the gap
// between the two.
// ---------------------------------------------------------------------------

const AUTHORITY_NOT_BEFORE = '2026-09-24T08:00:00.000Z'
const AUTHORITY_NOT_AFTER = '2026-09-24T09:00:00.000Z'
const PERMIT_VALID_UNTIL = '2026-09-24T09:00:30.000Z'

const NOW_AUTHORITY_VALID = '2026-09-24T08:59:50.000Z'
const NOW_AUTHORITY_EXPIRED = '2026-09-24T09:00:10.000Z'

// ---------------------------------------------------------------------------
// Two one-hop AuthorityDelegationV1 records, principal to acting agent, identical except
// for their nonce. DELEGATION_MAIN backs every decision except the one AEX-02 presents;
// that decision is backed by DELEGATION_FOR_REVOCATION_CASE alone, so marking it revoked
// cannot leak into any other vector's chain. Minted with the SDK's authority-delegation
// primitives, the same construction fixtures/approval-single-use/mint.ts uses.
// ---------------------------------------------------------------------------

function authorityVector() {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: ['calendar:write'] },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: 0 },
    time: { not_before: AUTHORITY_NOT_BEFORE, not_after: AUTHORITY_NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] as string[] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

function mintDelegation(nonceLabel: string) {
  const body = {
    record_type: 'aps:authority-delegation:v1' as const,
    version: '1.0' as const,
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject: ACTING_AGENT,
    verification_method: PRINCIPAL_KEY_ID,
    issued_at: AUTHORITY_NOT_BEFORE,
    nonce: seed(nonceLabel).slice(0, 32),
    authority: authorityVector(),
  }
  const delegation_id = computeAuthorityDelegationId(body)
  const draft = { ...body, delegation_id }
  const signature = signAuthorityDelegation(draft, principalPrivate)
  return { ...draft, signature }
}

const DELEGATION_MAIN = mintDelegation('delegation-main-nonce:v1')
const DELEGATION_FOR_REVOCATION_CASE = mintDelegation('delegation-revocation-case-nonce:v1')

const resolveDelegationKey = (_issuer: string, method: string) =>
  method === PRINCIPAL_KEY_ID ? principalPublic : null

// ---------------------------------------------------------------------------
// One action. Every decision in this family approves it.
// ---------------------------------------------------------------------------

const payloadRef = computePayloadRefV1({ event_id: 'evt-2026-09-24-0001', title: 'Board sync' })

const actionAInput = createActionReferenceInputV2({
  agent_id: ACTING_AGENT,
  action_type: 'calendar.write',
  target: 'https://calendar.example/api/v1/events',
  payload_ref: payloadRef,
  scope_required: ['calendar:write'],
  issued_at: '2026-09-24T08:59:39.000Z',
  nonce: seed('action-a-nonce:v1').slice(0, 32),
})

const actionRefA = computeActionRefV2(actionAInput)

type Signer = { signer: string; key_id: string; private_key: string }

const agentSigner: Signer = { signer: ACTING_AGENT, key_id: ACTING_AGENT_KEY_ID, private_key: actingAgentPrivate }
const boundarySigner: Signer = { signer: BOUNDARY, key_id: BOUNDARY_KEY_ID, private_key: boundaryPrivate }

function seal(fields: Record<string, unknown>, signers: Signer[]): Record<string, unknown> {
  return createReceiptV1(fields as never, signers) as unknown as Record<string, unknown>
}

const intentA = seal(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action-intent:v1',
    issuer: ACTING_AGENT,
    subject_agent: ACTING_AGENT,
    action_ref: actionRefA,
    delegation_ref: DELEGATION_MAIN.delegation_id,
    issued_at: '2026-09-24T08:59:39.500Z',
    evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  },
  [agentSigner],
)

// ---------------------------------------------------------------------------
// Decision evidence and decisions, built the way fixtures/approval-single-use/mint.ts
// builds them: decision_ref over real DecisionEvidenceV1 material.
// ---------------------------------------------------------------------------

function decisionEvidenceFor(
  delegation: typeof DELEGATION_MAIN,
  evaluatedAt: string,
  validUntil: string,
) {
  const authority_state = {
    profile: 'aps-conformance-suite:approval-authority-expiry:authority-state-v0',
    selected_chain: [delegation.delegation_id],
    authority_basis: 'delegation',
    spend_state: { mode: 'unbounded' },
  }
  const policy_input = {
    policy_id: 'calendar-write-v1',
    policy_version: '1.0.0',
    requested_scope: ['calendar:write'],
    target: actionAInput.target,
  }
  const decision_context = { enforcement_boundary: BOUNDARY, evaluated_at: evaluatedAt }
  const decision_output = {
    profile: 'aps-core-decision-output-v1' as const,
    verdict: 'permit' as const,
    effective_authority_ref: seed(`effective-authority-ref:${actionRefA}:${evaluatedAt}`),
    constraints: [] as string[],
    valid_until: validUntil,
  }
  const decision_ref = buildDecisionRefV1({ action_ref: actionRefA, authority_state, policy_input, decision_context, decision_output }).decision_ref
  return { authority_state, policy_input, decision_context, decision_output, decision_ref }
}

function sealDecision(evidence: ReturnType<typeof decisionEvidenceFor>) {
  return seal(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:policy-decision:v1',
      issuer: BOUNDARY,
      subject_agent: ACTING_AGENT,
      action_ref: actionRefA,
      delegation_ref: evidence.authority_state.selected_chain[0],
      decision_ref: evidence.decision_ref,
      issued_at: evidence.decision_context.evaluated_at,
      evidence_refs: [],
      result: evidence.decision_output,
      prev: intentA.receipt_id,
    },
    [boundarySigner],
  )
}

const evidencePermitControl = decisionEvidenceFor(DELEGATION_MAIN, '2026-09-24T08:59:40.000Z', PERMIT_VALID_UNTIL)
const decisionPermitControl = sealDecision(evidencePermitControl)

const evidencePermitForRevocation = decisionEvidenceFor(DELEGATION_FOR_REVOCATION_CASE, '2026-09-24T08:59:41.000Z', PERMIT_VALID_UNTIL)
const decisionPermitForRevocation = sealDecision(evidencePermitForRevocation)

const evidencePermitApprovalExpired = decisionEvidenceFor(DELEGATION_MAIN, '2026-09-24T08:59:42.000Z', '2026-09-24T08:59:44.000Z')
const decisionPermitApprovalExpired = sealDecision(evidencePermitApprovalExpired)

const evidencePermitAuthorityExpiry = decisionEvidenceFor(DELEGATION_MAIN, '2026-09-24T08:59:43.000Z', PERMIT_VALID_UNTIL)
const decisionPermitAuthorityExpiry = sealDecision(evidencePermitAuthorityExpiry)

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

assert(DELEGATION_MAIN.delegation_id !== DELEGATION_FOR_REVOCATION_CASE.delegation_id, 'the two delegations share a delegation_id')

const decisionReceiptIds = [
  decisionPermitControl.receipt_id,
  decisionPermitForRevocation.receipt_id,
  decisionPermitApprovalExpired.receipt_id,
  decisionPermitAuthorityExpiry.receipt_id,
]
assert(new Set(decisionReceiptIds).size === decisionReceiptIds.length, 'two decisions share a receipt_id')

function chainState(delegation: typeof DELEGATION_MAIN, now: string, revocation: 'active' | 'revoked') {
  const result = verifyAuthorityDelegationChain([delegation], {
    now,
    resolveVerificationKey: resolveDelegationKey,
    trustRoot: () => true,
    resolveRevocation: () => revocation,
  })
  return result.state === 'valid' ? 'valid' : `${result.state}/${result.failures[0]?.code}`
}

// The authority is valid at every decision's evaluated_at, so every decision in this file
// was issued under valid authority.
for (const evidence of [evidencePermitControl, evidencePermitApprovalExpired, evidencePermitAuthorityExpiry]) {
  const at = evidence.decision_context.evaluated_at
  assert(chainState(DELEGATION_MAIN, at, 'active') === 'valid', `DELEGATION_MAIN is not valid at decision time ${at}`)
}
assert(
  chainState(DELEGATION_FOR_REVOCATION_CASE, evidencePermitForRevocation.decision_context.evaluated_at, 'active') === 'valid',
  'DELEGATION_FOR_REVOCATION_CASE is not valid at decision time',
)

// The two consumption instants straddle the authority's not_after, and the SDK's own
// chain verifier says so under the code the harness will report.
assert(chainState(DELEGATION_MAIN, NOW_AUTHORITY_VALID, 'active') === 'valid', 'DELEGATION_MAIN is not valid at the control consumption instant')
assert(
  chainState(DELEGATION_MAIN, NOW_AUTHORITY_EXPIRED, 'active') === 'invalid/EXPIRED',
  `DELEGATION_MAIN does not verify invalid/EXPIRED at ${NOW_AUTHORITY_EXPIRED}: ${chainState(DELEGATION_MAIN, NOW_AUTHORITY_EXPIRED, 'active')}`,
)
assert(
  chainState(DELEGATION_FOR_REVOCATION_CASE, NOW_AUTHORITY_VALID, 'revoked') === 'invalid/REVOKED',
  'DELEGATION_FOR_REVOCATION_CASE does not fail REVOKED when the resolver answers revoked',
)

// The approval under test is itself still unexpired when the authority has expired.
assert(NOW_AUTHORITY_EXPIRED < PERMIT_VALID_UNTIL, 'the authority-expiry permit is itself expired at its consumption instant')
assert(AUTHORITY_NOT_AFTER <= NOW_AUTHORITY_EXPIRED, 'the authority has not expired at the authority-expiry consumption instant')

// Every minted receipt verifies signature-valid and stage-valid with the SDK's own
// verifyReceiptV1, the same entrypoint harness.ts calls at consumption time.
const resolveReceiptSignerKey = (signer: string, keyId: string) => {
  if (signer === ACTING_AGENT && keyId === ACTING_AGENT_KEY_ID) return actingAgentPublic
  if (signer === BOUNDARY && keyId === BOUNDARY_KEY_ID) return boundaryPublic
  return undefined
}
for (const [label, receipt] of Object.entries({
  intentA, decisionPermitControl, decisionPermitForRevocation, decisionPermitApprovalExpired, decisionPermitAuthorityExpiry,
})) {
  const verification = verifyReceiptV1(receipt as never, resolveReceiptSignerKey, { boundaryIdentity: BOUNDARY })
  assert(verification.status === 'valid', `${label} does not verify valid: ${JSON.stringify(verification)}`)
}

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
  profile: 'aps-approval-authority-expiry-v0',
  description:
    'draft-pidlisnyi-aps-03 section 4.3 lines 914-918: at consumption the boundary MUST ' +
    're-validate temporal validity. One action-intent, four permit policy-decision receipts, ' +
    'and two one-hop AuthorityDelegationV1 records sharing one validity window, minted and ' +
    'signature-verified with agent-passport-system 7.1.0.',
  minted_by: 'fixtures/approval-authority-expiry/mint.ts',
  seed_label_prefix: SEED_PREFIX,
  identities: { principal: PRINCIPAL, acting_agent: ACTING_AGENT, enforcement_boundary: BOUNDARY },
  verification_keys: {
    [PRINCIPAL_KEY_ID]: principalPublic,
    [ACTING_AGENT_KEY_ID]: actingAgentPublic,
    [BOUNDARY_KEY_ID]: boundaryPublic,
  },
  delegations: { main: DELEGATION_MAIN, for_revocation_case: DELEGATION_FOR_REVOCATION_CASE },
  actions: {
    a: { input: actionAInput, action_ref: actionRefA },
  },
  receipts: {
    intent_a: intentA,
    decision_permit_control: decisionPermitControl,
    decision_permit_for_revocation: decisionPermitForRevocation,
    decision_permit_approval_expired: decisionPermitApprovalExpired,
    decision_permit_authority_expiry: decisionPermitAuthorityExpiry,
  },
  decision_evidence: {
    decision_permit_control: evidencePermitControl,
    decision_permit_for_revocation: evidencePermitForRevocation,
    decision_permit_approval_expired: evidencePermitApprovalExpired,
    decision_permit_authority_expiry: evidencePermitAuthorityExpiry,
  },
}

fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('approval-authority-expiry: chain.json minted')
