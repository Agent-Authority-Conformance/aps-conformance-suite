// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the approval-single-use family, byte for byte.
//
// draft-pidlisnyi-aps-03 section 5.3.2 lines 1093-1099: a permit or narrow policy-decision
// record is a bounded, single-use approval for its action_ref. Before dispatch the
// enforcement boundary MUST verify it has not expired, atomically consume its receipt_id,
// recheck time and revocation state, and complete any spend reservation. An already
// consumed, expired, or stale approval MUST NOT admit dispatch. A deny record is terminal
// and MUST NOT be consumed as an approval.
//
// Neither reference SDK exposes a consume-once boundary API for a policy-decision record
// (see README "What exists"). This mint script produces real, signed section 5.3 records
// with the pinned TypeScript SDK, agent-passport-system 7.0.0: one action-intent and six
// policy-decision receipts bound to action A, one action-intent and one policy-decision
// receipt bound to narrowed action C, and two one-hop AuthorityDelegationV1 records. The
// family's own harness.ts, not the SDK, supplies the single-use consumption and
// consumption-time revocation recheck that lines 1093-1099 require.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are pinned
// constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/approval-single-use/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  authorityDelegationIdInput,
  buildDecisionRefV1,
  canonicalizeJCS,
  computeActionRefV2,
  computeAuthorityDelegationId,
  computePayloadRefV1,
  createActionReferenceInputV2,
  createReceiptV1,
  publicKeyFromPrivate,
  sign,
  signAuthorityDelegation,
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:approval-single-use:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

const PRINCIPAL = 'did:aps:example:asu-principal'
const ACTING_AGENT = 'did:aps:example:asu-acting-agent'
const BOUNDARY = 'did:aps:example:asu-enforcement-boundary'

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
// Two one-hop AuthorityDelegationV1 records, principal to acting agent. DELEGATION_MAIN
// backs every decision except the one case5 presents; that decision is backed by
// DELEGATION_FOR_REVOCATION_CASE alone, so marking it revoked at consumption time cannot
// also affect any other vector's chain. Both are minted the same way, out against the
// SDK's own authority-delegation primitives, because the TypeScript SDK exposes no
// issueAuthorityDelegation convenience function (that exists only on the Python side,
// used by fixtures/ancestor-revocation-chain/mint.py); this writes out the same formula
// createReceiptV1 uses internally for receipts, applied to the delegation primitives
// authorityDelegationIdInput / computeAuthorityDelegationId / signAuthorityDelegation.
// ---------------------------------------------------------------------------

function authorityVector() {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: ['calendar:write'] },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: 0 },
    time: { not_before: '2026-09-22T08:00:00.000Z', not_after: '2026-09-23T00:00:00.000Z' },
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
    issued_at: '2026-09-22T08:00:00.000Z',
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
// Three actions. A (primary, presented and consumed in cases 1, 2, 7), B (a different
// action, used only as the mismatched target in case 4's binding test, never itself the
// subject of a decision), and C (the narrower action case 8's narrow decision names).
// ---------------------------------------------------------------------------

const primaryPayloadRef = computePayloadRefV1({ event_id: 'evt-2026-09-22-0001', title: 'Quarterly review' })
const narrowPayloadRef = computePayloadRefV1({ event_id: 'evt-2026-09-22-0002', title: 'Single narrow event' })

const actionAInput = createActionReferenceInputV2({
  agent_id: ACTING_AGENT,
  action_type: 'calendar.write',
  target: 'https://calendar.example/api/v1/events',
  payload_ref: primaryPayloadRef,
  scope_required: ['calendar:write'],
  issued_at: '2026-09-22T08:59:59.500Z',
  nonce: seed('action-a-nonce:v1').slice(0, 32),
})

const actionBInput = createActionReferenceInputV2({
  ...actionAInput,
  target: 'https://calendar.example/api/v1/events/cancel',
})

const actionCInput = createActionReferenceInputV2({
  agent_id: ACTING_AGENT,
  action_type: 'calendar.write',
  target: 'https://calendar.example/api/v1/events/single',
  payload_ref: narrowPayloadRef,
  scope_required: ['calendar:write:single-event'],
  issued_at: '2026-09-22T09:00:07.000Z',
  nonce: seed('action-c-nonce:v1').slice(0, 32),
})

const actionRefA = computeActionRefV2(actionAInput)
const actionRefB = computeActionRefV2(actionBInput)
const actionRefC = computeActionRefV2(actionCInput)

// ---------------------------------------------------------------------------
// Signers and sealing. Every record here passes createReceiptV1's own validation, so no
// sealUnvalidated escape hatch is needed (compare fixtures/action-result-binding/mint.ts
// case 2, which needs one because its whole point is a body createReceiptV1 refuses).
// ---------------------------------------------------------------------------

type Signer = { signer: string; key_id: string; private_key: string }

const agentSigner: Signer = { signer: ACTING_AGENT, key_id: ACTING_AGENT_KEY_ID, private_key: actingAgentPrivate }
const boundarySigner: Signer = { signer: BOUNDARY, key_id: BOUNDARY_KEY_ID, private_key: boundaryPrivate }

function seal(fields: Record<string, unknown>, signers: Signer[]): Record<string, unknown> {
  return createReceiptV1(fields as never, signers) as unknown as Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Two action-intents, one per underlying action family (A backs six decisions, C backs
// one narrow decision), following the fixtures/action-result-binding precedent of one
// intent backing more than one later-stage record with the same action_ref.
// ---------------------------------------------------------------------------

const intentA = seal(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action-intent:v1',
    issuer: ACTING_AGENT,
    subject_agent: ACTING_AGENT,
    action_ref: actionRefA,
    delegation_ref: DELEGATION_MAIN.delegation_id,
    issued_at: '2026-09-22T09:00:00.000Z',
    evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  },
  [agentSigner],
)

const intentC = seal(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action-intent:v1',
    issuer: ACTING_AGENT,
    subject_agent: ACTING_AGENT,
    action_ref: actionRefC,
    delegation_ref: DELEGATION_MAIN.delegation_id,
    issued_at: '2026-09-22T09:00:07.500Z',
    evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  },
  [agentSigner],
)

// ---------------------------------------------------------------------------
// Decision evidence and decisions. Every decision below reuses the same policy_input and
// authority_basis shape; only decision_context.evaluated_at, decision_output and (for the
// case5 decision) the backing delegation differ, the same reuse pattern
// action-result-binding's permit and deny decisions establish.
// ---------------------------------------------------------------------------

function decisionEvidenceFor(
  delegation: typeof DELEGATION_MAIN,
  actionRef: string,
  target: string,
  requestedScope: string[],
  evaluatedAt: string,
  output: { verdict: 'permit' | 'narrow' | 'deny'; constraints: string[]; valid_until: string | null },
) {
  const authority_state = {
    profile: 'aps-conformance-suite:approval-single-use:authority-state-v0',
    selected_chain: [delegation.delegation_id],
    authority_basis: 'delegation',
    spend_state: { mode: 'unbounded' },
  }
  const policy_input = {
    policy_id: 'calendar-write-v1',
    policy_version: '1.0.0',
    requested_scope: requestedScope,
    target,
  }
  const decision_context = { enforcement_boundary: BOUNDARY, evaluated_at: evaluatedAt }
  const decision_output = {
    profile: 'aps-core-decision-output-v1' as const,
    verdict: output.verdict,
    effective_authority_ref: output.verdict === 'deny' ? null : seed(`effective-authority-ref:${actionRef}:${evaluatedAt}`),
    constraints: output.constraints,
    valid_until: output.valid_until,
  }
  const decision_ref = buildDecisionRefV1({ action_ref: actionRef, authority_state, policy_input, decision_context, decision_output }).decision_ref
  return { authority_state, policy_input, decision_context, decision_output, decision_ref }
}

function sealDecision(prev: string, actionRef: string, evidence: ReturnType<typeof decisionEvidenceFor>) {
  return seal(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:policy-decision:v1',
      issuer: BOUNDARY,
      subject_agent: ACTING_AGENT,
      action_ref: actionRef,
      delegation_ref: evidence.authority_state.selected_chain[0],
      decision_ref: evidence.decision_ref,
      issued_at: evidence.decision_context.evaluated_at,
      evidence_refs: [],
      result: evidence.decision_output,
      prev,
    },
    [boundarySigner],
  )
}

const evidencePermit1 = decisionEvidenceFor(
  DELEGATION_MAIN, actionRefA, actionAInput.target, ['calendar:write'],
  '2026-09-22T09:00:01.000Z',
  { verdict: 'permit', constraints: [], valid_until: '2026-09-22T09:00:31.000Z' },
)
const decisionPermit1 = sealDecision(intentA.receipt_id as string, actionRefA, evidencePermit1)

const evidencePermitExpired = decisionEvidenceFor(
  DELEGATION_MAIN, actionRefA, actionAInput.target, ['calendar:write'],
  '2026-09-22T09:00:02.000Z',
  { verdict: 'permit', constraints: [], valid_until: '2026-09-22T09:00:04.000Z' },
)
const decisionPermitExpired = sealDecision(intentA.receipt_id as string, actionRefA, evidencePermitExpired)

const evidencePermitForBinding = decisionEvidenceFor(
  DELEGATION_MAIN, actionRefA, actionAInput.target, ['calendar:write'],
  '2026-09-22T09:00:03.000Z',
  { verdict: 'permit', constraints: [], valid_until: '2026-09-22T09:00:33.000Z' },
)
const decisionPermitForBinding = sealDecision(intentA.receipt_id as string, actionRefA, evidencePermitForBinding)

const evidencePermitForRevocation = decisionEvidenceFor(
  DELEGATION_FOR_REVOCATION_CASE, actionRefA, actionAInput.target, ['calendar:write'],
  '2026-09-22T09:00:04.000Z',
  { verdict: 'permit', constraints: [], valid_until: '2026-09-22T09:00:34.000Z' },
)
const decisionPermitForRevocation = sealDecision(intentA.receipt_id as string, actionRefA, evidencePermitForRevocation)

const evidenceDeny = decisionEvidenceFor(
  DELEGATION_MAIN, actionRefA, actionAInput.target, ['calendar:write'],
  '2026-09-22T09:00:05.000Z',
  { verdict: 'deny', constraints: [], valid_until: null },
)
const decisionDeny = sealDecision(intentA.receipt_id as string, actionRefA, evidenceDeny)

const evidencePermitForRace = decisionEvidenceFor(
  DELEGATION_MAIN, actionRefA, actionAInput.target, ['calendar:write'],
  '2026-09-22T09:00:06.000Z',
  { verdict: 'permit', constraints: [], valid_until: '2026-09-22T09:00:36.000Z' },
)
const decisionPermitForRace = sealDecision(intentA.receipt_id as string, actionRefA, evidencePermitForRace)

const evidenceNarrow = decisionEvidenceFor(
  DELEGATION_MAIN, actionRefC, actionCInput.target, ['calendar:write:single-event'],
  '2026-09-22T09:00:08.000Z',
  { verdict: 'narrow', constraints: ['scope:calendar:write:single-event'], valid_until: '2026-09-22T09:00:38.000Z' },
)
const decisionNarrow = sealDecision(intentC.receipt_id as string, actionRefC, evidenceNarrow)

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

assert(actionRefA !== actionRefB, 'action A and action B share an action_ref')
assert(actionRefA !== actionRefC, 'action A and action C share an action_ref')
assert(DELEGATION_MAIN.delegation_id !== DELEGATION_FOR_REVOCATION_CASE.delegation_id, 'the two delegations share a delegation_id')

const decisionReceiptIds = [
  decisionPermit1.receipt_id,
  decisionPermitExpired.receipt_id,
  decisionPermitForBinding.receipt_id,
  decisionPermitForRevocation.receipt_id,
  decisionDeny.receipt_id,
  decisionPermitForRace.receipt_id,
  decisionNarrow.receipt_id,
]
assert(new Set(decisionReceiptIds).size === decisionReceiptIds.length, 'two decisions share a receipt_id')

// The chain used by every decision except decisionPermitForRevocation verifies valid when
// its own delegation's revocation resolver answers active, at every presentation instant
// this family uses.
const mainChainCheck = verifyAuthorityDelegationChain([DELEGATION_MAIN], {
  now: '2026-09-22T09:00:15.000Z',
  resolveVerificationKey: resolveDelegationKey,
  trustRoot: () => true,
  resolveRevocation: () => 'active',
})
assert(mainChainCheck.state === 'valid', `DELEGATION_MAIN does not verify valid: ${JSON.stringify(mainChainCheck)}`)

const revocationChainCheckActive = verifyAuthorityDelegationChain([DELEGATION_FOR_REVOCATION_CASE], {
  now: '2026-09-22T09:00:12.000Z',
  resolveVerificationKey: resolveDelegationKey,
  trustRoot: () => true,
  resolveRevocation: () => 'active',
})
assert(revocationChainCheckActive.state === 'valid', 'DELEGATION_FOR_REVOCATION_CASE does not verify valid when active')

const revocationChainCheckRevoked = verifyAuthorityDelegationChain([DELEGATION_FOR_REVOCATION_CASE], {
  now: '2026-09-22T09:00:12.000Z',
  resolveVerificationKey: resolveDelegationKey,
  trustRoot: () => true,
  resolveRevocation: () => 'revoked',
})
assert(
  revocationChainCheckRevoked.state === 'invalid' && revocationChainCheckRevoked.failures[0]?.code === 'REVOKED',
  'DELEGATION_FOR_REVOCATION_CASE does not fail REVOKED when the resolver answers revoked',
)

// Every minted policy-decision receipt verifies signature-valid and stage-valid with the
// SDK's own verifyReceiptV1, the same entrypoint harness.ts calls at consumption time.
const resolveReceiptSignerKey = (signer: string, keyId: string) => {
  if (signer === ACTING_AGENT && keyId === ACTING_AGENT_KEY_ID) return actingAgentPublic
  if (signer === BOUNDARY && keyId === BOUNDARY_KEY_ID) return boundaryPublic
  return undefined
}
for (const [label, receipt] of Object.entries({
  intentA, intentC, decisionPermit1, decisionPermitExpired, decisionPermitForBinding,
  decisionPermitForRevocation, decisionDeny, decisionPermitForRace, decisionNarrow,
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
  profile: 'aps-approval-single-use-v0',
  description:
    'draft-pidlisnyi-aps-03 section 5.3.2 lines 1093-1099: a permit or narrow policy-decision ' +
    'record is a bounded single-use approval. Two action-intents, seven policy-decision ' +
    'receipts (five permit, one deny, one narrow), and two one-hop AuthorityDelegationV1 ' +
    'records, minted and signature-verified with agent-passport-system 7.0.0.',
  minted_by: 'fixtures/approval-single-use/mint.ts',
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
    b: { input: actionBInput, action_ref: actionRefB },
    c: { input: actionCInput, action_ref: actionRefC },
  },
  receipts: {
    intent_a: intentA,
    intent_c: intentC,
    decision_permit_1: decisionPermit1,
    decision_permit_expired: decisionPermitExpired,
    decision_permit_for_binding: decisionPermitForBinding,
    decision_permit_for_revocation: decisionPermitForRevocation,
    decision_deny: decisionDeny,
    decision_permit_for_race: decisionPermitForRace,
    decision_narrow: decisionNarrow,
  },
  decision_evidence: {
    decision_permit_1: evidencePermit1,
    decision_permit_expired: evidencePermitExpired,
    decision_permit_for_binding: evidencePermitForBinding,
    decision_permit_for_revocation: evidencePermitForRevocation,
    decision_deny: evidenceDeny,
    decision_permit_for_race: evidencePermitForRace,
    decision_narrow: evidenceNarrow,
  },
}

fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('approval-single-use: chain.json minted')
