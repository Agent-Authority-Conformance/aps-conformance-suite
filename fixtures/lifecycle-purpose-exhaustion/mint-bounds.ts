// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint records-bounds.json for the lifecycle-purpose-exhaustion family, byte for byte.
//
// WHAT THIS FAMILY TESTS. Expiry or exhaustion by purpose, by use count and by budget,
// as a lifecycle state separate from revocation and from expiry. The proposed text is
// aeoess/agent-authority-lifecycle at commit 5c1bf09, section "Authority lifecycle
// state", entry "Expiry or exhaustion", and invariant "L10. Expiry is not revocation".
// Every vector in this family is labelled candidate_against_proposed. See README.md for
// the verbatim quotes and for the one dimension (budget) where draft-pidlisnyi-aps-03
// does state a rule of its own.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are
// pinned constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-purpose-exhaustion/mint-bounds.ts
//
// Then `git diff` on records-bounds.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildDecisionRefV1,
  canonicalizeJCS,
  computeActionRefV2,
  computeAuthorityDelegationId,
  computePayloadRefV1,
  createActionReferenceInputV2,
  createReceiptV1,
  isPurposePermitted,
  publicKeyFromPrivate,
  sign,
  signAuthorityDelegation,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
  InMemoryAuthorityBudgetLedger,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-purpose-exhaustion:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

// The principal is a facility office, not a named person: this family says nothing about
// what happens when an individual issuer leaves, which the proposed text leaves open.
const PRINCIPAL = 'did:aps:example:pxe-facility-principal'
const AGENT = 'did:aps:example:pxe-procurement-agent'
const BOUNDARY = 'did:aps:example:pxe-enforcement-boundary'
// A counterparty with a real key and no standing to attest fulfillment for these grants.
const VENDOR = 'did:aps:example:pxe-parts-vendor'

const PRINCIPAL_KEY_ID = `${PRINCIPAL}#key-1`
const AGENT_KEY_ID = `${AGENT}#key-1`
const BOUNDARY_KEY_ID = `${BOUNDARY}#key-1`
const VENDOR_KEY_ID = `${VENDOR}#key-1`

const principalPrivate = seed('principal:v1')
const agentPrivate = seed('agent:v1')
const boundaryPrivate = seed('boundary:v1')
const vendorPrivate = seed('vendor:v1')

const principalPublic = publicKeyFromPrivate(principalPrivate)
const agentPublic = publicKeyFromPrivate(agentPrivate)
const boundaryPublic = publicKeyFromPrivate(boundaryPrivate)
const vendorPublic = publicKeyFromPrivate(vendorPrivate)

// ---------------------------------------------------------------------------
// The timeline. One grant week: issued Monday, not_after Friday 00:00Z. The first
// purchase is Tuesday, the second is Wednesday, and one presentation lands Saturday
// after the grant's own not_after to separate expiry from exhaustion.
// ---------------------------------------------------------------------------

const MONDAY = '2026-09-21T00:00:00.000Z'
const TUESDAY = '2026-09-22T14:00:00.000Z'
const WEDNESDAY = '2026-09-23T10:00:00.000Z'
const FRIDAY = '2026-09-25T00:00:00.000Z'
const SATURDAY = '2026-09-26T09:00:00.000Z'

// One purpose string, hierarchical, so the SDK's own isPurposePermitted can decide
// membership. Membership is the check every SDK does supply. Exhaustion is not.
const PURPOSE = 'procurement:hvac:replace-compressor:ch-3'
const GRANT_SCOPE = 'procurement:hvac:replace-compressor:ch-3'

const BUDGET_UNIT = 'iso4217:USD:minor'
const BUDGET_CUMULATIVE = '480000'

// ---------------------------------------------------------------------------
// Five one-hop AuthorityDelegationV1 grants, principal to agent. Each vector family gets
// its own grant so that consuming one cannot leak into another. They differ only by
// nonce and, for the budget grant, by the signed spend facet.
//
// Note what is NOT here. draft-pidlisnyi-aps-03 section 3.2's authority vector is a closed
// set of seven facets (scope, spend, depth, time, reputation, values, reversibility). It
// has no purpose facet and no use-count facet. The purpose bound and the use-count bound
// therefore cannot live inside a signed delegation at all, which is why this family mints
// them as separate principal-signed artifacts below. That gap is a finding, recorded in
// README.md under "Where the proposed text was too vague to test".
// ---------------------------------------------------------------------------

type Spend = { mode: 'unbounded' } | { mode: 'bounded'; unit: string; per_action: string; cumulative: string }

function authorityVector(spend: Spend) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: [GRANT_SCOPE] },
    spend,
    depth: { remaining: 0 },
    time: { not_before: MONDAY, not_after: FRIDAY },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] as string[] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

function mintGrant(nonceLabel: string, spend: Spend) {
  const body = {
    record_type: 'aps:authority-delegation:v1' as const,
    version: '1.0' as const,
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject: AGENT,
    verification_method: PRINCIPAL_KEY_ID,
    issued_at: MONDAY,
    nonce: seed(nonceLabel).slice(0, 32),
    authority: authorityVector(spend),
  }
  const delegation_id = computeAuthorityDelegationId(body)
  const draft = { ...body, delegation_id }
  const signature = signAuthorityDelegation(draft, principalPrivate)
  return { ...draft, signature }
}

const UNBOUNDED: Spend = { mode: 'unbounded' }
const BOUNDED: Spend = { mode: 'bounded', unit: BUDGET_UNIT, per_action: BUDGET_CUMULATIVE, cumulative: BUDGET_CUMULATIVE }

// GRANT_PURPOSE backs the headline case: one replacement compressor, fulfillment
// established from an authenticated completion record.
const GRANT_PURPOSE = mintGrant('grant-purpose-nonce:v1', UNBOUNDED)
// GRANT_PURPOSE_BAD_SIG and GRANT_PURPOSE_NO_STANDING back the two negative controls.
// Each has its own grant so a rejected completion for one cannot touch the others.
const GRANT_PURPOSE_BAD_SIG = mintGrant('grant-purpose-bad-sig-nonce:v1', UNBOUNDED)
const GRANT_PURPOSE_NO_STANDING = mintGrant('grant-purpose-no-standing-nonce:v1', UNBOUNDED)
// GRANT_USE_COUNT backs the use_count 1 variant, GRANT_BUDGET the budget variant.
const GRANT_USE_COUNT = mintGrant('grant-use-count-nonce:v1', UNBOUNDED)
const GRANT_BUDGET = mintGrant('grant-budget-nonce:v1', BOUNDED)

const resolveDelegationKey = (_issuer: string, method: string) =>
  method === PRINCIPAL_KEY_ID ? principalPublic : null

// ---------------------------------------------------------------------------
// Purpose bounds. A fixture-local profile, not a protocol object.
//
// The proposed text says exhaustion "Ends authority because a declared time, use count,
// budget, purpose or other bound has been reached." It does not say where that bound is
// declared, who may declare a purpose fulfilled, or what evidence establishes fulfillment.
// draft-03 has no wire shape for any of it. This family therefore declares its own,
// signs it with the principal's key, and states plainly in README.md that the shape is
// this fixture's invention rather than anything either text specifies.
//
// fulfillment_attestors is the part that makes the negative controls decidable: it names
// who has standing to say the purpose was fulfilled. Without it, "a party without
// standing" has nothing to be measured against.
// ---------------------------------------------------------------------------

const PURPOSE_BOUND_PROFILE = 'aps-conformance-suite:lifecycle-purpose-exhaustion:purpose-bound-v0'
const PURPOSE_BOUND_SIG_DOMAIN = 'APS-CONFORMANCE-PURPOSE-BOUND-V0'

type Bound =
  | { mode: 'purpose'; purpose: string }
  | { mode: 'use_count'; limit: number }
  | { mode: 'budget'; unit: string; cumulative: string }

function mintPurposeBound(delegationId: string, bound: Bound) {
  const body = {
    profile: PURPOSE_BOUND_PROFILE,
    delegation_id: delegationId,
    issuer: PRINCIPAL,
    verification_method: PRINCIPAL_KEY_ID,
    issued_at: MONDAY,
    purpose: PURPOSE,
    bound,
    // Who may attest that the purpose was fulfilled. The enforcement boundary alone here.
    fulfillment_attestors: [BOUNDARY],
  }
  const payload = `${PURPOSE_BOUND_SIG_DOMAIN} ${canonicalizeJCS(body)}`
  const signature = sign(payload, principalPrivate)
  return { ...body, signature }
}

const BOUND_PURPOSE = mintPurposeBound(GRANT_PURPOSE.delegation_id, { mode: 'purpose', purpose: PURPOSE })
const BOUND_PURPOSE_BAD_SIG = mintPurposeBound(GRANT_PURPOSE_BAD_SIG.delegation_id, { mode: 'purpose', purpose: PURPOSE })
const BOUND_PURPOSE_NO_STANDING = mintPurposeBound(GRANT_PURPOSE_NO_STANDING.delegation_id, { mode: 'purpose', purpose: PURPOSE })
const BOUND_USE_COUNT = mintPurposeBound(GRANT_USE_COUNT.delegation_id, { mode: 'use_count', limit: 1 })
const BOUND_BUDGET = mintPurposeBound(GRANT_BUDGET.delegation_id, { mode: 'budget', unit: BUDGET_UNIT, cumulative: BUDGET_CUMULATIVE })

// ---------------------------------------------------------------------------
// Actions. One action_ref per purchase attempt, each with its own payload and nonce, so
// no two attempts share an identity. The budget ledger keys reservations by action_ref,
// which is why the two budget attempts must differ there too.
// ---------------------------------------------------------------------------

function mintAction(label: string, orderId: string, issuedAt: string) {
  return createActionReferenceInputV2({
    agent_id: AGENT,
    action_type: 'procurement.purchase',
    target: 'https://parts.example/api/v1/orders',
    payload_ref: computePayloadRefV1({ order_id: orderId, part: 'compressor-CH3-REPL', quantity: 1 }),
    scope_required: [GRANT_SCOPE],
    issued_at: issuedAt,
    nonce: seed(`action-nonce:${label}:v1`).slice(0, 32),
  })
}

const ACTIONS = {
  purpose_first: mintAction('purpose-first', 'PO-2026-0921-001', '2026-09-22T13:59:00.000Z'),
  purpose_second: mintAction('purpose-second', 'PO-2026-0923-002', '2026-09-23T09:59:00.000Z'),
  purpose_saturday: mintAction('purpose-saturday', 'PO-2026-0926-003', '2026-09-26T08:59:00.000Z'),
  bad_sig_first: mintAction('bad-sig-first', 'PO-2026-0923-004', '2026-09-23T09:59:00.000Z'),
  no_standing_first: mintAction('no-standing-first', 'PO-2026-0923-005', '2026-09-23T09:59:00.000Z'),
  use_count_first: mintAction('use-count-first', 'PO-2026-0922-006', '2026-09-22T13:59:00.000Z'),
  use_count_second: mintAction('use-count-second', 'PO-2026-0923-007', '2026-09-23T09:59:00.000Z'),
  budget_first: mintAction('budget-first', 'PO-2026-0922-008', '2026-09-22T13:59:00.000Z'),
  budget_second: mintAction('budget-second', 'PO-2026-0923-009', '2026-09-23T09:59:00.000Z'),
} as const

const ACTION_REFS = Object.fromEntries(
  Object.entries(ACTIONS).map(([k, v]) => [k, computeActionRefV2(v)]),
) as Record<keyof typeof ACTIONS, string>

// ---------------------------------------------------------------------------
// Completion records. Real draft-03 section 5.3.3 action-result receipts:
//
//     "An action-result record has receipt_type "aps:action-result:v1".  issuer is the
//     enforcement boundary"
//
// and, on what such a record does and does not establish:
//
//     "An action-result record attests to what the enforcement boundary observed after
//     dispatch.  External occurrence or settlement requires separately resolved
//     evidence."
//
// Three of them:
//   COMPLETION_AUTHENTIC     issuer BOUNDARY, signature verifies. Establishes fulfillment.
//   COMPLETION_BAD_SIGNATURE issuer BOUNDARY, signature bytes flipped after sealing.
//   COMPLETION_NO_STANDING   issuer VENDOR, signature verifies over the vendor's own key.
// ---------------------------------------------------------------------------

type Signer = { signer: string; key_id: string; private_key: string }

const agentSigner: Signer = { signer: AGENT, key_id: AGENT_KEY_ID, private_key: agentPrivate }
const boundarySigner: Signer = { signer: BOUNDARY, key_id: BOUNDARY_KEY_ID, private_key: boundaryPrivate }
const vendorSigner: Signer = { signer: VENDOR, key_id: VENDOR_KEY_ID, private_key: vendorPrivate }

function seal(fields: Record<string, unknown>, signers: Signer[]): Record<string, unknown> {
  return createReceiptV1(fields as never, signers) as unknown as Record<string, unknown>
}

function mintIntent(actionRef: string, delegationId: string, issuedAt: string) {
  return seal(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:action-intent:v1',
      issuer: AGENT,
      subject_agent: AGENT,
      action_ref: actionRef,
      delegation_ref: delegationId,
      issued_at: issuedAt,
      evidence_refs: [],
      result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
    },
    [agentSigner],
  )
}

// draft-03 section 5.3.3: "issuer is the enforcement boundary, prev is the consumed
// policy-decision receipt_id, and decision_ref MUST equal that decision's decision_ref."
// A completion record therefore needs a policy decision behind it, so each of the three
// cases below is a full intent -> decision -> result stage chain, not a bare result.
function mintDecisionEvidence(delegationId: string, actionRef: string, target: string, evaluatedAt: string) {
  const authority_state = {
    profile: 'aps-conformance-suite:lifecycle-purpose-exhaustion:authority-state-v0',
    selected_chain: [delegationId],
    authority_basis: 'delegation',
    spend_state: { mode: 'unbounded' },
  }
  const policy_input = {
    policy_id: 'procurement-replacement-part-v1',
    policy_version: '1.0.0',
    requested_scope: [GRANT_SCOPE],
    target,
  }
  const decision_context = { enforcement_boundary: BOUNDARY, evaluated_at: evaluatedAt }
  const decision_output = {
    profile: 'aps-core-decision-output-v1' as const,
    verdict: 'permit' as const,
    effective_authority_ref: seed(`effective-authority-ref:${actionRef}`),
    constraints: [] as string[],
    valid_until: '2026-09-22T18:00:00.000Z',
  }
  const decision_ref = buildDecisionRefV1({ action_ref: actionRef, authority_state, policy_input, decision_context, decision_output }).decision_ref
  return { authority_state, policy_input, decision_context, decision_output, decision_ref }
}

function mintDecision(prev: string, actionRef: string, evidence: ReturnType<typeof mintDecisionEvidence>) {
  return seal(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:policy-decision:v1',
      issuer: BOUNDARY,
      subject_agent: AGENT,
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

function mintCompletion(opts: {
  issuer: string
  signer: Signer
  actionRef: string
  delegationId: string
  decisionRef: string
  prev: string
  issuedAt: string
  effectLabel: string
}) {
  return seal(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:action-result:v1',
      issuer: opts.issuer,
      subject_agent: AGENT,
      action_ref: opts.actionRef,
      delegation_ref: opts.delegationId,
      decision_ref: opts.decisionRef,
      issued_at: opts.issuedAt,
      evidence_refs: [],
      prev: opts.prev,
      result: {
        profile: 'aps-action-result-v1',
        status: 'succeeded',
        effect_ref: seed(`effect:${opts.effectLabel}`),
        error_code: null,
      },
    },
    [opts.signer],
  )
}

const INTENT_AUTHENTIC = mintIntent(ACTION_REFS.purpose_first, GRANT_PURPOSE.delegation_id, '2026-09-22T14:00:00.000Z')
const INTENT_BAD_SIG = mintIntent(ACTION_REFS.bad_sig_first, GRANT_PURPOSE_BAD_SIG.delegation_id, '2026-09-22T14:00:00.000Z')
const INTENT_NO_STANDING = mintIntent(ACTION_REFS.no_standing_first, GRANT_PURPOSE_NO_STANDING.delegation_id, '2026-09-22T14:00:00.000Z')

const EVIDENCE_AUTHENTIC = mintDecisionEvidence(GRANT_PURPOSE.delegation_id, ACTION_REFS.purpose_first, ACTIONS.purpose_first.target, '2026-09-22T14:00:01.000Z')
const EVIDENCE_BAD_SIG = mintDecisionEvidence(GRANT_PURPOSE_BAD_SIG.delegation_id, ACTION_REFS.bad_sig_first, ACTIONS.bad_sig_first.target, '2026-09-22T14:00:01.000Z')
const EVIDENCE_NO_STANDING = mintDecisionEvidence(GRANT_PURPOSE_NO_STANDING.delegation_id, ACTION_REFS.no_standing_first, ACTIONS.no_standing_first.target, '2026-09-22T14:00:01.000Z')

const DECISION_AUTHENTIC = mintDecision(INTENT_AUTHENTIC.receipt_id as string, ACTION_REFS.purpose_first, EVIDENCE_AUTHENTIC)
const DECISION_BAD_SIG = mintDecision(INTENT_BAD_SIG.receipt_id as string, ACTION_REFS.bad_sig_first, EVIDENCE_BAD_SIG)
const DECISION_NO_STANDING = mintDecision(INTENT_NO_STANDING.receipt_id as string, ACTION_REFS.no_standing_first, EVIDENCE_NO_STANDING)

const COMPLETION_AUTHENTIC = mintCompletion({
  issuer: BOUNDARY,
  signer: boundarySigner,
  actionRef: ACTION_REFS.purpose_first,
  delegationId: GRANT_PURPOSE.delegation_id,
  decisionRef: EVIDENCE_AUTHENTIC.decision_ref,
  prev: DECISION_AUTHENTIC.receipt_id as string,
  issuedAt: '2026-09-22T16:30:00.000Z',
  effectLabel: 'compressor-installed-tuesday',
})

const COMPLETION_NO_STANDING = mintCompletion({
  issuer: VENDOR,
  signer: vendorSigner,
  actionRef: ACTION_REFS.no_standing_first,
  delegationId: GRANT_PURPOSE_NO_STANDING.delegation_id,
  decisionRef: EVIDENCE_NO_STANDING.decision_ref,
  prev: DECISION_NO_STANDING.receipt_id as string,
  issuedAt: '2026-09-22T16:30:00.000Z',
  effectLabel: 'compressor-installed-vendor-says-so',
})

// The unauthenticated one: sealed exactly like the authentic record, then its signature
// is replaced with a well-formed Ed25519 signature over different content, so the record
// is structurally intact and cryptographically wrong. This is the record a naive
// implementation reads result.status from without checking who signed it.
const COMPLETION_BAD_SIGNATURE_SEALED = mintCompletion({
  issuer: BOUNDARY,
  signer: boundarySigner,
  actionRef: ACTION_REFS.bad_sig_first,
  delegationId: GRANT_PURPOSE_BAD_SIG.delegation_id,
  decisionRef: EVIDENCE_BAD_SIG.decision_ref,
  prev: DECISION_BAD_SIG.receipt_id as string,
  issuedAt: '2026-09-22T16:30:00.000Z',
  effectLabel: 'compressor-installed-claim-unauthenticated',
})

const forgedSignature = sign(
  `${PURPOSE_BOUND_SIG_DOMAIN} forged-not-the-receipt-signing-payload`,
  boundaryPrivate,
)
const COMPLETION_BAD_SIGNATURE = {
  ...COMPLETION_BAD_SIGNATURE_SEALED,
  // ReceiptSignatureV1 carries the signature in `value`. Only that field is replaced, so
  // the envelope stays exactly the shape createReceiptV1 produced and the record fails on
  // its signature rather than on its shape. A shape failure would test the wrong thing.
  signatures: (COMPLETION_BAD_SIGNATURE_SEALED.signatures as Array<Record<string, unknown>>).map((s) => ({
    ...s,
    value: forgedSignature,
  })),
}

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written. Every claim this family
// makes about what the SDK returns is checked here and recorded in records-bounds.json, so the
// README quotes a recorded value rather than a remembered one.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint-bounds.ts: ${message}`)
    process.exit(1)
  }
}

const grantIds = [
  GRANT_PURPOSE.delegation_id,
  GRANT_PURPOSE_BAD_SIG.delegation_id,
  GRANT_PURPOSE_NO_STANDING.delegation_id,
  GRANT_USE_COUNT.delegation_id,
  GRANT_BUDGET.delegation_id,
]
assert(new Set(grantIds).size === grantIds.length, 'two grants share a delegation_id')

// Every purpose bound verifies under exactly the rule harness.ts applies: the principal's
// signature over the domain string, a space, and the JCS canonical bytes of the body
// without its signature field.
for (const [label, bound] of Object.entries({
  BOUND_PURPOSE, BOUND_PURPOSE_BAD_SIG, BOUND_PURPOSE_NO_STANDING, BOUND_USE_COUNT, BOUND_BUDGET,
})) {
  const { signature, ...body } = bound
  const payload = `${PURPOSE_BOUND_SIG_DOMAIN} ${canonicalizeJCS(body)}`
  assert(verifyEd25519(payload, signature, principalPublic), `${label} does not verify under the harness rule`)
}

const actionRefValues = Object.values(ACTION_REFS)
assert(new Set(actionRefValues).size === actionRefValues.length, 'two actions share an action_ref')

const chainOpts = (now: string, revocation: 'active' | 'revoked' = 'active') => ({
  now,
  resolveVerificationKey: resolveDelegationKey,
  trustRoot: () => true,
  resolveRevocation: () => revocation as 'active' | 'revoked',
})

// Every grant verifies valid on Tuesday and on Wednesday, with the resolver answering
// active. This is the load-bearing fact of the whole family: on Wednesday the grant that
// has already bought its one compressor is still a valid, unrevoked, unexpired chain.
const wednesdayStates: Record<string, string> = {}
for (const [label, grant] of Object.entries({
  purpose: GRANT_PURPOSE,
  purpose_bad_sig: GRANT_PURPOSE_BAD_SIG,
  purpose_no_standing: GRANT_PURPOSE_NO_STANDING,
  use_count: GRANT_USE_COUNT,
  budget: GRANT_BUDGET,
})) {
  const tue = verifyAuthorityDelegationChain([grant], chainOpts(TUESDAY))
  assert(tue.state === 'valid', `${label} does not verify valid on Tuesday: ${JSON.stringify(tue)}`)
  const wed = verifyAuthorityDelegationChain([grant], chainOpts(WEDNESDAY))
  assert(wed.state === 'valid', `${label} does not verify valid on Wednesday: ${JSON.stringify(wed)}`)
  wednesdayStates[label] = wed.state
}

// Saturday is after the grant's own not_after, so the same chain is no longer valid.
// Recorded, not assumed: whatever failure code the SDK gives is written into records-bounds.json.
const saturdayResult = verifyAuthorityDelegationChain([GRANT_PURPOSE], chainOpts(SATURDAY))
assert(saturdayResult.state !== 'valid', 'GRANT_PURPOSE still verifies valid after its not_after')
const saturdayCode = saturdayResult.failures[0]?.code ?? null
assert(typeof saturdayCode === 'string', 'expired chain produced no failure code')

// The SDK's purpose check answers the membership question and nothing else: the Wednesday
// purchase requests exactly the purpose the grant allows, so membership passes for both
// the first and the second purchase. That is why membership cannot decide exhaustion.
const membershipFirst = isPurposePermitted(PURPOSE, [GRANT_SCOPE])
const membershipSecond = isPurposePermitted(PURPOSE, [GRANT_SCOPE])
assert(membershipFirst === true, 'isPurposePermitted rejected the first purchase purpose')
assert(membershipSecond === true, 'isPurposePermitted rejected the second purchase purpose')

// Receipt verification. The resolver here is the one harness.ts uses.
const resolveReceiptSignerKey = (signer: string, keyId: string) => {
  if (signer === AGENT && keyId === AGENT_KEY_ID) return agentPublic
  if (signer === BOUNDARY && keyId === BOUNDARY_KEY_ID) return boundaryPublic
  if (signer === VENDOR && keyId === VENDOR_KEY_ID) return vendorPublic
  return undefined
}

const authenticResult = verifyReceiptV1(COMPLETION_AUTHENTIC as never, resolveReceiptSignerKey, { boundaryIdentity: BOUNDARY })
assert(authenticResult.status === 'valid', `COMPLETION_AUTHENTIC does not verify valid: ${JSON.stringify(authenticResult)}`)

const badSigResult = verifyReceiptV1(COMPLETION_BAD_SIGNATURE as never, resolveReceiptSignerKey, { boundaryIdentity: BOUNDARY })
assert(badSigResult.status !== 'valid', 'COMPLETION_BAD_SIGNATURE verifies valid, which defeats the negative control')

// The standing control. The vendor-issued record is presented to the SDK with the
// boundary named in the grant's own fulfillment_attestors list as the expected identity.
// Whatever the SDK answers on its boundary_identity axis is recorded, not assumed.
const noStandingResult = verifyReceiptV1(COMPLETION_NO_STANDING as never, resolveReceiptSignerKey, { boundaryIdentity: BOUNDARY })
const noStandingBoundaryAxis =
  (noStandingResult as unknown as { stage?: { boundary_identity?: string } }).stage?.boundary_identity ??
  (noStandingResult as unknown as { boundary_identity?: string }).boundary_identity ??
  null

// The vendor's own signature is genuine. The record is not unauthenticated. It is
// authenticated by someone without standing, and those two must not be confused.
const noStandingAsVendor = verifyReceiptV1(COMPLETION_NO_STANDING as never, resolveReceiptSignerKey, { boundaryIdentity: VENDOR })
assert(
  noStandingAsVendor.status === 'valid',
  `COMPLETION_NO_STANDING should verify valid when the vendor is the expected boundary: ${JSON.stringify(noStandingAsVendor)}`,
)

for (const [label, receipt] of Object.entries({ INTENT_AUTHENTIC, INTENT_BAD_SIG, INTENT_NO_STANDING })) {
  const r = verifyReceiptV1(receipt as never, resolveReceiptSignerKey, {})
  assert(r.status === 'valid' || r.status === 'indeterminate', `${label} does not verify: ${JSON.stringify(r)}`)
}
for (const [label, receipt] of Object.entries({ DECISION_AUTHENTIC, DECISION_BAD_SIG, DECISION_NO_STANDING })) {
  const r = verifyReceiptV1(receipt as never, resolveReceiptSignerKey, { boundaryIdentity: BOUNDARY })
  assert(r.status === 'valid', `${label} does not verify valid: ${JSON.stringify(r)}`)
}

// The budget ledger is the one exhaustion dimension a reference SDK implements. Checked
// here so the family's expectation for PXE-07 comes from the SDK rather than from us.
const mintLedger = new InMemoryAuthorityBudgetLedger()
const reserveFirst = mintLedger.reserve([GRANT_BUDGET], ACTION_REFS.budget_first, BUDGET_UNIT, BUDGET_CUMULATIVE)
assert(reserveFirst.ok, `budget reserve of the full cumulative failed: ${JSON.stringify(reserveFirst)}`)
mintLedger.markDispatched(ACTION_REFS.budget_first)
const commitFirst = mintLedger.commit(ACTION_REFS.budget_first)
assert(commitFirst.ok, `budget commit failed: ${JSON.stringify(commitFirst)}`)
const reserveSecond = mintLedger.reserve([GRANT_BUDGET], ACTION_REFS.budget_second, BUDGET_UNIT, '1')
assert(!reserveSecond.ok, 'a second reservation against an exhausted cumulative succeeded')
const budgetExhaustedCode = reserveSecond.code

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
  profile: 'aps-lifecycle-purpose-exhaustion-v0',
  description:
    'Exhaustion by purpose, by use count and by budget as a lifecycle state separate from ' +
    'revocation and from expiry. Five one-hop AuthorityDelegationV1 grants, five ' +
    'principal-signed purpose bounds (a fixture-local profile, not a protocol object), ' +
    'nine actions, three action-intent receipts and three action-result completion ' +
    'records, minted and verified with agent-passport-system 7.1.0.',
  minted_by: 'fixtures/lifecycle-purpose-exhaustion/mint-bounds.ts',
  seed_label_prefix: SEED_PREFIX,
  sdk: { typescript: 'agent-passport-system@7.1.0' },
  identities: { principal: PRINCIPAL, agent: AGENT, enforcement_boundary: BOUNDARY, vendor_without_standing: VENDOR },
  verification_keys: {
    [PRINCIPAL_KEY_ID]: principalPublic,
    [AGENT_KEY_ID]: agentPublic,
    [BOUNDARY_KEY_ID]: boundaryPublic,
    [VENDOR_KEY_ID]: vendorPublic,
  },
  purpose: PURPOSE,
  timeline: { monday: MONDAY, tuesday: TUESDAY, wednesday: WEDNESDAY, friday_not_after: FRIDAY, saturday: SATURDAY },
  grants: {
    purpose: GRANT_PURPOSE,
    purpose_bad_sig: GRANT_PURPOSE_BAD_SIG,
    purpose_no_standing: GRANT_PURPOSE_NO_STANDING,
    use_count: GRANT_USE_COUNT,
    budget: GRANT_BUDGET,
  },
  purpose_bounds: {
    purpose: BOUND_PURPOSE,
    purpose_bad_sig: BOUND_PURPOSE_BAD_SIG,
    purpose_no_standing: BOUND_PURPOSE_NO_STANDING,
    use_count: BOUND_USE_COUNT,
    budget: BOUND_BUDGET,
  },
  purpose_bound_signature_domain: PURPOSE_BOUND_SIG_DOMAIN,
  decision_evidence: {
    decision_authentic: EVIDENCE_AUTHENTIC,
    decision_bad_sig: EVIDENCE_BAD_SIG,
    decision_no_standing: EVIDENCE_NO_STANDING,
  },
  actions: Object.fromEntries(
    Object.entries(ACTIONS).map(([k, v]) => [k, { input: v, action_ref: ACTION_REFS[k as keyof typeof ACTIONS] }]),
  ),
  receipts: {
    intent_authentic: INTENT_AUTHENTIC,
    intent_bad_sig: INTENT_BAD_SIG,
    intent_no_standing: INTENT_NO_STANDING,
    decision_authentic: DECISION_AUTHENTIC,
    decision_bad_sig: DECISION_BAD_SIG,
    decision_no_standing: DECISION_NO_STANDING,
    completion_authentic: COMPLETION_AUTHENTIC,
    completion_bad_signature: COMPLETION_BAD_SIGNATURE,
    completion_no_standing: COMPLETION_NO_STANDING,
  },
  // Recorded SDK observations, taken at mint time from the pinned SDK rather than written
  // by hand. README.md and the handoff quote these values.
  mint_time_sdk_observations: {
    chain_state_wednesday: wednesdayStates,
    chain_state_saturday: { state: saturdayResult.state, first_failure_code: saturdayCode },
    is_purpose_permitted_first_purchase: membershipFirst,
    is_purpose_permitted_second_purchase: membershipSecond,
    completion_authentic_status: authenticResult.status,
    completion_bad_signature_status: badSigResult.status,
    completion_no_standing_status_expecting_boundary: noStandingResult.status,
    completion_no_standing_boundary_identity_axis: noStandingBoundaryAxis,
    completion_no_standing_status_expecting_vendor: noStandingAsVendor.status,
    budget_reserve_full_cumulative: reserveFirst.code,
    budget_commit_full_cumulative: commitFirst.code,
    budget_reserve_one_more_minor_unit: budgetExhaustedCode,
  },
}

fs.writeFileSync(path.join(here, 'records-bounds.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('lifecycle-purpose-exhaustion: records-bounds.json minted')
console.log(`  chain state on Wednesday, every grant: ${JSON.stringify(wednesdayStates)}`)
console.log(`  chain state on Saturday: ${saturdayResult.state}/${saturdayCode}`)
console.log(`  isPurposePermitted, second purchase: ${membershipSecond}`)
console.log(`  budget reserve of one more minor unit: ${budgetExhaustedCode}`)
console.log(`  completion_no_standing boundary_identity axis: ${noStandingBoundaryAxis}`)
