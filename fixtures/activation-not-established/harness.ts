// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The activation gate this family supplies, in five configurations.
//
// v2. The gate returns two distinct negative verdicts where v1 returned one:
//
//   not_yet_effective  the verifier establishes, from evidence the model
//                      accepts, that the condition had not been met at the
//                      action instant. A positive finding. The remedy is to
//                      wait.
//   not_established    the verifier cannot tell whether the condition was met,
//                      because nothing was presented, because what was
//                      presented is unusable, because it comes from a source
//                      the model does not accept for this condition, or because
//                      two acceptable records disagree. The remedy is a better
//                      source.
//
// Neither is invalid and neither is exercisable. Collapsing the first into the
// second throws away a decidable answer the verifier already had, which is what
// gate N4 exists to make visible.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real
// agent-passport-system chain verifier for the grant, and the real SDK Ed25519
// verify plus RFC 8785 canonicalizer for an attestation's signature. Everything
// after that -- the activation conditions, the attestor-role registry, the
// condition binding, the occurrence comparison against the action instant, and
// the four verdict names -- is implemented here, because neither reference SDK
// exposes an API for any of it. A pass is a result about this gate, not a
// conformance result about either SDK. README says this again, at length.
//
// VERDICT NAMES ARE NOT SUITE VOCABULARY. exercisable, not_yet_effective,
// not_established and invalid are this family's own local labels for
// discussion. CONTRIBUTING.md reserves failure-class names and verifier
// semantics to the maintainer, so these names are a proposal and not a minted
// taxonomy.

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

export type Verdict = 'exercisable' | 'not_yet_effective' | 'not_established' | 'invalid'
export type Stage = 'chain' | 'activation'

export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface EventActivationCondition {
  condition_id: string
  condition_type: 'recorded_event'
  description: string
  event_type: string
  event_id: string
  required_attestor_role: string
}

export interface DateActivationCondition {
  condition_id: string
  condition_type: 'date'
  description: string
  activation_date: string
}

export type ActivationCondition = EventActivationCondition | DateActivationCondition

export interface Attestation {
  record_type: string
  version: string
  assertion: 'condition_occurred' | 'condition_not_occurred_through'
  attestation_id: string
  signature: string
  attestor: string
  attestor_role: string
  condition_id: string
  event_id: string
  event_type: string
  occurred_at?: string
  not_occurred_through?: string
  attested_at: string
  verification_method: string
  [key: string]: unknown
}

export interface ChainFixture {
  clock: Record<string, string>
  verification_keys: Record<string, string>
  attestor_role_registry: Record<string, string>
  activation_conditions: Record<string, ActivationCondition | null>
  roles: Record<string, string>
  chains: Record<string, unknown[]>
  attestations: Record<string, Attestation>
}

export interface GateResult {
  verdict: Verdict
  stage: Stage
  code: string
  chain_state: string
  chain_failure_index: number | null
  /** One entry per presented attestation, in presentation order. */
  attestation_notes: string[]
}

export interface GateOptions {
  /** N1: read the role from the attestation body instead of the registry. */
  trustSelfDeclaredRole?: boolean
  /** N2: treat the instant the attestation was written as the instant the
   *  condition occurred, which is the defect the rewritten candidate text
   *  names. An occurrence attested after the action is rejected outright and
   *  an occurrence attested before it is taken to have happened before it. */
  keyOnAttestationDate?: boolean
  /** N3: report invalid wherever the reference gate reports not_established at
   *  the activation stage. */
  collapseNotEstablishedIntoInvalid?: boolean
  /** N4: report not_established wherever the reference gate reports
   *  not_yet_effective, which is the collapse the two-verdict split exists to
   *  prevent. */
  collapseNotYetEffectiveIntoNotEstablished?: boolean
}

// Rejection reasons, in check order. An attestation that fails one of these is
// not evidence at all, in either direction. The gate reports the reason of the
// attestation that got FURTHEST through the checks, so the code names the
// closest thing to usable evidence that was presented. Ties are broken by
// attestation_id ascending, which makes the answer independent of presentation
// order.
const REASON_RANK: Record<string, number> = {
  attestation_signature_unverified: 1,
  attestation_attestor_binding_mismatch: 2,
  attestation_role_claim_conflict: 3,
  attestation_attestor_role_mismatch: 4,
  attestation_condition_mismatch: 5,
  attestation_unknown_assertion: 6,
  attestation_does_not_reach_action: 7,
}

/** Rebuild the signed preimage: the body with no attestation_id and no
 *  signature member, canonicalized under RFC 8785 by the SDK's own
 *  canonicalizer. */
export function attestationPreimage(attestation: Attestation): string {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(attestation)) {
    if (key === 'attestation_id' || key === 'signature') continue
    body[key] = value
  }
  return canonicalizeJCS(body)
}

/** What an accepted attestation establishes about the condition at the action
 *  instant. Rejected attestations establish nothing. */
type Finding = 'occurred_by_action' | 'occurred_after_action' | 'not_occurred_through_action'

function classify(
  fixture: ChainFixture,
  attestation: Attestation,
  condition: EventActivationCondition,
  actionAt: string,
  options: GateOptions,
): { ok: true; finding: Finding } | { ok: false; reason: string } {
  // 1. Signature, using the SDK's Ed25519 verify over the SDK's canonical bytes.
  const publicKey = fixture.verification_keys[attestation.verification_method]
  if (typeof publicKey !== 'string') return { ok: false, reason: 'attestation_signature_unverified' }
  let signatureOk = false
  try {
    signatureOk = verifyEd25519(attestationPreimage(attestation), attestation.signature, publicKey)
  } catch {
    signatureOk = false
  }
  if (!signatureOk) return { ok: false, reason: 'attestation_signature_unverified' }

  // 2. The verification method has to belong to the attestor the body names,
  //    or a valid signature would say nothing about who attested.
  if (!attestation.verification_method.startsWith(`${attestation.attestor}#`)) {
    return { ok: false, reason: 'attestation_attestor_binding_mismatch' }
  }

  // 3. Role. The registry is authoritative. attestor_role is the attestor's own
  //    claim about itself; a claim that disagrees with the registry is reported
  //    as its own reason rather than folded into a plain role mismatch. A
  //    source the model does not accept for this condition is not evidence in
  //    either direction: it cannot establish the condition and it cannot
  //    establish that the condition has not been met.
  const registeredRole = fixture.attestor_role_registry[attestation.attestor]
  if (options.trustSelfDeclaredRole) {
    if (attestation.attestor_role !== condition.required_attestor_role) {
      return { ok: false, reason: 'attestation_attestor_role_mismatch' }
    }
  } else {
    if (typeof registeredRole !== 'string' || registeredRole !== attestation.attestor_role) {
      return { ok: false, reason: 'attestation_role_claim_conflict' }
    }
    if (registeredRole !== condition.required_attestor_role) {
      return { ok: false, reason: 'attestation_attestor_role_mismatch' }
    }
  }

  // 4. Condition binding.
  if (
    attestation.condition_id !== condition.condition_id ||
    attestation.event_type !== condition.event_type ||
    attestation.event_id !== condition.event_id
  ) {
    return { ok: false, reason: 'attestation_condition_mismatch' }
  }

  // 5. What it establishes, measured on the condition's own instants. The
  //    instant the record was written, attested_at, is never compared with the
  //    action instant by the reference gate: a record written on Thursday can
  //    establish a condition that obtained on Monday.
  if (attestation.assertion === 'condition_occurred') {
    const occurredAt = options.keyOnAttestationDate ? attestation.attested_at : attestation.occurred_at
    if (typeof occurredAt !== 'string') return { ok: false, reason: 'attestation_unknown_assertion' }
    if (options.keyOnAttestationDate && occurredAt > actionAt) {
      // N2's defect: the record is thrown away rather than read as evidence
      // that the condition was met after the action.
      return { ok: false, reason: 'attestation_does_not_reach_action' }
    }
    return { ok: true, finding: occurredAt <= actionAt ? 'occurred_by_action' : 'occurred_after_action' }
  }

  if (attestation.assertion === 'condition_not_occurred_through') {
    const through = attestation.not_occurred_through
    if (typeof through !== 'string') return { ok: false, reason: 'attestation_unknown_assertion' }
    // A negative that stops short of the action instant says nothing about the
    // interval between where it stops and the action.
    if (through < actionAt) return { ok: false, reason: 'attestation_does_not_reach_action' }
    return { ok: true, finding: 'not_occurred_through_action' }
  }

  return { ok: false, reason: 'attestation_unknown_assertion' }
}

function applyCollapses(verdict: Verdict, options: GateOptions): Verdict {
  if (verdict === 'not_established' && options.collapseNotEstablishedIntoInvalid) return 'invalid'
  if (verdict === 'not_yet_effective' && options.collapseNotYetEffectiveIntoNotEstablished) {
    return options.collapseNotEstablishedIntoInvalid ? 'invalid' : 'not_established'
  }
  return verdict
}

export function evaluate(
  fixture: ChainFixture,
  grantName: string,
  presentedAttestationIds: string[],
  actionAt: string,
  revocation: RevocationAnswer,
  options: GateOptions = {},
): GateResult {
  const chain = fixture.chains[grantName]
  if (chain === undefined) throw new Error(`activation-not-established: unknown grant ${grantName}`)

  // Stage one, the real SDK. Chain verification decides valid, invalid,
  // indeterminate or unsupported before the activation question is asked.
  const chainResult = verifyAuthorityDelegationChain(chain as never, {
    now: actionAt,
    resolveVerificationKey: ((_issuer: string, method: string) =>
      fixture.verification_keys[method] ?? null) as never,
    trustRoot: () => true,
    resolveRevocation: () => revocation,
  })
  const firstFailure = Array.isArray(chainResult.failures) ? chainResult.failures[0] : undefined
  const chainFailureIndex = typeof firstFailure?.index === 'number' ? firstFailure.index : null

  if (chainResult.state !== 'valid') {
    // invalid stays invalid. indeterminate and unsupported are not established:
    // the verifier could not establish current authority, which is not a claim
    // that the grant is bad and is not a claim that anything is merely waiting.
    return {
      verdict: chainResult.state === 'invalid' ? 'invalid' : 'not_established',
      stage: 'chain',
      code: firstFailure?.code ?? 'CHAIN_NOT_VALID',
      chain_state: chainResult.state,
      chain_failure_index: chainFailureIndex,
      attestation_notes: [],
    }
  }

  // Stage two, supplied by this fixture.
  const condition = fixture.activation_conditions[grantName] ?? null
  if (condition === null) {
    return {
      verdict: 'exercisable',
      stage: 'activation',
      code: 'no_activation_condition',
      chain_state: chainResult.state,
      chain_failure_index: null,
      attestation_notes: [],
    }
  }

  // A date condition needs no evidence at all. The verifier reads the date off
  // the condition and compares it with the action instant, so an unreached date
  // is a known negative and never an unknown one.
  if (condition.condition_type === 'date') {
    const reached = actionAt >= condition.activation_date
    return {
      verdict: applyCollapses(reached ? 'exercisable' : 'not_yet_effective', options),
      stage: 'activation',
      code: reached ? 'activation_established' : 'condition_date_not_reached',
      chain_state: chainResult.state,
      chain_failure_index: null,
      attestation_notes: presentedAttestationIds.map(label => `${label}=not_consulted_date_condition`),
    }
  }

  const notes: string[] = []
  const rejections: Array<{ id: string; reason: string }> = []
  const findings = new Set<Finding>()

  for (const label of presentedAttestationIds) {
    const attestation = fixture.attestations[label]
    if (attestation === undefined) {
      throw new Error(`activation-not-established: unknown attestation ${label}`)
    }
    const outcome = classify(fixture, attestation, condition, actionAt, options)
    if (outcome.ok) {
      findings.add(outcome.finding)
      notes.push(`${label}=${outcome.finding}`)
    } else {
      rejections.push({ id: attestation.attestation_id, reason: outcome.reason })
      notes.push(`${label}=${outcome.reason}`)
    }
  }

  const base = {
    stage: 'activation' as const,
    chain_state: chainResult.state,
    chain_failure_index: null,
    attestation_notes: notes,
  }

  // Two acceptable records that contradict each other about the action instant
  // leave the verifier unable to tell, which is not established and not a
  // finding that the condition was unmet.
  if (findings.has('occurred_by_action') && findings.has('not_occurred_through_action')) {
    return {
      ...base,
      verdict: applyCollapses('not_established', options),
      code: 'condition_evidence_conflict',
    }
  }

  if (findings.has('occurred_by_action')) {
    return { ...base, verdict: 'exercisable', code: 'activation_established' }
  }

  // Established not met, by a record from a source the model accepts. Positive
  // finding, distinct from an absence of evidence.
  if (findings.has('not_occurred_through_action')) {
    return {
      ...base,
      verdict: applyCollapses('not_yet_effective', options),
      code: 'condition_established_not_yet_occurred',
    }
  }

  // Acceptable evidence that the condition was first met after the action. The
  // same record establishes the condition for any later action, which is what
  // makes this a wait and not a failure.
  if (findings.has('occurred_after_action')) {
    return {
      ...base,
      verdict: applyCollapses('not_yet_effective', options),
      code: 'condition_first_occurred_after_action',
    }
  }

  let code = 'no_attestation_presented'
  if (rejections.length > 0) {
    const sorted = [...rejections].sort((a, b) => {
      const rankDelta = (REASON_RANK[b.reason] ?? 0) - (REASON_RANK[a.reason] ?? 0)
      return rankDelta !== 0 ? rankDelta : a.id.localeCompare(b.id)
    })
    code = sorted[0].reason
  }

  return { ...base, verdict: applyCollapses('not_established', options), code }
}

export const GATES: Record<string, GateOptions> = {
  'reference-gate': {},
  'N1-trusts-self-declared-role': { trustSelfDeclaredRole: true },
  'N2-keys-on-attestation-date': { keyOnAttestationDate: true },
  'N3-collapses-not-established-into-invalid': { collapseNotEstablishedIntoInvalid: true },
  'N4-collapses-not-yet-effective-into-not-established': {
    collapseNotYetEffectiveIntoNotEstablished: true,
  },
}
