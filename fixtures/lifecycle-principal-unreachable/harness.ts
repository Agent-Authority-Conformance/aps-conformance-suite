// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The confirmation gate this family supplies, plus five defective
// configurations used as negative controls.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real agent-passport-system
// chain verifier for the grant, and the real SDK Ed25519 verify plus the real
// RFC 8785 canonicalizer for every fixture-local record. The confirmation
// procedure, the per-action confirmation record, the unreachability and
// deadline observations and the six verdict names are implemented here,
// because neither reference SDK exposes an API for any of them.
//
// NOTHING IS REVOKED IN THIS FAMILY. Every vector answers active to the
// revocation resolver and the chain verifies valid at every action instant
// except the two chain-stage controls. A not_established verdict here is
// therefore never an unknown revocation state: it says the action was never
// established as authorized, which is the distinction this family exists for.
//
// VERDICT NAMES ARE NOT SUITE VOCABULARY. NO LEGAL CLAIM: see README.md.

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export type Stage = 'chain' | 'terms' | 'confirmation'
export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface SignedRecord {
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface ConfirmationEvent extends SignedRecord {
  event_id: string
  event_type: string
  attestor: string
  attestor_role: string
  subject_ref: string
  occurred_at: string
  recorded_at: string
  payload: Record<string, unknown>
}

export interface GrantTerms extends SignedRecord {
  terms_id: string
  delegation_id: string
  issuer: string
  terms: Record<string, unknown>
}

export interface ChainFixture {
  clock: Record<string, string>
  order_ref: string
  verification_keys: Record<string, string>
  attestor_role_registry: Record<string, string>
  event_standing: Record<string, string>
  terms_by_chain: Record<string, string>
  grant_terms: Record<string, GrantTerms>
  events: Record<string, ConfirmationEvent>
  chains: Record<string, Array<Record<string, unknown>>>
}

export interface GateOptions {
  /** N1: once the agreed deadline has passed with no answer, the action is
   *  treated as approved. */
  silenceAfterDeadlineIsApproval?: boolean
  /** N2: an unreachable principal is treated as a denial. */
  unreachableIsDenial?: boolean
  /** N3: any authentic confirmation is accepted, whoever signed it. */
  acceptsConfirmationFromAnyParty?: boolean
  /** N4: a confirmation is accepted without checking that it names this order
   *  and this procedure. */
  ignoresConfirmationBinding?: boolean
  /** N5: a confirmation recorded after the action instant is taken to cover
   *  that action. */
  acceptsConfirmationAfterTheAction?: boolean
}

export interface GateResult {
  verdict: Verdict
  stage: Stage
  code: string
  chain_state: string
  chain_failure_index: number | null
  notes: string[]
}

export interface VectorCase {
  id: string
  case_id: string
  status: string
  tests: string
  polarity: 'positive' | 'negative'
  negative_control?: boolean
  negative_control_note?: string
  grant: string
  action_class: string
  order_ref: string
  action_at: string
  revocation: RevocationAnswer
  presented_events: string[]
  expected: { verdict: Verdict; stage: Stage; code: string }
}

export function recordPreimage(record: SignedRecord, dropKeys: string[]): string {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (dropKeys.includes(key)) continue
    body[key] = value
  }
  return canonicalizeJCS(body)
}

function signatureOk(fixture: ChainFixture, record: SignedRecord, dropKeys: string[]): boolean {
  const publicKey = fixture.verification_keys[record.verification_method]
  if (typeof publicKey !== 'string') return false
  try {
    return verifyEd25519(recordPreimage(record, dropKeys), record.signature, publicKey)
  } catch {
    return false
  }
}

function classify(
  fixture: ChainFixture,
  label: string,
  requiredConfirmer: string,
  options: GateOptions,
): { ok: true; event: ConfirmationEvent } | { ok: false; reason: string } {
  const event = fixture.events[label]
  if (event === undefined) return { ok: false, reason: 'event_record_unknown' }
  if (!signatureOk(fixture, event, ['event_id', 'signature'])) {
    return { ok: false, reason: 'event_signature_unverified' }
  }
  if (!event.verification_method.startsWith(`${event.attestor}#`)) {
    return { ok: false, reason: 'event_attestor_binding_mismatch' }
  }
  const requiredRole = fixture.event_standing[event.event_type]
  if (typeof requiredRole !== 'string') {
    return { ok: false, reason: 'event_type_has_no_declared_standing' }
  }
  if (requiredRole === 'grant-principal') {
    // Who may confirm is a term of the procedure, read off the grant's terms.
    if (!options.acceptsConfirmationFromAnyParty && event.attestor !== requiredConfirmer) {
      return { ok: false, reason: 'confirmation_source_not_accepted' }
    }
  } else {
    const registeredRole = fixture.attestor_role_registry[event.attestor]
    if (typeof registeredRole !== 'string' || registeredRole !== event.attestor_role) {
      return { ok: false, reason: 'event_role_claim_conflict' }
    }
    if (registeredRole !== requiredRole) {
      return { ok: false, reason: 'event_attestor_role_mismatch' }
    }
  }
  return { ok: true, event }
}

export function gate(
  fixture: ChainFixture,
  vector: VectorCase,
  options: GateOptions = {},
): GateResult {
  const chain = fixture.chains[vector.grant]
  const now = fixture.clock[vector.action_at]
  const notes: string[] = []

  const chainResult = verifyAuthorityDelegationChain(chain as never, {
    now,
    resolveVerificationKey: ((_issuer: string, method: string) =>
      fixture.verification_keys[method] ?? null) as never,
    trustRoot: () => true,
    resolveRevocation: (() => vector.revocation) as never,
  }) as { state: string; failures?: Array<{ code: string; index: number }> }

  const chainState = chainResult.state
  const chainFailure = chainResult.failures?.[0] ?? null
  const finish = (verdict: Verdict, stage: Stage, code: string): GateResult => ({
    verdict,
    stage,
    code,
    chain_state: chainState,
    chain_failure_index: chainFailure ? chainFailure.index : null,
    notes,
  })

  if (chainState !== 'valid') {
    return finish(
      chainState === 'invalid' ? 'invalid' : 'not_established',
      'chain',
      chainFailure ? chainFailure.code : `chain_${chainState}`,
    )
  }

  const termsRecord = fixture.grant_terms[fixture.terms_by_chain[vector.grant]]
  if (termsRecord === undefined) return finish('not_established', 'terms', 'grant_terms_unknown')
  if (!signatureOk(fixture, termsRecord, ['terms_id', 'signature'])) {
    return finish('not_established', 'terms', 'grant_terms_signature_unverified')
  }
  const named = chain.find(member => member.delegation_id === termsRecord.delegation_id)
  if (named === undefined || named.issuer !== termsRecord.issuer) {
    return finish('not_established', 'terms', 'grant_terms_not_bound_to_chain')
  }

  const procedure = termsRecord.terms.confirmation_procedure as
    | {
        procedure_id: string
        required_confirmer: string
        applies_to_action_classes: string[]
        deadline?: string
      }
    | undefined

  if (procedure === undefined || !procedure.applies_to_action_classes.includes(vector.action_class)) {
    return finish('valid', 'confirmation', 'no_confirmation_required')
  }

  const accepted: ConfirmationEvent[] = []
  for (const label of vector.presented_events) {
    const result = classify(fixture, label, procedure.required_confirmer, options)
    if (result.ok) {
      accepted.push(result.event)
      notes.push(`${label}=accepted`)
    } else {
      notes.push(`${label}=rejected:${result.reason}`)
    }
  }
  const of = (eventType: string) => accepted.filter(event => event.event_type === eventType)

  const confirmations = of('principal_confirmation')
  const bound = confirmations.filter(event => {
    if (options.ignoresConfirmationBinding) return true
    return (
      event.payload.procedure_id === procedure.procedure_id &&
      event.payload.order_ref === vector.order_ref
    )
  })
  const covering = bound.filter(event => {
    if (options.acceptsConfirmationAfterTheAction) return true
    return (event.payload.confirmed_at as string) <= now
  })

  if (covering.length > 0) {
    return finish('valid', 'confirmation', 'confirmation_procedure_completed')
  }

  if (bound.length > 0) {
    // A confirmation exists for this order and it does not reach this action
    // instant. That is a positive finding about this action, distinct from
    // having no answer at all.
    return finish('not_established', 'confirmation', 'confirmation_after_action')
  }

  const deadlinePassed = of('deadline_elapsed_observation').find(
    event => event.payload.order_ref === vector.order_ref && event.occurred_at <= now,
  )
  if (deadlinePassed !== undefined && options.silenceAfterDeadlineIsApproval) {
    notes.push('silence_after_deadline_is_approval=on')
    return finish('valid', 'confirmation', 'confirmation_procedure_completed')
  }

  const unreachable = of('unreachability_observation').find(
    event => event.payload.order_ref === vector.order_ref && event.occurred_at <= now,
  )
  if (unreachable !== undefined && options.unreachableIsDenial) {
    notes.push('unreachable_is_denial=on')
    return finish('invalid', 'confirmation', 'unreachable_principal_denied')
  }
  if (unreachable !== undefined) {
    notes.push('unreachability_recorded')
  }

  // What makes this action effective as the principal's is completion of the
  // agreed procedure, not the passage of time and not a guess in the
  // principal's absence.
  return finish('not_established', 'confirmation', 'confirmation_procedure_not_completed')
}

export const NAIVE_CONFIGURATIONS: Record<string, GateOptions> = {
  'defective-silence-after-deadline-is-approval': { silenceAfterDeadlineIsApproval: true },
  'defective-unreachable-is-denial': { unreachableIsDenial: true },
  'defective-accepts-confirmation-from-any-party': { acceptsConfirmationFromAnyParty: true },
  'defective-ignores-confirmation-binding': { ignoresConfirmationBinding: true },
  'defective-accepts-confirmation-after-the-action': { acceptsConfirmationAfterTheAction: true },
}
