// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The renunciation gate this family supplies, plus four defective
// configurations used as negative controls.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real agent-passport-system
// chain verifier for the grant, and the real SDK Ed25519 verify plus the real
// RFC 8785 canonicalizer for every fixture-local record. Renunciation, its
// delivery instant, its stated effective date or triggering event, the
// principal's acceptance and the six verdict names are implemented here,
// because neither reference SDK exposes an API for any of them.
//
// WHAT THIS GATE NEVER RETURNS. A liability finding. Whether a renunciation
// breached some other obligation is a separate question this family keeps
// separate, and GateResult has no field for it. One vector asserts that the
// wrongful and the clean renunciation reach the same code.
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

export type Stage = 'chain' | 'renunciation'
export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface SignedRecord {
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface RenunciationEvent extends SignedRecord {
  event_id: string
  event_type: string
  attestor: string
  attestor_role: string
  subject_ref: string
  occurred_at: string
  recorded_at: string
  payload: Record<string, unknown>
}

export interface ChainFixture {
  clock: Record<string, string>
  verification_keys: Record<string, string>
  attestor_role_registry: Record<string, string>
  event_standing: Record<string, string>
  events: Record<string, RenunciationEvent>
  chains: Record<string, Array<Record<string, unknown>>>
}

export interface GateOptions {
  /** N1: a renunciation takes effect only once the principal records an
   *  acceptance, which builds in a veto by silence. */
  requiresPrincipalAcceptance?: boolean
  /** N2: a renunciation that breaches another obligation is held pending a
   *  liability determination instead of taking effect. */
  wrongfulRenunciationPendsLiability?: boolean
  /** N3: a stated later effective date is ignored and delivery controls. */
  ignoresStatedEffectiveDate?: boolean
  /** N4: an attestor's role is read off the record body instead of the
   *  registry. */
  trustsSelfDeclaredRole?: boolean
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
  action_at: string
  revocation: RevocationAnswer
  presented_events: string[]
  expected: { verdict: Verdict; stage: Stage; code: string }
  assert_no_liability_field?: boolean
  assert_same_code_as?: string
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
  leafSubject: string,
  rootIssuer: string,
  options: GateOptions,
): { ok: true; event: RenunciationEvent } | { ok: false; reason: string } {
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
  if (requiredRole === 'grant-subject') {
    // Only the agent may end its own role. Who that is comes off the grant.
    if (event.attestor !== leafSubject) return { ok: false, reason: 'not_from_grant_subject' }
  } else if (requiredRole === 'grant-principal') {
    if (event.attestor !== rootIssuer) return { ok: false, reason: 'not_from_grant_principal' }
  } else if (options.trustsSelfDeclaredRole) {
    if (event.attestor_role !== requiredRole) {
      return { ok: false, reason: 'event_attestor_role_mismatch' }
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

  const leaf = chain[chain.length - 1]
  const leafSubject = leaf.subject as string
  const leafDelegationId = leaf.delegation_id as string
  const rootIssuer = chain[0].issuer as string

  const accepted: RenunciationEvent[] = []
  for (const label of vector.presented_events) {
    const result = classify(fixture, label, leafSubject, rootIssuer, options)
    if (result.ok) {
      accepted.push(result.event)
      notes.push(`${label}=accepted`)
    } else {
      notes.push(`${label}=rejected:${result.reason}`)
    }
  }
  const of = (eventType: string) => accepted.filter(event => event.event_type === eventType)

  const renunciation = of('agent_renunciation').find(
    event => event.subject_ref === leafDelegationId && (event.payload.delivered_at as string) <= now,
  )
  if (renunciation === undefined) {
    return finish('valid', 'renunciation', 'no_renunciation_presented')
  }

  if (options.requiresPrincipalAcceptance) {
    const acceptance = of('principal_acceptance').find(
      event => event.subject_ref === leafDelegationId && event.occurred_at <= now,
    )
    if (acceptance === undefined) {
      notes.push('requires_principal_acceptance=on')
      return finish('valid', 'renunciation', 'no_renunciation_presented')
    }
  }

  if (options.wrongfulRenunciationPendsLiability) {
    const agreementRef = renunciation.payload.agreement_ref
    if (typeof agreementRef === 'string') {
      const agreement = of('no_exit_agreement').find(
        event => event.payload.agreement_ref === agreementRef,
      )
      const determination = of('liability_determination').find(
        event => event.payload.agreement_ref === agreementRef && event.occurred_at <= now,
      )
      if (agreement !== undefined && determination === undefined) {
        notes.push('wrongful_renunciation_pends_liability=on')
        return finish('suspended', 'renunciation', 'renunciation_pending_liability')
      }
    }
  }

  const statedDate = renunciation.payload.effective_date
  if (typeof statedDate === 'string' && !options.ignoresStatedEffectiveDate) {
    if (statedDate > now) {
      // The renunciation exists and names a later instant. That is a wait, not
      // a missing record and not a rejection.
      return finish('valid', 'renunciation', 'renunciation_not_yet_effective')
    }
    return finish('invalid', 'renunciation', 'renounced_on_stated_effective_date')
  }

  const statedEvent = renunciation.payload.effective_on_event
  if (typeof statedEvent === 'string') {
    const trigger = of(statedEvent).find(
      event =>
        event.payload.event_ref === renunciation.payload.event_ref && event.occurred_at <= now,
    )
    if (trigger === undefined) {
      // The record names an event as its own effective date and nothing
      // establishes that the event happened. Nothing is invalid here.
      return finish('valid', 'renunciation', 'renunciation_trigger_not_recorded')
    }
    return finish('invalid', 'renunciation', 'renounced_on_recorded_event')
  }

  // Delivery controls. The principal's acceptance is not part of it, and
  // whether the renunciation breached some other obligation is not either.
  return finish('invalid', 'renunciation', 'renounced_on_delivery')
}

export const NAIVE_CONFIGURATIONS: Record<string, GateOptions> = {
  'defective-requires-principal-acceptance': { requiresPrincipalAcceptance: true },
  'defective-wrongful-renunciation-pends-liability': { wrongfulRenunciationPendsLiability: true },
  'defective-ignores-stated-effective-date': { ignoresStatedEffectiveDate: true },
  'defective-trusts-self-declared-role': { trustsSelfDeclaredRole: true },
}
