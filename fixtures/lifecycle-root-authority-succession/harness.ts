// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The subject-binding gate this family supplies, plus six defective
// configurations used as negative controls.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real agent-passport-system
// chain verifier for the grant, and the real SDK Ed25519 verify plus the real
// RFC 8785 canonicalizer for every fixture-local record. The subject binding
// mode, the office-holder registry, office vacancy and the six verdict names
// are implemented here, because neither reference SDK exposes an API for any of
// them. A pass is a result about this gate, not a conformance result about
// either SDK.
//
// THE SILENT CASE IS THE POINT. AUTHORITY-LIFECYCLE.md does not say which
// binding mode a verifier should assume when a delegation does not declare one,
// and OPEN-QUESTIONS.md leaves office vacancy open. This family encodes the
// only answer that does not invent the missing term: not established. Two
// defective configurations below pick a default in each direction, and both
// fail the same vector.
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

export type Stage = 'chain' | 'terms' | 'binding'
export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface SignedRecord {
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface OfficeEvent extends SignedRecord {
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
  verification_keys: Record<string, string>
  attestor_role_registry: Record<string, string>
  event_standing: Record<string, string>
  terms_by_chain: Record<string, string>
  grant_terms: Record<string, GrantTerms>
  events: Record<string, OfficeEvent>
  chains: Record<string, Array<Record<string, unknown>>>
}

export interface GateOptions {
  /** N1: a delegation that declares no binding mode is read as role bound. */
  silentBindingDefaultsToRole?: boolean
  /** N2: a delegation that declares no binding mode is read as identity bound. */
  silentBindingDefaultsToIdentity?: boolean
  /** N3: a role-bound delegation is treated as identity bound, forcing a
   *  reissuance sweep on every personnel change. */
  roleBoundNeedsReissuance?: boolean
  /** N4: an identity-bound delegation is treated as role bound, handing a
   *  departing person's own grants to whoever backfills the title. */
  identityBoundFollowsTheOffice?: boolean
  /** N5: during a recorded vacancy, the last known office holder is still
   *  treated as the current one. */
  vacancyDefaultsToLastKnownHolder?: boolean
  /** N6: an attestor's role is read off the record body instead of the
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
  actor: string
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
  options: GateOptions,
): { ok: true; event: OfficeEvent } | { ok: false; reason: string } {
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
  if (options.trustsSelfDeclaredRole) {
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

  const leafSubject = chain[chain.length - 1].subject as string
  const termsRecord = fixture.grant_terms[fixture.terms_by_chain[vector.grant]]
  if (termsRecord === undefined) return finish('not_established', 'terms', 'grant_terms_unknown')
  if (!signatureOk(fixture, termsRecord, ['terms_id', 'signature'])) {
    return finish('not_established', 'terms', 'grant_terms_signature_unverified')
  }
  const named = chain.find(member => member.delegation_id === termsRecord.delegation_id)
  if (named === undefined || named.issuer !== termsRecord.issuer) {
    return finish('not_established', 'terms', 'grant_terms_not_bound_to_chain')
  }
  const terms = termsRecord.terms

  const accepted: OfficeEvent[] = []
  for (const label of vector.presented_events) {
    const result = classify(fixture, label, options)
    if (result.ok) {
      accepted.push(result.event)
      notes.push(`${label}=accepted`)
    } else {
      notes.push(`${label}=rejected:${result.reason}`)
    }
  }

  let mode = terms.subject_binding_mode
  if (typeof mode !== 'string') {
    if (vector.actor === leafSubject) {
      // Silence does not matter while the actor is the very subject the
      // delegation names. Nothing has to be resolved to answer this.
      return finish('valid', 'binding', 'actor_is_the_named_subject')
    }
    if (options.silentBindingDefaultsToRole) {
      mode = 'role_bound'
      notes.push('silent_binding_defaults_to_role=on')
    } else if (options.silentBindingDefaultsToIdentity) {
      mode = 'identity_bound'
      notes.push('silent_binding_defaults_to_identity=on')
    } else {
      // Which binding mode applies is a term of the delegation. The record does
      // not carry it, so the answer is not established rather than a guess in
      // either direction.
      return finish('not_established', 'binding', 'subject_binding_mode_not_declared')
    }
  }

  if (mode === 'identity_bound' && !options.identityBoundFollowsTheOffice) {
    if (vector.actor === leafSubject) {
      return finish('valid', 'binding', 'identity_bound_subject_acting')
    }
    return finish('invalid', 'binding', 'identity_bound_no_transfer')
  }
  if (mode === 'role_bound' && options.roleBoundNeedsReissuance) {
    if (vector.actor === leafSubject) {
      return finish('valid', 'binding', 'identity_bound_subject_acting')
    }
    return finish('invalid', 'binding', 'identity_bound_no_transfer')
  }

  // Role bound. The office is the subject; who occupies it at this instant is a
  // registry fact the verifier has to be able to establish.
  const officeRef = (terms.office_ref as string) ?? leafSubject
  const vacancy = accepted.find(
    event =>
      event.event_type === 'office_vacancy' &&
      event.payload.office_ref === officeRef &&
      (event.payload.from as string) <= now &&
      (event.payload.through as string) > now,
  )
  if (vacancy !== undefined && !options.vacancyDefaultsToLastKnownHolder) {
    // Office vacancy is an open question in the proposed text. Returning
    // not_established states the gap rather than filling it.
    return finish('not_established', 'binding', 'office_holder_not_established')
  }
  const covering = accepted.filter(
    event =>
      event.event_type === 'office_holder_record' &&
      event.payload.office_ref === officeRef &&
      (event.payload.from as string) <= now &&
      (options.vacancyDefaultsToLastKnownHolder || (event.payload.through as string) > now),
  )
  if (covering.length === 0) {
    return finish('not_established', 'binding', 'office_holder_not_established')
  }
  if (covering.some(event => event.payload.holder === vector.actor)) {
    return finish('valid', 'binding', 'role_bound_current_occupant')
  }
  return finish('invalid', 'binding', 'not_the_current_office_holder')
}

export const NAIVE_CONFIGURATIONS: Record<string, GateOptions> = {
  'defective-silent-binding-defaults-to-role': { silentBindingDefaultsToRole: true },
  'defective-silent-binding-defaults-to-identity': { silentBindingDefaultsToIdentity: true },
  'defective-role-bound-needs-reissuance': { roleBoundNeedsReissuance: true },
  'defective-identity-bound-follows-the-office': { identityBoundFollowsTheOffice: true },
  'defective-vacancy-defaults-to-last-known-holder': { vacancyDefaultsToLastKnownHolder: true },
  'defective-trusts-self-declared-role': { trustsSelfDeclaredRole: true },
}
