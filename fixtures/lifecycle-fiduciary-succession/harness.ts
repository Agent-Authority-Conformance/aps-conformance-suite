// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The fiduciary-succession gate this family supplies, plus nine defective
// configurations used as negative controls.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real agent-passport-system
// chain verifier for the grant, and the real SDK Ed25519 verify plus the real
// RFC 8785 canonicalizer for every fixture-local record's signature. The
// co-holder instrument, the quorum rule, the temporary mandate, ratification
// and its three bounds, the attestor-role registry and the six verdict names
// are implemented here, because neither reference SDK exposes an API for any of
// them. A pass is a result about this gate, not a conformance result about
// either SDK.
//
// TWO CLOCK POSITIONS, NOT ONE. Every vector carries action_at, the instant the
// action is presented, and evaluated_at, the instant this decision is made. A
// record is usable only if it was recorded at or before evaluated_at, and what
// it establishes is compared against action_at. That split is what lets this
// family show that a ratification recorded later reaches an earlier act without
// rewriting the receipt the boundary produced at that earlier act: the two are
// separate decisions from separate evidence sets, and the runners pin the bytes
// of the earlier one.
//
// VERDICT NAMES ARE NOT SUITE VOCABULARY. CONTRIBUTING.md reserves failure-class
// names and verifier semantics to the maintainer.
//
// NO LEGAL CLAIM. The human instruments quoted in README.md are the source of
// the cases. Nothing here states or implies that any legal doctrine applies to
// AI agents, and the gate never returns a liability finding.

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

export type Stage = 'chain' | 'terms' | 'quorum' | 'mandate' | 'ratification'
export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface SignedRecord {
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface SuccessionEvent extends SignedRecord {
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
  act_id: string
  action_ref: string
  target: string
  verification_keys: Record<string, string>
  attestor_role_registry: Record<string, string>
  event_standing: Record<string, string>
  terms_by_chain: Record<string, string>
  grant_terms: Record<string, GrantTerms>
  events: Record<string, SuccessionEvent>
  chains: Record<string, Array<Record<string, unknown>>>
}

export interface GateOptions {
  /** N1: an approval recorded by a holder who has since vacated is still
   *  counted toward the quorum. */
  countsApprovalFromVacatedHolder?: boolean
  /** N2: every named co-holder must approve, so any dissent or vacancy blocks
   *  the action. */
  requiresUnanimityOfNamedHolders?: boolean
  /** N3: a vacancy must be filled before the remaining co-holders can act. */
  requiresBackfillBeforeActing?: boolean
  /** N4: a temporary mandate is treated as ordinary successor authority, so its
   *  narrower permitted action classes are not enforced. */
  temporaryAdminHasFullSuccessorPowers?: boolean
  /** N5: only an explicit revocation answer ends authority, so a mandate that
   *  ends on an external event keeps running. */
  revokeOnly?: boolean
  /** N6: ratification is treated as a clean rewrite of history that reaches
   *  through an intervening third-party interest. */
  ratificationReachesInterveningInterest?: boolean
  /** N7: a ratification naming part of one integrated act is accepted for that
   *  part. */
  acceptsPartialRatification?: boolean
  /** N8: the principal's capacity at the instant of ratifying is not checked. */
  ignoresCapacityAtRatification?: boolean
  /** N9: an attestor's role is read off the record body instead of the
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
  action_class: string
  action_at: string
  evaluated_at: string
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

type Classified =
  | { ok: true; event: SuccessionEvent }
  | { ok: false; reason: string }

function classify(
  fixture: ChainFixture,
  label: string,
  rootIssuer: string,
  coHolders: string[],
  evaluatedAt: string,
  options: GateOptions,
): Classified {
  const event = fixture.events[label]
  if (event === undefined) return { ok: false, reason: 'event_record_unknown' }
  if (!signatureOk(fixture, event, ['event_id', 'signature'])) {
    return { ok: false, reason: 'event_signature_unverified' }
  }
  if (!event.verification_method.startsWith(`${event.attestor}#`)) {
    return { ok: false, reason: 'event_attestor_binding_mismatch' }
  }
  // A record the verifier does not hold yet cannot decide anything. This is
  // what keeps a later finding from reaching back into an earlier receipt.
  if (event.recorded_at > evaluatedAt) return { ok: false, reason: 'event_recorded_after_evaluation' }
  const requiredRole = fixture.event_standing[event.event_type]
  if (typeof requiredRole !== 'string') {
    return { ok: false, reason: 'event_type_has_no_declared_standing' }
  }
  if (requiredRole === 'grant-principal') {
    if (event.attestor !== rootIssuer) return { ok: false, reason: 'not_from_grant_principal' }
  } else if (requiredRole === 'named-co-holder') {
    if (!coHolders.includes(event.attestor)) return { ok: false, reason: 'not_a_named_co_holder' }
  } else if (options.trustsSelfDeclaredRole) {
    if (event.attestor_role !== requiredRole) return { ok: false, reason: 'event_attestor_role_mismatch' }
  } else {
    const registeredRole = fixture.attestor_role_registry[event.attestor]
    if (typeof registeredRole !== 'string' || registeredRole !== event.attestor_role) {
      return { ok: false, reason: 'event_role_claim_conflict' }
    }
    if (registeredRole !== requiredRole) return { ok: false, reason: 'event_attestor_role_mismatch' }
  }
  return { ok: true, event }
}

export function gate(
  fixture: ChainFixture,
  vector: VectorCase,
  options: GateOptions = {},
): GateResult {
  const chain = fixture.chains[vector.grant]
  const actionAt = fixture.clock[vector.action_at]
  const evaluatedAt = fixture.clock[vector.evaluated_at]
  const notes: string[] = [`action_at=${vector.action_at} evaluated_at=${vector.evaluated_at}`]

  const chainResult = verifyAuthorityDelegationChain(chain as never, {
    now: actionAt,
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
  const rootIssuer = chain[0].issuer as string

  const termsLabel = fixture.terms_by_chain[vector.grant]
  const termsRecord = fixture.grant_terms[termsLabel]
  if (termsRecord === undefined) return finish('not_established', 'terms', 'grant_terms_unknown')
  if (!signatureOk(fixture, termsRecord, ['terms_id', 'signature'])) {
    return finish('not_established', 'terms', 'grant_terms_signature_unverified')
  }
  const named = chain.find(member => member.delegation_id === termsRecord.delegation_id)
  if (named === undefined || named.issuer !== termsRecord.issuer) {
    return finish('not_established', 'terms', 'grant_terms_not_bound_to_chain')
  }
  const terms = termsRecord.terms
  const coHolders = Array.isArray(terms.co_holders) ? (terms.co_holders as string[]) : []

  const accepted: SuccessionEvent[] = []
  for (const label of vector.presented_events) {
    const result = classify(fixture, label, rootIssuer, coHolders, evaluatedAt, options)
    if (result.ok) {
      accepted.push(result.event)
      notes.push(`${label}=accepted`)
    } else {
      notes.push(`${label}=rejected:${result.reason}`)
    }
  }
  const of = (eventType: string) => accepted.filter(event => event.event_type === eventType)

  // --- quorum over the co-holders of one instrument ------------------------
  if (coHolders.length > 0) {
    const vacancies = of('holder_vacancy').filter(event => event.occurred_at <= actionAt)
    const vacated = new Set(vacancies.map(event => event.subject_ref))
    if (vacated.has(leafSubject)) {
      return finish('invalid', 'quorum', 'acting_holder_vacated')
    }
    if (vacated.size > 0 && options.requiresBackfillBeforeActing) {
      return finish('not_established', 'quorum', 'vacancy_must_be_filled')
    }
    const current = coHolders.filter(holder => !vacated.has(holder))
    const approvals = of('co_holder_approval').filter(event => {
      if (event.payload.action_ref !== terms.action_ref) return false
      if (event.occurred_at > actionAt) return false
      // An approval given by a holder who has since vacated is not an approval
      // by a current holder. The record stays authentic and keeps saying what
      // it said; it is simply not in the denominator's numerator any more.
      if (!options.countsApprovalFromVacatedHolder && vacated.has(event.attestor)) return false
      return true
    })
    const approvers = new Set(approvals.map(event => event.attestor))
    notes.push(`current_holders=${current.length} approvals=${approvers.size}`)
    if (options.requiresUnanimityOfNamedHolders) {
      if (approvers.size < coHolders.length) {
        return finish('not_established', 'quorum', 'majority_not_reached')
      }
    } else if (approvers.size * 2 <= current.length) {
      return finish('not_established', 'quorum', 'majority_not_reached')
    }
    const permitted = terms.permitted_action_classes as string[] | undefined
    if (Array.isArray(permitted) && !permitted.includes(vector.action_class)) {
      return finish('invalid', 'quorum', 'action_class_outside_instrument')
    }
    return finish('valid', 'quorum', 'majority_of_current_holders')
  }

  // --- a temporary mandate -------------------------------------------------
  const mandate = terms.mandate as Record<string, unknown> | undefined
  if (mandate !== undefined) {
    if (!options.revokeOnly) {
      const endsOn = mandate.ends_on_event
      const ending = of(typeof endsOn === 'string' ? endsOn : '__none__').find(
        event =>
          event.occurred_at <= actionAt && event.payload.dispute_ref === mandate.dispute_ref,
      )
      if (ending !== undefined) {
        // No revocation record exists anywhere in this vector. The mandate
        // reached its declared end, which is exhaustion, not revocation.
        return finish('invalid', 'mandate', 'temporary_mandate_ended_on_resolution')
      }
    } else {
      notes.push('revoke_only=on')
    }
    const permitted = mandate.permitted_action_classes as string[] | undefined
    if (
      !options.temporaryAdminHasFullSuccessorPowers &&
      Array.isArray(permitted) &&
      !permitted.includes(vector.action_class)
    ) {
      return finish('invalid', 'mandate', 'outside_preservation_scope')
    }
    return finish('valid', 'mandate', 'within_temporary_mandate')
  }

  // --- an act outside the declared scope, and ratification -----------------
  const permitted = terms.permitted_action_classes as string[] | undefined
  if (Array.isArray(permitted) && permitted.includes(vector.action_class)) {
    return finish('valid', 'ratification', 'within_declared_scope')
  }

  const integrated = (terms.integrated_acts ?? {}) as Record<
    string,
    { components: string[]; target: string }
  >
  const act = integrated[fixture.act_id]
  const ratification = of('principal_ratification').find(
    event => event.payload.act_id === fixture.act_id && event.occurred_at >= actionAt,
  )
  if (ratification === undefined || act === undefined) {
    return finish('invalid', 'ratification', 'act_outside_declared_scope')
  }

  if (!options.ignoresCapacityAtRatification) {
    const lacking = of('principal_capacity_finding').find(
      event =>
        event.subject_ref === rootIssuer &&
        event.payload.finding === 'lacks_capacity' &&
        (event.payload.covers_from as string) <= ratification.occurred_at &&
        (event.payload.covers_through as string) >= ratification.occurred_at,
    )
    if (lacking !== undefined) {
      return finish(
        'invalid',
        'ratification',
        'ratification_ineffective_principal_lacked_capacity',
      )
    }
  }

  if (!options.acceptsPartialRatification) {
    const covered = new Set(ratification.payload.covers_components as string[])
    const missing = act.components.filter(component => !covered.has(component))
    if (missing.length > 0) {
      return finish('invalid', 'ratification', 'partial_ratification_ineffective')
    }
  }

  if (!options.ratificationReachesInterveningInterest) {
    const intervening = of('intervening_interest').find(event => {
      if (event.payload.target !== act.target) return false
      const acquiredAt = event.payload.acquired_at as string
      return acquiredAt > actionAt && acquiredAt < ratification.occurred_at
    })
    if (intervening !== undefined) {
      // The ratification stands between principal and agent. What it cannot do
      // is reach an interest a party outside the transaction acquired in the
      // meantime, so the effect on that target is restricted rather than
      // authorized.
      return finish('restricted', 'ratification', 'ratified_but_intervening_interest_not_reached')
    }
  }

  return finish('valid', 'ratification', 'ratified_entirety')
}

export const NAIVE_CONFIGURATIONS: Record<string, GateOptions> = {
  'defective-counts-approval-from-vacated-holder': { countsApprovalFromVacatedHolder: true },
  'defective-requires-unanimity-of-named-holders': { requiresUnanimityOfNamedHolders: true },
  'defective-requires-backfill-before-acting': { requiresBackfillBeforeActing: true },
  'defective-temporary-admin-has-full-successor-powers': { temporaryAdminHasFullSuccessorPowers: true },
  'defective-revoke-only': { revokeOnly: true },
  'defective-ratification-reaches-intervening-interest': { ratificationReachesInterveningInterest: true },
  'defective-accepts-partial-ratification': { acceptsPartialRatification: true },
  'defective-ignores-capacity-at-ratification': { ignoresCapacityAtRatification: true },
  'defective-trusts-self-declared-role': { trustsSelfDeclaredRole: true },
}
