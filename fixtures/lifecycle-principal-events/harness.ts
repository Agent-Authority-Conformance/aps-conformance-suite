// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The principal-event gate this family supplies, plus eight defective
// configurations used as negative controls.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real agent-passport-system
// chain verifier for the grant, and the real SDK Ed25519 verify plus the real
// RFC 8785 canonicalizer for every fixture-local record's signature. Everything
// after that -- grant terms, principal-event records, the attestor-role
// registry, the event-standing table, notice, retroactive forfeiture, external
// lifecycle standing, coupled-interest survival, successor activation and the
// six verdict names -- is implemented here, because neither reference SDK
// exposes an API for any of it. A pass is a result about this gate, not a
// conformance result about either SDK. README.md says this again, at length.
//
// VERDICT NAMES ARE NOT SUITE VOCABULARY. valid, invalid, not_established,
// not_yet_effective, suspended and restricted are this family's local labels.
// CONTRIBUTING.md reserves failure-class names and verifier semantics to the
// maintainer, so these are a proposal, not a minted taxonomy.
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

export type Stage = 'chain' | 'terms' | 'standing' | 'principal_event' | 'succession'
export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface SignedRecord {
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface PrincipalEvent extends SignedRecord {
  record_type: string
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
  record_type: string
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
  events: Record<string, PrincipalEvent>
  chains: Record<string, Array<Record<string, unknown>>>
}

export interface GateOptions {
  /** N1: a grant whose terms say durable is treated as surviving the
   *  principal's death, not only the principal's incapacity. */
  durabilitySurvivesDeath?: boolean
  /** N2: only an explicit revocation answer ends authority. Death, incapacity
   *  and the end of the relationship a designation depends on are ignored. */
  revokeOnly?: boolean
  /** N3: a forfeiture finding is applied forward from the instant it was
   *  recorded, instead of reaching the appointment it names. */
  forfeitureIsForwardOnly?: boolean
  /** N4: the appointment of a guardian is itself read as terminating the
   *  delegation the guardian did not issue and is not a party to. */
  guardianAppointmentIsRevocation?: boolean
  /** N5: an attestor's role is read off the record body instead of the
   *  registry. */
  trustsSelfDeclaredRole?: boolean
  /** N6: the issuer's own survives_principal_death claim is honoured with no
   *  independent record of an interest in the subject matter. */
  trustsSelfDeclaredSurvival?: boolean
  /** N7: a relationship binding that declares no termination trigger is read
   *  as if it declared the decree. */
  silentTriggerDefaultsToDecree?: boolean
  /** N8: a named successor is treated as reaching every delegation a
   *  predecessor issued, not only the instrument that names the successor. */
  successorInheritsTree?: boolean
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
  actor: string | null
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

type Classified =
  | { ok: true; event: PrincipalEvent; reachesNow: boolean }
  | { ok: false; label: string; reason: string }

function classify(
  fixture: ChainFixture,
  label: string,
  leafSubject: string,
  now: string,
  options: GateOptions,
): Classified {
  const event = fixture.events[label]
  if (event === undefined) return { ok: false, label, reason: 'event_record_unknown' }
  if (!signatureOk(fixture, event, ['event_id', 'signature'])) {
    return { ok: false, label, reason: 'event_signature_unverified' }
  }
  // A valid signature says who signed. It says nothing about who attested
  // unless the verification method belongs to the attestor the body names.
  if (!event.verification_method.startsWith(`${event.attestor}#`)) {
    return { ok: false, label, reason: 'event_attestor_binding_mismatch' }
  }
  const requiredRole = fixture.event_standing[event.event_type]
  if (typeof requiredRole !== 'string') {
    return { ok: false, label, reason: 'event_type_has_no_declared_standing' }
  }
  if (requiredRole === 'grant-subject') {
    // "The subject of this grant" is not a registry fact. It is read off the
    // grant being checked.
    if (event.attestor !== leafSubject) {
      return { ok: false, label, reason: 'notice_not_from_grant_subject' }
    }
  } else if (options.trustsSelfDeclaredRole) {
    if (event.attestor_role !== requiredRole) {
      return { ok: false, label, reason: 'event_attestor_role_mismatch' }
    }
  } else {
    const registeredRole = fixture.attestor_role_registry[event.attestor]
    if (typeof registeredRole !== 'string' || registeredRole !== event.attestor_role) {
      return { ok: false, label, reason: 'event_role_claim_conflict' }
    }
    if (registeredRole !== requiredRole) {
      return { ok: false, label, reason: 'event_attestor_role_mismatch' }
    }
  }
  return { ok: true, event, reachesNow: event.occurred_at <= now }
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
  const chainFailureIndex = chainFailure ? chainFailure.index : null

  const finish = (verdict: Verdict, stage: Stage, code: string): GateResult => ({
    verdict,
    stage,
    code,
    chain_state: chainState,
    chain_failure_index: chainFailureIndex,
    notes,
  })

  if (chainState !== 'valid') {
    const verdict: Verdict = chainState === 'invalid' ? 'invalid' : 'not_established'
    return finish(verdict, 'chain', chainFailure ? chainFailure.code : `chain_${chainState}`)
  }

  const leaf = chain[chain.length - 1]
  const leafSubject = leaf.subject as string
  const leafDelegationId = leaf.delegation_id as string
  const rootIssuer = chain[0].issuer as string

  // --- grant terms ---------------------------------------------------------
  const termsLabel = fixture.terms_by_chain[vector.grant]
  let terms: Record<string, unknown> = {}
  if (typeof termsLabel === 'string') {
    const record = fixture.grant_terms[termsLabel]
    if (record === undefined) return finish('not_established', 'terms', 'grant_terms_unknown')
    if (!signatureOk(fixture, record, ['terms_id', 'signature'])) {
      return finish('not_established', 'terms', 'grant_terms_signature_unverified')
    }
    // Terms are only the issuer's terms if the issuer of the delegation they
    // name signed them.
    const named = chain.find(member => member.delegation_id === record.delegation_id)
    if (named === undefined || named.issuer !== record.issuer) {
      return finish('not_established', 'terms', 'grant_terms_not_bound_to_chain')
    }
    terms = record.terms
    notes.push(`terms=${termsLabel}`)
  } else {
    notes.push('terms=none')
  }

  // --- classify every presented record ------------------------------------
  const accepted: Array<{ event: PrincipalEvent; reachesNow: boolean }> = []
  for (const label of vector.presented_events) {
    const result = classify(fixture, label, leafSubject, now, options)
    if (result.ok) {
      accepted.push({ event: result.event, reachesNow: result.reachesNow })
      notes.push(`${label}=accepted${result.reachesNow ? '' : ':after_action'}`)
    } else {
      notes.push(`${label}=rejected:${result.reason}`)
    }
  }
  const find = (eventType: string, predicate?: (event: PrincipalEvent) => boolean) =>
    accepted.find(
      entry => entry.event.event_type === eventType && (predicate ? predicate(entry.event) : true),
    )

  // --- 1. who may act under this grant ------------------------------------
  const actor = vector.actor ?? leafSubject
  if (actor !== leafSubject) {
    const order = Array.isArray(terms.successor_order) ? (terms.successor_order as string[]) : null
    const position = order ? order.indexOf(actor) : -1
    if (position <= 0) {
      if (options.successorInheritsTree) {
        notes.push('successor_inherits_tree=on')
      } else {
        // The actor is not this instrument's subject and this instrument does
        // not name it in a successor order. Authority pre-committed inside one
        // instrument reaches that instrument only.
        return finish('invalid', 'succession', 'successor_scope_limited_to_instrument')
      }
    } else {
      const predecessors = (order as string[]).slice(0, position)
      const stillServing = predecessors.filter(predecessor => {
        const exit = find('agent_exit', event => event.subject_ref === predecessor)
        return exit === undefined || !exit.reachesNow
      })
      if (stillServing.length > 0) {
        // A successor may not act until every predecessor has exited, so an
        // unrecorded predecessor exit is a wait, not a rejection.
        return finish('not_yet_effective', 'succession', 'predecessor_still_serving')
      }
      notes.push(`successor_activated=${actor}`)
    }
  }

  // --- 2. retroactive forfeiture ------------------------------------------
  // A finding that a party in this chain forfeited its appointment reaches the
  // appointment it names, not only the instants after the finding was
  // recorded. This is a new record that references the appointment. It never
  // rewrites an earlier receipt: see the receipt-immutability assertion the
  // runners make for the LC-A-009 vectors.
  const chainParties = new Set<string>()
  for (const member of chain) {
    chainParties.add(member.issuer as string)
    chainParties.add(member.subject as string)
  }
  const forfeiture = find('felonious_killing_finding', event => chainParties.has(event.subject_ref))
  if (forfeiture !== undefined) {
    if (!options.forfeitureIsForwardOnly || forfeiture.reachesNow) {
      return finish('invalid', 'principal_event', 'appointment_void_from_inception')
    }
    notes.push('forfeiture_forward_only=on')
  }

  // --- 3. lifecycle standing from outside the chain ------------------------
  const terminateOrder = find(
    'court_order_terminate_delegation',
    event => event.subject_ref === leafDelegationId,
  )
  if (terminateOrder !== undefined && terminateOrder.reachesNow) {
    return finish('invalid', 'standing', 'terminated_by_external_order')
  }
  const suspendOrder = find(
    'court_order_suspend_delegation',
    event => event.subject_ref === leafDelegationId,
  )
  if (suspendOrder !== undefined && suspendOrder.reachesNow) {
    return finish('suspended', 'standing', 'suspended_by_external_order')
  }
  const guardian = find('guardian_appointment', event => event.subject_ref === rootIssuer)
  if (guardian !== undefined && guardian.reachesNow) {
    if (options.guardianAppointmentIsRevocation) {
      return finish('invalid', 'standing', 'terminated_by_external_order')
    }
    notes.push('guardian_appointed_delegation_continues')
  }

  if (options.revokeOnly) {
    notes.push('revoke_only=on')
    return finish('valid', 'principal_event', 'no_terminating_event_established')
  }

  // --- 4. the principal's death -------------------------------------------
  const death = find('principal_death', event => event.subject_ref === rootIssuer)
  if (death !== undefined && death.reachesNow) {
    const claimsSurvival = terms.survives_principal_death === true
    const durable = terms.durability === 'durable'
    if (durable && options.durabilitySurvivesDeath) {
      notes.push('durability_survives_death=on')
    } else if (claimsSurvival) {
      if (options.trustsSelfDeclaredSurvival) {
        notes.push('self_declared_survival=on')
      } else {
        const subjectMatter = terms.subject_matter_ref
        const interest = find(
          'collateral_interest_in_subject_matter',
          event =>
            event.payload.holder === leafSubject &&
            event.payload.subject_matter_ref === subjectMatter,
        )
        if (interest === undefined || !interest.reachesNow) {
          // The issuer's own flag is a claim, not a finding. Missing evidence
          // for the survival basis is not established, not false.
          return finish('not_established', 'principal_event', 'coupled_interest_not_established')
        }
        notes.push('coupled_interest_established')
      }
    } else {
      const notice = find('notice_of_principal_death', event => event.subject_ref === rootIssuer)
      if (notice !== undefined && notice.reachesNow) {
        return finish('invalid', 'principal_event', 'terminated_on_notice_of_death')
      }
      // The death is recorded. That the subject had notice of it is not.
      // The world state and what the verifier can establish differ here, and
      // the verdict says which one it is reporting.
      return finish('valid', 'principal_event', 'death_recorded_notice_not_established')
    }
  }

  // --- 5. the principal's incapacity --------------------------------------
  const incapacity = find('principal_incapacity', event => event.subject_ref === rootIssuer)
  if (incapacity !== undefined && incapacity.reachesNow) {
    if (terms.durability === 'durable') {
      notes.push('durable_survives_incapacity')
    } else {
      return finish('invalid', 'principal_event', 'terminated_on_principal_incapacity')
    }
  }

  // --- 6. the relationship the designation depends on ---------------------
  const binding = terms.relationship_binding as Record<string, unknown> | undefined
  if (binding !== undefined) {
    const relationshipEvents = accepted.filter(
      entry =>
        (entry.event.event_type === 'marriage_dissolution_filing' ||
          entry.event.event_type === 'marriage_dissolution_decree') &&
        entry.event.subject_ref === rootIssuer &&
        entry.event.payload.counterparty === leafSubject,
    )
    let trigger = binding.termination_trigger
    if (typeof trigger !== 'string') {
      if (options.silentTriggerDefaultsToDecree) {
        trigger = 'marriage_dissolution_decree'
        notes.push('silent_trigger_defaults_to_decree=on')
      } else if (relationshipEvents.length > 0) {
        // Which event ends this designation is a term of the designation. The
        // record does not carry it, so the result is not established rather
        // than a guess in either direction.
        return finish('not_established', 'principal_event', 'termination_trigger_not_declared')
      }
    }
    if (typeof trigger === 'string') {
      const triggered = relationshipEvents.find(
        entry => entry.event.event_type === trigger && entry.reachesNow,
      )
      if (triggered !== undefined) {
        return finish('invalid', 'principal_event', 'relationship_terminated_no_revocation_record')
      }
      if (relationshipEvents.length > 0) {
        // A relationship event was presented and it is not the one this
        // designation names, or it has not happened yet at this instant.
        return finish('valid', 'principal_event', 'termination_trigger_not_reached')
      }
    }
  }

  return finish('valid', 'principal_event', 'no_terminating_event_established')
}

export const NAIVE_CONFIGURATIONS: Record<string, GateOptions> = {
  'defective-durability-survives-death': { durabilitySurvivesDeath: true },
  'defective-revoke-only': { revokeOnly: true },
  'defective-forfeiture-forward-only': { forfeitureIsForwardOnly: true },
  'defective-guardian-appointment-is-revocation': { guardianAppointmentIsRevocation: true },
  'defective-trusts-self-declared-role': { trustsSelfDeclaredRole: true },
  'defective-trusts-self-declared-survival': { trustsSelfDeclaredSurvival: true },
  'defective-silent-trigger-defaults-to-decree': { silentTriggerDefaultsToDecree: true },
  'defective-successor-inherits-tree': { successorInheritsTree: true },
}
