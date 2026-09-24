// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference authorization boundary for the lifecycle-time-and-scheduling family.
//
// WHAT THIS IS. The proposed text this family tests is aeoess/agent-authority-lifecycle,
// AUTHORITY-LIFECYCLE.md at commit 7796e22 or later, together with the fourteen cases in
// the "Time and scheduling" section of CASES.md at commit 2bf5c7e. Neither that text nor
// draft-pidlisnyi-aps-03 defines a wire shape for a handover acknowledgment, a rotation
// schedule, a pre-authorized fallback scope, a pinned policy version, an occurrence
// template, a wind-down grace bound, a queued action, or a clock attestation, and
// draft-03's authority vector (section 3.2) is a closed set of seven facets with room for
// none of them. This family therefore declares its own signed record profile (see
// mint.ts) and implements the boundary here.
//
// THE BOUNDARY IS THIS FIXTURE'S CODE, NOT AN SDK CONFORMANCE RESULT, for every one of
// the fourteen lifecycle rules. It calls the real SDK for every part the SDK does supply:
//
//   verifyAuthorityDelegationChain   the grant's structural, temporal and revocation state
//   isPurposePermitted               scope membership, which is not a lifecycle state
//   verify over canonicalizeJCS      each fixture-local record's issuer signature
//
// and it reports the SDK's own answer on every vector next to, never merged into, the
// lifecycle verdict. The two differ on purpose in several places, and where they differ
// the README says so.
//
// VERDICT VOCABULARY. valid, invalid, not_established, not_yet_effective, suspended,
// restricted. The wording rules this family follows: a missing record gives
// not_established and never invalid. A bound not yet reached gives not_yet_effective and
// never invalid. A later record never rewrites an earlier one. Nothing here says a legal
// doctrine applies to AI agents.
//
// Node builtins only, plus the pinned SDK. No wall clock: every instant compared here is
// supplied by the caller from the fixture's pinned timeline or read from a signed clock
// attestation, never read from the system.

import {
  canonicalizeJCS,
  isPurposePermitted,
  verify,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export interface SignedRecord {
  profile: string
  kind: string
  record_id: string
  issuer: string
  verification_method: string
  issued_at: string
  body: Record<string, unknown>
  signature: string
}

export interface ActionEntry {
  action_ref: string
  requested_scope: string
  issued_at: string
}

export interface Outcome {
  verdict: Verdict
  reason: string
  /** The SDK's own chain verdict at the instant this boundary selected, never merged. */
  sdk_chain_state: string | null
  sdk_failure_code: string | null
  detail?: string
}

export interface Event {
  id: string
  check: string
  grant: AuthorityDelegationV1
  action: ActionEntry
  now: string
  /** Revocation state as a function of the instant, so a grant can be revoked between
   *  the moment work is queued and the moment it fires. */
  resolveRevocation: (now: string) => RevocationResolution
  records: SignedRecord[]
}

export interface BoundaryOptions {
  name: string
  /** reference: true. defective-boundary-issuer-clock: false. */
  usesCheckingPartyClock: boolean
  /** reference: true. defective-boundary-single-clock-trusted: false. */
  requiresTimeSourceCrossCheck: boolean
  /** reference: false. defective-boundary-single-clock-trusted: true. */
  treatsClockMismatchAsTampering: boolean
  /** reference: true. defective-boundary-queue-time-only: false. */
  checksLiveStateAtFireTime: boolean
  /** reference: true. defective-boundary-current-version-only: false. */
  usesPinnedVersions: boolean
  /** reference: true. defective-boundary-instant-transfer: false. */
  requiresAcknowledgedTransfer: boolean
}

export interface Fixture {
  identities: Record<string, string>
  verification_keys: Record<string, string>
  record_signature_domain: string
}

// ---------------------------------------------------------------------------
// Which registry role a record kind has to be signed by. A valid signature establishes
// who signed. It does not establish that the signer was allowed to make the statement,
// so standing is read from the office's own signed registry, never from the record
// asserting something about itself.
//
// Four kinds are deliberately absent. `direction` and `handover_ack` carry their standing
// from the succession rule and the handover offer, checked inside those two rules.
// `clock_attestation` has no registry role at all, because LC-G-007's whole point is that
// every checking party has its own clock and none of them is the authoritative one.
// `standing_registry` is the root of this check and cannot be checked against itself.
// ---------------------------------------------------------------------------

const REQUIRED_ROLE: Record<string, string> = {
  succession_default: 'succession_rule_author',
  role_tenure: 'tenure_attestor',
  vacancy: 'vacancy_attestor',
  fallback_authorization: 'fallback_author',
  contact_observation: 'observation_attestor',
  rotation_schedule: 'schedule_author',
  rest_ledger: 'rest_attestor',
  atomic_relief: 'relief_author',
  departure: 'relief_author',
  designation: 'relief_author',
  qualification: 'qualification_attestor',
  policy: 'policy_author',
  instance_start: 'instance_attestor',
  series: 'series_author',
  identity_removal: 'identity_removal_attestor',
  occurrence_template: 'template_author',
  occurrence: 'occurrence_attestor',
  wind_down: 'wind_down_attestor',
  scheduled_job: 'job_author',
  queued_action: 'queue_attestor',
  suspension: 'suspension_author',
}

// ---------------------------------------------------------------------------
// Small helpers over the pinned timeline. Every one of these takes its instants from the
// caller or from a signed record.
// ---------------------------------------------------------------------------

const ms = (t: string): number => Date.parse(t)
const DAY_MS = 24 * 60 * 60 * 1000

function out(
  verdict: Verdict,
  reason: string,
  chain: { state: string; code: string | null } | null,
  detail?: string,
): Outcome {
  return {
    verdict,
    reason,
    sdk_chain_state: chain === null ? null : chain.state,
    sdk_failure_code: chain === null ? null : chain.code,
    ...(detail === undefined ? {} : { detail }),
  }
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

export class AuthorityBoundary {
  constructor(
    private readonly options: BoundaryOptions,
    private readonly fixture: Fixture,
  ) {}

  get name(): string {
    return this.options.name
  }

  handle(event: Event): Outcome {
    const byKind = new Map<string, SignedRecord[]>()
    for (const rec of event.records) {
      // Step 0, every boundary: a record nobody could authenticate carries no lifecycle
      // claim at all. Real SDK signature verification over JCS canonical bytes.
      if (!this.authentic(rec)) {
        return out('not_established', 'record_not_authentic', null, rec.record_id)
      }
      const list = byKind.get(rec.kind) ?? []
      list.push(rec)
      byKind.set(rec.kind, list)
    }

    const registry = byKind.get('standing_registry')?.[0]
    if (registry === undefined) {
      return out('not_established', 'standing_registry_not_presented', null)
    }

    // Step 1, every boundary: standing, from the office's own signed registry.
    for (const rec of event.records) {
      const role = REQUIRED_ROLE[rec.kind]
      if (role === undefined) continue
      const allowed = (registry.body[role] as string[] | undefined) ?? []
      if (!allowed.includes(rec.issuer)) {
        return out('not_established', 'record_without_standing', null, `${rec.record_id}/${rec.kind}`)
      }
    }

    const rule = RULES[event.check]
    if (rule === undefined) {
      return out('not_established', 'unknown_check', null, event.check)
    }
    return rule(this, event, byKind)
  }

  // -------------------------------------------------------------------------
  // Shared steps
  // -------------------------------------------------------------------------

  opt<K extends keyof BoundaryOptions>(key: K): BoundaryOptions[K] {
    return this.options[key]
  }

  authentic(rec: SignedRecord): boolean {
    const { signature, ...unsigned } = rec
    const publicKey = this.fixture.verification_keys[rec.verification_method]
    if (publicKey === undefined) return false
    const payload = `${this.fixture.record_signature_domain} ${canonicalizeJCS(unsigned)}`
    return verify(payload, signature, publicKey)
  }

  /** The SDK's chain verdict at one instant. Revocation and time, run for real. */
  chain(event: Event, now: string): { state: string; code: string | null } {
    const result = verifyAuthorityDelegationChain([event.grant], {
      now,
      resolveVerificationKey: (_issuer: string, method: string) =>
        this.fixture.verification_keys[method] ?? null,
      trustRoot: (root: { issuer?: string }) => root.issuer === this.fixture.identities.OFFICE,
      resolveRevocation: () => event.resolveRevocation(now),
    })
    return { state: result.state, code: result.failures[0]?.code ?? null }
  }

  /**
   * Every rule below starts here: scope membership and the grant's own chain state at the
   * instant the rule selected. This is the step that makes the family's point. On every
   * vector where a lifecycle bound decides the answer, this step still returns `valid`:
   * none of the fourteen bounds is visible to chain verification.
   */
  chainGate(event: Event, now: string): { chain: { state: string; code: string | null }; blocked: Outcome | null } {
    const chain = this.chain(event, now)
    if (chain.state === 'invalid' && chain.code === 'REVOKED') {
      return { chain, blocked: out('invalid', 'grant_revoked', chain) }
    }
    if (chain.state === 'indeterminate') {
      return { chain, blocked: out('not_established', 'chain_state_indeterminate', chain) }
    }
    if (chain.state === 'invalid' && chain.code === 'NOT_YET_VALID') {
      return { chain, blocked: out('not_yet_effective', 'grant_window_not_reached', chain) }
    }
    if (chain.state !== 'valid') {
      return { chain, blocked: out('invalid', 'grant_chain_not_valid', chain, chain.code ?? undefined) }
    }
    return { chain, blocked: null }
  }

  /** chainGate plus scope membership, the common opening of most rules. */
  base(event: Event, now: string): { chain: { state: string; code: string | null }; blocked: Outcome | null } {
    const gate = this.chainGate(event, now)
    if (gate.blocked) return gate
    if (!isPurposePermitted(event.action.requested_scope, event.grant.authority.scope.grants)) {
      return { chain: gate.chain, blocked: out('invalid', 'scope_not_in_grant', gate.chain) }
    }
    return gate
  }
}

// ---------------------------------------------------------------------------
// One rule per CASES.md case. Each receives the already authenticated records grouped by
// kind, and each is responsible for exactly one case's lifecycle question.
// ---------------------------------------------------------------------------

type Rule = (b: AuthorityBoundary, e: Event, r: Map<string, SignedRecord[]>) => Outcome

const one = (r: Map<string, SignedRecord[]>, kind: string): SignedRecord | undefined =>
  r.get(kind)?.[0]

const RULES: Record<string, Rule> = {
  // LC-C-008. A vacancy with no explicit successor designation. Absence of a designation
  // is not a revocation and is not an unknown revocation answer either: it is a missing
  // record, which gives not_established unless a recorded instrument names a default and
  // the candidate meets the eligibility the instrument itself declares. This family makes
  // no claim that office-based authority continues in general. Vacancy and succession stay
  // open in OPEN-QUESTIONS.md, and this rule reads only what the records say.
  succession_default(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const vacancy = one(r, 'vacancy')
    if (vacancy === undefined) return out('not_established', 'vacancy_not_recorded', chain)
    const direction = one(r, 'direction')
    if (direction === undefined) return out('not_established', 'no_direction_for_the_vacant_office', chain)
    const rule = one(r, 'succession_default')
    if (rule === undefined) {
      return out('not_established', 'no_successor_designation_and_no_declared_default', chain)
    }
    const tenure = (r.get('role_tenure') ?? []).find((t) => t.body.holder === direction.issuer)
    if (tenure === undefined) {
      return out('not_established', 'default_successor_tenure_not_recorded', chain)
    }
    if (tenure.body.role !== rule.body.default_successor_role) {
      return out('not_established', 'default_successor_role_does_not_match', chain)
    }
    const heldDays = (ms(vacancy.body.vacant_from as string) - ms(tenure.body.held_since as string)) / DAY_MS
    if (heldDays < (rule.body.minimum_tenure_days as number)) {
      return out('not_established', 'default_successor_eligibility_not_met', chain, `tenure_days=${Math.floor(heldDays)}`)
    }
    return out('valid', 'default_successor_resolved', chain, `acting=${direction.issuer}`)
  },

  // LC-C-014. A handover the incoming holder has to acknowledge. Until the acknowledgment
  // arrives, authority stays with the outgoing holder: it does not transfer and it does
  // not go vacant. The incoming holder's own claim is not_yet_effective, never invalid,
  // because nothing says the transfer will not happen.
  acknowledged_handover(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const offer = one(r, 'handover_offer')
    if (offer === undefined) return out('not_established', 'handover_offer_not_recorded', chain)
    const acting = e.grant.subject
    const ack = (r.get('handover_ack') ?? []).find(
      (a) => a.body.offer_id === offer.record_id && a.issuer === offer.body.incoming,
    )
    if (!b.opt('requiresAcknowledgedTransfer')) {
      // The declared defect: transfer is one timestamped event at the offer.
      return acting === offer.body.incoming
        ? out('valid', 'transfer_treated_as_instantaneous', chain)
        : out('invalid', 'outgoing_holder_treated_as_departed', chain)
    }
    if (ack === undefined) {
      const wrongSigner = (r.get('handover_ack') ?? []).some((a) => a.body.offer_id === offer.record_id)
      if (acting === offer.body.outgoing) {
        return out('valid', 'authority_retained_pending_acknowledgment', chain)
      }
      return out(
        'not_yet_effective',
        wrongSigner ? 'acknowledgment_without_standing' : 'handover_not_acknowledged',
        chain,
      )
    }
    if (ack.body.briefing_digest !== offer.body.briefing_digest) {
      return out('not_yet_effective', 'acknowledged_briefing_does_not_match_the_offer', chain)
    }
    if (ms(e.now) < ms(ack.body.acknowledged_at as string)) {
      return acting === offer.body.outgoing
        ? out('valid', 'authority_retained_pending_acknowledgment', chain)
        : out('not_yet_effective', 'handover_not_acknowledged', chain)
    }
    return acting === offer.body.incoming
      ? out('valid', 'handover_acknowledged', chain)
      : out('invalid', 'authority_transferred', chain)
  },

  // LC-C-015. Loss of the live directing channel. This is not a revocation and not an
  // unknown revocation answer. Where a pre-authorized fallback scope was recorded at grant
  // time, authority narrows to it (restricted) rather than stopping. Outside that scope
  // there is no authority for the action, and with no fallback recorded at all the
  // boundary cannot establish that the action is currently directed.
  directed_fallback(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const contact = one(r, 'contact_observation')
    if (contact === undefined) return out('not_established', 'contact_state_not_recorded', chain)
    const restored = contact.body.restored_at as string | null
    if (restored !== null && ms(e.now) >= ms(restored)) {
      return out('valid', 'live_direction_restored', chain)
    }
    const fallback = one(r, 'fallback_authorization')
    const gapSeconds = (ms(e.now) - ms(contact.body.last_contact_at as string)) / 1000
    if (fallback === undefined) {
      if (gapSeconds <= 0) return out('valid', 'live_direction_present', chain)
      return out('not_established', 'no_pre_authorized_fallback_and_no_live_direction', chain)
    }
    if (gapSeconds < (fallback.body.contact_loss_threshold_seconds as number)) {
      return out('valid', 'live_direction_present', chain)
    }
    const fallbackScope = fallback.body.fallback_scope as string[]
    if (!isPurposePermitted(e.action.requested_scope, fallbackScope)) {
      return out('invalid', 'outside_fallback_scope', chain, `fallback=${fallbackScope.join(',')}`)
    }
    return out('restricted', 'fallback_scope_active', chain, `fallback=${fallbackScope.join(',')}`)
  },

  // LC-C-017. A standing rotation schedule is its own form of pre-authorization. A swap at
  // a declared slot with the required rest recorded needs no fresh authorization event. A
  // swap off the schedule is not established, and a swap before the required rest has
  // elapsed is not_yet_effective, not invalid: the rest period ends on its own.
  rotation_schedule(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const schedule = one(r, 'rotation_schedule')
    if (schedule === undefined) return out('not_established', 'rotation_schedule_not_recorded', chain)
    const slots = schedule.body.slots as Array<{ at: string; outgoing: string; incoming: string }>
    const slot = slots.find((s) => s.at === e.now && s.incoming === e.grant.subject)
    if (slot === undefined) return out('not_established', 'swap_not_in_rotation_schedule', chain)
    const rest = (r.get('rest_ledger') ?? []).find((x) => x.body.holder === slot.incoming)
    if (rest === undefined) return out('not_established', 'rest_state_not_established', chain)
    const ended = rest.body.rest_ended_at as string | null
    if (ended === null || ms(ended) > ms(slot.at)) {
      return out('not_yet_effective', 'required_rest_period_not_elapsed', chain)
    }
    const restedSeconds = (ms(ended) - ms(rest.body.rest_started_at as string)) / 1000
    if (restedSeconds < (schedule.body.minimum_rest_seconds as number)) {
      return out('not_yet_effective', 'required_rest_period_not_elapsed', chain, `rested_seconds=${restedSeconds}`)
    }
    return out('valid', 'scheduled_swap_pre_authorized', chain, `slot=${slot.at}`)
  },

  // LC-C-025. A position whose governing record requires the designation and the departure
  // to be one operation. Inside a gap between two separate records there is no holder a
  // verifier can establish, which is not_established rather than a verdict against either
  // party.
  continuous_coverage(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const atomic = one(r, 'atomic_relief')
    const qualified = (holder: unknown) =>
      (r.get('qualification') ?? []).some((q) => q.body.holder === holder)
    if (atomic !== undefined) {
      if (ms(e.now) < ms(atomic.body.effective_at as string)) {
        return out('not_yet_effective', 'relief_not_yet_effective', chain)
      }
      if (e.grant.subject !== atomic.body.designated) {
        return out('invalid', 'acting_party_is_not_the_designated_holder', chain)
      }
      if (!qualified(atomic.body.designated)) {
        return out('not_established', 'designee_qualification_not_established', chain)
      }
      return out('valid', 'departure_and_designation_recorded_atomically', chain)
    }
    const departure = one(r, 'departure')
    const designation = one(r, 'designation')
    if (departure === undefined) return out('not_established', 'departure_not_recorded', chain)
    if (designation === undefined) return out('not_established', 'no_designated_holder_in_gap', chain)
    const gapOpen = ms(e.now) >= ms(departure.body.effective_at as string)
    const designated = ms(e.now) >= ms(designation.body.effective_at as string)
    if (gapOpen && !designated) {
      if (!b.opt('requiresAcknowledgedTransfer')) {
        // The declared defect: the designation is backdated to the departure instant, so
        // the gap the case exists to catch is never visible.
        return out('valid', 'gap_treated_as_instantaneous_transfer', chain)
      }
      return out('not_established', 'no_designated_holder_in_gap', chain)
    }
    if (!designated) return out('not_yet_effective', 'designation_not_yet_effective', chain)
    if (e.grant.subject !== designation.body.designated) {
      return out('invalid', 'acting_party_is_not_the_designated_holder', chain)
    }
    if (!qualified(designation.body.designated)) {
      return out('not_established', 'designee_qualification_not_established', chain)
    }
    return out('valid', 'designation_recorded', chain)
  },

  // LC-E-008. A durable instance's remaining steps resolve against the policy version the
  // instance pinned when it started, not the version deployed now. An instance that pinned
  // nothing, or pinned a version no recorded policy matches, gives not_established: the
  // boundary cannot say which rules the instance has been running under.
  pinned_policy_version(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const instance = one(r, 'instance_start')
    if (instance === undefined) return out('not_established', 'instance_start_not_recorded', chain)
    const policies = r.get('policy') ?? []
    const pinned = instance.body.pinned_policy_version as string | null
    let selected: SignedRecord | undefined
    if (b.opt('usesPinnedVersions') && pinned !== null) {
      selected = policies.find((p) => p.body.policy_version === pinned)
      if (selected === undefined) {
        return out('not_established', 'pinned_policy_version_not_resolvable', chain, `pinned=${pinned}`)
      }
    } else {
      if (b.opt('usesPinnedVersions') && pinned === null) {
        return out('not_established', 'policy_version_not_pinned', chain)
      }
      // The declared defect, and also the honest path for a boundary with no pin: the
      // latest policy already in force at this instant.
      const inForce = policies
        .filter((p) => ms(p.body.effective_from as string) <= ms(e.now))
        .sort((x, y) => ms(x.body.effective_from as string) - ms(y.body.effective_from as string))
      selected = inForce[inForce.length - 1]
      if (selected === undefined) return out('not_established', 'no_policy_in_force', chain)
    }
    const denied = (selected.body.denied_scopes as string[]) ?? []
    if (denied.includes(e.action.requested_scope)) {
      return out(
        'invalid',
        'denied_under_selected_policy_version',
        chain,
        `policy_version=${selected.body.policy_version as string}`,
      )
    }
    return out(
      'valid',
      'permitted_under_selected_policy_version',
      chain,
      `policy_version=${selected.body.policy_version as string}`,
    )
  },

  // LC-E-014. A recurring series outliving the identity that scheduled it. Three endings
  // that a naive cleanup collapses into one: the owner's authority revoked (invalid, and
  // the SDK says so), the owner removed from the registry with nothing revoked
  // (not_established), and a series whose own record declared a disposition for exactly
  // this event (valid under the reassigned principal's own grant).
  series_owner(b, e, r) {
    const series = one(r, 'series')
    if (series === undefined) {
      return out('not_established', 'series_not_recorded', null)
    }
    const removal = (r.get('identity_removal') ?? []).find((x) => x.body.identity === series.body.owner)
    const removedNow = removal !== undefined && ms(e.now) >= ms(removal.body.removed_at as string)
    const disposition = series.body.disposition_on_owner_removal as
      | { mode: string; reassign_to: string; grant: string }
      | null
    if (removedNow && disposition !== null && disposition.mode === 'reassign') {
      // The reassigned principal's own grant is the one presented as the event's grant.
      const { chain, blocked } = b.base(e, e.now)
      if (blocked) return blocked
      if (e.grant.subject !== disposition.reassign_to || e.grant.delegation_id !== disposition.grant) {
        return out('not_established', 'series_disposition_does_not_name_this_grant', chain)
      }
      return out('valid', 'series_disposition_reassignment_recorded', chain)
    }
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    if (removedNow) {
      // Nothing was revoked. The owner simply is not there, and the series record is
      // untouched. That is not_established, not invalid.
      return out('not_established', 'series_owner_not_resolvable', chain, `removed_at=${removal!.body.removed_at as string}`)
    }
    return out('valid', 'series_owner_resolvable', chain)
  },

  // LC-E-018. An occurrence keeps the template it was created under. Only the next
  // occurrence picks up a tightened template. An occurrence that did not record which
  // version it was created under gives not_established: an auditor cannot tell.
  occurrence_template(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const occurrence = one(r, 'occurrence')
    if (occurrence === undefined) return out('not_established', 'occurrence_not_recorded', chain)
    const templates = r.get('occurrence_template') ?? []
    const createdUnder = occurrence.body.created_under_template_version as string | null
    let selected: SignedRecord | undefined
    if (b.opt('usesPinnedVersions')) {
      if (createdUnder === null) {
        return out('not_established', 'occurrence_template_version_not_recorded', chain)
      }
      selected = templates.find((t) => t.body.template_version === createdUnder)
      if (selected === undefined) {
        return out('not_established', 'occurrence_template_version_not_resolvable', chain)
      }
    } else {
      const inForce = templates
        .filter((t) => ms(t.body.effective_from as string) <= ms(e.now))
        .sort((x, y) => ms(x.body.effective_from as string) - ms(y.body.effective_from as string))
      selected = inForce[inForce.length - 1]
      if (selected === undefined) return out('not_established', 'no_template_in_force', chain)
    }
    const scope = selected.body.scope as string[]
    if (!isPurposePermitted(e.action.requested_scope, scope)) {
      return out(
        'invalid',
        'outside_occurrence_template_scope',
        chain,
        `template_version=${selected.body.template_version as string}`,
      )
    }
    return out(
      'valid',
      'within_the_selected_occurrence_template',
      chain,
      `template_version=${selected.body.template_version as string}`,
    )
  },

  // LC-E-019. Termination in progress is a third state, neither suspension nor revocation.
  // Authority stays usable for the declared grace bound and then stops. Where the record
  // declares no bound, the boundary cannot establish when the window closes.
  wind_down(b, e, r) {
    const { chain, blocked } = b.base(e, e.now)
    if (blocked) return blocked
    const wind = one(r, 'wind_down')
    if (wind === undefined) return out('not_established', 'wind_down_not_recorded', chain)
    const started = ms(wind.body.termination_started_at as string)
    if (ms(e.now) < started) return out('valid', 'termination_not_started', chain)
    if (!b.opt('requiresAcknowledgedTransfer')) {
      // The declared defect: the termination signal is read as an implicit revocation.
      return out('invalid', 'termination_treated_as_revocation', chain)
    }
    const grace = wind.body.grace_seconds as number | null
    if (grace === null) return out('not_established', 'wind_down_bound_not_declared', chain)
    if (ms(e.now) <= started + grace * 1000) {
      return out('valid', 'within_wind_down_grace', chain, `grace_seconds=${grace}`)
    }
    return out('invalid', 'wind_down_grace_elapsed', chain, `grace_seconds=${grace}`)
  },

  // LC-E-020. A dormant scheduled job whose declared scope is untouched while the identity
  // it executes as is narrowed. The job definition is not the authority. The next
  // occurrence is measured against the creator grant the job names, as that grant stands
  // now, and a job naming no creator grant gives not_established.
  scheduled_job(b, e, r) {
    const job = one(r, 'scheduled_job')
    if (job === undefined) return out('not_established', 'scheduled_job_not_recorded', null)
    if (job.body.creator_grant === null) {
      return out('not_established', 'job_creator_authority_not_recorded', null)
    }
    const { chain, blocked } = b.chainGate(e, e.now)
    if (blocked) return blocked
    if (e.grant.delegation_id !== job.body.creator_grant) {
      return out('not_established', 'presented_grant_is_not_the_job_creator_grant', chain)
    }
    if (!isPurposePermitted(job.body.action_scope as string, e.grant.authority.scope.grants)) {
      return out('invalid', 'outside_current_creator_scope', chain, `job_scope=${job.body.action_scope as string}`)
    }
    return out('valid', 'within_current_creator_scope', chain, `job_scope=${job.body.action_scope as string}`)
  },

  // LC-E-034. Dormant queued work. The reference boundary checks live state at fire time.
  // The defective one checks at queue time and, on the benign timeline, reaches the same
  // answer for the wrong reason. That vector is this family's negative control.
  queued_action(b, e, r) {
    const queued = one(r, 'queued_action')
    if (queued === undefined) return out('not_established', 'queued_action_not_recorded', null)
    const at = b.opt('checksLiveStateAtFireTime')
      ? (queued.body.fires_at as string)
      : (queued.body.queued_at as string)
    const { chain, blocked } = b.base(e, at)
    if (blocked) return blocked
    if (!b.opt('checksLiveStateAtFireTime')) {
      // The declared defect. It reports the same reason the reference boundary reports
      // and has established none of it: on the benign timeline it is right by accident.
      return out('valid', 'live_state_clear_at_fire_time', chain)
    }
    const suspensions = (r.get('suspension') ?? []).filter((s) => s.body.grant === queued.body.grant)
    if (queued.body.requires_live_suspension_source === true && suspensions.length === 0) {
      return out('not_established', 'suspension_state_not_established_at_fire_time', chain)
    }
    for (const s of suspensions) {
      const from = ms(s.body.suspended_at as string)
      const released = s.body.released_at as string | null
      const active = ms(at) >= from && (released === null || ms(at) < ms(released))
      if (active) {
        return out('suspended', 'suspended_at_fire_time', chain, `cause=${s.body.cause as string}`)
      }
    }
    return out('valid', 'live_state_clear_at_fire_time', chain)
  },

  // LC-G-007. "Currently valid" is answered against the clock of the party doing the
  // checking, at the moment they check. Two checking parties can reach different answers
  // about the same artifact and both be right. The defective boundary reads the issuer's
  // claimed time out of the action reference instead.
  checking_party_clock(b, e, r) {
    const attestation = one(r, 'clock_attestation')
    if (b.opt('usesCheckingPartyClock')) {
      if (attestation === undefined) {
        return out('not_established', 'checking_party_clock_not_recorded', null)
      }
    }
    const now = b.opt('usesCheckingPartyClock')
      ? (attestation!.body.reading as string)
      : e.action.issued_at
    const chain = b.chain(e, now)
    if (chain.state === 'valid') {
      return out('valid', 'valid_on_the_selected_clock', chain, `reading=${now}`)
    }
    if (chain.code === 'EXPIRED') {
      return out('invalid', 'expired_on_the_selected_clock', chain, `reading=${now}`)
    }
    if (chain.code === 'NOT_YET_VALID') {
      // The lifecycle verdict and the SDK verdict part company here on purpose. The
      // settled vocabulary separates not_yet_effective from invalid. The pinned SDKs do
      // not: both return invalid with NOT_YET_VALID. Both answers are reported.
      return out('not_yet_effective', 'not_yet_effective_on_the_selected_clock', chain, `reading=${now}`)
    }
    return out('not_established', 'chain_state_not_decidable', chain, `reading=${now}`)
  },

  // LC-G-008. One external time source with no independent check. A wrapped reading is
  // well formed and wrong, and the device cannot tell from the inside. The reference
  // boundary will not convert a reading it cannot corroborate into a lifecycle verdict.
  time_source(b, e, r) {
    const attestation = one(r, 'clock_attestation')
    if (attestation === undefined) return out('not_established', 'clock_attestation_not_recorded', null)
    const reading = attestation.body.reading as string
    const source = attestation.body.source as string
    const cross = attestation.body.cross_check as { source: string; reading: string; bound_ms: number } | null
    if (b.opt('requiresTimeSourceCrossCheck')) {
      if (source === '') return out('not_established', 'time_source_not_recorded', null)
      if (cross === null) {
        return out('not_established', 'time_source_not_cross_checked', null, `source=${source}`)
      }
      const delta = Math.abs(ms(reading) - ms(cross.reading))
      if (delta > cross.bound_ms) {
        return out('not_established', 'time_sources_disagree_past_bound', null, `delta_ms=${delta}`)
      }
    }
    const chain = b.chain(e, reading)
    if (chain.state === 'valid') return out('valid', 'reading_accepted', chain, `reading=${reading}`)
    if (chain.code === 'NOT_YET_VALID') {
      return out('not_yet_effective', 'not_yet_effective_on_the_recorded_reading', chain, `reading=${reading}`)
    }
    if (chain.code === 'EXPIRED') {
      return out('invalid', 'expired_on_the_recorded_reading', chain, `reading=${reading}`)
    }
    return out('not_established', 'chain_state_not_decidable', chain, `reading=${reading}`)
  },

  // LC-G-009. Two correctly run clocks disagreeing inside a declared smear window. Neither
  // reading is the wrong one, and a divergence with no declared window behind it is
  // not_established, never a finding of tampering.
  clock_divergence(b, e, r) {
    const attestations = r.get('clock_attestation') ?? []
    if (attestations.length < 2) return out('not_established', 'two_clock_attestations_not_presented', null)
    const [a, c] = attestations
    const delta = Math.abs(ms(a.body.reading as string) - ms(c.body.reading as string))
    const windowA = a.body.smear_policy as { window_start: string; window_end: string; bound_ms: number } | null
    const windowC = c.body.smear_policy as { window_start: string; window_end: string; bound_ms: number } | null
    const declared =
      windowA !== null &&
      windowC !== null &&
      windowA.window_start === windowC.window_start &&
      windowA.window_end === windowC.window_end
    if (b.opt('treatsClockMismatchAsTampering') && delta > 0) {
      // The declared defect: any mismatch between two timestamps reads as a fault.
      return out('invalid', 'clock_mismatch_treated_as_tampering', null, `delta_ms=${delta}`)
    }
    if (!declared) {
      return out('not_established', 'divergence_outside_any_declared_window', null, `delta_ms=${delta}`)
    }
    const inWindow = [a, c].every((x) => {
      const w = x.body.smear_policy as { window_start: string; window_end: string }
      const t = ms(x.body.reading as string)
      return t >= ms(w.window_start) && t <= ms(w.window_end)
    })
    if (!inWindow) {
      return out('not_established', 'reading_outside_the_declared_window', null, `delta_ms=${delta}`)
    }
    if (delta > windowA!.bound_ms) {
      return out('not_established', 'divergence_exceeds_declared_smear_bound', null, `delta_ms=${delta}`)
    }
    const chain = b.chain(e, a.body.reading as string)
    if (chain.state !== 'valid') {
      return out('not_established', 'chain_state_not_decidable', chain, `delta_ms=${delta}`)
    }
    return out('valid', 'divergence_within_declared_smear_bound', chain, `delta_ms=${delta}`)
  },
}

// ---------------------------------------------------------------------------
// The six configurations
// ---------------------------------------------------------------------------

const REFERENCE: Omit<BoundaryOptions, 'name'> = {
  usesCheckingPartyClock: true,
  requiresTimeSourceCrossCheck: true,
  treatsClockMismatchAsTampering: false,
  checksLiveStateAtFireTime: true,
  usesPinnedVersions: true,
  requiresAcknowledgedTransfer: true,
}

export function makeReferenceBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary({ ...REFERENCE, name: 'reference-boundary' }, f)
}

/**
 * Negative control 1, LC-E-034. Checks authority state when work is queued and never
 * again. On the benign timeline (suspension lifted before the action fires) it returns
 * the same answer as the reference boundary, having checked nothing. That vector is the
 * one a naive implementation passes wrongly.
 */
export function makeQueueTimeOnlyBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary(
    { ...REFERENCE, name: 'defective-boundary-queue-time-only', checksLiveStateAtFireTime: false },
    f,
  )
}

/**
 * Negative control 2, LC-E-008 and LC-E-018. Always evaluates against whatever version is
 * deployed now, which is the naive reading of "a tightened rule should apply immediately".
 */
export function makeCurrentVersionOnlyBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary(
    { ...REFERENCE, name: 'defective-boundary-current-version-only', usesPinnedVersions: false },
    f,
  )
}

/**
 * Negative control 3, LC-C-014, LC-C-025 and LC-E-019. Models every transfer as a single
 * timestamped event, so an unacknowledged handover transfers anyway, a gap between two
 * records disappears, and a termination signal reads as a revocation.
 */
export function makeInstantTransferBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary(
    { ...REFERENCE, name: 'defective-boundary-instant-transfer', requiresAcknowledgedTransfer: false },
    f,
  )
}

/**
 * Negative control 4, LC-G-007. Reads the time the issuer's own action reference claims
 * instead of the checking party's clock.
 */
export function makeIssuerClockBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary(
    { ...REFERENCE, name: 'defective-boundary-issuer-clock', usesCheckingPartyClock: false },
    f,
  )
}

/**
 * Negative control 5, LC-G-008 and LC-G-009. Trusts one external time source because it is
 * external, and reads any disagreement between two sources as a fault in one of them.
 */
export function makeSingleClockTrustedBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary(
    {
      ...REFERENCE,
      name: 'defective-boundary-single-clock-trusted',
      requiresTimeSourceCrossCheck: false,
      treatsClockMismatchAsTampering: true,
    },
    f,
  )
}
