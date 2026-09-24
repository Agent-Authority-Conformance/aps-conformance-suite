// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference boundary and negative controls for the
// lifecycle-multiple-principals-and-conflict family.
//
// Fourteen deciders, one per case in the "Multiple principals and conflict" section of
// CASES.md v0.2 that this family builds as vectors, plus twelve defective boundaries.
// Each control drops exactly one part of the proposed text, so a divergence is
// attributable to the part it dropped rather than to a blend of defects. Every control
// runs against every vector for the concepts it covers, not only the ones predicted to
// diverge.
//
// Every decider is a pure function of a record set and one evaluation instant. Nothing
// here reads the clock, the network or the filesystem. Chain verification is not
// reimplemented: the runners call the SDK for that layer and pass the result in.
//
// Verdict vocabulary, settled: valid, invalid, not_established, not_yet_effective,
// suspended, restricted. A missing record gives not_established, never invalid, and
// not_established says the records do not establish the thing, never that it is false.
//
// Timestamps are RFC 3339 with millisecond precision and a literal Z, so lexicographic
// string comparison is the same as chronological comparison across every record here.
// That is asserted by the runners before any decider runs.

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export interface BoundaryProfile {
  name: string
  /** Requires every role a multi-party gate names, not one authorized signature (LC-C-011, LC-C-018). */
  checksMultiPartyGate: boolean
  /** Applies a different threshold by direction of the action (LC-C-016). */
  asymmetricByDirection: boolean
  /** Checks each contributor's own caveats rather than a pooled set (LC-C-029). */
  caveatsPerContributor: boolean
  /** A joint objective record commits parties without adding scope (LC-C-012). */
  objectiveAddsNoScope: boolean
  /** Resolves contradictory instructions by the named default, not by timestamp (LC-H-002). */
  ordersByRule: boolean
  /** A revival has to precede the termination to be effective at all (LC-H-003). */
  enforcesRevivalSequence: boolean
  /** A revival stays undoable until the end of the declared window (LC-H-003). */
  enforcesRescissionWindow: boolean
  /** A later finding is a new record and does not rewrite earlier receipts (LC-C-006). */
  findingIsProspectiveOnly: boolean
  /** A standing override takes effect without a revocation record (LC-C-031). */
  hasStandingOverride: boolean
  /** Has a state between initiation and ratification (LC-C-022). */
  hasPendingRatification: boolean
  /** A joint grant is divisible by contributed share (LC-H-001). */
  grantDivisibleByShare: boolean
  /** Silence past a contest deadline reverts to the challenged party (LC-C-002). */
  revertsOnDeadline: boolean
  /** Competing valid sources need a declared priority rule (LC-C-005). */
  requiresSourcePriority: boolean
  /** An ad hoc position dissolves rather than reverting (LC-C-020). */
  positionDissolves: boolean
}

export const REFERENCE: BoundaryProfile = {
  name: 'reference',
  checksMultiPartyGate: true,
  asymmetricByDirection: true,
  caveatsPerContributor: true,
  objectiveAddsNoScope: true,
  ordersByRule: true,
  enforcesRevivalSequence: true,
  enforcesRescissionWindow: true,
  findingIsProspectiveOnly: true,
  hasStandingOverride: true,
  hasPendingRatification: true,
  grantDivisibleByShare: true,
  revertsOnDeadline: true,
  requiresSourcePriority: true,
  positionDissolves: true,
}

const control = (name: string, patch: Partial<BoundaryProfile>): BoundaryProfile => ({
  ...REFERENCE,
  name,
  ...patch,
})

export const CONTROLS: Record<string, BoundaryProfile> = {
  'signature-suffices': control('signature-suffices', { checksMultiPartyGate: false }),
  'symmetric-threshold': control('symmetric-threshold', { asymmetricByDirection: false }),
  'pooled-caveats': control('pooled-caveats', { caveatsPerContributor: false }),
  'objective-unions-scope': control('objective-unions-scope', { objectiveAddsNoScope: false }),
  'last-write-wins': control('last-write-wins', { ordersByRule: false }),
  'sequence-ignored': control('sequence-ignored', { enforcesRevivalSequence: false }),
  'window-ignored': control('window-ignored', { enforcesRescissionWindow: false }),
  'retroactive-finding': control('retroactive-finding', { findingIsProspectiveOnly: false }),
  'revocation-channel-only': control('revocation-channel-only', { hasStandingOverride: false }),
  'finalize-on-initiation': control('finalize-on-initiation', { hasPendingRatification: false }),
  'indivisible-grant': control('indivisible-grant', { grantDivisibleByShare: false }),
  'default-continues': control('default-continues', { revertsOnDeadline: false }),
  'first-presented-wins': control('first-presented-wins', { requiresSourcePriority: false }),
  'pre-named-default-holder': control('pre-named-default-holder', { positionDissolves: false }),
}

// --- shared -----------------------------------------------------------------------

export type RoleRegistry = Record<string, string>

export interface Confirmation {
  role: string
  actor: string
  decision: 'affirm' | 'dissent'
  at: string
  signature_verifies: boolean
}

/** Milliseconds between two RFC 3339 instants. Positive when b is after a. */
function msBetween(a: string, b: string): number {
  return Date.parse(b) - Date.parse(a)
}

export type RoleStatus = 'affirmed' | 'refused' | 'stale' | 'silent'

/**
 * Per-role status for a gate. A confirmation counts for a role only when the registry
 * places its actor in that role, its own declared role agrees, its signature verifies,
 * and it was recorded at or before the evaluation instant and within the freshness bound.
 * A confirmation whose declared role differs from the registered one never counts: the
 * record's own claim about its author's role is not what decides the role.
 */
export function roleStatuses(
  roles: string[],
  confirmations: Confirmation[],
  registry: RoleRegistry,
  at: string,
  freshnessSeconds: number,
): Record<string, RoleStatus> {
  const out: Record<string, RoleStatus> = {}
  for (const role of roles) {
    const forRole = confirmations.filter(
      c => registry[c.actor] === role && c.role === role && c.signature_verifies && c.at <= at,
    )
    const fresh = forRole.filter(c => msBetween(c.at, at) <= freshnessSeconds * 1000)
    if (fresh.some(c => c.decision === 'dissent')) out[role] = 'refused'
    else if (fresh.some(c => c.decision === 'affirm')) out[role] = 'affirmed'
    else if (forRole.some(c => c.decision === 'affirm')) out[role] = 'stale'
    else out[role] = 'silent'
  }
  return out
}

export interface GateDecision {
  verdict: Verdict
  code: string
  role_status: Record<string, RoleStatus>
  silence_treated_as_consent: boolean
}

/**
 * LC-C-011 and LC-C-018. A gate at the next authorization boundary, not a second chain to
 * union with the first. One valid authorization is insufficient however senior it is, and
 * a role that said nothing is never read as having consented.
 *
 * Precedence: an active refusal makes the action invalid; silence or a stale-only
 * confirmation leaves it not established. Those are different verdicts on purpose. A
 * refusal is a recorded fact about the role's position. Silence is an absence of
 * evidence, and calling it invalid would claim the role refused when no record says so.
 */
export function decideRoleGate(
  gate: { required_roles: string[]; freshness_seconds: number },
  confirmations: Confirmation[],
  registry: RoleRegistry,
  at: string,
  profile: BoundaryProfile,
): GateDecision {
  const status = roleStatuses(gate.required_roles, confirmations, registry, at, gate.freshness_seconds)

  const values = Object.values(status)

  if (!profile.checksMultiPartyGate) {
    // The defect: any properly signed affirmation from a principal the registry knows
    // satisfies the gate, whatever role it came from and however many roles are silent.
    //
    // When every required role affirmed, this boundary reaches the reference answer by
    // the same route, so it is not made to diverge there. A control that diverged on the
    // positive vectors too would make its declared divergence set uninformative about
    // which part of the proposed text it actually dropped.
    const anyAffirm = confirmations.some(
      c => c.signature_verifies && c.at <= at && c.decision === 'affirm' && registry[c.actor] !== undefined,
    )
    if (values.some(v => v !== 'affirmed') && anyAffirm) {
      return {
        verdict: 'valid',
        code: 'SIGNED_BY_AUTHORIZED_PRINCIPAL',
        role_status: status,
        silence_treated_as_consent: true,
      }
    }
  }
  if (values.includes('refused')) {
    return { verdict: 'invalid', code: 'CONCURRENCE_REFUSED', role_status: status, silence_treated_as_consent: false }
  }
  if (values.includes('silent')) {
    return { verdict: 'not_established', code: 'CONCURRENCE_MISSING', role_status: status, silence_treated_as_consent: false }
  }
  if (values.includes('stale')) {
    return { verdict: 'not_established', code: 'CONCURRENCE_STALE', role_status: status, silence_treated_as_consent: false }
  }
  return { verdict: 'valid', code: 'CONCURRENCE_PRESENT', role_status: status, silence_treated_as_consent: false }
}

export interface DirectionPolicy {
  mode: 'all' | 'any'
  roles: string[]
}

/**
 * LC-C-016. The bar for originating or continuing and the bar for stopping are not the
 * same bar. Continuation needs every named party's current concurrence; cancelling or
 * restricting needs one, and a co-party's contrary affirmation does not block it.
 */
export function decideAsymmetricThreshold(
  gate: { directions: Record<string, DirectionPolicy>; freshness_seconds: number },
  direction: string,
  confirmations: Confirmation[],
  registry: RoleRegistry,
  at: string,
  profile: BoundaryProfile,
): GateDecision {
  // The defect: one policy, taken from the origination direction, used in every
  // direction, so stopping becomes as hard as starting.
  const policy = profile.asymmetricByDirection
    ? gate.directions[direction]
    : gate.directions.originate
  const status = roleStatuses(policy.roles, confirmations, registry, at, gate.freshness_seconds)
  const values = Object.values(status)

  if (policy.mode === 'any') {
    if (values.includes('affirmed')) {
      return { verdict: 'valid', code: 'THRESHOLD_MET_ANY', role_status: status, silence_treated_as_consent: false }
    }
    if (values.includes('refused')) {
      return { verdict: 'invalid', code: 'THRESHOLD_REFUSED', role_status: status, silence_treated_as_consent: false }
    }
    return { verdict: 'not_established', code: 'THRESHOLD_MISSING', role_status: status, silence_treated_as_consent: false }
  }

  if (values.includes('refused')) {
    return { verdict: 'invalid', code: 'THRESHOLD_REFUSED', role_status: status, silence_treated_as_consent: false }
  }
  if (values.includes('silent') || values.includes('stale')) {
    return { verdict: 'not_established', code: 'THRESHOLD_MISSING', role_status: status, silence_treated_as_consent: false }
  }
  return { verdict: 'valid', code: 'THRESHOLD_MET_ALL', role_status: status, silence_treated_as_consent: false }
}

// --- LC-C-002 -----------------------------------------------------------------------

export interface ContestRecord {
  seat_id: string
  challenged_party: string
  asserting_party: string
  default_holder: string | null
  opened_at: string
  deadline_at: string
  override: Array<{ class: string; required: number; eligible: string[] }>
}

export interface Vote {
  actor: string
  class: string
  at: string
  signature_verifies: boolean
}

export interface ContestDecision {
  verdict: Verdict
  code: string
  threshold_met_by_deadline: boolean
  governing_party: string | null
}

/**
 * LC-C-002. Two live claims to one seat, with a declared default holder for the whole
 * contested window, a hard deadline, and a supermajority that can flip the default.
 * Silence past the deadline reverts to the party being challenged, not to whoever holds
 * the seat at that moment.
 */
export function decideContestedSeat(
  contest: ContestRecord,
  votes: Vote[],
  actor: string,
  at: string,
  profile: BoundaryProfile,
): ContestDecision {
  // Votes recorded after the deadline do not count toward a threshold the deadline
  // closed. That is what makes the deadline hard rather than advisory.
  const thresholdMet = contest.override.every(req => {
    const counted = votes.filter(
      v => v.class === req.class && v.signature_verifies && v.at <= contest.deadline_at && req.eligible.includes(v.actor),
    )
    return counted.length >= req.required
  })

  const base = { threshold_met_by_deadline: thresholdMet }

  if (at < contest.opened_at) {
    return { ...base, verdict: 'not_established', code: 'CONTEST_NOT_OPEN', governing_party: null }
  }
  if (contest.default_holder === null) {
    return { ...base, verdict: 'not_established', code: 'NO_DEFAULT_HOLDER', governing_party: null }
  }

  const parties = [contest.default_holder, contest.challenged_party]
  if (!parties.includes(actor)) {
    return { ...base, verdict: 'invalid', code: 'NOT_A_PARTY_TO_THE_CONTEST', governing_party: null }
  }

  if (at <= contest.deadline_at) {
    const governing = contest.default_holder
    return actor === governing
      ? { ...base, verdict: 'valid', code: 'CONTEST_WINDOW_DEFAULT', governing_party: governing }
      : { ...base, verdict: 'suspended', code: 'CONTEST_WINDOW_CHALLENGED', governing_party: governing }
  }

  if (!profile.revertsOnDeadline && !thresholdMet) {
    // The defect: the default holder simply continues past the deadline. Where the
    // supermajority was in fact recorded by the deadline, this boundary and the reference
    // agree that the default holder continues, so it is not made to diverge there.
    const governing = contest.default_holder
    return actor === governing
      ? { ...base, verdict: 'valid', code: 'DEFAULT_CONTINUES', governing_party: governing }
      : { ...base, verdict: 'invalid', code: 'DEFAULT_CONTINUES', governing_party: governing }
  }

  const governing = thresholdMet ? contest.default_holder : contest.challenged_party
  const code = thresholdMet ? 'OVERRIDE_SUSTAINED' : 'CONTEST_REVERTED'
  return actor === governing
    ? { ...base, verdict: 'valid', code, governing_party: governing }
    : { ...base, verdict: 'invalid', code, governing_party: governing }
}

// --- LC-C-005 -----------------------------------------------------------------------

export interface SuccessionSource {
  source_id: string
  chain: string
  names_holder: string
}

export interface SuccessionDecision {
  verdict: Verdict
  code: string
  governing_holder: string | null
  per_chain: Record<string, Verdict>
}

/**
 * LC-C-005. Two independently valid sources naming different holders for one seat.
 * Presenting a chain is not the same as that chain being the one that governs, so with no
 * declared priority between sources the question is not established rather than answered
 * by whichever chain a relying party submitted.
 */
export function decideCompetingSuccession(
  sources: SuccessionSource[],
  priorityRule: { ordered_source_ids: string[] } | null,
  profile: BoundaryProfile,
): SuccessionDecision {
  const holders = new Set(sources.map(s => s.names_holder))
  const all = (v: Verdict): Record<string, Verdict> =>
    Object.fromEntries(sources.map(s => [s.chain, v]))

  if (holders.size === 1) {
    return {
      verdict: 'valid',
      code: 'NO_CONFLICT',
      governing_holder: sources[0].names_holder,
      per_chain: all('valid'),
    }
  }

  const pick = (winner: SuccessionSource, code: string): SuccessionDecision => ({
    verdict: 'valid',
    code,
    governing_holder: winner.names_holder,
    per_chain: Object.fromEntries(
      sources.map(s => [s.chain, (s.source_id === winner.source_id ? 'valid' : 'invalid') as Verdict]),
    ),
  })

  if (!profile.requiresSourcePriority) {
    // The defect: verify whichever chain was presented first and call it the answer.
    return pick(sources[0], 'FIRST_PRESENTED')
  }

  if (priorityRule === null) {
    return { verdict: 'not_established', code: 'NO_SOURCE_PRIORITY', governing_holder: null, per_chain: all('not_established') }
  }

  // A rule that does not order every source a relying party could present does not
  // decide between them either.
  const unordered = sources.filter(s => !priorityRule.ordered_source_ids.includes(s.source_id))
  if (unordered.length > 0) {
    return { verdict: 'not_established', code: 'PRIORITY_RULE_INCOMPLETE', governing_holder: null, per_chain: all('not_established') }
  }

  const winner = [...sources].sort(
    (a, b) =>
      priorityRule.ordered_source_ids.indexOf(a.source_id) -
      priorityRule.ordered_source_ids.indexOf(b.source_id),
  )[0]
  return pick(winner, 'SOURCE_PRIORITY_APPLIED')
}

// --- LC-C-006 -----------------------------------------------------------------------

export interface Finding {
  kind: 'void_from_issuance'
  target_role: string
  found_at: string
  by: string
  standing_ref: string | null
}

export interface Receipt {
  receipt_id: string
  at: string
  verdict: Verdict
  code: string | null
}

export interface FindingDecision {
  verdict: Verdict
  code: string
  no_revocation_record: boolean
  earlier_receipts: Receipt[]
}

/**
 * LC-C-006. An ancestor invalid from issuance, discovered long after the fact. Nobody
 * revoked anything, so the verdict is not REVOKED, and the finding is a new record that
 * references the earlier receipts rather than rewriting them.
 */
export function decideVoidFromIssuance(
  finding: Finding | null,
  chainVerdictOnItsOwnRecords: Verdict,
  earlierReceipts: Receipt[],
  registry: { finders_with_standing: string[] },
  at: string,
  profile: BoundaryProfile,
): FindingDecision {
  // The defect: the finding reaches back and relabels every earlier receipt, so the
  // record no longer shows what a verifier could establish at the time it acted.
  const receipts = profile.findingIsProspectiveOnly
    ? earlierReceipts
    : earlierReceipts.map(r => ({ ...r, verdict: 'invalid' as Verdict, code: 'VOID_FROM_ISSUANCE' }))

  if (finding === null) {
    return { verdict: chainVerdictOnItsOwnRecords, code: 'CHAIN_VERIFIED', no_revocation_record: true, earlier_receipts: receipts }
  }
  if (finding.standing_ref === null || !registry.finders_with_standing.includes(finding.by)) {
    return {
      verdict: chainVerdictOnItsOwnRecords,
      code: 'FINDING_STANDING_NOT_ESTABLISHED',
      no_revocation_record: true,
      earlier_receipts: receipts,
    }
  }
  if (at < finding.found_at) {
    return {
      verdict: chainVerdictOnItsOwnRecords,
      code: 'FINDING_NOT_YET_RECORDED',
      no_revocation_record: true,
      earlier_receipts: receipts,
    }
  }
  return { verdict: 'invalid', code: 'VOID_FROM_ISSUANCE', no_revocation_record: true, earlier_receipts: receipts }
}

// --- LC-C-012 -----------------------------------------------------------------------

export interface JointObjective {
  objective_id: string
  parties: Array<{ party: string; chain: string; signature_verifies: boolean }>
}

export interface ObjectiveDecision {
  verdict: Verdict
  code: string
  objective_state: Verdict
  bound_parties: string[]
}

/**
 * LC-C-012. Independently rooted chains commit jointly to a shared objective without
 * merging their scopes. The objective record binds its signatories; it never widens what
 * any one chain authorizes, and one party withdrawing does not invalidate the others.
 */
export function decideJointObjective(
  objective: JointObjective | null,
  grantsByChain: Record<string, string[]>,
  action: { needs_grants: string[]; under_chain: string },
  withdrawal: { by: string; at: string } | null,
  at: string,
  profile: BoundaryProfile,
): ObjectiveDecision {
  const bound = objective === null ? [] : objective.parties.filter(p => p.signature_verifies).map(p => p.party).sort()

  let objectiveState: Verdict = 'not_established'
  if (objective !== null) {
    const allSigned = objective.parties.every(p => p.signature_verifies)
    if (!allSigned) objectiveState = 'not_established'
    else if (withdrawal !== null && at >= withdrawal.at) {
      objectiveState = bound.length > 1 ? 'restricted' : 'invalid'
    } else objectiveState = 'valid'
  }

  const withdrawnChains =
    objective === null || withdrawal === null || at < withdrawal.at
      ? []
      : objective.parties.filter(p => p.party === withdrawal.by).map(p => p.chain)

  if (withdrawnChains.includes(action.under_chain)) {
    return { verdict: 'invalid', code: 'PARTY_WITHDRAWN', objective_state: objectiveState, bound_parties: bound }
  }

  // The selected chain is checked first, so a boundary that also pools scopes reaches the
  // reference answer wherever the selected chain covers the action on its own. Its
  // divergence set then names only the vectors where pooling changed the answer.
  const selected = new Set(grantsByChain[action.under_chain] ?? [])
  if (action.needs_grants.every(g => selected.has(g))) {
    return {
      verdict: 'valid',
      code: 'SCOPE_COVERED_BY_SELECTED_CHAIN',
      objective_state: objectiveState,
      bound_parties: bound,
    }
  }

  // The defect: the objective record is read as pooling the parties' scopes, so an
  // action no single chain covers is admitted because some other party's chain covers it.
  if (!profile.objectiveAddsNoScope) {
    const pooled = new Set(
      (objective?.parties ?? [])
        .filter(p => !withdrawnChains.includes(p.chain))
        .flatMap(p => grantsByChain[p.chain] ?? []),
    )
    if (action.needs_grants.every(g => pooled.has(g))) {
      return {
        verdict: 'valid',
        code: 'SCOPE_UNIONED_ACROSS_PARTIES',
        objective_state: objectiveState,
        bound_parties: bound,
      }
    }
  }

  return { verdict: 'invalid', code: 'SCOPE_NOT_COVERED', objective_state: objectiveState, bound_parties: bound }
}

// --- LC-C-020 -----------------------------------------------------------------------

export interface PositionRule {
  position_id: string
  eligible_roles: string[]
  trigger_event_id: string
}

export interface PositionDecision {
  verdict: Verdict
  code: string
  holder: string | null
  reverts_to: string | null
}

/**
 * LC-C-020. A position whose first holder is decided by an eligibility rule evaluated
 * live, with no grant record naming anyone in advance. Replacing that holder goes through
 * the same accept-and-acknowledge step as a planned handover, and when the triggering
 * condition ends the position dissolves rather than reverting to anyone.
 */
export function decideAdHocPosition(
  rule: PositionRule,
  trigger: { event_id: string; opened_at: string; closed_at: string | null } | null,
  claims: Array<{ actor: string; at: string }>,
  handovers: Array<{ from: string; to: string; accepted_at: string | null }>,
  registry: RoleRegistry,
  at: string,
  profile: BoundaryProfile,
): PositionDecision {
  const eligibleClaims = claims
    .filter(c => rule.eligible_roles.includes(registry[c.actor] ?? '') && c.at <= at)
    .sort((a, b) => a.at.localeCompare(b.at))
  const firstHolder = eligibleClaims.length > 0 ? eligibleClaims[0].actor : null

  if (trigger === null || trigger.event_id !== rule.trigger_event_id) {
    return { verdict: 'not_established', code: 'POSITION_NOT_TRIGGERED', holder: null, reverts_to: null }
  }
  if (at < trigger.opened_at) {
    return { verdict: 'not_yet_effective', code: 'TRIGGER_NOT_OPEN', holder: null, reverts_to: null }
  }
  if (trigger.closed_at !== null && at >= trigger.closed_at) {
    // The defect: the position is assumed to have a standing holder, so when the
    // emergency ends it falls back to whoever held it rather than ceasing to exist.
    return profile.positionDissolves
      ? { verdict: 'invalid', code: 'POSITION_DISSOLVED', holder: null, reverts_to: null }
      : { verdict: 'valid', code: 'POSITION_REVERTED', holder: firstHolder, reverts_to: firstHolder }
  }

  const anyClaim = claims.filter(c => c.at <= at)
  if (anyClaim.length === 0) {
    return { verdict: 'not_established', code: 'NO_CLAIM', holder: null, reverts_to: null }
  }
  if (firstHolder === null) {
    return { verdict: 'invalid', code: 'NOT_ELIGIBLE', holder: null, reverts_to: null }
  }

  const accepted = handovers.filter(
    h => h.from === firstHolder && h.accepted_at !== null && h.accepted_at <= at &&
      rule.eligible_roles.includes(registry[h.to] ?? ''),
  )
  if (accepted.length > 0) {
    return { verdict: 'valid', code: 'HANDOVER_ACCEPTED', holder: accepted[accepted.length - 1].to, reverts_to: null }
  }
  const pending = handovers.filter(h => h.from === firstHolder && h.accepted_at === null)
  if (pending.length > 0) {
    return { verdict: 'not_established', code: 'HANDOVER_NOT_ACCEPTED', holder: firstHolder, reverts_to: null }
  }
  return { verdict: 'valid', code: 'FIRST_ELIGIBLE_CLAIM', holder: firstHolder, reverts_to: null }
}

// --- LC-C-022 -----------------------------------------------------------------------

export interface Relief {
  action_id: string
  by: string
  target_role: string
  at: string
  requires_ratification_by_class: string
}

export interface Ratification {
  action_id: string
  decision: 'granted' | 'denied'
  at: string
  by: string
}

export interface RatificationDecision {
  verdict: Verdict
  code: string
  action_state: Verdict
  action_characterisation: string
  claims_revocation_reversed: boolean
  earlier_receipts: Receipt[]
}

/**
 * LC-C-022. An external, unilateral suspension by a superior that becomes a final
 * revocation only on a separate approval. Before that approval the target is suspended
 * and the action is not yet effective as a revocation. If the approval never comes, the
 * record says the action was provisional throughout, which is a different statement from
 * a final revocation having been reversed.
 */
export function decidePendingRatification(
  relief: Relief,
  ratification: Ratification | null,
  registry: { class_members: Record<string, string[]> },
  earlierReceipts: Receipt[],
  at: string,
  profile: BoundaryProfile,
): RatificationDecision {
  const base = { earlier_receipts: earlierReceipts }

  if (at < relief.at) {
    return {
      ...base,
      verdict: 'valid',
      code: 'ACTION_NOT_YET_RECORDED',
      action_state: 'not_yet_effective',
      action_characterisation: 'not_initiated',
      claims_revocation_reversed: false,
    }
  }

  if (!profile.hasPendingRatification) {
    // The defect: the initiating principal's action is treated as final at once. A later
    // denial then has to be expressed as a revocation being reversed, and the ratifier's
    // standing is never an input, because the action was already final without it.
    const effective = ratification !== null && at >= ratification.at
    if (effective && ratification!.decision === 'denied') {
      return {
        ...base,
        verdict: 'valid',
        code: 'REVOCATION_REVERSED',
        action_state: 'invalid',
        action_characterisation: 'final_then_reversed',
        claims_revocation_reversed: true,
      }
    }
    if (effective) {
      return {
        ...base,
        verdict: 'invalid',
        code: 'REVOKED_AFTER_RATIFICATION',
        action_state: 'valid',
        action_characterisation: 'final_from_ratification',
        claims_revocation_reversed: false,
      }
    }
    return {
      ...base,
      verdict: 'invalid',
      code: 'FINALIZED_ON_INITIATION',
      action_state: 'valid',
      action_characterisation: 'final_on_initiation',
      claims_revocation_reversed: false,
    }
  }

  if (ratification === null || at < ratification.at) {
    return {
      ...base,
      verdict: 'suspended',
      code: 'RATIFICATION_PENDING',
      action_state: 'not_yet_effective',
      action_characterisation: 'provisional',
      claims_revocation_reversed: false,
    }
  }

  const eligible = registry.class_members[relief.requires_ratification_by_class] ?? []
  if (!eligible.includes(ratification.by)) {
    return {
      ...base,
      verdict: 'suspended',
      code: 'RATIFIER_STANDING_NOT_ESTABLISHED',
      action_state: 'not_yet_effective',
      action_characterisation: 'provisional',
      claims_revocation_reversed: false,
    }
  }

  if (ratification.decision === 'granted') {
    return {
      ...base,
      verdict: 'invalid',
      code: 'REVOKED_AFTER_RATIFICATION',
      action_state: 'valid',
      action_characterisation: 'final_from_ratification',
      claims_revocation_reversed: false,
    }
  }
  return {
    ...base,
    verdict: 'valid',
    code: 'RATIFICATION_DENIED',
    action_state: 'invalid',
    action_characterisation: 'provisional_throughout',
    claims_revocation_reversed: false,
  }
}

// --- LC-C-029 -----------------------------------------------------------------------

export interface Caveat {
  contributor: string
  forbids: string[]
  targets: string[]
}

export interface CaveatDecision {
  verdict: Verdict
  code: string
  /** Contributors whose own caveat forbade this action. Empty when nothing forbade it. */
  forbidden_by: string[]
}

/**
 * LC-C-029. A shared coalition grant carrying different, individually attached
 * restrictions per contributing source. Each contributor's subset is a strict narrowing
 * of its own full authority, and its caveat is checked against that contributor's
 * contribution rather than against a pooled ruleset.
 */
export function decidePerContributorCaveat(
  contributions: Array<{ contributor: string; chain: string; grants: string[] }>,
  caveats: Caveat[],
  action: { grant: string; target: string; under_contributor: string | null },
  profile: BoundaryProfile,
): CaveatDecision {
  if (action.under_contributor === null) {
    return { verdict: 'not_established', code: 'CONTRIBUTOR_NOT_NAMED', forbidden_by: [] }
  }
  const contribution = contributions.find(c => c.contributor === action.under_contributor)
  if (contribution === undefined) {
    return { verdict: 'not_established', code: 'NO_SUCH_CONTRIBUTION', forbidden_by: [] }
  }
  // Scope is checked before any caveat: a grant outside the contributed subset is not
  // reached by a caveat question at all.
  if (!contribution.grants.includes(action.grant)) {
    return { verdict: 'invalid', code: 'SCOPE_NOT_COVERED', forbidden_by: [] }
  }

  // The defect: one pooled ruleset for every contributed force. Something is forbidden
  // only where every contributor forbids it, so the most permissive contributor's rules
  // reach forces the other contributor supplied.
  const applicable = profile.caveatsPerContributor
    ? caveats.filter(c => c.contributor === action.under_contributor)
    : caveats.every(c => c.forbids.includes(action.grant))
      ? caveats
      : []

  const forbidding = applicable.filter(
    c => c.forbids.includes(action.grant) && (c.targets.length === 0 || c.targets.includes(action.target)),
  )
  return forbidding.length > 0
    ? { verdict: 'invalid', code: 'CAVEAT_FORBIDS', forbidden_by: forbidding.map(c => c.contributor).sort() }
    : { verdict: 'valid', code: 'WITHIN_CONTRIBUTED_SUBSET', forbidden_by: [] }
}

// --- LC-C-031 -----------------------------------------------------------------------

export interface Override {
  by: string
  at: string
  cause: string | null
}

export interface OverrideDecision {
  verdict: Verdict
  code: string
  cause_required: boolean
  no_revocation_record: boolean
}

/**
 * LC-C-031. A standing, always-live override sitting above a concurrently exercised
 * delegated authority. The delegate's action is valid only while the override has not been
 * exercised, and exercising it needs no cause, no notice and no revocation record.
 */
export function decideStandingOverride(
  standing: { override_right_holder: string },
  override: Override | null,
  chainVerdict: Verdict,
  revocationRecordPresent: boolean,
  at: string,
  profile: BoundaryProfile,
): OverrideDecision {
  const base = { cause_required: false, no_revocation_record: !revocationRecordPresent }

  if (override === null) {
    return { ...base, verdict: chainVerdict, code: 'CONCURRENT_EXERCISE' }
  }
  if (override.by !== standing.override_right_holder) {
    return { ...base, verdict: chainVerdict, code: 'OVERRIDE_STANDING_NOT_ESTABLISHED' }
  }
  if (at < override.at) {
    return { ...base, verdict: chainVerdict, code: 'OVERRIDE_NOT_YET_EXERCISED' }
  }
  // The defect: only a revocation record can end the delegate's authority, so an override
  // with no revocation channel behind it changes nothing. Placed after the standing and
  // timing checks, so this boundary's divergence set names only the vectors where an
  // override was in fact exercised by the party holding the right.
  if (!profile.hasStandingOverride) {
    return { ...base, verdict: chainVerdict, code: 'REVOCATION_CHANNEL_ONLY' }
  }
  return { ...base, verdict: 'invalid', code: 'STANDING_OVERRIDE_EXERCISED' }
}

// --- LC-H-001 -----------------------------------------------------------------------

export interface Share {
  issuer: string
  share_id: string
  chain: string
  grants: string[]
}

export interface DivisibleDecision {
  verdict: Verdict
  code: string
  grant_state: Verdict
  per_share: Record<string, Verdict>
  reached_shares: string[]
}

/**
 * LC-H-001. A joint grant divisible along contributed share, so one co-issuer's
 * revocation reaches that issuer's own share and not the part attributable to a co-issuer
 * who never acted. Amendment and revocation carry different thresholds.
 */
export function decideDivisibleGrant(
  jointGrant: { grant_id: string; shares: Share[]; amendment_policy: 'joint_action' | 'any_issuer' },
  revocation: { by: string; scope: 'own_share' | 'whole_grant' } | null,
  amendment: { by: string[] } | null,
  action: { needs_grants: string[] },
  profile: BoundaryProfile,
): DivisibleDecision {
  let reached: string[] = []
  if (revocation !== null) {
    // The defect: the joint grant is one indivisible object, so any co-issuer's
    // revocation kills every share including the one they did not contribute.
    reached = profile.grantDivisibleByShare
      ? jointGrant.shares.filter(s => s.issuer === revocation.by).map(s => s.share_id)
      : jointGrant.shares.map(s => s.share_id)
  }
  reached = [...reached].sort()

  const perShare: Record<string, Verdict> = Object.fromEntries(
    jointGrant.shares.map(s => [s.share_id, (reached.includes(s.share_id) ? 'invalid' : 'valid') as Verdict]),
  )
  const grantState: Verdict =
    reached.length === 0 ? 'valid' : reached.length === jointGrant.shares.length ? 'invalid' : 'restricted'

  if (amendment !== null && jointGrant.amendment_policy === 'joint_action') {
    const issuers = new Set(jointGrant.shares.map(s => s.issuer))
    const signed = new Set(amendment.by)
    if ([...issuers].some(i => !signed.has(i))) {
      return {
        verdict: 'not_established',
        code: 'AMENDMENT_NOT_JOINT',
        grant_state: grantState,
        per_share: perShare,
        reached_shares: reached,
      }
    }
  }

  const available = new Set(
    jointGrant.shares.filter(s => !reached.includes(s.share_id)).flatMap(s => s.grants),
  )
  const covered = action.needs_grants.every(g => available.has(g))
  return {
    verdict: covered ? 'valid' : 'invalid',
    code: covered ? 'SHARE_COVERS_ACTION' : 'SHARE_REVOKED',
    grant_state: grantState,
    per_share: perShare,
    reached_shares: reached,
  }
}

// --- LC-H-002 -----------------------------------------------------------------------

export interface Instruction {
  kind: 'stop' | 'pay'
  by: string
  at: string
  item: string | null
  signature_verifies: boolean
}

export interface InstructionDecision {
  verdict: Verdict
  code: string
  controlling_instruction: string | null
}

/**
 * LC-H-002. On an account needing more than one signer, a stop instruction from any one
 * required signer controls over a contradictory pay instruction from a co-signer. It is a
 * fixed named default, so it does not depend on which instruction arrived first and does
 * not need the co-signer's concurrence or notice.
 */
export function decideInstructionPrecedence(
  account: { required_signers: number; signer_set: string[] },
  instructions: Instruction[],
  item: string,
  profile: BoundaryProfile,
): InstructionDecision {
  const authentic = instructions.filter(i => i.signature_verifies)
  const unboundStop = authentic.find(i => i.kind === 'stop' && i.item === null)
  if (unboundStop !== undefined) {
    return { verdict: 'not_established', code: 'INSTRUCTION_ITEM_NOT_BOUND', controlling_instruction: null }
  }

  const bound = authentic.filter(i => i.item === item)
  const counted = bound.filter(i => account.signer_set.includes(i.by))
  const uncountedStop = bound.some(i => i.kind === 'stop' && !account.signer_set.includes(i.by))

  if (counted.length === 0) {
    return uncountedStop
      ? { verdict: 'not_established', code: 'INSTRUCTION_STANDING_NOT_ESTABLISHED', controlling_instruction: null }
      : { verdict: 'not_established', code: 'NO_INSTRUCTION', controlling_instruction: null }
  }

  if (!profile.ordersByRule) {
    // The defect: whichever counted instruction is latest wins, so a pay recorded after a
    // stop pays the item, and a stop from outside the signer set is simply ignored rather
    // than leaving the item undecided. The codes are the reference's, so a divergence
    // shows up as a different answer rather than as a different label for the same one.
    const latest = [...counted].sort((a, b) => a.at.localeCompare(b.at))[counted.length - 1]
    return latest.kind === 'stop'
      ? { verdict: 'invalid', code: 'STOP_CONTROLS', controlling_instruction: 'stop' }
      : { verdict: 'valid', code: 'PAY_AUTHORIZED', controlling_instruction: 'pay' }
  }

  // A stop from a non-signer alongside a stop from a signer changes nothing: the
  // signer's stop already controls, so the counted stop is checked first.
  const stop = counted.find(i => i.kind === 'stop')
  if (stop !== undefined) {
    return { verdict: 'invalid', code: 'STOP_CONTROLS', controlling_instruction: 'stop' }
  }
  if (uncountedStop) {
    return { verdict: 'not_established', code: 'INSTRUCTION_STANDING_NOT_ESTABLISHED', controlling_instruction: null }
  }
  return { verdict: 'valid', code: 'PAY_AUTHORIZED', controlling_instruction: 'pay' }
}

// --- LC-H-003 -----------------------------------------------------------------------

export interface Revival {
  target: string
  made_at: string
  filed_at: string
  window_seconds: number
}

export interface RevivalDecision {
  verdict: Verdict
  code: string
  window_end: string | null
  rescission_status: Verdict | null
}

/**
 * LC-H-003. A terminating record and a targeted revival of the same authority arriving
 * close together, resolved by a sequencing rule plus a standing window rather than by
 * comparing two timestamps. The revival has to precede the termination to be effective at
 * all, and it stays undoable until the later of the termination and the filing plus the
 * window.
 */
export function decideSequencedRevival(
  termination: { target: string; effective_at: string },
  revival: Revival | null,
  rescission: { at: string } | null,
  at: string,
  profile: BoundaryProfile,
): RevivalDecision {
  if (revival === null) {
    return { verdict: 'invalid', code: 'TERMINATED', window_end: null, rescission_status: null }
  }

  const filedPlusWindow = new Date(Date.parse(revival.filed_at) + revival.window_seconds * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, '.000Z')
  const windowEnd = filedPlusWindow > termination.effective_at ? filedPlusWindow : termination.effective_at

  // The first defect: the ordering rule is dropped, so a revival made after the
  // termination took effect is admitted on the strength of its later timestamp.
  if (profile.enforcesRevivalSequence && revival.made_at >= termination.effective_at) {
    return { verdict: 'invalid', code: 'REVIVAL_OUT_OF_SEQUENCE', window_end: windowEnd, rescission_status: null }
  }

  if (rescission !== null) {
    // The second defect: the window is dropped, so a rescission recorded at any time
    // reaches the revival.
    if (!profile.enforcesRescissionWindow || rescission.at <= windowEnd) {
      return { verdict: 'invalid', code: 'RESCINDED', window_end: windowEnd, rescission_status: 'valid' }
    }
    // A rescission outside the window does not reach the revival, and the record says so
    // rather than saying the rescission never happened.
    return { verdict: 'valid', code: 'RESCISSION_OUT_OF_WINDOW', window_end: windowEnd, rescission_status: 'not_established' }
  }

  if (profile.enforcesRescissionWindow && at <= windowEnd) {
    return { verdict: 'not_yet_effective', code: 'RESCISSION_WINDOW_OPEN', window_end: windowEnd, rescission_status: null }
  }
  return { verdict: 'valid', code: 'REVIVAL_EFFECTIVE', window_end: windowEnd, rescission_status: null }
}
