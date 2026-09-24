// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference boundary and negative controls for the lifecycle-outside-the-chain-standing
// family. Three deciders, one per case in the "Outside-the-chain standing" section of
// CASES.md v0.2, plus four defective boundaries that each drop one part of the proposed
// text and are expected to diverge on exactly the vectors vectors.json declares.
//
// Every decider is a pure function of a record set and one evaluation instant. Nothing
// here reads the clock, the network or the filesystem. Chain verification is not
// reimplemented: verify.ts calls the SDK for that layer and passes the result in.
//
// Verdict vocabulary, settled: valid, invalid, not_established, not_yet_effective,
// suspended, restricted. A missing record gives not_established, never invalid. A
// verdict of not_established says the records do not establish the thing, and never
// that the thing is false.

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export interface BoundaryProfile {
  name: string
  /** Checks the issuing body had quorum to transact business at all (LC-H-004). */
  checksIssuingBodyQuorum: boolean
  /** Applies the majority-of-total-seats floor under a declared lesser number (LC-H-004). */
  appliesMajorityFloor: boolean
  /** Treats an external order as a new grant rather than a revival (LC-H-005). */
  treatsOrderAsNewGrant: boolean
  /** Has a verdict for a root held pending a neutral forum (LC-H-006). */
  hasHeldPendingForum: boolean
}

export const REFERENCE: BoundaryProfile = {
  name: 'reference',
  checksIssuingBodyQuorum: true,
  appliesMajorityFloor: true,
  treatsOrderAsNewGrant: true,
  hasHeldPendingForum: true,
}

export const WELL_FORMED_RECORD_SUFFICES: BoundaryProfile = {
  ...REFERENCE,
  name: 'well-formed-record-suffices',
  checksIssuingBodyQuorum: false,
}

export const BYLAW_NUMBER_WINS: BoundaryProfile = {
  ...REFERENCE,
  name: 'bylaw-number-wins',
  appliesMajorityFloor: false,
}

export const REVIVAL_RESTORES: BoundaryProfile = {
  ...REFERENCE,
  name: 'revival-restores',
  treatsOrderAsNewGrant: false,
}

export const FORCED_BINARY: BoundaryProfile = {
  ...REFERENCE,
  name: 'forced-binary',
  hasHeldPendingForum: false,
}

// --- LC-H-004 -------------------------------------------------------------------

export interface BodyRecord {
  body_id: string
  total_seats: number
  bylaw_quorum: number | null
  seated_directors: string[]
  participants: string[]
}

export interface SuspensionRecord {
  suspension_id: string
  target_role: string
  by_body: string
  at: string
  signed_by: string[]
}

export interface QuorumDecision {
  verdict: Verdict
  code: string
  target_chain_verdict: Verdict
  body_action_exists: boolean
  effective_quorum: number
  counted_participants: number
}

/** The majority default: more than half the total number of seats. */
export function majorityFloor(totalSeats: number): number {
  return Math.floor(totalSeats / 2) + 1
}

/**
 * LC-H-004. The body's own composition is a precondition for the validity of what it
 * issued, separate from whether the record it produced is well formed.
 *
 * `chainVerdictWhenNoBodyAction` is the SDK's verdict for the targeted chain on its own
 * records, passed in rather than recomputed here.
 */
export function decideIssuingBodyQuorum(
  body: BodyRecord,
  suspension: SuspensionRecord,
  chainVerdictWhenNoBodyAction: Verdict,
  profile: BoundaryProfile,
): QuorumDecision {
  const declared = body.bylaw_quorum
  const floor = majorityFloor(body.total_seats)
  // A bylaw may require a greater number than the default. A declared lesser number
  // does not lower the default, so the effective quorum is the larger of the two. The
  // bylaw-number-wins control drops the floor and takes the declared number as given.
  const effectiveQuorum = profile.appliesMajorityFloor
    ? Math.max(floor, declared ?? 0)
    : (declared ?? floor)

  const seated = new Set(body.seated_directors)
  const counted = body.participants.filter(p => seated.has(p))
  const countedSet = new Set(counted)
  const signersPresent = suspension.signed_by.filter(s => countedSet.has(s))

  if (profile.checksIssuingBodyQuorum && counted.length < effectiveQuorum) {
    return {
      verdict: 'not_established',
      code: 'ISSUING_BODY_QUORUM_NOT_ESTABLISHED',
      target_chain_verdict: chainVerdictWhenNoBodyAction,
      body_action_exists: false,
      effective_quorum: effectiveQuorum,
      counted_participants: counted.length,
    }
  }

  // A body action needs a signature from the body that met quorum. This check is not
  // the quorum check: it survives in every profile, including the controls, so a
  // control's divergence is attributable to the part it actually dropped.
  if (signersPresent.length === 0) {
    return {
      verdict: 'not_established',
      code: 'BODY_ACTION_NOT_SIGNED_BY_PARTICIPANT',
      target_chain_verdict: chainVerdictWhenNoBodyAction,
      body_action_exists: false,
      effective_quorum: effectiveQuorum,
      counted_participants: counted.length,
    }
  }

  return {
    verdict: 'suspended',
    code: 'SUSPENDED_BY_BODY',
    target_chain_verdict: 'suspended',
    body_action_exists: true,
    effective_quorum: effectiveQuorum,
    counted_participants: counted.length,
  }
}

// --- LC-H-005 -------------------------------------------------------------------

export interface OrderRecord {
  order_id: string
  by_body: string
  standing_ref: string | null
  at: string
  terms: { chain: string; extra_grants: string[] }
  predicate: { discharged_for_cause: boolean }
}

export interface ReinstatementDecision {
  verdict: Verdict
  code: string
  old_chain_verdict: Verdict
  old_chain_failure_code: string | null
  old_chain_verdict_unchanged_by_order: boolean
  new_chain_verdict: Verdict | null
  new_chain_root_issuer_differs?: boolean
  new_chain_carries_grant_absent_from_old?: string[]
}

/**
 * LC-H-005. An order from a body with standing outside the original relationship issues
 * a new grant. It never switches the terminated chain back on.
 *
 * `oldChain` and `newChain` carry the SDK's verdict for each chain on its own records,
 * plus the grant lists the runner read off those records.
 */
export function decideExternalReinstatement(
  order: OrderRecord | null,
  newChainPresent: boolean,
  registry: { bodies_with_standing: string[] },
  oldChain: { verdict: Verdict; failureCode: string | null; rootIssuer: string; grants: string[] },
  newChain: { verdict: Verdict; rootIssuer: string; grants: string[] } | null,
  profile: BoundaryProfile,
): ReinstatementDecision {
  const base = {
    old_chain_verdict: oldChain.verdict,
    old_chain_failure_code: oldChain.failureCode,
    old_chain_verdict_unchanged_by_order: true,
  }

  if (order === null) {
    return { ...base, verdict: 'not_established', code: 'NO_REPLACEMENT_GRANT', new_chain_verdict: null }
  }

  const hasStanding =
    registry.bodies_with_standing.includes(order.by_body) && order.standing_ref !== null
  if (!hasStanding) {
    return {
      ...base,
      verdict: 'not_established',
      code: 'ORDER_STANDING_NOT_ESTABLISHED',
      new_chain_verdict: newChainPresent ? 'not_established' : null,
    }
  }

  // The order is conditional on a fact its own record carries. Where the record says the
  // exception applies, the order does not issue at all, so there is nothing to verify.
  if (order.predicate.discharged_for_cause) {
    return { ...base, verdict: 'not_established', code: 'ORDER_PREDICATE_NOT_MET', new_chain_verdict: null }
  }

  if (!newChainPresent || newChain === null) {
    return { ...base, verdict: 'not_established', code: 'NO_REPLACEMENT_GRANT', new_chain_verdict: null }
  }

  if (!profile.treatsOrderAsNewGrant) {
    // The revival defect: the order flips the terminated chain back on, and the
    // replacement chain's own terms never enter the answer.
    return {
      old_chain_verdict: 'valid',
      old_chain_failure_code: null,
      old_chain_verdict_unchanged_by_order: false,
      verdict: 'valid',
      code: 'OLD_CHAIN_REVIVED',
      new_chain_verdict: newChain.verdict,
    }
  }

  const oldGrants = new Set(oldChain.grants)
  return {
    ...base,
    verdict: newChain.verdict === 'valid' ? 'valid' : newChain.verdict,
    code: 'NEW_GRANT_FROM_EXTERNAL_ISSUER',
    new_chain_verdict: newChain.verdict,
    new_chain_root_issuer_differs: newChain.rootIssuer !== oldChain.rootIssuer,
    new_chain_carries_grant_absent_from_old: newChain.grants.filter(g => !oldGrants.has(g)).sort(),
  }
}

// --- LC-H-006 -------------------------------------------------------------------

export interface DepositRecord {
  deposit_id: string
  subject: string
  forum_id: string
  deposited_at: string
  claimants: string[]
  secured_by: 'deposit' | 'bond' | null
}

export interface DeterminationRecord {
  forum_id: string
  chosen_claimant: string
  at: string
}

export interface HoldDecision {
  verdict: Verdict
  code: string
  per_chain: Record<string, Verdict>
  holder_must_choose: boolean
}

/**
 * LC-H-006. A disputed root can sit in a state that is neither valid nor invalid, with
 * the current holder discharged from picking a claimant.
 *
 * `claims` pairs each claimant with the chain they present. The chains' own SDK verdicts
 * are deliberately not an input: both verify valid on their own records, and that is the
 * gap. What decides this is the deposit and the determination.
 */
export function decideDisputedRoot(
  claims: Array<{ claimant: string; chain: string }>,
  deposit: DepositRecord | null,
  determination: DeterminationRecord | null,
  profile: BoundaryProfile,
  issuedAtByChain: Record<string, string>,
): HoldDecision {
  const allNotEstablished = (): Record<string, Verdict> =>
    Object.fromEntries(claims.map(c => [c.chain, 'not_established' as Verdict]))

  const forcedBinary = (code: string): HoldDecision => {
    // The defect: pick the earliest-issued claimed root and call it the answer.
    const winner = [...claims].sort((a, b) =>
      issuedAtByChain[a.chain].localeCompare(issuedAtByChain[b.chain]),
    )[0]
    return {
      verdict: 'valid',
      code,
      per_chain: Object.fromEntries(
        claims.map(c => [c.chain, (c.chain === winner.chain ? 'valid' : 'invalid') as Verdict]),
      ),
      holder_must_choose: false,
    }
  }

  const resolveOrHold = (code: string): HoldDecision =>
    profile.hasHeldPendingForum
      ? { verdict: 'not_established', code, per_chain: allNotEstablished(), holder_must_choose: false }
      : forcedBinary(code)

  if (deposit === null) {
    // No mechanism holds the question open, so the holder is not discharged. A profile
    // without the held state still has to answer, and answers by picking.
    return profile.hasHeldPendingForum
      ? {
          verdict: 'not_established',
          code: 'DISPUTE_UNRESOLVED_NO_FORUM',
          per_chain: allNotEstablished(),
          holder_must_choose: true,
        }
      : forcedBinary('DISPUTE_UNRESOLVED_NO_FORUM')
  }

  if (deposit.secured_by === null) {
    return profile.hasHeldPendingForum
      ? {
          verdict: 'not_established',
          code: 'HOLD_NOT_SECURED',
          per_chain: allNotEstablished(),
          holder_must_choose: true,
        }
      : forcedBinary('HOLD_NOT_SECURED')
  }

  if (determination === null) return resolveOrHold('HELD_PENDING_FORUM')
  if (determination.forum_id !== deposit.forum_id) return resolveOrHold('DETERMINATION_FORUM_MISMATCH')
  if (determination.at < deposit.deposited_at) return resolveOrHold('DETERMINATION_PRECEDES_DEPOSIT')
  if (!deposit.claimants.includes(determination.chosen_claimant)) {
    return resolveOrHold('DETERMINATION_CLAIMANT_NOT_A_PARTY')
  }

  return {
    verdict: 'valid',
    code: 'FORUM_DETERMINED',
    per_chain: Object.fromEntries(
      claims.map(c => [
        c.chain,
        (c.claimant === determination.chosen_claimant ? 'valid' : 'invalid') as Verdict,
      ]),
    ),
    holder_must_choose: false,
  }
}
