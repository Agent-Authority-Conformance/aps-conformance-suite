// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the conflicting-status-sources candidate family.
//
// WHAT THIS IS. A synthetic verifier that consults a declared set of status
// sources about one delegation, at one authorization boundary, and produces a
// status-observation record. It is protocol neutral: no APS type, no APS
// receipt, no network call, no wall-clock read. Every instant in it comes from
// the vector.
//
// WHAT IT MODELS, in the vocabulary of the proposed text it is written
// against (agent-authority-lifecycle, commit 5c1bf09):
//
//   Verifier trust policy   the declared source set, each source's freshness
//                           bound, and whether the verifier is online or
//                           declares itself offline with a snapshot.
//   Status observation      one source's answer about one delegation, the
//                           instant that source says the answer was known
//                           correct (as_of), and the age of that answer at the
//                           boundary.
//   Coverage                whether every source the trust policy requires
//                           produced a usable determinate answer.
//
// THE FOUR AXES the policies differ along are named in PolicyProfile below.
// Everything else -- the clock arithmetic, the record writer, the coverage
// count -- is shared, so a divergence between two policies is attributable to
// the declared axis and to nothing else.
//
// Node builtins only, except for the suite's vendored RFC 8785 canonicalizer,
// which is used to produce the pinned record bytes.

import { canonicalizeJCS } from '../../runners/ts/canonicalize.js'
import { createHash } from 'node:crypto'

/** What a source can answer. `unavailable` is the source failing to answer. */
export type SourceAnswer = 'active' | 'revoked' | 'unavailable'

/** A verdict this model can reach. There is no fourth value, and `admit` is
 *  never reached through a conflict or an unestablished status. */
export type Verdict = 'admit' | 'deny' | 'not_established'

/** One source as the trust policy declares it. */
export interface DeclaredSource {
  source_id: string
  /** Maximum age, in seconds, of an answer this verifier will treat as usable
   *  from this source. Modelled on the freshness bound a status answer already
   *  carries in existing deployed practice. See README, Sources. */
  freshness_bound_s: number
}

/** The verifier's declared trust policy for one boundary. */
export interface TrustPolicy {
  mode: 'online' | 'offline'
  /** Sources the policy requires an answer from. Coverage is measured against
   *  this list, not against whatever answers happened to arrive. */
  required_sources: DeclaredSource[]
  /** Only in offline mode: the snapshot source and the bound the verifier
   *  declares for it. */
  snapshot_source?: DeclaredSource
  /** Only in offline mode: the maximum snapshot age, in seconds, this verifier
   *  declared in advance that it would admit on. */
  declared_offline_bound_s?: number
}

/** One answer, as the vector supplies it. */
export interface Observation {
  source_id: string
  answer: SourceAnswer
  /** The instant the source says the answer was known correct. Absent for an
   *  `unavailable` answer, which dates nothing. */
  as_of?: string
}

/** One authorization boundary in a case. */
export interface Boundary {
  boundary_id: string
  /** The instant the verifier evaluated. Nothing here reads the wall clock. */
  evaluated_at: string
  trust_policy: TrustPolicy
  observations: Observation[]
  /** Digest of the record written at an earlier boundary, when this boundary
   *  follows one. A later finding is a NEW record that references the earlier
   *  one. It never rewrites it. */
  prior_record_sha256: string | null
}

/** One source line inside a record. Every field is always present. */
export interface RecordedSource {
  source_id: string
  answer: SourceAnswer
  as_of: string | null
  age_s: number | null
  freshness_bound_s: number
  within_bound: boolean
  used: boolean
  use_basis: string
}

export interface RecordedSnapshot {
  source_id: string
  as_of: string
  age_s: number
  declared_bound_s: number
}

export interface CoverageBlock {
  required: number
  usable_determinate: number
  complete: boolean
}

export interface ConflictBlock {
  states: string[]
  sources: string[]
}

/** The status-observation record. This is the artifact the family pins. */
export interface StatusObservationRecord {
  record_type: 'aac.status-observation-record.v0'
  boundary_id: string
  delegation_ref: string
  evaluated_at: string
  verifier_mode: 'online' | 'offline'
  decision: Verdict
  reason: string
  required_sources: string[]
  sources_consulted: RecordedSource[]
  coverage: CoverageBlock
  conflict: ConflictBlock | null
  snapshot: RecordedSnapshot | null
  prior_record_sha256: string | null
}

/**
 * The four axes a policy can differ along. The reference policy sets all four
 * the way the proposed text reads, and each negative control changes exactly one.
 */
export interface PolicyProfile {
  name: string
  /** How disagreement between determinate answers is resolved.
   *  'conflict'    disagreement is a conflict and never admits.
   *  'latest_wins' the answer with the newest as_of decides, alone. */
  disagreement: 'conflict' | 'latest_wins'
  /** Whether an observed `revoked` answer is used even when its age is past
   *  the source's freshness bound. The reference policy uses it, because a
   *  revocation that was observed does not become unobserved with age. */
  revoked_is_sticky: boolean
  /** Whether coverage is measured against the declared required-source list
   *  ('declared') or against whatever usable answers arrived ('arrived'). */
  coverage_basis: 'declared' | 'arrived'
  /** Whether an offline admission writes the snapshot identity, its as_of and
   *  its age into the record. */
  records_snapshot_basis: boolean
}

export const REFERENCE_VERIFIER: PolicyProfile = {
  name: 'reference-verifier',
  disagreement: 'conflict',
  revoked_is_sticky: true,
  coverage_basis: 'declared',
  records_snapshot_basis: true,
}

/** N1. Differs from the reference on one axis: disagreement resolution. */
export const LATEST_ANSWER_WINS: PolicyProfile = {
  ...REFERENCE_VERIFIER,
  name: 'latest-answer-wins',
  disagreement: 'latest_wins',
}

/** N2. Differs from the reference on two coupled parts of one axis: it drops
 *  every answer past its bound before deciding, so a stale revocation stops
 *  counting and the coverage count is taken over what survived the drop. */
export const DROP_STALE_THEN_DECIDE: PolicyProfile = {
  ...REFERENCE_VERIFIER,
  name: 'drop-stale-then-decide',
  revoked_is_sticky: false,
  coverage_basis: 'arrived',
}

/** N3. Differs from the reference on one axis: it reaches the same offline
 *  admissions without writing what it admitted on. */
export const OFFLINE_ADMIT_WITHOUT_RECORDING: PolicyProfile = {
  ...REFERENCE_VERIFIER,
  name: 'offline-admit-without-recording',
  records_snapshot_basis: false,
}

function parseInstant(value: string): number {
  const ms = Date.parse(value)
  if (Number.isNaN(ms)) throw new Error(`not an instant: ${value}`)
  return ms
}

/** Age in whole seconds. A negative age (an answer dated after the boundary)
 *  is reported as 0, which is the conservative direction: it never makes an
 *  answer look older than it is, and the fixture has no such vector. */
function ageSeconds(asOf: string, evaluatedAt: string): number {
  const delta = parseInstant(evaluatedAt) - parseInstant(asOf)
  return delta < 0 ? 0 : Math.floor(delta / 1000)
}

export function recordDigest(record: StatusObservationRecord): string {
  return createHash('sha256').update(canonicalizeJCS(record), 'utf8').digest('hex')
}

export function canonicalRecordBytes(record: StatusObservationRecord): string {
  return canonicalizeJCS(record)
}

/**
 * Evaluate one boundary under one policy.
 *
 * The order is fixed: age every answer against the boundary instant, decide
 * which answers the policy uses, resolve disagreement, then measure coverage.
 * Coverage is measured last because an incomplete set of agreeing answers is a
 * weaker claim than a complete one, not a different one.
 */
export function evaluateBoundary(
  boundary: Boundary,
  delegationRef: string,
  policy: PolicyProfile,
): StatusObservationRecord {
  const tp = boundary.trust_policy
  const declared = new Map<string, DeclaredSource>()
  for (const s of tp.required_sources) declared.set(s.source_id, s)
  if (tp.snapshot_source) declared.set(tp.snapshot_source.source_id, tp.snapshot_source)

  const recorded: RecordedSource[] = []
  for (const obs of boundary.observations) {
    const source = declared.get(obs.source_id)
    if (!source) throw new Error(`observation from undeclared source ${obs.source_id}`)
    const isOffline = tp.mode === 'offline' && tp.snapshot_source?.source_id === obs.source_id
    const bound = isOffline
      ? (tp.declared_offline_bound_s ?? source.freshness_bound_s)
      : source.freshness_bound_s
    const age = obs.as_of === undefined ? null : ageSeconds(obs.as_of, boundary.evaluated_at)
    const withinBound = age !== null && age <= bound

    let used: boolean
    let basis: string
    if (obs.answer === 'unavailable') {
      used = false
      basis = 'source_gave_no_answer'
    } else if (obs.answer === 'revoked' && !withinBound && policy.revoked_is_sticky) {
      used = true
      basis = 'revocation_observed_outside_bound_still_used'
    } else if (withinBound) {
      used = true
      basis = 'within_freshness_bound'
    } else {
      used = false
      basis = 'stale_beyond_bound'
    }

    recorded.push({
      source_id: obs.source_id,
      answer: obs.answer,
      as_of: obs.as_of ?? null,
      age_s: age,
      freshness_bound_s: bound,
      within_bound: withinBound,
      used,
      use_basis: basis,
    })
  }
  recorded.sort((a, b) => (a.source_id < b.source_id ? -1 : a.source_id > b.source_id ? 1 : 0))

  const usedDeterminate = recorded.filter(r => r.used && r.answer !== 'unavailable')
  const states = Array.from(new Set(usedDeterminate.map(r => r.answer))).sort()

  const requiredIds = tp.required_sources.map(s => s.source_id)
  const usableRequired = requiredIds.filter(id =>
    recorded.some(r => r.source_id === id && r.used && r.answer !== 'unavailable'),
  )
  const coverage: CoverageBlock = {
    required: requiredIds.length,
    usable_determinate:
      policy.coverage_basis === 'declared' ? usableRequired.length : usedDeterminate.length,
    complete:
      policy.coverage_basis === 'declared'
        ? usableRequired.length === requiredIds.length
        : usedDeterminate.length > 0,
  }

  const silentRequired = requiredIds.filter(
    id => !recorded.some(r => r.source_id === id),
  )
  const staleRequired = requiredIds.filter(id =>
    recorded.some(r => r.source_id === id && !r.used && r.answer !== 'unavailable'),
  )

  let snapshot: RecordedSnapshot | null = null
  const snapshotLine =
    tp.mode === 'offline' && tp.snapshot_source
      ? recorded.find(r => r.source_id === tp.snapshot_source!.source_id)
      : undefined

  const write = (
    decision: Verdict,
    reason: string,
    conflict: ConflictBlock | null,
  ): StatusObservationRecord => ({
    record_type: 'aac.status-observation-record.v0',
    boundary_id: boundary.boundary_id,
    delegation_ref: delegationRef,
    evaluated_at: boundary.evaluated_at,
    verifier_mode: tp.mode,
    decision,
    reason,
    required_sources: requiredIds,
    sources_consulted: recorded,
    coverage,
    conflict,
    snapshot,
    prior_record_sha256: boundary.prior_record_sha256,
  })

  // Disagreement first. A conflict never admits, whatever coverage says.
  if (states.length > 1) {
    if (policy.disagreement === 'conflict') {
      const conflict: ConflictBlock = {
        states,
        sources: usedDeterminate.map(r => r.source_id).sort(),
      }
      return write('deny', 'status_sources_conflict', conflict)
    }
    // latest_wins: the newest as_of decides, alone.
    const newest = usedDeterminate
      .filter(r => r.as_of !== null)
      .sort((a, b) => parseInstant(b.as_of as string) - parseInstant(a.as_of as string))[0]
    if (newest && newest.answer === 'revoked') return write('deny', 'status_revoked', null)
    if (newest && newest.answer === 'active') {
      return write('admit', 'status_active_all_sources_agree', null)
    }
  }

  if (states.length === 1 && states[0] === 'revoked') {
    return write('deny', 'status_revoked', null)
  }

  if (states.length === 0) {
    if (tp.mode === 'offline' && snapshotLine) {
      return write('not_established', 'status_stale_beyond_bound', null)
    }
    return write('not_established', 'status_no_usable_observation', null)
  }

  // states === ['active'] from here.
  if (tp.mode === 'offline' && tp.snapshot_source && snapshotLine?.used) {
    if (policy.records_snapshot_basis) {
      snapshot = {
        source_id: snapshotLine.source_id,
        as_of: snapshotLine.as_of as string,
        age_s: snapshotLine.age_s as number,
        declared_bound_s: tp.declared_offline_bound_s ?? snapshotLine.freshness_bound_s,
      }
    }
    return write('admit', 'admitted_on_snapshot_within_declared_bound', null)
  }

  if (!coverage.complete) {
    if (silentRequired.length > 0) {
      return write('not_established', 'status_coverage_incomplete', null)
    }
    if (staleRequired.length > 0) {
      return write('not_established', 'status_stale_beyond_bound', null)
    }
    return write('not_established', 'status_no_usable_observation', null)
  }

  return write('admit', 'status_active_all_sources_agree', null)
}

/** Replay every boundary of a case in order, threading each record's digest
 *  into the next boundary's prior_record_sha256 when the vector declares one.
 *  An earlier record is never revisited: this returns the records as written. */
export function evaluateCase(
  boundaries: Boundary[],
  delegationRef: string,
  policy: PolicyProfile,
): StatusObservationRecord[] {
  const out: StatusObservationRecord[] = []
  for (const boundary of boundaries) {
    const prior =
      boundary.prior_record_sha256 === 'PRIOR'
        ? recordDigest(out[out.length - 1])
        : boundary.prior_record_sha256
    out.push(evaluateBoundary({ ...boundary, prior_record_sha256: prior }, delegationRef, policy))
  }
  return out
}
