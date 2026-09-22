// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the cached-authorization-revocation candidate family.
//
// Replays every case in vectors.json against both harness implementations.
//
//   correct       must match every expected outcome in every case
//   stale-cache   must fail exactly the cases the fixture declares it fails,
//                 checked in BOTH directions -- a declared failure that starts
//                 passing is as loud as an undeclared one that starts failing
//
// The second half is what makes the family worth anything. Vectors that a known
// defect also satisfies do not discriminate, so the defective implementation is
// run on purpose and its failures are pinned by name.
//
// Two tallies are printed and they are not the same number. A case can match
// and still establish nothing: the residual-exposure case is unconstrained by
// the source inside the propagation window, and the already-executed case is a
// denial the source calls insufficient evidence. Those are excluded from the
// enforcement tally by declaration in the fixture rather than by being quietly
// counted as passes.
//
// Run: npx tsx fixtures/cached-authorization-revocation/verify.ts
// Exit 0 when both halves hold, 1 otherwise.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CORRECT_POLICY,
  DownstreamDouble,
  EnforcementPoint,
  LedgerAuthority,
  STALE_CACHE_POLICY,
  SyntheticClock,
  type AuditRecord,
  type CachePolicy,
  type Limits,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

type ConstrainedOutcome = 'allowed' | 'denied'
type ExpectedOutcome = ConstrainedOutcome | 'unconstrained_by_source'

interface Expected {
  outcome: ExpectedOutcome
  downstream_reached: boolean | 'unconstrained_by_source'
  reason?: string
  reason_any_of?: string[]
  record_as?: 'residual_exposure'
  evidence_value?: 'insufficient'
  note?: string
}

type TimelineEvent =
  | { event: 'issue_grant'; grant: string; client: string; credential: string; refresh_credential: string | null }
  | { event: 'call'; request: string; grant: string; session: string; worker: string; operation: string; expected: Expected }
  | { event: 'call_begin'; request: string; grant: string; session: string; worker: string; operation: string; expected: Expected }
  | { event: 'call_end'; request: string; expected: Expected }
  | { event: 'advance_clock'; ms: number }
  | { event: 'revoke_grant'; grant: string; revocation_event: string; acknowledged_at_ms: number }
  | { event: 'reconnect'; client: string; from_session: string; to_session: string }
  | { event: 'set_authority_available'; available: boolean }
  | { event: 'make_grant_state_unresolvable'; grant: string }

interface Case {
  id: string
  covers: { kind: string; check: number | null }
  role: string
  description: string
  stale_cache_expected_to_fail: boolean
  counts_as_revocation_enforcement_evidence: boolean
  evidence_note?: string
  timeline: TimelineEvent[]
}

interface AuditRequirements {
  fields_present_per_call: string[]
  fields_non_empty_per_call: string[]
  must_not_appear: string[]
}

interface Vectors {
  family: string
  source: { pull_request: number; head_sha: string; file: string; kind: string }
  parameters: {
    clock_start_ms: number
    propagation_limit_ms: number
    freshness_limit_ms: number
    downstream_credential: string
  }
  audit_requirements: AuditRequirements
  cases: Case[]
}

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors

const limits: Limits = {
  propagationLimitMs: vectors.parameters.propagation_limit_ms,
  freshnessLimitMs: vectors.parameters.freshness_limit_ms,
}

interface CaseRun {
  caseId: string
  failures: string[]
  residualExposure: string[]
}

/** Replays one case against one implementation and returns everything observed. */
function runCase(testCase: Case, policy: CachePolicy): CaseRun {
  const clock = new SyntheticClock(vectors.parameters.clock_start_ms)
  const authority = new LedgerAuthority()
  const downstream = new DownstreamDouble()
  const point = new EnforcementPoint(
    policy,
    limits,
    authority,
    downstream,
    clock,
    vectors.parameters.downstream_credential,
  )

  const failures: string[] = []
  const residualExposure: string[] = []
  const declaredResidual = new Set<string>()
  const sessionsSeen = new Set<string>()
  const inFlight = new Map<string, { grant: string; session: string; worker: string; operation: string }>()

  const fail = (detail: string): void => {
    failures.push(detail)
  }

  /** Checks one observed call against its expected block. */
  const checkCall = (requestId: string, grantId: string, expected: Expected, decision: string, reason: string): void => {
    const reached = downstream.reached(requestId)

    if (expected.outcome !== 'unconstrained_by_source' && decision !== expected.outcome) {
      fail(`${requestId}: outcome expected ${expected.outcome}, observed ${decision}`)
    }
    if (expected.downstream_reached !== 'unconstrained_by_source' && reached !== expected.downstream_reached) {
      fail(`${requestId}: downstream_reached expected ${String(expected.downstream_reached)}, observed ${String(reached)}`)
    }
    if (expected.reason !== undefined && reason !== expected.reason) {
      fail(`${requestId}: reason expected ${expected.reason}, observed ${reason}`)
    }
    if (expected.reason_any_of !== undefined && !expected.reason_any_of.includes(reason)) {
      fail(`${requestId}: reason expected one of [${expected.reason_any_of.join(', ')}], observed ${reason}`)
    }
    if (expected.record_as === 'residual_exposure') declaredResidual.add(requestId)

    // Residual exposure is labelled by the runner from the timeline's own
    // ground truth, not by the implementation. The source asks the person
    // running the checks to record successful calls inside the propagation
    // window; an implementation serving a stale allow does not know it is
    // inside one.
    if (decision === 'allowed') {
      const revocation = authority.acknowledgedRevocation(grantId, clock.nowMs())
      if (revocation !== null && clock.nowMs() - revocation.acknowledgedAtMs <= limits.propagationLimitMs) {
        residualExposure.push(requestId)
      }
    }
  }

  for (const event of testCase.timeline) {
    switch (event.event) {
      case 'issue_grant':
        point.registerGrant(event.grant, event.client, event.credential, event.refresh_credential)
        break

      case 'advance_clock':
        clock.advance(event.ms)
        break

      case 'revoke_grant':
        if (clock.nowMs() !== event.acknowledged_at_ms) {
          fail(`${event.revocation_event}: declared acknowledged_at_ms ${event.acknowledged_at_ms}, timeline is at ${clock.nowMs()}`)
        }
        authority.revoke(event.grant, event.revocation_event, clock.nowMs())
        break

      case 'make_grant_state_unresolvable':
        authority.makeUnresolvable(event.grant)
        break

      case 'set_authority_available':
        authority.setAvailable(event.available)
        break

      case 'reconnect':
        if (sessionsSeen.has(event.to_session)) {
          fail(`reconnect: ${event.to_session} was already used, so it is not a reconnection`)
        }
        sessionsSeen.add(event.to_session)
        break

      case 'call': {
        sessionsSeen.add(event.session)
        const outcome = point.call({
          requestId: event.request,
          grantId: event.grant,
          sessionId: event.session,
          workerId: event.worker,
          operation: event.operation,
        })
        checkCall(event.request, event.grant, event.expected, outcome.decision, outcome.reason)
        break
      }

      case 'call_begin': {
        sessionsSeen.add(event.session)
        inFlight.set(event.request, {
          grant: event.grant,
          session: event.session,
          worker: event.worker,
          operation: event.operation,
        })
        const outcome = point.beginCall({
          requestId: event.request,
          grantId: event.grant,
          sessionId: event.session,
          workerId: event.worker,
          operation: event.operation,
        })
        checkCall(event.request, event.grant, event.expected, outcome.decision, outcome.reason)
        break
      }

      case 'call_end': {
        const begun = inFlight.get(event.request)
        if (begun === undefined) {
          fail(`${event.request}: call_end with no matching call_begin`)
          break
        }
        inFlight.delete(event.request)
        const outcome = point.endCall(event.request)
        checkCall(event.request, begun.grant, event.expected, outcome.decision, outcome.reason)
        break
      }
    }
  }

  if (inFlight.size > 0) {
    fail(`case ended with unanswered calls: [${[...inFlight.keys()].join(', ')}]`)
  }

  // Residual exposure, in both directions. A recorded exposure the fixture did
  // not declare is a surprise; a declared one that was allowed and not recorded
  // is a labelling that stopped working.
  for (const requestId of residualExposure) {
    if (!declaredResidual.has(requestId)) {
      fail(`${requestId}: recorded as residual exposure but the fixture does not declare it`)
    }
  }
  for (const requestId of declaredResidual) {
    const record = point.audit.find(r => r.request_id === requestId)
    if (record?.decision === 'allowed' && !residualExposure.includes(requestId)) {
      fail(`${requestId}: declared residual exposure and was allowed, but was not recorded`)
    }
  }

  failures.push(...auditFailures(testCase, point.audit, authority))
  return { caseId: testCase.id, failures, residualExposure }
}

/** Check 5, run over every case's audit trail. */
function auditFailures(testCase: Case, audit: AuditRecord[], authority: LedgerAuthority): string[] {
  const out: string[] = []
  const requirements = vectors.audit_requirements

  const expectedRequests = testCase.timeline
    .filter((e): e is Extract<TimelineEvent, { event: 'call' | 'call_begin' }> => e.event === 'call' || e.event === 'call_begin')
    .map(e => e.request)
  const recorded = audit.map(r => r.request_id)
  for (const requestId of expectedRequests) {
    if (!recorded.includes(requestId)) out.push(`audit: no record for ${requestId}`)
  }
  if (recorded.length !== expectedRequests.length) {
    out.push(`audit: expected ${expectedRequests.length} records, observed ${recorded.length}`)
  }

  for (const record of audit) {
    const asObject = record as unknown as Record<string, unknown>
    for (const field of requirements.fields_present_per_call) {
      if (!(field in asObject)) out.push(`audit ${record.request_id}: missing field ${field}`)
    }
    for (const field of requirements.fields_non_empty_per_call) {
      const value = asObject[field]
      const empty = value === null || value === undefined || value === ''
      if (empty) out.push(`audit ${record.request_id}: field ${field} is empty`)
    }

    const revocation = authority.acknowledgedRevocation(record.grant_id, record.decided_at_ms)
    const expectedEventId = revocation?.revocationEventId ?? null
    if (record.revocation_event_id !== expectedEventId) {
      out.push(
        `audit ${record.request_id}: revocation_event_id expected ${String(expectedEventId)}, observed ${String(record.revocation_event_id)}`,
      )
    }
  }

  const serialized = JSON.stringify(audit)
  for (const secret of requirements.must_not_appear) {
    if (serialized.includes(secret)) out.push(`audit: credential value appears in the trail (${secret.slice(0, 12)}...)`)
  }

  return out
}

function runImplementation(policy: CachePolicy): Map<string, CaseRun> {
  const results = new Map<string, CaseRun>()
  console.log(`implementation: ${policy.name}`)
  for (const testCase of vectors.cases) {
    const run = runCase(testCase, policy)
    results.set(testCase.id, run)
    const check = testCase.covers.check === null ? 'stated principle' : `check ${testCase.covers.check}`
    if (run.failures.length === 0) {
      const residual = run.residualExposure.length > 0 ? `  residual_exposure=[${run.residualExposure.join(', ')}]` : ''
      console.log(`  MATCH    ${testCase.id}  (${check})${residual}`)
    } else {
      console.log(`  MISMATCH ${testCase.id}  (${check})`)
      for (const failure of run.failures) console.log(`             ${failure}`)
    }
  }
  console.log()
  return results
}

console.log(`cached-authorization-revocation: ${vectors.cases.length} candidate cases`)
console.log(
  `source: ${vectors.source.kind}, ${vectors.source.file} at PR #${vectors.source.pull_request} head ${vectors.source.head_sha}`,
)
console.log(`limits: propagation ${limits.propagationLimitMs} ms, freshness ${limits.freshnessLimitMs} ms`)
console.log()

const correct = runImplementation(CORRECT_POLICY)
const staleCache = runImplementation(STALE_CACHE_POLICY)

let failed = 0

// Half one: correct matches everything.
const correctMismatches = [...correct.values()].filter(r => r.failures.length > 0).map(r => r.caseId)
if (correctMismatches.length > 0) {
  failed += 1
  console.log(`FAIL correct did not match: [${correctMismatches.join(', ')}]`)
} else {
  console.log(`ok   correct matched all ${vectors.cases.length} cases`)
}

// Half two: stale-cache fails exactly the declared set, both directions.
const declaredToFail = vectors.cases.filter(c => c.stale_cache_expected_to_fail).map(c => c.id)
const observedToFail = [...staleCache.values()].filter(r => r.failures.length > 0).map(r => r.caseId)
const undeclared = observedToFail.filter(id => !declaredToFail.includes(id))
const stoppedFailing = declaredToFail.filter(id => !observedToFail.includes(id))

if (undeclared.length > 0) {
  failed += 1
  console.log(`FAIL stale-cache failed cases the fixture does not declare: [${undeclared.join(', ')}]`)
}
if (stoppedFailing.length > 0) {
  failed += 1
  console.log(`FAIL stale-cache no longer fails declared cases: [${stoppedFailing.join(', ')}]`)
}
if (undeclared.length === 0 && stoppedFailing.length === 0) {
  console.log(`ok   stale-cache failed exactly the declared set: [${declaredToFail.join(', ')}]`)
}

// The two tallies. Matching is not the same as establishing.
const excluded = vectors.cases.filter(c => !c.counts_as_revocation_enforcement_evidence)
const counted = vectors.cases.filter(c => c.counts_as_revocation_enforcement_evidence)
console.log()
console.log(`cases matched by correct:                       ${vectors.cases.length - correctMismatches.length}/${vectors.cases.length}`)
console.log(`of those, counted as revocation enforcement:    ${counted.length}`)
console.log(`excluded from that count:                       ${excluded.length}`)
for (const c of excluded) {
  console.log(`  ${c.id}`)
  console.log(`    ${c.evidence_note ?? 'no note recorded'}`)
}

console.log()
if (failed > 0) {
  console.log('FAILED')
  process.exit(1)
}
console.log('PASSED: correct matched every case, stale-cache failed exactly the declared set')
process.exit(0)
