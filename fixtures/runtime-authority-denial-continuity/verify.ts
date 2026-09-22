// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the runtime-authority-denial-continuity candidate family.
//
// Replays every case in vectors.json against three policies:
//
//   reference-gate       must match every vector it runs (Property A and B)
//   fresh-path-control    (N1) runs against Property A only, must fail exactly
//                          the declared set and pass the rest
//   per-write-control      (N2) runs against Property B only, must fail exactly
//                          the declared set and pass the rest
//
// Why N1 is not run against Property B and N2 is not run against Property A:
// each negative control isolates one axis of the model (path scoping vs
// composed-effect identification). Running N1 against decomposition vectors
// would blend its path-scoping defect with the separate composed-effect
// question the vector is meant to isolate; see harness.ts's PolicyProfile
// comment. Both negative controls are still run against every vector on
// their own property, not only the ones predicted to fail, so an
// undeclared failure or a declared failure that stops failing is loud
// either way.
//
// Run: npx tsx fixtures/runtime-authority-denial-continuity/verify.ts
// Exit 0 when all three expectations hold, 1 otherwise.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  EnforcementPoint,
  FRESH_PATH_CONTROL,
  PER_WRITE_CONTROL,
  REFERENCE_GATE,
  ResourceStore,
  type DecomposedWrite,
  type EffectIdentity,
  type PolicyProfile,
  type RecordState,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

interface ExpectedBlock {
  outcome: 'allow' | 'deny'
  reason?: string
  requires_capability?: 'composed_effect_identification'
  capability_absent_outcome?: 'allow' | 'deny'
}

type TimelineEvent =
  | { event: 'deny'; request: string; tool: string; effect: EffectIdentity; context: string; reason: string; expected: ExpectedBlock }
  | { event: 'attempt'; request: string; tool: string; effect: EffectIdentity; context: string; expected: ExpectedBlock }
  | { event: 'reauthorize'; request: string; effect: EffectIdentity; context: string; denial_ref: string | null; basis: string; expected: ExpectedBlock }
  | { event: 'decompose_write'; request: string; tool: string; resource: string; write: DecomposedWrite; context: string; expected: ExpectedBlock }

interface Case {
  id: string
  property: 'A' | 'B'
  role: string
  description: string
  timeline: TimelineEvent[]
  final_state?: Record<string, Partial<RecordState>>
}

interface PolicyDecl {
  name: string
  runs_against_properties: Array<'A' | 'B'>
  must_match_all?: boolean
  expected_fail_ids?: string[]
}

interface Vectors {
  family: string
  source: { issue: string; status: string; comments: Array<{ url: string; author: string; cited_for: string }> }
  cases: Case[]
  policies: { reference_gate: PolicyDecl; n1_fresh_path_control: PolicyDecl; n2_per_write_control: PolicyDecl }
}

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors

interface StepResult {
  request: string
  ok: boolean
  detail: string
  label: 'MATCH' | 'MISMATCH' | 'not_identifiable'
}

interface CaseRun {
  caseId: string
  steps: StepResult[]
  failures: string[]
}

/** Replays one case's timeline against one fresh EnforcementPoint. */
function runCase(testCase: Case, policy: PolicyProfile): CaseRun {
  const store = new ResourceStore()
  const point = new EnforcementPoint(policy, store)
  const steps: StepResult[] = []
  const failures: string[] = []

  for (const step of testCase.timeline) {
    let observed: { decision: string; reason: string }

    switch (step.event) {
      case 'deny':
        observed = point.deny(step.request, step.tool, step.effect, step.context, step.reason)
        break
      case 'attempt':
        observed = point.attempt(step.request, step.tool, step.effect, step.context)
        break
      case 'reauthorize':
        observed = point.reauthorize(step.request, step.effect, step.context, step.denial_ref, step.basis)
        break
      case 'decompose_write':
        observed = point.decomposeWrite(step.request, step.tool, step.resource, step.write, step.context)
        break
    }

    const expected = step.expected
    if (expected.requires_capability !== undefined) {
      const has = expected.requires_capability === 'composed_effect_identification' ? policy.hasComposedEffectIdentification : false
      if (!has) {
        const target = expected.capability_absent_outcome ?? expected.outcome
        const flawMatches = observed.decision === target
        if (!flawMatches) {
          failures.push(`${step.request}: capability-absent outcome expected ${target} (documented flaw), observed ${observed.decision} -- even the declared bypass no longer matches`)
        }
        // A capability-absent step never establishes the property, whether or not it
        // matches the documented flaw outcome. It always contributes to this case's
        // tally, structurally, rather than being caught only incidentally by a
        // downstream final_state check.
        failures.push(
          `${step.request}: not_identifiable -- composed_effect_identification absent, property not established (observed ${observed.decision}, documented flaw outcome ${target})`,
        )
        steps.push({ request: step.request, ok: flawMatches, label: 'not_identifiable', detail: `not_identifiable; flaw outcome ${target} observed ${observed.decision}` })
        continue
      }
    }

    const outcomeOk = observed.decision === expected.outcome
    const reasonOk = expected.reason === undefined || observed.reason === expected.reason
    const ok = outcomeOk && reasonOk
    if (!outcomeOk) failures.push(`${step.request}: outcome expected ${expected.outcome}, observed ${observed.decision}`)
    if (!reasonOk) failures.push(`${step.request}: reason expected ${expected.reason}, observed ${observed.reason}`)
    steps.push({ request: step.request, ok, label: ok ? 'MATCH' : 'MISMATCH', detail: `${observed.decision}/${observed.reason}` })
  }

  if (testCase.final_state !== undefined) {
    for (const [resourceId, expectedPartial] of Object.entries(testCase.final_state)) {
      const actual = store.get(resourceId)
      for (const [field, expectedValue] of Object.entries(expectedPartial)) {
        const actualValue = (actual as unknown as Record<string, unknown>)[field]
        if (JSON.stringify(actualValue) !== JSON.stringify(expectedValue)) {
          failures.push(`final_state record:${resourceId}.${field} expected ${JSON.stringify(expectedValue)}, observed ${JSON.stringify(actualValue)}`)
        }
      }
    }
  }

  return { caseId: testCase.id, steps, failures }
}

function runPolicy(policy: PolicyProfile, properties: Array<'A' | 'B'>): Map<string, CaseRun> {
  const results = new Map<string, CaseRun>()
  console.log(`policy: ${policy.name}  (properties: ${properties.join(', ')})`)
  for (const testCase of vectors.cases.filter(c => properties.includes(c.property))) {
    const run = runCase(testCase, policy)
    results.set(testCase.id, run)
    const overallOk = run.failures.length === 0
    const labels = run.steps.map(s => s.label).join(',')
    console.log(`  ${overallOk ? 'MATCH   ' : 'MISMATCH'} ${testCase.id}  [${labels}]`)
    if (!overallOk) {
      for (const f of run.failures) console.log(`             ${f}`)
    }
  }
  console.log()
  return results
}

console.log(`runtime-authority-denial-continuity: ${vectors.cases.length} candidate cases`)
console.log(`source: ${vectors.source.issue} (${vectors.source.status})`)
console.log()

const referenceResults = runPolicy(REFERENCE_GATE, vectors.policies.reference_gate.runs_against_properties)
const n1Results = runPolicy(FRESH_PATH_CONTROL, vectors.policies.n1_fresh_path_control.runs_against_properties)
const n2Results = runPolicy(PER_WRITE_CONTROL, vectors.policies.n2_per_write_control.runs_against_properties)

let failed = 0

const referenceMismatches = [...referenceResults.values()].filter(r => r.failures.length > 0).map(r => r.caseId)
if (referenceMismatches.length > 0) {
  failed += 1
  console.log(`FAIL reference-gate did not match: [${referenceMismatches.join(', ')}]`)
} else {
  console.log(`ok   reference-gate matched all ${referenceResults.size} cases it ran`)
}

function checkNegativeControl(name: string, results: Map<string, CaseRun>, expectedFailIds: string[]): void {
  const observedFailIds = [...results.values()].filter(r => r.failures.length > 0).map(r => r.caseId)
  const undeclared = observedFailIds.filter(id => !expectedFailIds.includes(id))
  const stoppedFailing = expectedFailIds.filter(id => !observedFailIds.includes(id))
  if (undeclared.length > 0) {
    failed += 1
    console.log(`FAIL ${name} failed cases the fixture does not declare: [${undeclared.join(', ')}]`)
  }
  if (stoppedFailing.length > 0) {
    failed += 1
    console.log(`FAIL ${name} no longer fails declared cases: [${stoppedFailing.join(', ')}]`)
  }
  if (undeclared.length === 0 && stoppedFailing.length === 0) {
    console.log(`ok   ${name} failed exactly the declared set: [${expectedFailIds.join(', ')}]`)
  }
}

checkNegativeControl('fresh-path-control (N1)', n1Results, vectors.policies.n1_fresh_path_control.expected_fail_ids ?? [])
checkNegativeControl('per-write-control (N2)', n2Results, vectors.policies.n2_per_write_control.expected_fail_ids ?? [])

console.log()
if (failed > 0) {
  console.log('FAILED')
  process.exit(1)
}
console.log('PASSED: reference-gate matched every case, N1 and N2 each failed exactly their declared set')
process.exit(0)
