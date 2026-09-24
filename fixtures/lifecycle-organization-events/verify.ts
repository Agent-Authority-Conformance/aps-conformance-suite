// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-organization-events candidate family.
//
// The boundary vectors are evaluated once per boundary policy against a fresh
// instance. The in-flight vectors are replayed as four ordered timelines, once
// per in-flight policy, each timeline against a fresh instance, in file order.
//
// The reference run decides each vector's expected block. Each defective run
// is checked against the fail set the family declares for it, so a defective
// policy that quietly started agreeing with the reference on a vector it is
// supposed to get wrong is a test failure and not a silent improvement.
//
// Exit 0 when everything matches, 1 otherwise, 2 when the fixture is not
// minted.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  AuthorityBoundary,
  InFlightBoundary,
  POLICY_PROFILES,
  type BoundaryResult,
  type FlowResult,
  type Fixture,
  type InFlightPolicy,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<Fixture>('chains.json')
const vectors = readJson<any>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.mint_now !== 'string' ||
  Object.keys(fixture.chains ?? {}).length !== 8 ||
  !fixture.verification_keys ||
  !fixture.roles ||
  !fixture.principal_of_root ||
  !fixture.attestor_standing ||
  !fixture.external_records ||
  !fixture.refusals
) {
  console.error(
    'lifecycle-organization-events chains.json is not minted. Run ' +
    'python3 fixtures/lifecycle-organization-events/mint.py first.'
  )
  process.exit(2)
}

const BOUNDARY_POLICIES = Object.keys(vectors.policies.boundary)
const FLOW_POLICIES = Object.keys(vectors.policies.flow) as InFlightPolicy[]

// Every named boundary policy must exist in the harness, so a vectors.json
// that named a policy nobody implemented would fail here rather than be
// silently skipped.
for (const name of BOUNDARY_POLICIES) {
  if (POLICY_PROFILES[name] === undefined) {
    console.error(`FAIL vectors.json names boundary policy ${name}, which harness.ts does not implement`)
    process.exit(1)
  }
}

const BOUNDARY_FIELDS: (keyof BoundaryResult)[] = [
  'outcome', 'authority_verdict', 'reason', 'failure_code', 'failure_index', 'principal_established',
]
const FLOW_FIELDS: (keyof FlowResult)[] = [
  'outcome', 'order_state', 'reason', 'authority_verdict', 'failure_code',
]

const boundaryRuns = new Map<string, Map<string, BoundaryResult>>()
for (const policy of BOUNDARY_POLICIES) {
  const instance = new AuthorityBoundary(fixture, policy)
  const out = new Map<string, BoundaryResult>()
  for (const vector of vectors.cases) {
    if (vector.kind !== 'boundary') continue
    out.set(vector.id, instance.evaluate(vector.request))
  }
  boundaryRuns.set(policy, out)
}

const byId = new Map<string, any>(vectors.cases.map((c: any) => [c.id, c]))
const flowRuns = new Map<string, Map<string, FlowResult>>()
for (const policy of FLOW_POLICIES) {
  const out = new Map<string, FlowResult>()
  for (const ids of Object.values(vectors.timelines as Record<string, string[]>)) {
    const instance = new InFlightBoundary(fixture, policy)
    for (const id of ids) out.set(id, instance.step(byId.get(id).event))
  }
  flowRuns.set(policy, out)
}

let passed = 0
let failed = 0

for (const vector of vectors.cases) {
  let ok = true
  const details: string[] = []
  const mismatched: string[] = []

  if (vector.kind === 'issuance') {
    const refusal = fixture.refusals[vector.refusal]
    ok = refusal !== undefined && refusal.raised === vector.expected.raised && refusal.code === vector.expected.code
    details.push(`raised=${refusal?.raised} code=${refusal?.code}`)
  } else {
    const isBoundary = vector.kind === 'boundary'
    const policies = isBoundary ? BOUNDARY_POLICIES : FLOW_POLICIES
    const runs: Map<string, Map<string, any>> = isBoundary ? boundaryRuns : (flowRuns as any)
    const fields: string[] = isBoundary ? (BOUNDARY_FIELDS as string[]) : (FLOW_FIELDS as string[])

    const actual = runs.get('reference')!.get(vector.id)!
    for (const field of fields) {
      if (actual[field] !== vector.expected[field]) mismatched.push(field)
    }
    ok = mismatched.length === 0
    details.push(`reference=${actual.outcome}/${actual.reason}`)

    for (const policy of policies) {
      if (policy === 'reference') continue
      const declared: string[] = vectors.declared_fail_sets[policy] ?? []
      const other = runs.get(policy)!.get(vector.id)!
      // An outcome divergence is the defective policy deciding differently.
      // A record divergence is the two policies deciding the same and
      // recording a different lifecycle state for it. They are checked apart.
      const outcomeDiffers = other.outcome !== actual.outcome
      const recordDiffers = fields.some(field => other[field] !== actual[field])
      const shouldDifferOutcome = declared.includes(vector.id)
      const shouldDifferRecord =
        shouldDifferOutcome ||
        ((vectors.record_divergence ?? {})[policy] ?? {})[vector.id] !== undefined
      ok = ok && outcomeDiffers === shouldDifferOutcome && recordDiffers === shouldDifferRecord
      if (recordDiffers || shouldDifferRecord) {
        details.push(
          `${policy}=${other.outcome}/${other.reason}(outcome_differs=${outcomeDiffers},record_differs=${recordDiffers})`
        )
      }
    }

    if (vector.negative_control) {
      const inAFailSet = Object.values(vectors.declared_fail_sets as Record<string, string[]>)
        .some(ids => ids.includes(vector.id))
      ok = ok && inAFailSet
      details.push(`negative_control=${inAFailSet}`)
    }
  }

  if (ok) {
    passed += 1
    console.log(`PASS ${vector.id} ${details.join(' ')}`)
  } else {
    failed += 1
    console.error(`FAIL ${vector.id}`)
    for (const field of mismatched) {
      const actual = (vector.kind === 'boundary' ? boundaryRuns : flowRuns).get('reference')!.get(vector.id)! as any
      console.error(`  ${field}: expected ${JSON.stringify(vector.expected[field])} actual ${JSON.stringify(actual[field])}`)
    }
    console.error(`  ${details.join(' ')}`)
  }
}

const allIds = new Set(vectors.cases.map((c: any) => c.id))
for (const [policy, ids] of Object.entries(vectors.declared_fail_sets as Record<string, string[]>)) {
  for (const id of ids) {
    if (!allIds.has(id)) {
      console.error(`FAIL declared_fail_sets.${policy} names an unknown vector ${id}`)
      failed += 1
    }
  }
}
for (const [policy, entries] of Object.entries((vectors.record_divergence ?? {}) as Record<string, Record<string, string>>)) {
  for (const id of Object.keys(entries)) {
    if (!allIds.has(id)) {
      console.error(`FAIL record_divergence.${policy} names an unknown vector ${id}`)
      failed += 1
    }
  }
}

console.log(`lifecycle-organization-events TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(failed === 0 ? 0 : 1)
