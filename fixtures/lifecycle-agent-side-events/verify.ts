// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs every presentation in vectors.json through the reference boundary and the
// declared defective negative control, and checks the control in both directions.
//
//     npm run verify:lifecycle-agent-side-events

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import {
  makeDefectiveBoundary,
  makeReferenceBoundary,
  type AgentSideEventBoundary,
  type BoundaryOptions,
  type Outcome,
  type Presentation,
} from './harness.ts'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<any>('chain.json')
const vectors = readJson<any>('vectors.json')

if (fixture._placeholder || !fixture.grants || !fixture.credentials || !fixture.standing) {
  console.error(
    'lifecycle-agent-side-events chain.json is not minted. Run ' +
      '`npx tsx fixtures/lifecycle-agent-side-events/mint.ts` first.',
  )
  process.exit(2)
}

// The labelling contract. A vector that loses its candidate label, names proposed
// text this file does not define, or stops carrying its CASES.md case id, is a
// failure of the family and not of an implementation, so it stops the run before any
// boundary is built.
if (vectors.status !== 'candidate_against_proposed') {
  console.error('lifecycle-agent-side-events vectors.json must declare status candidate_against_proposed')
  process.exit(2)
}
const PROPOSED = new Set(Object.keys(vectors.proposed_text ?? {}))
for (const presentation of vectors.presentations) {
  if (presentation.status !== 'candidate_against_proposed') {
    console.error(`lifecycle-agent-side-events ${presentation.id} lost its candidate label`)
    process.exit(2)
  }
  if (!Array.isArray(presentation.tests_proposed_text) || presentation.tests_proposed_text.length === 0) {
    console.error(`lifecycle-agent-side-events ${presentation.id} names no proposed text`)
    process.exit(2)
  }
  for (const name of presentation.tests_proposed_text) {
    if (!PROPOSED.has(name)) {
      console.error(`lifecycle-agent-side-events ${presentation.id} names undefined proposed text ${name}`)
      process.exit(2)
    }
  }
  if (typeof presentation.case_id !== 'string' || !presentation.id.includes(presentation.case_id)) {
    console.error(`lifecycle-agent-side-events ${presentation.id} does not carry its CASES.md case id`)
    process.exit(2)
  }
}

const options: BoundaryOptions = {
  standing: fixture.standing,
  recordKeys: fixture.record_keys as Record<string, string>,
  resolveDelegationVerificationKey: (_issuer, method) => fixture.verification_keys[method] ?? null,
  trustRoot: () => true,
}

function pick<T>(table: Record<string, T>, name: string, kind: string): T {
  const value = table[name]
  if (value === undefined) throw new Error(`unknown ${kind} ${name}`)
  return value
}

function presentationFor(vector: any): Presentation {
  return {
    label: vector.id,
    grant: pick(fixture.grants, vector.grant, 'grant') as AuthorityDelegationV1,
    presenter: pick(fixture.parties, vector.presenter, 'party') as string,
    requestedCapability: vector.requested_capability,
    credential: pick(fixture.credentials, vector.credential, 'credential') as any,
    consumed: (vector.consumed as string[]).map(
      (name) => (pick(fixture.credentials, name, 'credential') as any).credential_id as string,
    ),
    cacheLostAt: vector.cache_lost_at ?? null,
    executorRecords: (vector.executor_records as string[]).map((name) => pick(fixture.executors, name, 'executor') as any),
    claims: (vector.claims as string[]).map((name) => pick(fixture.claims, name, 'claim') as any),
    declaredCapabilities: pick(fixture.capability_declarations, vector.declared_capabilities, 'declaration') as string[],
    consentRecords: (vector.consent_records as string[]).map((name) => pick(fixture.consents, name, 'consent') as any),
    revocationNotices: (vector.revocation_notices as string[]).map(
      (name) => pick(fixture.revocations, name, 'revocation') as any,
    ),
    at: vector.at,
  }
}

function matches(actual: Outcome, expected: any): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.reason !== expected.reason) return false
  if (expected.detail !== undefined && actual.detail !== expected.detail) return false
  if (expected.chain_state !== undefined && actual.chain_state !== expected.chain_state) return false
  return true
}

function render(outcome: Outcome): string {
  const parts = [`${outcome.verdict}/${outcome.reason}`]
  if (outcome.chain_state) parts.push(`chain=${outcome.chain_state}`)
  if (outcome.detail) parts.push(`detail=${outcome.detail}`)
  return parts.join(' ')
}

function run(boundary: AgentSideEventBoundary): Map<string, boolean> {
  const results = new Map<string, boolean>()
  console.log(`\n${boundary.name}`)
  for (const vector of vectors.presentations) {
    const outcome = boundary.admit(presentationFor(vector))
    const ok = matches(outcome, vector.expected)
    results.set(vector.id, ok)
    console.log(`  ${ok ? 'MATCH        ' : 'DIVERGES     '} ${vector.id}  ${render(outcome)}`)
    if (!ok && boundary.name === 'reference-boundary') {
      console.error(`    expected: ${JSON.stringify(vector.expected)}`)
    }
  }
  return results
}

const reference = run(makeReferenceBoundary(options))
const defective = run(makeDefectiveBoundary(options))

const total = vectors.presentations.length
const referenceMatched = [...reference.values()].filter(Boolean).length
const declared: string[] = vectors.declared_defective_fail_set
const declaredSet = new Set(declared)

const undeclaredFailures = [...defective.entries()].filter(([id, ok]) => !ok && !declaredSet.has(id)).map(([id]) => id)
const declaredButPassing = declared.filter((id) => defective.get(id) === true)

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${total}`)
console.log(`defective-boundary declared failing set: ${declared.length}`)
if (undeclaredFailures.length > 0) console.error(`  undeclared divergence: ${undeclaredFailures.join(', ')}`)
if (declaredButPassing.length > 0) console.error(`  declared but matched: ${declaredButPassing.join(', ')}`)

const ok = referenceMatched === total && undeclaredFailures.length === 0 && declaredButPassing.length === 0
console.log(
  ok
    ? 'PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set'
    : 'FAILED',
)
process.exit(ok ? 0 : 1)
