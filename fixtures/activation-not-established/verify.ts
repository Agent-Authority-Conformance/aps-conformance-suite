// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the activation-not-established family.
//
// Runs all five gate configurations over all nineteen cases and checks, in both
// directions, that:
//   - reference-gate matches every case's expected verdict, stage and code
//   - every negative gate fails exactly its declared set and matches the rest
//
// v2. The family asserts two distinct negative verdicts, not_yet_effective and
// not_established, and gate N4 is the control that pins the difference.
//
// No network. Reads chain.json and vectors.json from this directory only.
//
// Run: npm run verify:activation-not-established

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { GATES, evaluate, type ChainFixture, type RevocationAnswer } from './harness.js'

type Expected = {
  verdict: string
  stage: string
  code: string
  chain_state?: string
  chain_failure_index?: number | null
}

type VectorCase = {
  id: string
  status: string
  grant: string
  action_at: string
  revocation: RevocationAnswer
  presented_attestations: string[]
  expected: Expected
}

type GateSpec = {
  name: string
  declared_failing_cases: string[]
}

type Vectors = {
  profile: string
  status: string
  cases: VectorCase[]
  gates: GateSpec[]
}

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

// Structural guards. A fixture that lost its records, its registry or its
// condition must stop the run rather than report a vacuous pass.
const guards: Array<[string, boolean]> = [
  ['chain.json has a clock', typeof fixture.clock === 'object' && Object.keys(fixture.clock).length > 0],
  ['chain.json has verification keys', Object.keys(fixture.verification_keys ?? {}).length > 0],
  ['chain.json has an attestor-role registry', Object.keys(fixture.attestor_role_registry ?? {}).length > 0],
  [
    'chain.json declares a recorded-event activation condition for GRANT',
    fixture.activation_conditions?.GRANT?.condition_type === 'recorded_event',
  ],
  [
    'chain.json declares a date activation condition for GRANT_DATED',
    fixture.activation_conditions?.GRANT_DATED?.condition_type === 'date',
  ],
  [
    'chain.json declares no activation condition for GRANT_FUTURE_WINDOW',
    fixture.activation_conditions?.GRANT_FUTURE_WINDOW === null,
  ],
  [
    'chain.json has all three chains',
    Boolean(fixture.chains?.GRANT && fixture.chains?.GRANT_DATED && fixture.chains?.GRANT_FUTURE_WINDOW),
  ],
  ['chain.json has ten attestations', Object.keys(fixture.attestations ?? {}).length === 10],
  ['every case is labelled candidate_against_proposed', vectors.cases.every(c => c.status === 'candidate_against_proposed')],
  ['vectors.json is labelled candidate_against_proposed', vectors.status === 'candidate_against_proposed'],
  // v2's whole point. A vectors.json that lost one of the two negative verdicts,
  // or the gate that pins them apart, must stop the run rather than report a
  // pass for the collapsed rule v1 encoded.
  [
    'vectors.json asserts at least one not_yet_effective case',
    vectors.cases.some(c => c.expected.verdict === 'not_yet_effective'),
  ],
  [
    'vectors.json asserts at least one not_established case at the activation stage',
    vectors.cases.some(c => c.expected.verdict === 'not_established' && c.expected.stage === 'activation'),
  ],
  [
    'vectors.json declares the gate that collapses not_yet_effective into not_established',
    vectors.gates.some(g => g.name === 'N4-collapses-not-yet-effective-into-not-established'),
  ],
]
const brokenGuards = guards.filter(([, ok]) => !ok)
if (brokenGuards.length > 0) {
  for (const [name] of brokenGuards) console.error(`activation-not-established structural guard failed: ${name}`)
  process.exit(2)
}

function resolveInstant(label: string): string {
  const value = fixture.clock[label]
  if (typeof value !== 'string') {
    console.error(`activation-not-established: no clock entry named ${label}`)
    process.exit(2)
  }
  return value
}

function matches(actual: ReturnType<typeof evaluate>, expected: Expected): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.stage !== expected.stage) return false
  if (actual.code !== expected.code) return false
  if (expected.chain_state !== undefined && actual.chain_state !== expected.chain_state) return false
  if (
    expected.chain_failure_index !== undefined &&
    actual.chain_failure_index !== expected.chain_failure_index
  ) {
    return false
  }
  return true
}

let exitCode = 0
const summary: string[] = []

for (const gate of vectors.gates) {
  const options = GATES[gate.name]
  if (options === undefined) {
    console.error(`activation-not-established: vectors.json names gate ${gate.name}, harness.ts has no such gate`)
    process.exit(2)
  }

  const observedFailures: string[] = []
  for (const vector of vectors.cases) {
    const actual = evaluate(
      fixture,
      vector.grant,
      vector.presented_attestations,
      resolveInstant(vector.action_at),
      vector.revocation,
      options,
    )
    const ok = matches(actual, vector.expected)
    if (!ok) observedFailures.push(vector.id)
    const line =
      `${ok ? 'MATCH  ' : 'DIVERGE'} ${gate.name} ${vector.id} ` +
      `-> ${actual.verdict}/${actual.stage}/${actual.code}` +
      (actual.attestation_notes.length > 0 ? ` [${actual.attestation_notes.join(' ')}]` : '')
    console.log(line)
    if (!ok) {
      console.log(`         expected ${vector.expected.verdict}/${vector.expected.stage}/${vector.expected.code}`)
    }
  }

  const declared = [...gate.declared_failing_cases].sort()
  const observed = [...observedFailures].sort()
  const setsAgree = declared.length === observed.length && declared.every((id, i) => id === observed[i])
  if (setsAgree) {
    summary.push(
      `  ok   ${gate.name}: ${vectors.cases.length - observed.length}/${vectors.cases.length} matched, ` +
        `failing set ${observed.length === 0 ? 'empty' : observed.join(', ')} as declared`,
    )
  } else {
    exitCode = 1
    summary.push(`  FAIL ${gate.name}: declared [${declared.join(', ')}] observed [${observed.join(', ')}]`)
  }
  console.log()
}

console.log('activation-not-established gate summary')
for (const line of summary) console.log(line)
console.log()

if (exitCode === 0) {
  console.log(
    'PASSED: reference-gate matched every case, N1, N2, N3 and N4 each failed exactly their declared set',
  )
} else {
  console.error('FAILED: at least one gate diverged from its declared failing set')
}
process.exit(exitCode)
