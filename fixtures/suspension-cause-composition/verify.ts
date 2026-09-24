// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the suspension-cause-composition family.
//
// Runs all five gate configurations over all sixteen cases and checks, in both
// directions, that:
//   - reference-gate matches every case's expected verdict, stage, code and
//     remaining cause set
//   - every negative gate fails exactly its declared set and matches the rest
//
// A declared failure that quietly starts passing fails the run as loudly as an
// undeclared failure.
//
// No network. Reads chain.json and vectors.json from this directory only.
//
// Run: npm run verify:suspension-cause-composition

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { GATES, evaluate, type ChainFixture, type RevocationAnswer } from './harness.js'

type Expected = {
  verdict: string
  stage: string
  code: string
  remaining_causes: string[]
  chain_state?: string
  chain_failure_index?: number | null
}

type VectorCase = {
  id: string
  status: string
  grant: string
  evaluated_at: string
  revocation: RevocationAnswer
  presented_releases: string[]
  assert_revocation_within_suspension_window?: boolean
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

// Structural guards. A fixture that lost its records, its standing registry or
// its cause set must stop the run rather than report a vacuous pass.
const guards: Array<[string, boolean]> = [
  ['chain.json has a clock', typeof fixture.clock === 'object' && Object.keys(fixture.clock).length > 0],
  ['chain.json has verification keys', Object.keys(fixture.verification_keys ?? {}).length > 0],
  ['chain.json has a cause-standing registry for all three causes', ['REG', 'FIRM', 'DECREE'].every(label => Array.isArray(fixture.cause_standing?.[label]) && fixture.cause_standing[label].length > 0)],
  ['GRANT carries exactly three causes', (fixture.cause_sets?.GRANT ?? []).length === 3],
  ['GRANT_CLEAN carries no cause', (fixture.cause_sets?.GRANT_CLEAN ?? ['x']).length === 0],
  ['chain.json has both chains', Boolean(fixture.chains?.GRANT && fixture.chains?.GRANT_CLEAN)],
  ['chain.json has three cause records', Object.keys(fixture.causes ?? {}).length === 3],
  ['two causes are suspensions and one is a restriction', Object.values(fixture.causes ?? {}).filter(c => c.cause_kind === 'suspension').length === 2 && Object.values(fixture.causes ?? {}).filter(c => c.cause_kind === 'restriction').length === 1],
  ['chain.json has eleven release records', Object.keys(fixture.releases ?? {}).length === 11],
  ['every case is labelled candidate_against_proposed', vectors.cases.every(c => c.status === 'candidate_against_proposed')],
  ['vectors.json is labelled candidate_against_proposed', vectors.status === 'candidate_against_proposed'],
  ['vectors.json names the proposed text it tests', typeof (vectors as unknown as { proposed_text?: { commit?: string } }).proposed_text?.commit === 'string'],
]
const brokenGuards = guards.filter(([, ok]) => !ok)
if (brokenGuards.length > 0) {
  for (const [name] of brokenGuards) console.error(`suspension-cause-composition structural guard failed: ${name}`)
  process.exit(2)
}

function resolveInstant(label: string): string {
  const value = fixture.clock[label]
  if (typeof value !== 'string') {
    console.error(`suspension-cause-composition: no clock entry named ${label}`)
    process.exit(2)
  }
  return value
}

/** Checked against chain.json directly, not derived from any gate result: the
 *  revocation instant falls after every imposition on the grant and before the
 *  earliest release the case presents. Without this, "a revocation that
 *  happened during suspension" would be narrative rather than a property of the
 *  records. */
function revocationWithinSuspensionWindow(vector: VectorCase): boolean {
  const causeLabels = fixture.cause_sets[vector.grant] ?? []
  if (causeLabels.length === 0 || vector.presented_releases.length === 0) return false
  const latestImposition = causeLabels
    .map(label => fixture.causes[label].imposed_at)
    .reduce((a, b) => (a > b ? a : b))
  const earliestRelease = vector.presented_releases
    .map(label => fixture.releases[label].released_at)
    .reduce((a, b) => (a < b ? a : b))
  const recordedAt = fixture.revocation_timeline_note.recorded_at
  return (
    fixture.revocation_timeline_note.grant_delegation_id === fixture.roles.PRINCIPAL_TO_AGENT &&
    recordedAt > latestImposition &&
    recordedAt < earliestRelease
  )
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index])
}

function matches(actual: ReturnType<typeof evaluate>, expected: Expected): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.stage !== expected.stage) return false
  if (actual.code !== expected.code) return false
  if (!sameList(actual.remaining_causes, expected.remaining_causes)) return false
  if (expected.chain_state !== undefined && actual.chain_state !== expected.chain_state) return false
  if (expected.chain_failure_index !== undefined && actual.chain_failure_index !== expected.chain_failure_index) {
    return false
  }
  return true
}

let exitCode = 0
const summary: string[] = []

// The structural window check is a property of the records, so it is checked
// once rather than per gate.
for (const vector of vectors.cases) {
  if (vector.assert_revocation_within_suspension_window !== true) continue
  if (revocationWithinSuspensionWindow(vector)) {
    console.log(`STRUCT  ${vector.id}: revocation instant falls inside the suspension window`)
  } else {
    exitCode = 1
    console.error(`STRUCT  FAIL ${vector.id}: revocation instant is not inside the suspension window`)
  }
}
console.log()

for (const gate of vectors.gates) {
  const options = GATES[gate.name]
  if (options === undefined) {
    console.error(`suspension-cause-composition: vectors.json names gate ${gate.name}, harness.ts has no such gate`)
    process.exit(2)
  }

  const observedFailures: string[] = []
  for (const vector of vectors.cases) {
    const actual = evaluate(
      fixture,
      vector.grant,
      vector.presented_releases,
      resolveInstant(vector.evaluated_at),
      vector.revocation,
      options,
    )
    const ok = matches(actual, vector.expected)
    if (!ok) observedFailures.push(vector.id)
    const remaining = actual.remaining_causes.length > 0 ? actual.remaining_causes.join('+') : 'none'
    const line =
      `${ok ? 'MATCH  ' : 'DIVERGE'} ${gate.name} ${vector.id} ` +
      `-> ${actual.verdict}/${actual.stage}/${actual.code} remaining=${remaining}` +
      (actual.release_notes.length > 0 ? ` [${actual.release_notes.join(' ')}]` : '')
    console.log(line)
    if (!ok) {
      const expectedRemaining =
        vector.expected.remaining_causes.length > 0 ? vector.expected.remaining_causes.join('+') : 'none'
      console.log(
        `         expected ${vector.expected.verdict}/${vector.expected.stage}/${vector.expected.code} ` +
          `remaining=${expectedRemaining}`,
      )
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

console.log('suspension-cause-composition gate summary')
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
