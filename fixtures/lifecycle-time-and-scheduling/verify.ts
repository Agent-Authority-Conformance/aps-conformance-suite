// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the sixty-one lifecycle-time-and-scheduling vectors against harness.ts's reference
// boundary and its five declared defective negative controls, over chain.json's real,
// agent-passport-system 7.1.0-signed grants, records and action references.
//
// This is evidence about this family's own reference boundary for fourteen lifecycle
// rules no published specification states, and an SDK result for every chain, time,
// revocation, scope-membership and signature step underneath them. See README
// "What a pass establishes" and "Does not claim".
//
// Every vector gets a freshly constructed boundary, so no vector's result depends on the
// order of the list. No network. Exit 0 when the reference boundary matches every vector
// and each defective boundary diverges on exactly its declared set.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1, RevocationResolution } from 'agent-passport-system'

import {
  AuthorityBoundary,
  makeCurrentVersionOnlyBoundary,
  makeInstantTransferBoundary,
  makeIssuerClockBoundary,
  makeQueueTimeOnlyBoundary,
  makeReferenceBoundary,
  makeSingleClockTrustedBoundary,
  type ActionEntry,
  type Event,
  type Fixture,
  type Outcome,
  type SignedRecord,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface ChainFixture extends Fixture {
  grants: Record<string, AuthorityDelegationV1>
  records: Record<string, SignedRecord>
  actions: Record<string, ActionEntry>
}

interface ExpectedOutcome {
  verdict: string
  reason: string
  sdk_chain_state: string | null
  sdk_failure_code: string | null
  detail?: string
}

interface Vector {
  id: string
  case: string
  check: string
  tests: string
  differs_from: string | null
  grant: string
  action: string
  now: string
  revocation: 'active' | 'revoked'
  revoked_from?: string
  records: string[]
  expected: ExpectedOutcome
}

interface Vectors {
  profile: string
  status_label: string
  description: string
  declared_fail_sets: Record<string, string[]>
  vectors: Vector[]
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

function fail(message: string): never {
  console.error(`lifecycle-time-and-scheduling: ${message}`)
  process.exit(2)
}

function toEvent(v: Vector): Event {
  const grant = fixture.grants[v.grant]
  if (grant === undefined) fail(`vectors.json names an unknown grant "${v.grant}"`)
  const action = fixture.actions[v.action]
  if (action === undefined) fail(`vectors.json names an unknown action "${v.action}"`)
  const records = v.records.map((id) => {
    const rec = fixture.records[id]
    if (rec === undefined) fail(`vectors.json names an unknown record "${id}"`)
    return rec
  })
  // Revocation as a function of the instant. `revoked_from` is what makes LC-E-034-c a
  // question about when the boundary asked rather than about what the answer was.
  const resolveRevocation = (now: string): RevocationResolution => {
    if (v.revoked_from !== undefined) {
      return Date.parse(now) >= Date.parse(v.revoked_from) ? 'revoked' : 'active'
    }
    return v.revocation
  }
  return { id: v.id, check: v.check, grant, action, now: v.now, resolveRevocation, records }
}

function matches(actual: Outcome, expected: ExpectedOutcome): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.reason !== expected.reason) return false
  if (actual.sdk_chain_state !== expected.sdk_chain_state) return false
  if (actual.sdk_failure_code !== expected.sdk_failure_code) return false
  if ((actual.detail ?? null) !== (expected.detail ?? null)) return false
  return true
}

function line(a: Outcome): string {
  return `verdict=${a.verdict} reason=${a.reason} sdk=${a.sdk_chain_state}/${a.sdk_failure_code}${a.detail !== undefined ? ` detail=${a.detail}` : ''}`
}

function runBoundary(make: (f: Fixture) => AuthorityBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  for (const v of vectors.vectors) {
    // A fresh instance per vector. This family's vectors are independent by construction
    // and the runner enforces that rather than assuming it.
    results.set(v.id, make(fixture).handle(toEvent(v)))
  }
  return results
}

console.log(`lifecycle-time-and-scheduling: ${vectors.vectors.length} vectors, status label ${vectors.status_label}`)
console.log('')
console.log('boundary: reference-boundary')

const referenceResults = runBoundary(makeReferenceBoundary)
let referenceMatched = 0
for (const v of vectors.vectors) {
  const actual = referenceResults.get(v.id)!
  const ok = matches(actual, v.expected)
  if (ok) referenceMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${v.id}  ${line(actual)}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(v.expected)}`)
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

const DEFECTIVE = [
  ['defective-boundary-queue-time-only', makeQueueTimeOnlyBoundary],
  ['defective-boundary-current-version-only', makeCurrentVersionOnlyBoundary],
  ['defective-boundary-instant-transfer', makeInstantTransferBoundary],
  ['defective-boundary-issuer-clock', makeIssuerClockBoundary],
  ['defective-boundary-single-clock-trusted', makeSingleClockTrustedBoundary],
] as const

let allDefectivesOk = true
for (const [name, make] of DEFECTIVE) {
  const declared = vectors.declared_fail_sets[name]
  if (declared === undefined) fail(`vectors.json declares no fail set for ${name}`)
  const declaredSet = new Set(declared)
  for (const id of declaredSet) {
    if (!vectors.vectors.some((v) => v.id === id)) fail(`${name}'s declared fail set names an unknown vector "${id}"`)
  }
  const results = runBoundary(make)
  let ok = true
  console.log('')
  console.log(`boundary: ${name}`)
  for (const v of vectors.vectors) {
    const actual = results.get(v.id)!
    const shouldMatch = !declaredSet.has(v.id)
    const actuallyMatches = matches(actual, v.expected)
    const entryOk = shouldMatch ? actuallyMatches : !actuallyMatches
    if (!entryOk) ok = false
    const label = shouldMatch
      ? entryOk
        ? 'MATCH'
        : 'UNDECLARED MISMATCH'
      : entryOk
        ? 'DECLARED FAIL'
        : 'DEFECT DID NOT REPRODUCE'
    if (label !== 'MATCH') console.log(`  ${label} ${v.id}  ${line(actual)}`)
  }
  console.log(`  ${name} diverged on exactly its declared set: ${ok}`)
  if (!ok) allDefectivesOk = false
}

// Every case in the family's scope has at least one vector, checked by the run rather
// than by reading the list.
const CASES = [
  'LC-C-008', 'LC-C-014', 'LC-C-015', 'LC-C-017', 'LC-C-025', 'LC-E-008', 'LC-E-014',
  'LC-E-018', 'LC-E-019', 'LC-E-020', 'LC-E-034', 'LC-G-007', 'LC-G-008', 'LC-G-009',
]
const covered = new Set(vectors.vectors.map((v) => v.case))
const missing = CASES.filter((c) => !covered.has(c))
for (const v of vectors.vectors) {
  if (!v.id.startsWith(`${v.case}-`)) fail(`vector ${v.id} does not carry its case id`)
}

// What came from the pinned TypeScript SDK and what did not. Printed by the run rather
// than written by hand, so the record cannot drift from the code above.
const SDK_SUPPORT: Array<[string, 'supported' | 'not_supported', string]> = [
  ['chain state, including the time facet and revocation', 'supported', 'verifyAuthorityDelegationChain'],
  ['scope membership', 'supported', 'isPurposePermitted'],
  ['fixture-local record signatures', 'supported', 'verify over canonicalizeJCS'],
  ['action reference identity', 'supported', 'computeActionRefV2 at mint time'],
  ['not_yet_effective as a state distinct from invalid', 'not_supported', 'the SDK returns invalid with NOT_YET_VALID; the lifecycle verdict is supplied by harness.ts'],
  ['suspension as a resolver answer', 'not_supported', 'the resolver recognizes active and revoked; any other answer is REVOCATION_UNKNOWN. Suspension is supplied by harness.ts'],
  ['restricted as a state', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['handover acknowledgment', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['rotation schedule and rest ledger', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['pre-authorized fallback scope', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['pinned policy version', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['occurrence template pinning', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['wind-down grace bound', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['queued-action fire-time recheck', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['clock attestation, time-source cross-check, smear tolerance', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
]

console.log('')
console.log('TypeScript SDK support, agent-passport-system 7.1.0:')
for (const [concept, verdict, how] of SDK_SUPPORT) {
  console.log(`  ${verdict.padEnd(14)} ${concept}  (${how})`)
}

const referenceOk = referenceMatched === vectors.vectors.length

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${vectors.vectors.length}`)
console.log(`cases with at least one vector: ${CASES.length - missing.length}/${CASES.length}${missing.length ? ` missing ${missing.join(',')}` : ''}`)
console.log(`all five defective boundaries diverged on exactly their declared sets: ${allDefectivesOk}`)

if (referenceOk && allDefectivesOk && missing.length === 0) {
  console.log('PASSED: reference-boundary matched every vector, every case is covered, and each defective boundary diverged on exactly its declared set')
  process.exit(0)
} else {
  console.error('FAILED')
  process.exit(1)
}
