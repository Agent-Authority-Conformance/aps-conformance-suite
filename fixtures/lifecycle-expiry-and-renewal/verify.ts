// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the fifteen lifecycle-expiry-and-renewal vectors against harness.ts's reference
// boundary and its two declared defective negative controls, over chain.json's real,
// agent-passport-system 7.1.0-signed chains, records and action references.
//
// No network. Exit 0 when the reference boundary matches every vector and each defective
// boundary diverges on exactly its declared set.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import {
  AuthorityBoundary,
  makeBooleanValidityBoundary,
  makeReferenceBoundary,
  makeRenewalExtendsIdentityBoundary,
  type ActionEntry,
  type Event,
  type Fixture,
  type Outcome,
  type SignedRecord,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const readJson = <T,>(name: string): T => JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T

interface ChainFixture extends Fixture {
  chains: Record<string, AuthorityDelegationV1[]>
  records: Record<string, SignedRecord>
  actions: Record<string, ActionEntry>
}

interface ExpectedOutcome {
  verdict: string
  reason: string
  ending: string | null
  detail?: string
}

// The SDK chain answer is a second assertion, not part of the lifecycle verdict. It sits
// beside `expected` in vectors.json rather than inside it, because the two are never
// merged here: the SDK's own `EXPIRED` sits next to the ending kind, not instead of it.
// Both are still checked on every vector, and a vector passes only when both match.
interface SdkCrossCheck {
  chain_state: string | null
  failure_code: string | null
}

interface Vector {
  id: string
  case: string
  check: string
  tests: string
  differs_from: string | null
  chain: string
  action: string
  now: string
  revocation: 'active' | 'revoked'
  records: string[]
  expected: ExpectedOutcome
  sdk_cross_check: SdkCrossCheck
}

interface Vectors {
  profile: string
  status_label: string
  declared_fail_sets: Record<string, string[]>
  vectors: Vector[]
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

function fail(message: string): never {
  console.error(`lifecycle-expiry-and-renewal: ${message}`)
  process.exit(2)
}

function toEvent(v: Vector): Event {
  const chain = fixture.chains[v.chain]
  if (chain === undefined) fail(`vectors.json names an unknown chain "${v.chain}"`)
  const action = fixture.actions[v.action]
  if (action === undefined) fail(`vectors.json names an unknown action "${v.action}"`)
  const records = v.records.map((id) => {
    const rec = fixture.records[id]
    if (rec === undefined) fail(`vectors.json names an unknown record "${id}"`)
    return rec
  })
  return { id: v.id, check: v.check, chain, action, now: v.now, revocation: v.revocation, records }
}

function matchesLifecycle(a: Outcome, e: ExpectedOutcome): boolean {
  return (
    a.verdict === e.verdict &&
    a.reason === e.reason &&
    (a.ending ?? null) === (e.ending ?? null) &&
    (a.detail ?? null) === (e.detail ?? null)
  )
}

function matchesSdkCrossCheck(a: Outcome, c: SdkCrossCheck): boolean {
  return a.sdk_chain_state === c.chain_state && a.sdk_failure_code === c.failure_code
}

function matches(a: Outcome, v: Vector): boolean {
  return matchesLifecycle(a, v.expected) && matchesSdkCrossCheck(a, v.sdk_cross_check)
}

const line = (a: Outcome): string =>
  `verdict=${a.verdict} ending=${a.ending} reason=${a.reason} sdk=${a.sdk_chain_state}/${a.sdk_failure_code}${a.detail !== undefined ? ` detail=${a.detail}` : ''}`

function runBoundary(make: (f: Fixture) => AuthorityBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  for (const v of vectors.vectors) results.set(v.id, make(fixture).handle(toEvent(v)))
  return results
}

console.log(`lifecycle-expiry-and-renewal: ${vectors.vectors.length} vectors, status label ${vectors.status_label}`)
console.log('')
console.log('boundary: reference-boundary')

const referenceResults = runBoundary(makeReferenceBoundary)
let referenceMatched = 0
for (const v of vectors.vectors) {
  const actual = referenceResults.get(v.id)!
  const ok = matches(actual, v)
  if (ok) referenceMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${v.id}  ${line(actual)}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(v.expected)}`)
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

const DEFECTIVE = [
  ['defective-boundary-boolean-validity', makeBooleanValidityBoundary],
  ['defective-boundary-renewal-extends-identity', makeRenewalExtendsIdentityBoundary],
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
    const entryOk = shouldMatch ? matches(actual, v) : !matches(actual, v)
    if (!entryOk) ok = false
    const label = shouldMatch
      ? entryOk ? 'MATCH' : 'UNDECLARED MISMATCH'
      : entryOk ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE'
    if (label !== 'MATCH') console.log(`  ${label} ${v.id}  ${line(actual)}`)
  }
  console.log(`  ${name} diverged on exactly its declared set: ${ok}`)
  if (!ok) allDefectivesOk = false
}

// LC-I-007's own claim, checked rather than asserted: on every vector where a grant has
// ended, the boolean-validity boundary returns the same verdict as the reference boundary
// and a different ending. A checker comparing only the verdict passes it.
const booleanResults = runBoundary(makeBooleanValidityBoundary)
const endingVectors = vectors.vectors.filter((v) => v.expected.ending !== null && v.case === 'LC-I-007')
const verdictIdentical = endingVectors.every(
  (v) => booleanResults.get(v.id)!.verdict === referenceResults.get(v.id)!.verdict,
)
const endingDiffers = endingVectors.every(
  (v) => (booleanResults.get(v.id)!.ending ?? null) !== (referenceResults.get(v.id)!.ending ?? null),
)

const CASES = ['LC-I-007', 'LC-I-008', 'LC-I-009']
const covered = new Set(vectors.vectors.map((v) => v.case))
const missing = CASES.filter((c) => !covered.has(c))
for (const v of vectors.vectors) {
  if (!v.id.startsWith(`${v.case}-`)) fail(`vector ${v.id} does not carry its case id`)
}

const SDK_SUPPORT: Array<[string, 'supported' | 'not_supported', string]> = [
  ['chain state, including the time facet and revocation', 'supported', 'verifyAuthorityDelegationChain'],
  ['identifier binding to content', 'supported', 'verifyAuthorityDelegationChain, ID_MISMATCH'],
  ['scope and time narrowing between parent and child', 'supported', 'verifyAuthorityDelegationChain, SCOPE_WIDENING and TIME_WIDENING'],
  ['scope membership', 'supported', 'isPurposePermitted'],
  ['fixture-local record signatures', 'supported', 'verify over canonicalizeJCS'],
  ['which of the two endings happened', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['the ground and the actor of an early ending', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['lifecycle standing to end an artifact early', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['renewal as an operation, in either sense', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['an interim or caretaking mandate', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
]

console.log('')
console.log('TypeScript SDK support, agent-passport-system 7.1.0:')
for (const [concept, verdict, how] of SDK_SUPPORT) console.log(`  ${verdict.padEnd(14)} ${concept}  (${how})`)

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${vectors.vectors.length}`)
console.log(`cases with at least one vector: ${CASES.length - missing.length}/${CASES.length}${missing.length ? ` missing ${missing.join(',')}` : ''}`)
console.log(`both defective boundaries diverged on exactly their declared sets: ${allDefectivesOk}`)
console.log(`boolean-validity boundary returns the same verdict on every LC-I-007 ending vector: ${verdictIdentical}`)
console.log(`boolean-validity boundary returns a different ending on every one of them: ${endingDiffers}`)

const ok = referenceMatched === vectors.vectors.length && allDefectivesOk && missing.length === 0 && verdictIdentical && endingDiffers
if (ok) {
  console.log('PASSED: reference-boundary matched every vector, every case is covered, each defective boundary diverged on exactly its declared set, and the boolean-validity boundary differs only in the ending field')
  process.exit(0)
} else {
  console.error('FAILED')
  process.exit(1)
}
