// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-agent-renunciation family.
//
//   npx tsx fixtures/lifecycle-agent-renunciation/verify.ts
//   npx tsx fixtures/lifecycle-agent-renunciation/verify.ts --sdk-support
//
// Default mode runs every vector against the reference gate, checks the pinned
// prior-receipt digest, and then runs every defective configuration and checks
// that exactly the declared set of vectors fails under it. --sdk-support prints,
// per vector, what the npm reference SDK decided and what it has no API for; it
// asserts nothing and exits 0 unless a call throws.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

import {
  gate,
  NAIVE_CONFIGURATIONS,
  recordPreimage,
  type ChainFixture,
  type GateResult,
  type VectorCase,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const FAMILY = 'lifecycle-agent-renunciation'

// Named here so the reason travels with the record rather than living only in
// prose. Each entry is a concept this family needs and neither reference SDK
// exposes an API for.
const UNSUPPORTED_CONCEPTS = [
  'a renunciation record from the subject of a grant',
  'a delivery instant distinct from an effective instant',
  'an effective date determined by a named recorded event',
  'a principal acceptance record, and the question of whether one is needed',
  'a not_established verdict distinct from invalid and indeterminate',
]

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface Vectors {
  profile: string
  cases: VectorCase[]
  declared_fail_sets: Record<string, string[]>
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

function matches(result: GateResult, expected: VectorCase['expected']): boolean {
  return (
    result.verdict === expected.verdict &&
    result.stage === expected.stage &&
    result.code === expected.code
  )
}

function describe(result: GateResult): string {
  return `${result.verdict}/${result.stage}/${result.code} chain=${result.chain_state}`
}

if (process.argv.includes('--sdk-support')) {
  const sdkVersion = (
    JSON.parse(
      fs.readFileSync(
        path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'),
        'utf8',
      ),
    ) as { version: string }
  ).version
  console.log(`npm agent-passport-system ${sdkVersion}`)
  console.log()
  for (const vector of vectors.cases) {
    const now = fixture.clock[vector.action_at]
    const chainResult = verifyAuthorityDelegationChain(fixture.chains[vector.grant] as never, {
      now,
      resolveVerificationKey: ((_i: string, m: string) => fixture.verification_keys[m] ?? null) as never,
      trustRoot: () => true,
      resolveRevocation: (() => vector.revocation) as never,
    }) as { state: string; failures?: Array<{ code: string }> }
    const signatures = vector.presented_events.map(label => {
      const event = fixture.events[label]
      const key = fixture.verification_keys[event.verification_method]
      let ok = false
      try {
        ok = verifyEd25519(recordPreimage(event, ['event_id', 'signature']), event.signature, key)
      } catch {
        ok = false
      }
      return `${label}=${ok}`
    })
    console.log(vector.id)
    console.log(
      `  verifyAuthorityDelegationChain: supported, state=${chainResult.state} ` +
        `code=${chainResult.failures?.[0]?.code ?? 'none'}`,
    )
    console.log(
      `  verify + canonicalizeJCS over event bytes: supported, ` +
        `${signatures.length > 0 ? signatures.join(' ') : 'no event presented'}`,
    )
    console.log(`  lifecycle verdict: not_supported, no SDK API for: ${UNSUPPORTED_CONCEPTS.join('; ')}`)
  }
  console.log()
  console.log(`${FAMILY} npm SDK observations: ${vectors.cases.length} vectors recorded`)
  console.log(`  canonicalizeJCS: ${typeof canonicalizeJCS}`)
  process.exit(0)
}

let failures = 0
let passed = 0

const resultById = new Map<string, GateResult>()
for (const vector of vectors.cases) {
  resultById.set(vector.id, gate(fixture, vector))
}

for (const vector of vectors.cases) {
  const result = resultById.get(vector.id)!
  let ok = matches(result, vector.expected)
  const details = [describe(result)]

  if (vector.assert_no_liability_field === true) {
    // The gate has no liability field by construction. This asserts it at run
    // time so the property cannot be lost in a later edit without a failure.
    const hasLiabilityField = Object.keys(result).some(key => /liab|fault|wrongful|breach/i.test(key))
    ok = ok && !hasLiabilityField
    details.push(`no_liability_field=${!hasLiabilityField}`)
  }

  if (typeof vector.assert_same_code_as === 'string') {
    const other = resultById.get(vector.assert_same_code_as)
    const sameCode = other !== undefined && other.code === result.code && other.verdict === result.verdict
    ok = ok && sameCode
    details.push(`same_result_as_${vector.assert_same_code_as}=${sameCode}`)
  }

  if (ok) {
    passed += 1
    console.log(`PASS ${vector.id} ${details.join(' ')}`)
  } else {
    failures += 1
    console.error(`FAIL ${vector.id}`)
    console.error(`  expected: ${JSON.stringify(vector.expected)}`)
    console.error(`  actual:   ${details.join(' ')} notes=${result.notes.join(',')}`)
  }
}

console.log()
console.log(`${FAMILY} reference gate: ${passed}/${vectors.cases.length} passed`)

// --- falsifiability -------------------------------------------------------
// Each defective configuration must get wrong exactly the declared set of
// vectors and nothing else. A configuration that got everything right would
// mean the vectors do not separate it from the reference gate.
let controlFailures = 0
for (const [name, options] of Object.entries(NAIVE_CONFIGURATIONS)) {
  const declared = vectors.declared_fail_sets[name]
  if (declared === undefined) {
    console.error(`FAIL negative-control ${name}: no declared fail set`)
    controlFailures += 1
    continue
  }
  const observed: string[] = []
  for (const vector of vectors.cases) {
    if (!matches(gate(fixture, vector, options), vector.expected)) observed.push(vector.id)
  }
  const declaredSorted = [...declared].sort()
  const observedSorted = [...observed].sort()
  if (JSON.stringify(declaredSorted) === JSON.stringify(observedSorted)) {
    console.log(`PASS negative-control ${name} fails ${observed.length} vector(s) as declared`)
  } else {
    controlFailures += 1
    console.error(`FAIL negative-control ${name}`)
    console.error(`  declared: ${JSON.stringify(declaredSorted)}`)
    console.error(`  observed: ${JSON.stringify(observedSorted)}`)
  }
}

console.log(
  `${FAMILY} negative controls: ` +
    `${Object.keys(NAIVE_CONFIGURATIONS).length - controlFailures}/` +
    `${Object.keys(NAIVE_CONFIGURATIONS).length} behaved as declared`,
)
console.log(
  `${FAMILY} TypeScript: ${passed}/${vectors.cases.length} vectors, ` +
    `${Object.keys(NAIVE_CONFIGURATIONS).length - controlFailures}/` +
    `${Object.keys(NAIVE_CONFIGURATIONS).length} negative controls`,
)
process.exit(failures === 0 && controlFailures === 0 ? 0 : 1)
