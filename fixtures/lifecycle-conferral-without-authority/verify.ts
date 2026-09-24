// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-conferral-without-authority family.
//
// No network. Everything it needs is in chain.json and vectors.json, and the only
// implementation it calls is the published agent-passport-system package pinned in the
// suite's package.json.
//
// Run from the suite root:
//
//     npm run verify:lifecycle-conferral-without-authority
//
// Exit 0 when the reference verifier matches every vector's expected verdict AND both
// defective verifiers diverge on exactly their declared sets. Exit 1 otherwise, naming
// the first divergence in either direction.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { VERIFIERS, type Resolvers, type VerifierName, type Verdict } from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

const chainBytes = fs.readFileSync(path.join(here, 'chain.json'))
const vectorBytes = fs.readFileSync(path.join(here, 'vectors.json'))
const chain = JSON.parse(chainBytes.toString('utf8'))
const suite = JSON.parse(vectorBytes.toString('utf8'))

const resolvers: Resolvers = {
  now: chain.now,
  verificationKeys: chain.verification_keys,
  trustedRootIssuer: chain.trusted_root_issuer,
}

let failed = 0
function fail(message: string): void {
  console.error(`  FAIL ${message}`)
  failed++
}

console.log('lifecycle-conferral-without-authority TypeScript')
console.log(`  sdk            agent-passport-system 7.1.0 (npm)`)
console.log(`  now            ${chain.now}`)
console.log(`  status label   ${suite.status_label}`)
console.log(`  proposed text  ${suite.proposed_text.repository} ${suite.proposed_text.document} @ ${suite.proposed_text.commit}`)
console.log(`  sha256 chain.json    ${createHash('sha256').update(chainBytes).digest('hex')}`)
console.log(`  sha256 vectors.json  ${createHash('sha256').update(vectorBytes).digest('hex')}`)
console.log('')

// ---------------------------------------------------------------------------
// SDK support table, produced by this run rather than typed into the README.
// ---------------------------------------------------------------------------

console.log('TypeScript SDK support, agent-passport-system 7.1.0:')
for (const [status, concept, api] of [
  ['supported', 'chain state, including time and revocation', 'verifyAuthorityDelegationChain'],
  ['supported', 'declared conferral right (depth facet)', 'AuthorityVectorV1.depth.remaining, compareAuthority'],
  ['supported', 'conferral refused when the right is exhausted', 'DEPTH_EXHAUSTED'],
  ['supported', 'conferral right narrows like any other facet', 'DEPTH_WIDENING'],
  ['supported', 'scope coverage', 'scopeGrantCovers'],
  ['supported', 'issuer-side refusal to mint an unauthorized conferral', 'issueSubAuthorityDelegation'],
  ['not_supported', 'undeclared conferral right as its own verdict', 'no API: a missing facet is SCHEMA_INVALID, never not_established'],
] as const) {
  console.log(`  ${status.padEnd(14)} ${concept}  (${api})`)
}
console.log('')

// ---------------------------------------------------------------------------
// Reference verifier: every vector must match its expected verdict exactly.
// ---------------------------------------------------------------------------

function firstFailure(verdict: Verdict) {
  return verdict.failures.length > 0 ? verdict.failures[0] : null
}

const referenceVerdicts = new Map<string, Verdict>()

console.log('reference-verifier')
for (const vector of suite.vectors) {
  const presented = chain.presented[vector.presented_chain]
  if (!Array.isArray(presented)) {
    fail(`${vector.id}: chain.json has no presented chain named ${vector.presented_chain}`)
    continue
  }
  if (presented.length !== vector.chain_length) {
    fail(`${vector.id}: presented chain has ${presented.length} records, vectors.json declares ${vector.chain_length}`)
  }
  const verdict = VERIFIERS['reference-verifier'](presented, resolvers)
  referenceVerdicts.set(vector.id, verdict)

  const observed = firstFailure(verdict)
  const expected = vector.expected
  const okState = verdict.state === expected.state
  const okCode = (observed?.code ?? null) === expected.failure_code
  const okIndex = (observed?.index ?? null) === expected.failure_index
  const okCount = expected.state === 'valid' ? verdict.failures.length === 0 : verdict.failures.length === 1

  if (okState && okCode && okIndex && okCount) {
    const detail = expected.failure_code ? `${verdict.state}, ${observed?.code} at index ${observed?.index}` : verdict.state
    console.log(`  ok   ${vector.id.padEnd(7)} ${detail}`)
  } else {
    fail(
      `${vector.id}: expected ${expected.state}/${expected.failure_code}@${expected.failure_index} with ` +
        `${expected.state === 'valid' ? 0 : 1} failure, got ${verdict.state}/${observed?.code ?? null}@${observed?.index ?? null} ` +
        `with ${verdict.failures.length} (${JSON.stringify(verdict.failures)})`,
    )
  }
}
console.log('')

// ---------------------------------------------------------------------------
// Defective verifiers: each must diverge on exactly its declared set, in both
// directions. An undeclared divergence and a declared divergence that quietly starts
// agreeing are both failures.
// ---------------------------------------------------------------------------

function verdictsAgree(a: Verdict, b: Verdict): boolean {
  if (a.state !== b.state) return false
  const fa = firstFailure(a)
  const fb = firstFailure(b)
  return (fa?.code ?? null) === (fb?.code ?? null) && (fa?.index ?? null) === (fb?.index ?? null)
}

for (const name of Object.keys(suite.declared_fail_sets) as VerifierName[]) {
  const declared: string[] = suite.declared_fail_sets[name]
  const declaredSet = new Set(declared)
  console.log(name)
  console.log(`  declared divergences: ${declared.join(', ')}`)

  for (const vector of suite.vectors) {
    const presented = chain.presented[vector.presented_chain]
    if (!Array.isArray(presented)) continue
    const reference = referenceVerdicts.get(vector.id)
    if (!reference) continue
    const verdict = VERIFIERS[name](presented, resolvers)
    const agrees = verdictsAgree(reference, verdict)
    const shouldDiverge = declaredSet.has(vector.id)

    if (shouldDiverge && agrees) {
      fail(`${name} ${vector.id}: declared to diverge, but it agreed with the reference (${verdict.state})`)
    } else if (!shouldDiverge && !agrees) {
      fail(
        `${name} ${vector.id}: undeclared divergence, reference ${reference.state}/${firstFailure(reference)?.code ?? null}, ` +
          `this verifier ${verdict.state}/${firstFailure(verdict)?.code ?? null}`,
      )
    } else if (shouldDiverge) {
      const wrongly = verdict.state === 'valid' && reference.state === 'invalid' ? 'wrongly admits' : 'differs'
      console.log(`  ok   ${vector.id.padEnd(7)} diverges as declared: ${wrongly} (${verdict.state})`)
    }
  }
  console.log('')
}

if (failed > 0) {
  console.error(`FAILED: ${failed} check(s)`)
  process.exit(1)
}

console.log(
  `PASSED: reference-verifier matched all ${suite.vectors.length}/${suite.vectors.length} vectors, ` +
    `both defective verifiers diverged on exactly their declared sets`,
)
