// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the nine approval-single-use presentations against harness.ts's reference boundary
// and its declared defective negative control, both over chain.json's real,
// agent-passport-system 7.1.0-signed decision and delegation records.
//
// This is evidence about this family's own reference boundary, not an SDK conformance
// result. See README "What this establishes" and "Does not claim".

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import { DispatchBoundary, makeDefectiveBoundary, makeReferenceBoundary, type PolicyDecisionReceipt } from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface ChainFixture {
  identities: { principal: string; acting_agent: string; enforcement_boundary: string }
  verification_keys: Record<string, string>
  delegations: { main: AuthorityDelegationV1; for_revocation_case: AuthorityDelegationV1 }
  actions: Record<'a' | 'b' | 'c', { action_ref: string }>
  receipts: Record<string, PolicyDecisionReceipt>
}

interface Presentation {
  id: string
  differs_from: string | null
  decision: string
  requested_action: 'a' | 'b' | 'c'
  now: string
  chain: 'main' | 'for_revocation_case'
  revocation: 'active' | 'revoked'
  expected: { admitted: boolean; reason: string; detail?: string }
}

interface Vectors {
  profile: string
  description: string
  declared_defective_fail_set: string[]
  presentations: Presentation[]
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

const BOUNDARY = fixture.identities.enforcement_boundary

const resolveReceiptSignerKey = (signer: string, keyId: string) => fixture.verification_keys[keyId] && signer ? fixture.verification_keys[keyId] : undefined
const resolveDelegationVerificationKey = (_issuer: string, method: string) => fixture.verification_keys[method] ?? null
const trustRoot = () => true

const decisionKeyFor: Record<string, string> = {
  decision_permit_1: 'decision_permit_1',
  decision_permit_expired: 'decision_permit_expired',
  decision_permit_for_binding: 'decision_permit_for_binding',
  decision_permit_for_revocation: 'decision_permit_for_revocation',
  decision_deny: 'decision_deny',
  decision_permit_for_race: 'decision_permit_for_race',
  decision_narrow: 'decision_narrow',
}

function chainFor(name: 'main' | 'for_revocation_case'): AuthorityDelegationV1[] {
  return [fixture.delegations[name]]
}

function runBoundary(boundary: DispatchBoundary): Map<string, { admitted: boolean; reason: string; detail?: string }> {
  const results = new Map<string, { admitted: boolean; reason: string; detail?: string }>()
  for (const presentation of vectors.presentations) {
    const decisionKey = decisionKeyFor[presentation.decision]
    if (decisionKey === undefined) {
      console.error(`approval-single-use: vectors.json names an unknown decision "${presentation.decision}"`)
      process.exit(2)
    }
    const decision = fixture.receipts[decisionKey]
    const requestedActionRef = fixture.actions[presentation.requested_action].action_ref
    const outcome = boundary.consume({
      label: presentation.id,
      decision,
      requestedActionRef,
      now: presentation.now,
      chain: chainFor(presentation.chain),
      resolveRevocation: () => presentation.revocation,
    })
    results.set(presentation.id, outcome)
  }
  return results
}

const sharedOptions = { boundaryIdentity: BOUNDARY, resolveReceiptSignerKey, resolveDelegationVerificationKey, trustRoot }

const referenceBoundary = makeReferenceBoundary(sharedOptions)
const defectiveBoundary = makeDefectiveBoundary(sharedOptions)

const referenceResults = runBoundary(referenceBoundary)
const defectiveResults = runBoundary(defectiveBoundary)

function matches(actual: { admitted: boolean; reason: string; detail?: string }, expected: Presentation['expected']): boolean {
  if (actual.admitted !== expected.admitted) return false
  if (actual.reason !== expected.reason) return false
  if (expected.detail !== undefined && actual.detail !== expected.detail) return false
  return true
}

let referenceMatched = 0
console.log(`approval-single-use: ${vectors.presentations.length} presentations`)
console.log('')
console.log('boundary: reference-boundary')
for (const presentation of vectors.presentations) {
  const actual = referenceResults.get(presentation.id)!
  const ok = matches(actual, presentation.expected)
  if (ok) referenceMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${presentation.id}  admitted=${actual.admitted} reason=${actual.reason}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(presentation.expected)}`)
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

const declaredFailSet = new Set(vectors.declared_defective_fail_set)
let defectiveOk = true
console.log('')
console.log(`boundary: ${defectiveBoundary.name}`)
for (const presentation of vectors.presentations) {
  const actual = defectiveResults.get(presentation.id)!
  const shouldMatchExpected = !declaredFailSet.has(presentation.id)
  const actuallyMatches = matches(actual, presentation.expected)
  const ok = shouldMatchExpected ? actuallyMatches : !actuallyMatches
  if (!ok) defectiveOk = false
  const label = shouldMatchExpected ? (ok ? 'MATCH' : 'UNDECLARED MISMATCH') : (ok ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE')
  console.log(`  ${label} ${presentation.id}  admitted=${actual.admitted} reason=${actual.reason}`)
}

const referenceOk = referenceMatched === vectors.presentations.length

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${vectors.presentations.length}`)
console.log(`${defectiveBoundary.name} failed exactly the declared set: ${defectiveOk}`)

if (referenceOk && defectiveOk) {
  console.log('PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set')
  process.exit(0)
} else {
  console.error('FAILED')
  process.exit(1)
}
