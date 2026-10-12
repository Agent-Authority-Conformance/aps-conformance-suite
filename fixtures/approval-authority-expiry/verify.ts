// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the five approval-authority-expiry presentations against harness.ts's reference
// boundary and its declared defective negative control, both over chain.json's
// agent-passport-system 7.1.0-signed decision and delegation records.
//
// This is evidence about this family's own reference boundary, not an SDK conformance
// result. See README "What a pass establishes" and "Does not claim".

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import { ConsumptionBoundary, makeDefectiveBoundary, makeReferenceBoundary, type Outcome, type PolicyDecisionReceipt } from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface ChainFixture {
  identities: { principal: string; acting_agent: string; enforcement_boundary: string }
  verification_keys: Record<string, string>
  delegations: { main: AuthorityDelegationV1; for_revocation_case: AuthorityDelegationV1 }
  actions: Record<'a', { action_ref: string }>
  receipts: Record<string, PolicyDecisionReceipt>
}

interface Presentation {
  id: string
  differs_from: string | null
  decision: string
  requested_action: 'a'
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

// A key resolves only for the signer whose identifier prefixes its key id, so a receipt
// signed with another party's key does not verify as the boundary's.
const resolveReceiptSignerKey = (signer: string, keyId: string) =>
  keyId.startsWith(`${signer}#`) ? fixture.verification_keys[keyId] : undefined
const resolveDelegationVerificationKey = (issuer: string, method: string) =>
  method.startsWith(`${issuer}#`) ? fixture.verification_keys[method] ?? null : null
const trustRoot = () => true

// Fail closed on malformed input before any boundary runs: an empty or duplicate-id
// presentation list, presentations out of clock order (the family runs one forward-moving
// clock), a declared id that is not presented, an unknown decision, chain or action name,
// or a presentation that pairs a decision with a chain other than the one its
// delegation_ref names.
function inputError(message: string): never {
  console.error(`approval-authority-expiry: ${message}`)
  process.exit(2)
}
if (!Array.isArray(vectors.presentations) || vectors.presentations.length === 0) inputError('vectors.json has no presentations')
if (!Array.isArray(vectors.declared_defective_fail_set)) inputError('vectors.json has no declared_defective_fail_set array')
const presentedIds = new Set(vectors.presentations.map(p => p.id))
if (presentedIds.size !== vectors.presentations.length) inputError('vectors.json repeats a presentation id')
for (let i = 1; i < vectors.presentations.length; i++) {
  if (vectors.presentations[i].now < vectors.presentations[i - 1].now) inputError(`${vectors.presentations[i].id} is earlier than the presentation before it`)
}
for (const id of vectors.declared_defective_fail_set) {
  if (!presentedIds.has(id)) inputError(`declared_defective_fail_set names "${id}", which is not presented`)
}
for (const presentation of vectors.presentations) {
  const decision = fixture.receipts[presentation.decision]
  if (decision === undefined || !presentation.decision.startsWith('decision_')) inputError(`vectors.json names an unknown decision "${presentation.decision}"`)
  const delegation = fixture.delegations[presentation.chain]
  if (delegation === undefined) inputError(`vectors.json names an unknown chain "${presentation.chain}"`)
  if (fixture.actions[presentation.requested_action] === undefined) inputError(`vectors.json names an unknown action "${presentation.requested_action}"`)
  if (decision.delegation_ref !== delegation.delegation_id) inputError(`${presentation.id} pairs ${presentation.decision} with chain "${presentation.chain}", which its delegation_ref does not name`)
}

function runBoundary(boundary: ConsumptionBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  for (const presentation of vectors.presentations) {
    const decision = fixture.receipts[presentation.decision]
    const outcome = boundary.consume({
      decision,
      requestedActionRef: fixture.actions[presentation.requested_action].action_ref,
      now: presentation.now,
      chain: [fixture.delegations[presentation.chain]],
      resolveRevocation: () => presentation.revocation,
    })
    results.set(presentation.id, outcome)
  }
  return results
}

const sharedOptions = {
  boundaryIdentity: fixture.identities.enforcement_boundary,
  resolveReceiptSignerKey,
  resolveDelegationVerificationKey,
  trustRoot,
}

const referenceBoundary = makeReferenceBoundary(sharedOptions)
const defectiveBoundary = makeDefectiveBoundary(sharedOptions)

const referenceResults = runBoundary(referenceBoundary)
const defectiveResults = runBoundary(defectiveBoundary)

function matches(actual: Outcome, expected: Presentation['expected']): boolean {
  if (actual.admitted !== expected.admitted) return false
  if (actual.reason !== expected.reason) return false
  if (expected.detail !== undefined && actual.detail !== expected.detail) return false
  return true
}

let referenceMatched = 0
console.log(`approval-authority-expiry: ${vectors.presentations.length} presentations`)
console.log('')
console.log(`boundary: ${referenceBoundary.name}`)
for (const presentation of vectors.presentations) {
  const actual = referenceResults.get(presentation.id)!
  const ok = matches(actual, presentation.expected)
  if (ok) referenceMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${presentation.id}  admitted=${actual.admitted} reason=${actual.reason}${actual.detail ? ` detail=${actual.detail}` : ''}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(presentation.expected)}`)
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

const declaredFailSet = new Set(vectors.declared_defective_fail_set)
let defectiveOk = declaredFailSet.size > 0
console.log('')
console.log(`boundary: ${defectiveBoundary.name}`)
for (const presentation of vectors.presentations) {
  const actual = defectiveResults.get(presentation.id)!
  const shouldMatchExpected = !declaredFailSet.has(presentation.id)
  const actuallyMatches = matches(actual, presentation.expected)
  const ok = shouldMatchExpected ? actuallyMatches : !actuallyMatches
  if (!ok) defectiveOk = false
  const label = shouldMatchExpected ? (ok ? 'MATCH' : 'UNDECLARED MISMATCH') : (ok ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE')
  console.log(`  ${label} ${presentation.id}  admitted=${actual.admitted} reason=${actual.reason}${actual.detail ? ` detail=${actual.detail}` : ''}`)
}
for (const id of declaredFailSet) {
  if (!referenceResults.has(id)) {
    console.log(`  DECLARED ID NOT PRESENTED ${id}`)
    defectiveOk = false
  }
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
