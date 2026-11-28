// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the nine approval-single-use presentations against harness.ts's reference boundary
// and its declared defective negative control, both over chain.json's real,
// agent-passport-system 7.1.0-signed decision and delegation records.
//
// This is evidence about this family's own reference boundary, not an SDK conformance
// result. See README "What this establishes" and "Does not claim".

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { createReceiptV1, type AuthorityDelegationV1 } from 'agent-passport-system'

import { DispatchBoundary, makeDefectiveBoundary, makeReferenceBoundary, type PolicyDecisionReceipt } from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface ChainFixture {
  seed_label_prefix: string
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

// A key resolves only for the signer whose identifier prefixes its key id, so a receipt
// signed with another party's key does not verify as the boundary's. The signer-binding
// probe below fails if this binding is removed.
const resolveReceiptSignerKey = (signer: string, keyId: string) =>
  keyId.startsWith(`${signer}#`) ? fixture.verification_keys[keyId] : undefined
const resolveDelegationVerificationKey = (issuer: string, method: string) =>
  method.startsWith(`${issuer}#`) ? fixture.verification_keys[method] ?? null : null
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

// Signer-binding probe. Not a presentation, not in vectors.json, and not counted above.
// decision_permit_1's fields, re-signed with the principal's published seed key under the
// principal's key id while still naming the boundary as issuer and signer. A fresh
// reference boundary must refuse it at step 0. It would be admitted if the receipt key
// resolver handed out any key in chain.json for any signer.
const principalKeyId = `${fixture.identities.principal}#key-1`
const principalPrivate = createHash('sha256').update(`${fixture.seed_label_prefix}principal:v1`, 'utf8').digest('hex')
const { receipt_id: _receiptId, signatures: _signatures, ...permit1Fields } = fixture.receipts.decision_permit_1
const forgedPermit = createReceiptV1(permit1Fields as never, [
  { signer: BOUNDARY, key_id: principalKeyId, private_key: principalPrivate },
]) as unknown as PolicyDecisionReceipt
const probeOutcome = makeReferenceBoundary(sharedOptions).consume({
  label: 'signer-binding-probe',
  decision: forgedPermit,
  requestedActionRef: fixture.actions.a.action_ref,
  now: '2026-09-22T09:00:05.000Z',
  chain: chainFor('main'),
  resolveRevocation: () => 'active',
})
const probeOk = !probeOutcome.admitted && probeOutcome.reason === 'signature_or_shape_invalid'
console.log('')
console.log('signer-binding probe: decision_permit_1 re-signed with the principal key, boundary named as signer')
console.log(`  ${probeOk ? 'REFUSED' : 'NOT REFUSED'} admitted=${probeOutcome.admitted} reason=${probeOutcome.reason}`)

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${vectors.presentations.length}`)
console.log(`${defectiveBoundary.name} failed exactly the declared set: ${defectiveOk}`)
console.log(`signer-binding probe refused: ${probeOk}`)

if (referenceOk && defectiveOk && probeOk) {
  console.log('PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set')
  process.exit(0)
} else {
  console.error('FAILED')
  process.exit(1)
}
