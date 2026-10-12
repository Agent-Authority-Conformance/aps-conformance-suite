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
  profile: string
  identities: { enforcement_boundary: string }
  verification_keys: Record<string, string>
  delegations: Record<string, AuthorityDelegationV1>
  chains: Record<string, string[]>
  actions: Record<string, { action_ref: string }>
  receipts: Record<string, PolicyDecisionReceipt>
  decision_evidence: Record<string, { authority_state: { selected_chain: string[] } }>
}

interface Presentation {
  id: string
  differs_from: string | null
  decision: string
  requested_action: string
  now: string
  chain: string
  revocation: 'active' | 'revoked'
  expected: { admitted: boolean; reason: string; detail?: string }
}

interface Vectors {
  profile: string
  description: string
  declared_defective_fail_set: string[]
  presentations: Presentation[]
}

const PROFILE = 'aps-approval-authority-expiry-v0'

// The family's case inventory, in presentation order. AEX-02 and AEX-03 are the controls
// that give the declared failing set its meaning, so a corpus without them is malformed,
// not a smaller pass.
const REQUIRED_IDS = [
  'AEX-01-accept-authority-valid-at-consumption',
  'AEX-02-reject-authority-revoked-at-consumption',
  'AEX-03-reject-approval-expired',
  'AEX-05-reject-authority-at-exact-not-after',
  'AEX-04-reject-authority-expired-approval-unexpired',
]
const REQUIRED_DECLARED = ['AEX-04-reject-authority-expired-approval-unexpired', 'AEX-05-reject-authority-at-exact-not-after']

// The declared defect is wrongful admission. A declared vector counts as a declared
// failure only when the defective boundary admits it this way. A refusal for any other
// reason is a mismatch, not the defect.
const DECLARED_DEFECT_OUTCOME: Outcome = { admitted: true, reason: 'dispatch_admitted' }

const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

// A key resolves only for the signer whose identifier prefixes its key id, so a receipt
// signed with another party's key does not verify as the boundary's.
const resolveReceiptSignerKey = (signer: string, keyId: string) =>
  keyId.startsWith(`${signer}#`) ? fixture.verification_keys[keyId] : undefined
const resolveDelegationVerificationKey = (issuer: string, method: string) =>
  method.startsWith(`${issuer}#`) ? fixture.verification_keys[method] ?? null : null
const trustRoot = () => true

// Fail closed on malformed input before any boundary runs. Exit 2 on: a profile other than
// this family's, a presentation list that is not exactly the required inventory in order,
// a declared failing set other than exactly AEX-04 and AEX-05, a field of the wrong type,
// a revocation answer other than active or revoked, presentations out of clock order (the
// family runs one forward-moving clock), an unknown decision, chain or action name, a
// chain whose leaf is not the decision's delegation_ref, or a chain that differs from the
// decision evidence's selected_chain.
function inputError(message: string): never {
  console.error(`approval-authority-expiry: ${message}`)
  process.exit(2)
}
const isString = (v: unknown): v is string => typeof v === 'string'
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)

if (fixture.profile !== PROFILE) inputError(`chain.json profile is not ${PROFILE}`)
if (vectors.profile !== PROFILE) inputError(`vectors.json profile is not ${PROFILE}`)
if (!Array.isArray(vectors.presentations) || vectors.presentations.length === 0) inputError('vectors.json has no presentations')
if (!Array.isArray(vectors.declared_defective_fail_set)) inputError('vectors.json has no declared_defective_fail_set array')
if (!isObject(fixture.chains)) inputError('chain.json has no chains map')

for (const [index, p] of vectors.presentations.entries()) {
  if (!isObject(p)) inputError(`presentation ${index} is not an object`)
  if (!isString(p.id)) inputError(`presentation ${index} has no string id`)
  if (!(p.differs_from === null || isString(p.differs_from))) inputError(`${p.id} differs_from is neither null nor a string`)
  for (const field of ['decision', 'requested_action', 'chain'] as const) {
    if (!isString(p[field])) inputError(`${p.id} has no string ${field}`)
  }
  if (!isString(p.now) || !INSTANT.test(p.now)) inputError(`${p.id} now is not a UTC millisecond instant`)
  if (p.revocation !== 'active' && p.revocation !== 'revoked') inputError(`${p.id} revocation is neither "active" nor "revoked"`)
  const expected = p.expected as unknown
  if (!isObject(expected)) inputError(`${p.id} has no expected object`)
  if (typeof expected.admitted !== 'boolean') inputError(`${p.id} expected.admitted is not a boolean`)
  if (!isString(expected.reason)) inputError(`${p.id} expected.reason is not a string`)
  if (expected.detail !== undefined && !isString(expected.detail)) inputError(`${p.id} expected.detail is not a string`)
}

const presentedIds = vectors.presentations.map(p => p.id)
if (presentedIds.length !== REQUIRED_IDS.length || presentedIds.some((id, i) => id !== REQUIRED_IDS[i])) {
  inputError(`vectors.json presents [${presentedIds.join(', ')}], not the required inventory [${REQUIRED_IDS.join(', ')}]`)
}
const declaredIds = vectors.declared_defective_fail_set
if (
  declaredIds.length !== REQUIRED_DECLARED.length ||
  new Set(declaredIds).size !== declaredIds.length ||
  !REQUIRED_DECLARED.every(id => declaredIds.includes(id))
) {
  inputError(`declared_defective_fail_set is not exactly [${REQUIRED_DECLARED.join(', ')}]`)
}
for (let i = 1; i < vectors.presentations.length; i++) {
  if (vectors.presentations[i].now < vectors.presentations[i - 1].now) inputError(`${vectors.presentations[i].id} is earlier than the presentation before it`)
}

const chains = new Map<string, AuthorityDelegationV1[]>()
for (const presentation of vectors.presentations) {
  const decision = fixture.receipts[presentation.decision]
  if (decision === undefined || !presentation.decision.startsWith('decision_')) inputError(`vectors.json names an unknown decision "${presentation.decision}"`)
  const memberNames = fixture.chains[presentation.chain]
  if (!Array.isArray(memberNames) || memberNames.length === 0) inputError(`vectors.json names an unknown chain "${presentation.chain}"`)
  const members = memberNames.map(name => {
    const delegation = fixture.delegations[name]
    if (delegation === undefined) inputError(`chain "${presentation.chain}" names an unknown delegation "${name}"`)
    return delegation
  })
  if (fixture.actions[presentation.requested_action] === undefined) inputError(`vectors.json names an unknown action "${presentation.requested_action}"`)
  if (decision.delegation_ref !== members[members.length - 1].delegation_id) inputError(`${presentation.id} pairs ${presentation.decision} with chain "${presentation.chain}", whose leaf its delegation_ref does not name`)
  const selected = fixture.decision_evidence[presentation.decision]?.authority_state?.selected_chain
  const memberIds = members.map(d => d.delegation_id)
  if (!Array.isArray(selected) || selected.length !== memberIds.length || selected.some((id, i) => id !== memberIds[i])) {
    inputError(`${presentation.id} chain "${presentation.chain}" is not ${presentation.decision}'s selected_chain`)
  }
  chains.set(presentation.chain, members)
}

function runBoundary(boundary: ConsumptionBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  for (const presentation of vectors.presentations) {
    const decision = fixture.receipts[presentation.decision]
    const outcome = boundary.consume({
      decision,
      requestedActionRef: fixture.actions[presentation.requested_action].action_ref,
      now: presentation.now,
      chain: chains.get(presentation.chain)!,
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

function isDeclaredDefect(actual: Outcome): boolean {
  return actual.admitted === DECLARED_DEFECT_OUTCOME.admitted && actual.reason === DECLARED_DEFECT_OUTCOME.reason && actual.detail === undefined
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
let defectiveOk = true
console.log('')
console.log(`boundary: ${defectiveBoundary.name}`)
for (const presentation of vectors.presentations) {
  const actual = defectiveResults.get(presentation.id)!
  const declared = declaredFailSet.has(presentation.id)
  const ok = declared ? isDeclaredDefect(actual) : matches(actual, presentation.expected)
  if (!ok) defectiveOk = false
  const label = declared ? (ok ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE') : (ok ? 'MATCH' : 'UNDECLARED MISMATCH')
  console.log(`  ${label} ${presentation.id}  admitted=${actual.admitted} reason=${actual.reason}${actual.detail ? ` detail=${actual.detail}` : ''}`)
  if (declared && !ok) console.log(`    declared defect: ${JSON.stringify(DECLARED_DEFECT_OUTCOME)}`)
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
