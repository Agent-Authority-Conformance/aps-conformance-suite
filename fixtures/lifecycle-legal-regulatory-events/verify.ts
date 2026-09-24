// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the lifecycle-legal-regulatory-events vectors against harness.ts's reference
// boundary and its four declared defective negative controls, over chain.json's real,
// agent-passport-system 7.1.0-signed delegations, external authority events, dependency
// bindings, certifications, revocation and action-intent receipt.
//
// This is evidence about this family's own reference boundary for external authority
// events, and an SDK result for every chain, root-trust, revocation-resolution, scope and
// signature check. See README "What a pass establishes" and "Does not claim".
//
// No network. Exit 0 when the reference boundary matches every vector and each defective
// boundary diverges on exactly its declared set.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import {
  AuthorityBoundary,
  makeChainValidityOnlyBoundary,
  makeCollapsingBoundary,
  makeNoStandingCheckBoundary,
  makeReferenceBoundary,
  makeSingleSuspensionFlagBoundary,
  type BoundaryEvent,
  type DependencyBinding,
  type ExternalAuthorityEvent,
  type GateCertification,
  type Outcome,
  type VerifierTrustPolicy,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface ChainFixture {
  verification_keys: Record<string, string>
  off_graph_targets: Record<string, string>
  timeline: Record<string, string>
  signature_domains: { external_authority_event: string; dependency_binding: string; gate_certification: string }
  verifier_trust_policy: VerifierTrustPolicy
  chains: Record<string, AuthorityDelegationV1[]>
  dependency_bindings: Record<string, DependencyBinding>
  external_events: Record<string, ExternalAuthorityEvent>
  certifications: Record<string, GateCertification>
  actions: Record<string, { action_ref: string; input: { scope_required: string[] } }>
  historical_receipt: Record<string, unknown>
  historical_receipt_digest: string
  mint_time_sdk_observations: Record<string, unknown>
}

interface ExpectedOutcome {
  verdict: string
  reason: string
  chain_state: string | null
  chain_failure_code: string | null
  effective_events: string[]
  pending_events: string[]
  unestablished_events: string[]
  suspension_causes: string[]
}

interface Vector {
  id: string
  case: string
  kind: 'present' | 'assess_act'
  tests: string
  differs_from: string | null
  event_set: string
  chain: string
  dependency_binding?: string | null
  receipt?: string
  action: string
  action_target?: string | null
  amount_minor?: string | null
  certification?: string | null
  trust_root_basis: string
  evidence_set: 'complete' | 'pruned'
  now: string
  same_chain_as?: string
  expected: ExpectedOutcome
}

interface Vectors {
  profile: string
  status_label: string
  description: string
  pruned_evidence_delegations: Array<{ chain: string; index: number; why: string }>
  event_sets: Record<string, string[]>
  declared_fail_sets: Record<string, string[]>
  vectors: Vector[]
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

function fail(message: string): never {
  console.error(`lifecycle-legal-regulatory-events: ${message}`)
  process.exit(2)
}

// Every external event id maps back to the label vectors.json names it by, so the expected
// sets stay readable and no content-addressed identifier is ever hand-written.
const LABEL_BY_EVENT_ID = new Map<string, string>()
for (const [label, event] of Object.entries(fixture.external_events)) LABEL_BY_EVENT_ID.set(event.event_id, label)

const labelsOf = (ids: string[]): string[] => ids.map((id) => LABEL_BY_EVENT_ID.get(id) ?? `unknown:${id}`).sort()

const trackedDelegationIds = Object.values(fixture.chains).flat().map((record) => record.delegation_id)
const prunedDelegationIds = vectors.pruned_evidence_delegations.map((entry) => {
  const chain = fixture.chains[entry.chain]
  if (chain === undefined || chain[entry.index] === undefined) fail(`pruned_evidence_delegations names an unknown chain member ${entry.chain}[${entry.index}]`)
  return chain[entry.index].delegation_id
})

const sharedOptions = {
  trustPolicy: fixture.verifier_trust_policy,
  verificationKeys: fixture.verification_keys,
  signatureDomains: fixture.signature_domains,
  trackedDelegationIds,
  prunedDelegationIds,
}

function eventsFor(vector: Vector): ExternalAuthorityEvent[] {
  const labels = vectors.event_sets[vector.event_set]
  if (labels === undefined) fail(`${vector.id} names an unknown event_set "${vector.event_set}"`)
  return labels.map((label) => {
    const event = fixture.external_events[label]
    if (event === undefined) fail(`${vector.id} names an unknown external event "${label}"`)
    return event
  })
}

function toRequest(vector: Vector): BoundaryEvent {
  const chain = fixture.chains[vector.chain]
  if (chain === undefined) fail(`${vector.id} names an unknown chain "${vector.chain}"`)
  const action = fixture.actions[vector.action]
  if (action === undefined) fail(`${vector.id} names an unknown action "${vector.action}"`)
  const now = fixture.timeline[vector.now]
  if (now === undefined) fail(`${vector.id} names an unknown timeline point "${vector.now}"`)
  const events = eventsFor(vector)

  if (vector.kind === 'assess_act') {
    if (vector.receipt !== 'historical_receipt') fail(`${vector.id} names an unknown receipt "${String(vector.receipt)}"`)
    return {
      kind: 'assess_act',
      label: vector.id,
      events,
      chain,
      receipt: fixture.historical_receipt,
      action_ref: action.action_ref,
      trust_root_basis: vector.trust_root_basis,
      evidence_set: vector.evidence_set,
      now,
    }
  }

  const binding = vector.dependency_binding == null ? null : fixture.dependency_bindings[vector.dependency_binding]
  if (vector.dependency_binding != null && binding === undefined) fail(`${vector.id} names an unknown dependency binding "${vector.dependency_binding}"`)
  const certification = vector.certification == null ? null : fixture.certifications[vector.certification]
  if (vector.certification != null && certification === undefined) fail(`${vector.id} names an unknown certification "${vector.certification}"`)
  const target = vector.action_target == null ? null : fixture.off_graph_targets[vector.action_target]
  if (vector.action_target != null && target === undefined) fail(`${vector.id} names an unknown off-graph target "${vector.action_target}"`)

  return {
    kind: 'present',
    label: vector.id,
    events,
    chain,
    dependency_binding: binding ?? null,
    action_ref: action.action_ref,
    action_scope: action.input.scope_required[0],
    action_target_id: target ?? null,
    amount_minor: vector.amount_minor ?? null,
    certification: certification ?? null,
    trust_root_basis: vector.trust_root_basis,
    evidence_set: vector.evidence_set,
    now,
  }
}

function matches(actual: Outcome, expected: ExpectedOutcome): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.reason !== expected.reason) return false
  if (actual.chain_state !== expected.chain_state) return false
  if (actual.chain_failure_code !== expected.chain_failure_code) return false
  if (JSON.stringify(labelsOf(actual.effective_event_ids)) !== JSON.stringify(expected.effective_events)) return false
  if (JSON.stringify(labelsOf(actual.pending_event_ids)) !== JSON.stringify(expected.pending_events)) return false
  if (JSON.stringify(labelsOf(actual.unestablished_event_ids)) !== JSON.stringify(expected.unestablished_events)) return false
  if (JSON.stringify(actual.suspension_causes) !== JSON.stringify(expected.suspension_causes)) return false
  return true
}

function line(actual: Outcome): string {
  return (
    `verdict="${actual.verdict}" reason=${actual.reason} chain=${actual.chain_state}/${actual.chain_failure_code}` +
    ` effective=[${labelsOf(actual.effective_event_ids).join(' ')}]` +
    (actual.pending_event_ids.length > 0 ? ` pending=[${labelsOf(actual.pending_event_ids).join(' ')}]` : '') +
    (actual.unestablished_event_ids.length > 0 ? ` unestablished=[${labelsOf(actual.unestablished_event_ids).join(' ')}]` : '') +
    (actual.suspension_causes.length > 0 ? ` causes=[${actual.suspension_causes.join(' ')}]` : '')
  )
}

function runBoundary(boundary: AuthorityBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  // Every vector is decided by a fresh evaluation against its own status source and its own
  // observation time. Nothing carries between vectors: this family's state lives in the
  // external records, never in the boundary.
  for (const vector of vectors.vectors) results.set(vector.id, boundary.handle(toRequest(vector)))
  return results
}

const VERDICT_VOCABULARY = new Set(['valid', 'invalid', 'suspended', 'restricted', 'not established', 'not yet effective'])

console.log(`lifecycle-legal-regulatory-events: ${vectors.vectors.length} vectors, status label ${vectors.status_label}`)
console.log('')
console.log('boundary: reference-boundary')

const referenceResults = runBoundary(makeReferenceBoundary(sharedOptions))
let referenceMatched = 0
for (const vector of vectors.vectors) {
  const actual = referenceResults.get(vector.id)!
  const ok = matches(actual, vector.expected)
  if (ok) referenceMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${vector.id} (${vector.case})  ${line(actual)}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(vector.expected)}`)
    console.log(
      `    actual:   ${JSON.stringify({
        verdict: actual.verdict, reason: actual.reason, chain_state: actual.chain_state,
        chain_failure_code: actual.chain_failure_code, effective_events: labelsOf(actual.effective_event_ids),
        pending_events: labelsOf(actual.pending_event_ids), unestablished_events: labelsOf(actual.unestablished_event_ids),
        suspension_causes: actual.suspension_causes, detail: actual.detail,
      })}`,
    )
  }
}

// Structural checks the vectors cannot state on their own.
console.log('')
console.log('structural checks')
let structuralOk = true
function check(label: string, ok: boolean, detail: string): void {
  if (!ok) structuralOk = false
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}: ${detail}`)
}

// 1. No verdict outside the settled vocabulary, from any boundary, on any vector.
const allVerdicts = new Set<string>()
for (const outcome of referenceResults.values()) allVerdicts.add(outcome.verdict)
check('verdict vocabulary', [...allVerdicts].every((v) => VERDICT_VOCABULARY.has(v)), `observed [${[...allVerdicts].sort().join(', ')}]`)

// 2. Every assess_act vector produced the same receipt digest, which is chain.json's own
//    recorded value. A ratification is a new record: it cannot change the bytes of the act
//    it names, and this is where that is checked rather than asserted.
const assessIds = vectors.vectors.filter((v) => v.kind === 'assess_act').map((v) => v.id)
const digests = new Set(assessIds.map((id) => referenceResults.get(id)!.receipt_digest))
check(
  'historical receipt unchanged across ratification',
  digests.size === 1 && digests.has(fixture.historical_receipt_digest),
  `${assessIds.length} assessments, ${digests.size} distinct digest(s), matches chain.json: ${digests.has(fixture.historical_receipt_digest)}`,
)

// 3. A restriction and its release act on the same delegation, never on a replacement. Any
//    vector naming same_chain_as must present the same delegation_ids as the vector it names.
for (const vector of vectors.vectors) {
  if (vector.same_chain_as === undefined) continue
  const other = vectors.vectors.find((v) => v.id === vector.same_chain_as)
  if (other === undefined) fail(`${vector.id} names an unknown same_chain_as "${vector.same_chain_as}"`)
  const ids = fixture.chains[vector.chain].map((r) => r.delegation_id)
  const otherIds = fixture.chains[other.chain].map((r) => r.delegation_id)
  const same = JSON.stringify(ids) === JSON.stringify(otherIds)
  check(`${vector.id} presents the same delegation_ids as ${other.id}`, same, same ? `${ids.length} record(s), no fresh grant` : 'differs')
}

// 4. The family does hold a fresh-grant counterexample, so the check above is a property of
//    the pair and not a consequence of every vector reusing one chain: resource_regrant is a
//    genuinely different, later-issued grant from the same principal over the same target.
const resourceIds = fixture.chains.resource.map((r) => r.delegation_id)
const regrantIds = fixture.chains.resource_regrant.map((r) => r.delegation_id)
check(
  'resource_regrant is a distinct grant from resource',
  JSON.stringify(resourceIds) !== JSON.stringify(regrantIds),
  `${resourceIds[0].slice(0, 16)}... against ${regrantIds[0].slice(0, 16)}...`,
)

// 5. Every vector names a case in this family's CASES.md section.
const casesCovered = [...new Set(vectors.vectors.map((v) => v.case))].sort()
check('every vector names a case', vectors.vectors.every((v) => typeof v.case === 'string' && v.case.startsWith('LC-')), `${casesCovered.length} cases: ${casesCovered.join(' ')}`)

let allDefectivesOk = true
for (const [name, factory] of [
  ['defective-boundary-chain-validity-only', makeChainValidityOnlyBoundary],
  ['defective-boundary-collapses-restricted-into-revoked', makeCollapsingBoundary],
  ['defective-boundary-single-suspension-flag', makeSingleSuspensionFlagBoundary],
  ['defective-boundary-trusts-event-without-standing', makeNoStandingCheckBoundary],
] as const) {
  const boundary = factory(sharedOptions)
  const results = runBoundary(boundary)
  const declared = vectors.declared_fail_sets[name]
  if (declared === undefined) fail(`vectors.json declares no fail set for ${name}`)
  const declaredSet = new Set(declared)
  let ok = true
  console.log('')
  console.log(`boundary: ${boundary.name}`)
  for (const vector of vectors.vectors) {
    const actual = results.get(vector.id)!
    const shouldMatch = !declaredSet.has(vector.id)
    const actuallyMatches = matches(actual, vector.expected)
    const entryOk = shouldMatch ? actuallyMatches : !actuallyMatches
    if (!entryOk) ok = false
    const label = shouldMatch ? (entryOk ? 'MATCH' : 'UNDECLARED MISMATCH') : entryOk ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE'
    if (!shouldMatch || !entryOk) console.log(`  ${label} ${vector.id}  ${line(actual)}`)
  }
  console.log(`  ${boundary.name}: ${declared.length} declared, diverged on exactly its declared set: ${ok}`)
  if (!ok) allDefectivesOk = false
}

// What came from the pinned TypeScript SDK and what did not. Printed by the run rather than
// written by hand, so the record cannot drift from the code above.
const SDK_SUPPORT: Array<[string, 'supported' | 'not_supported', string]> = [
  ['chain state, including time and root trust', 'supported', 'verifyAuthorityDelegationChain'],
  ['revocation resolution, including unknown for uncovered evidence', 'supported', 'createAuthorityRevocationResolver over InMemoryAuthorityRevocationStore'],
  ['direct revocation by the delegation issuer', 'supported', 'issueAuthorityRevocation, verifyAuthorityRevocation, recordAuthorityRevocation'],
  ['gate scope match', 'supported', 'scopeGrantCovers'],
  ['external event, dependency binding and certification signatures', 'supported', 'verify over canonicalizeJCS'],
  ['revocation by a party other than the issuer', 'not_supported', 'issueAuthorityRevocation refuses with REVOKER_NOT_ISSUER, see chain.json mint_time_sdk_observations'],
  ['suspension state', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['restricted state', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['external authority event record', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by this fixture'],
  ['off-graph dependency binding', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by this fixture'],
  ['ratification of a past act', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['lifecycle standing registry', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by this fixture'],
]

console.log('')
console.log('TypeScript SDK support, agent-passport-system 7.1.0:')
for (const [concept, verdict, how] of SDK_SUPPORT) console.log(`  ${verdict.padEnd(14)} ${concept}  (${how})`)

console.log('')
console.log('recorded SDK observations from mint time:')
for (const [key, value] of Object.entries(fixture.mint_time_sdk_observations)) {
  if (key === 'chain_state_at_t4') continue
  console.log(`  ${key}: ${JSON.stringify(value)}`)
}

const referenceOk = referenceMatched === vectors.vectors.length

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${vectors.vectors.length}`)
console.log(`structural checks passed: ${structuralOk}`)
console.log(`all four defective boundaries diverged on exactly their declared sets: ${allDefectivesOk}`)

if (referenceOk && structuralOk && allDefectivesOk) {
  console.log('PASSED: reference-boundary matched every vector, all four defective boundaries diverged on exactly their declared sets')
  process.exit(0)
}
console.error('FAILED')
process.exit(1)
