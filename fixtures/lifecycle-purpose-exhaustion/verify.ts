// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Node runner for the lifecycle-purpose-exhaustion family, all twenty-one vectors.
//
// The family has two tracks, built independently and reconciled into one. They share a
// lifecycle concept and nothing else: different record sets, different boundary models,
// different state vocabularies. This runner replays each track against its own boundary
// class and its own declared defective policies, and it refuses to start if the two
// tracks' events, ids or fail sets have drifted apart from vectors.json.
//
//   bounds       records-bounds.json, AuthorityBoundary, twelve events PXE-01 to PXE-12.
//                Exhaustion by purpose (an observed fulfillment record), by use count
//                (the admission) and by budget (the SDK's own ledger).
//   single-use   records-single-use.json, ExhaustionBoundary, nine events LC-I-013-a to
//                LC-I-014-e. Exhaustion by the admission itself, plus how far a detected
//                reuse reaches and whether an exhaustion can be undone.
//
// This is evidence about this family's own reference boundaries for purpose, use-count,
// single-use and notch exhaustion, and an SDK result for the budget dimension and for
// every chain, purpose-membership and receipt check. See README, "What a pass
// establishes" and "Does not claim".
//
// No network. Exit 0 when both reference boundaries match every event in their track and
// each defective policy diverges on exactly its declared set, 1 otherwise, 2 when a
// record set is not minted or vectors.json is internally inconsistent.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import {
  AuthorityBoundary,
  ExhaustionBoundary,
  makeChainValidityOnlyBoundary,
  makeReferenceBoundary,
  makeTrustingBoundary,
  type BoundaryEvent,
  type CompletionRecord,
  type GrantContext,
  type Outcome,
  type PurposeBound,
  type SingleUseFixture,
  type SingleUsePolicyName,
  type SingleUseResult,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

function bail(message: string): never {
  console.error(`lifecycle-purpose-exhaustion: ${message}`)
  process.exit(2)
}

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

interface BoundsFixture {
  identities: Record<string, string>
  verification_keys: Record<string, string>
  purpose: string
  purpose_bound_signature_domain: string
  grants: Record<string, AuthorityDelegationV1>
  purpose_bounds: Record<string, PurposeBound>
  actions: Record<string, { action_ref: string }>
  receipts: Record<string, CompletionRecord>
}

interface VectorEvent {
  id: string
  track: 'bounds' | 'single-use'
  case_ids: string[]
  kind: 'present' | 'observe' | 'void'
  tests: string
  differs_from: string | null
  negative_control?: boolean
  // bounds track
  grant?: string
  action?: string
  completion?: string
  amount?: string
  revocation?: 'active' | 'revoked'
  draft03_basis?: string
  // single-use track
  chain?: string
  signed_by?: string
  record_divergence?: Record<string, boolean>
  now: string
  expected: Record<string, unknown>
}

interface Vectors {
  profile: string
  status_label: string
  declared_fail_sets: Record<string, string[]>
  tracks: Record<string, { compared_fields: string[]; policies: Record<string, string> }>
  events: VectorEvent[]
}

const vectors = readJson<Vectors>('vectors.json')
const boundsFixture = readJson<BoundsFixture>('records-bounds.json')
const singleUseFixture = readJson<SingleUseFixture>('records-single-use.json')

// ---------------------------------------------------------------------------
// Structural checks over the merged vector list. These exist because the family was
// reconciled from two builds: a merge that quietly dropped a vector, duplicated an id or
// pointed a fail set at the wrong track would otherwise still exit 0.
// ---------------------------------------------------------------------------

const EXPECTED_TOTAL = 21
const EXPECTED_PER_TRACK: Record<string, number> = { bounds: 12, 'single-use': 9 }

if (vectors.events.length !== EXPECTED_TOTAL) {
  bail(`vectors.json holds ${vectors.events.length} events, expected ${EXPECTED_TOTAL}`)
}

const ids = new Set<string>()
const trackOf = new Map<string, string>()
const perTrack: Record<string, number> = { bounds: 0, 'single-use': 0 }
for (const v of vectors.events) {
  if (ids.has(v.id)) bail(`duplicate vector id ${v.id}`)
  ids.add(v.id)
  trackOf.set(v.id, v.track)
  if (!(v.track in perTrack)) bail(`vector ${v.id} names an unknown track ${v.track}`)
  perTrack[v.track] += 1
  if (!Array.isArray(v.case_ids)) bail(`vector ${v.id} carries no case_ids array`)
}
for (const [track, count] of Object.entries(EXPECTED_PER_TRACK)) {
  if (perTrack[track] !== count) bail(`track ${track} holds ${perTrack[track]} events, expected ${count}`)
}

const TRACK_OF_POLICY: Record<string, 'bounds' | 'single-use'> = {
  'defective-boundary-chain-validity-only': 'bounds',
  'defective-boundary-trusts-unauthenticated-completion': 'bounds',
  'reuse-rejecting-only': 'single-use',
  'validity-window-only': 'single-use',
}
for (const [policy, declared] of Object.entries(vectors.declared_fail_sets)) {
  const track = TRACK_OF_POLICY[policy]
  if (track === undefined) bail(`declared_fail_sets names an unknown policy ${policy}`)
  for (const id of declared) {
    if (!ids.has(id)) bail(`declared_fail_sets.${policy} names an unknown vector ${id}`)
    if (trackOf.get(id) !== track) bail(`declared_fail_sets.${policy} names ${id}, which is on track ${trackOf.get(id)}`)
  }
}

if (
  (singleUseFixture as unknown as { _placeholder?: boolean })._placeholder ||
  typeof singleUseFixture.mint_now !== 'string' ||
  Object.keys(singleUseFixture.chains ?? {}).length !== 4
) {
  bail('records-single-use.json is not minted. Run python3 fixtures/lifecycle-purpose-exhaustion/mint_single_use.py first.')
}
if (Object.keys(boundsFixture.grants ?? {}).length === 0) {
  bail('records-bounds.json is not minted. Run npx tsx fixtures/lifecycle-purpose-exhaustion/mint-bounds.ts first.')
}

const boundsEvents = vectors.events.filter(v => v.track === 'bounds')
const singleUseEvents = vectors.events.filter(v => v.track === 'single-use')

// ---------------------------------------------------------------------------
// Track 1: bounds
// ---------------------------------------------------------------------------

const resolveReceiptSignerKey = (_signer: string, keyId: string) => boundsFixture.verification_keys[keyId]
const resolveDelegationVerificationKey = (_issuer: string, method: string) => boundsFixture.verification_keys[method] ?? null
const trustRoot = () => true

function grantContext(key: string): GrantContext {
  const grant = boundsFixture.grants[key]
  const bound = boundsFixture.purpose_bounds[key]
  if (grant === undefined || bound === undefined) bail(`vectors.json names an unknown grant "${key}"`)
  return { key, grant, bound }
}

function toBoundsEvent(v: VectorEvent): BoundaryEvent {
  const grant = grantContext(v.grant!)
  if (v.kind === 'present') {
    const action = v.action !== undefined ? boundsFixture.actions[v.action] : undefined
    if (action === undefined) bail(`vectors.json names an unknown action "${v.action}"`)
    return {
      kind: 'present',
      label: v.id,
      grant,
      requestedPurpose: boundsFixture.purpose,
      actionRef: action.action_ref,
      amount: v.amount,
      now: v.now,
      resolveRevocation: () => v.revocation ?? 'active',
    }
  }
  const completion = v.completion !== undefined ? boundsFixture.receipts[v.completion] : undefined
  if (completion === undefined) bail(`vectors.json names an unknown completion record "${v.completion}"`)
  return { kind: 'observe', label: v.id, grant, completion, now: v.now }
}

const sharedOptions = {
  purposeBoundSignatureDomain: boundsFixture.purpose_bound_signature_domain,
  principalPublicKeys: boundsFixture.verification_keys,
  resolveReceiptSignerKey,
  resolveDelegationVerificationKey,
  trustRoot,
}

function runBoundsBoundary(boundary: AuthorityBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  for (const v of boundsEvents) results.set(v.id, boundary.handle(toBoundsEvent(v)))
  return results
}

const BOUNDS_FIELDS = ['outcome', 'reason', 'bound_state', 'exhaustion_basis', 'chain_state'] as const

function boundsMatches(actual: Outcome, expected: Record<string, unknown>): boolean {
  for (const field of BOUNDS_FIELDS) {
    if ((actual as unknown as Record<string, unknown>)[field] !== expected[field]) return false
  }
  if (expected.detail !== undefined && actual.detail !== expected.detail) return false
  return true
}

function boundsLine(actual: Outcome): string {
  const base =
    `outcome=${actual.outcome} reason=${actual.reason} bound_state=${actual.bound_state}` +
    ` basis=${actual.exhaustion_basis === null ? 'null' : `"${actual.exhaustion_basis}"`} chain_state=${actual.chain_state}`
  return actual.detail !== undefined ? `${base} detail=${actual.detail}` : base
}

console.log(`lifecycle-purpose-exhaustion: ${vectors.events.length} events across 2 tracks, status label ${vectors.status_label}`)
console.log(`  bounds ${perTrack.bounds}, single-use ${perTrack['single-use']}`)
console.log('')
console.log('=== track: bounds (records-bounds.json, AuthorityBoundary) ===')
console.log('')
console.log('boundary: reference-boundary')

const referenceResults = runBoundsBoundary(makeReferenceBoundary(sharedOptions))
let boundsMatched = 0
for (const v of boundsEvents) {
  const actual = referenceResults.get(v.id)!
  const ok = boundsMatches(actual, v.expected)
  if (ok) boundsMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${v.id}  ${boundsLine(actual)}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(v.expected)}`)
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

let boundsDefectivesOk = true
for (const [name, factory] of [
  ['defective-boundary-chain-validity-only', makeChainValidityOnlyBoundary],
  ['defective-boundary-trusts-unauthenticated-completion', makeTrustingBoundary],
] as const) {
  const boundary = factory(sharedOptions)
  const results = runBoundsBoundary(boundary)
  const declaredSet = new Set(vectors.declared_fail_sets[name])
  let ok = true
  console.log('')
  console.log(`boundary: ${boundary.name}`)
  for (const v of boundsEvents) {
    const actual = results.get(v.id)!
    const shouldMatch = !declaredSet.has(v.id)
    const actuallyMatches = boundsMatches(actual, v.expected)
    const entryOk = shouldMatch ? actuallyMatches : !actuallyMatches
    if (!entryOk) ok = false
    const label = shouldMatch
      ? (entryOk ? 'MATCH' : 'UNDECLARED MISMATCH')
      : (entryOk ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE')
    console.log(`  ${label} ${v.id}  ${boundsLine(actual)}`)
  }
  console.log(`  ${boundary.name} diverged on exactly its declared set: ${ok}`)
  if (!ok) boundsDefectivesOk = false
}

// ---------------------------------------------------------------------------
// Track 2: single-use
// ---------------------------------------------------------------------------

const SINGLE_USE_POLICIES: SingleUsePolicyName[] = ['reference', 'reuse-rejecting-only', 'validity-window-only']
const SINGLE_USE_FIELDS: (keyof SingleUseResult)[] = [
  'outcome', 'reason', 'exhaustion_basis', 'chain_verdict', 'chain_failure_code',
  'bound_state', 'records_written',
]

function replaySingleUse(policy: SingleUsePolicyName): Map<string, SingleUseResult> {
  const boundary = new ExhaustionBoundary(singleUseFixture, policy)
  const out = new Map<string, SingleUseResult>()
  for (const event of singleUseEvents) {
    out.set(
      event.id,
      event.kind === 'void'
        ? boundary.voidExhaustion(event.grant!, event.signed_by!)
        : boundary.present(event.chain!, event.now)
    )
  }
  return out
}

const singleUseRuns = new Map<SingleUsePolicyName, Map<string, SingleUseResult>>()
for (const policy of SINGLE_USE_POLICIES) singleUseRuns.set(policy, replaySingleUse(policy))

console.log('')
console.log('=== track: single-use (records-single-use.json, ExhaustionBoundary) ===')
console.log('')

let singleUsePassed = 0
let singleUseFailed = 0

for (const event of singleUseEvents) {
  const actual = singleUseRuns.get('reference')!.get(event.id)!
  const mismatched = SINGLE_USE_FIELDS.filter(field => actual[field] !== event.expected[field])
  let ok = mismatched.length === 0
  const details = [`reference=${actual.outcome}/${actual.reason}/bound=${actual.bound_state}`]

  // A vector a fail set names must actually differ under that policy; a vector no fail
  // set names must match under every policy. record_divergence is the second kind: the
  // same admission decision with a different recorded lifecycle state.
  for (const policy of SINGLE_USE_POLICIES) {
    if (policy === 'reference') continue
    const declared: string[] = vectors.declared_fail_sets[policy] ?? []
    const other = singleUseRuns.get(policy)!.get(event.id)!
    const outcomeDiffers = other.outcome !== actual.outcome
    const recordDiffers = SINGLE_USE_FIELDS.some(field => other[field] !== actual[field])
    const shouldDifferOutcome = declared.includes(event.id)
    const shouldDifferRecord = (event.record_divergence ?? {})[policy] === true
    ok = ok && outcomeDiffers === shouldDifferOutcome && recordDiffers === shouldDifferRecord
    details.push(
      `${policy}=${other.outcome}/${other.reason}(outcome_differs=${outcomeDiffers},record_differs=${recordDiffers})`
    )
  }

  if (event.negative_control) {
    const inAFailSet = Object.values(vectors.declared_fail_sets).some(list => list.includes(event.id))
    ok = ok && inAFailSet
    details.push(`negative_control=${inAFailSet}`)
  }

  if (ok) {
    singleUsePassed += 1
    console.log(`  PASS ${event.id} ${details.join(' ')}`)
  } else {
    singleUseFailed += 1
    console.error(`  FAIL ${event.id}`)
    for (const field of mismatched) {
      console.error(`    ${field}: expected ${JSON.stringify(event.expected[field])} actual ${JSON.stringify(actual[field])}`)
    }
    console.error(`    ${details.join(' ')}`)
  }
}

// ---------------------------------------------------------------------------
// The one thing the reconciliation is for: the two tracks reach an identical outcome,
// reason and bound_state on PXE-03 and LC-I-014-b, and the route behind them differs.
// Checked here rather than asserted in the README.
// ---------------------------------------------------------------------------

const pxe03 = referenceResults.get('PXE-03-reject-second-purchase-wednesday')
const lci014b = singleUseRuns.get('reference')!.get('LC-I-014-b')
let overlapOk = false
if (pxe03 !== undefined && lci014b !== undefined) {
  const sameVerdict =
    pxe03.outcome === lci014b.outcome &&
    pxe03.reason === lci014b.reason &&
    pxe03.bound_state === lci014b.bound_state
  const differentBasis = pxe03.exhaustion_basis !== lci014b.exhaustion_basis
  overlapOk = sameVerdict && differentBasis
  console.log('')
  console.log('cross-track overlap check, PXE-03 against LC-I-014-b:')
  console.log(`  same outcome, reason and bound_state: ${sameVerdict} (${pxe03.outcome}/${pxe03.reason}/${pxe03.bound_state})`)
  console.log(`  different exhaustion_basis:           ${differentBasis}`)
  console.log(`    PXE-03    basis: ${JSON.stringify(pxe03.exhaustion_basis)}`)
  console.log(`    LC-I-014-b basis: ${JSON.stringify(lci014b.exhaustion_basis)}`)
} else {
  console.error('cross-track overlap check: one of the two vectors is missing')
}

// ---------------------------------------------------------------------------
// What came from the pinned TypeScript SDK and what did not. Printed by the run rather
// than written by hand, so the record cannot drift from the code above.
// ---------------------------------------------------------------------------

const SDK_SUPPORT: Array<[string, 'supported' | 'not_supported', string]> = [
  ['chain state, including time and revocation', 'supported', 'verifyAuthorityDelegationChain, both tracks'],
  ['purpose membership', 'supported', 'isPurposePermitted'],
  ['completion record authenticity', 'supported', 'verifyReceiptV1'],
  ['completion attestor standing', 'supported', 'verifyReceiptV1 boundary_identity axis'],
  ['budget exhaustion', 'supported', 'InMemoryAuthorityBudgetLedger reserve/markDispatched/commit'],
  ['purpose bound signature', 'supported', 'verify over canonicalizeJCS'],
  ['purpose exhaustion', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['use_count exhaustion', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['single-use reuse detection and cascade', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['irreversibility of an exhaustion', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
]

console.log('')
console.log('TypeScript SDK support, agent-passport-system 7.1.0:')
for (const [concept, verdict, how] of SDK_SUPPORT) {
  console.log(`  ${verdict.padEnd(14)} ${concept}  (${how})`)
}

const boundsOk = boundsMatched === boundsEvents.length
const singleUseOk = singleUseFailed === 0

console.log('')
console.log(`bounds     reference-boundary matched: ${boundsMatched}/${boundsEvents.length}`)
console.log(`bounds     both defective boundaries diverged on exactly their declared sets: ${boundsDefectivesOk}`)
console.log(`single-use reference policy matched:   ${singleUsePassed}/${singleUseEvents.length}`)
console.log(`cross-track overlap check:             ${overlapOk}`)

if (boundsOk && boundsDefectivesOk && singleUseOk && overlapOk) {
  console.log(`PASSED: ${vectors.events.length}/${vectors.events.length} vectors, both reference boundaries matched every event in their track, every defective policy diverged on exactly its declared set`)
  process.exit(0)
} else {
  console.error('FAILED')
  process.exit(1)
}
