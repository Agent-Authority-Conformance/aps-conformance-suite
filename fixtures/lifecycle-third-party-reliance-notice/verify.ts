// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the lifecycle-third-party-reliance-notice vectors against harness.ts's reference
// boundary and its four declared defective negative controls, over chain.json's real,
// agent-passport-system 7.1.0-signed delegations, draft-03 revocations, notice records and
// prior-dealing register.
//
// This is evidence about this family's own reference boundary for notice, and an SDK result
// for every chain, revocation-resolution and signature check. It establishes nothing about
// whether any outside party's reliance is protected. See README "Does not claim".
//
// No network. Exit 0 when the reference boundary matches every vector, the structural checks
// hold, and each defective boundary diverges on exactly its declared set.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1 } from 'agent-passport-system'

import {
  AuthorityBoundary,
  makeNewestWinsBoundary,
  makeNoticeWithoutStandingBoundary,
  makePublicationCoversEveryoneBoundary,
  makeReferenceBoundary,
  makeSingleNoticeBooleanBoundary,
  type AuthorityRevocationRecord,
  type NoticeRecord,
  type Outcome,
  type PresentRequest,
  type PriorDealingRegister,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

interface ChainFixture {
  verification_keys: Record<string, string>
  counterparties: Record<string, string>
  timeline: Record<string, string>
  signature_domains: { notice_record: string; prior_dealing_register: string }
  chains: Record<string, AuthorityDelegationV1[]>
  revocations: Record<string, AuthorityRevocationRecord>
  notices: Record<string, NoticeRecord>
  prior_dealing_register: PriorDealingRegister
  mint_time_sdk_observations: Record<string, unknown>
}

interface ExpectedOutcome {
  authority_verdict: string
  authority_reason: string
  chain_state: string
  chain_failure_code: string | null
  notice_state: string
  notice_basis: string | null
  notice_reason: string
  held_grant_count: number
}

interface Vector {
  id: string
  case: string
  tests: string
  differs_from: string | null
  chain: string
  held: string
  revocation_set: string
  notice_set: string
  counterparty: string
  now: string
  expected: ExpectedOutcome
}

interface Vectors {
  profile: string
  status_label: string
  description: string
  revocation_sets: Record<string, string[]>
  notice_sets: Record<string, string[]>
  held_sets: Record<string, string[]>
  declared_fail_sets: Record<string, string[]>
  vectors: Vector[]
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

function fail(message: string): never {
  console.error(`lifecycle-third-party-reliance-notice: ${message}`)
  process.exit(2)
}

const sharedOptions = {
  verificationKeys: fixture.verification_keys,
  signatureDomains: fixture.signature_domains,
  trackedDelegationIds: Object.values(fixture.chains).flat().map((record) => record.delegation_id),
}

function toRequest(vector: Vector): PresentRequest {
  const chain = fixture.chains[vector.chain]
  if (chain === undefined) fail(`${vector.id} names an unknown chain "${vector.chain}"`)
  const heldNames = vectors.held_sets[vector.held]
  if (heldNames === undefined) fail(`${vector.id} names an unknown held set "${vector.held}"`)
  const revocationNames = vectors.revocation_sets[vector.revocation_set]
  if (revocationNames === undefined) fail(`${vector.id} names an unknown revocation set "${vector.revocation_set}"`)
  const noticeNames = vectors.notice_sets[vector.notice_set]
  if (noticeNames === undefined) fail(`${vector.id} names an unknown notice set "${vector.notice_set}"`)
  const counterparty = fixture.counterparties[vector.counterparty]
  if (counterparty === undefined) fail(`${vector.id} names an unknown counterparty "${vector.counterparty}"`)
  const now = fixture.timeline[vector.now]
  if (now === undefined) fail(`${vector.id} names an unknown timeline point "${vector.now}"`)

  return {
    label: vector.id,
    chain,
    held_chains: heldNames.map((name) => {
      const held = fixture.chains[name]
      if (held === undefined) fail(`${vector.id} names an unknown held chain "${name}"`)
      return held
    }),
    revocations: revocationNames.map((name) => {
      const revocation = fixture.revocations[name]
      if (revocation === undefined) fail(`${vector.id} names an unknown revocation "${name}"`)
      return revocation
    }),
    notices: noticeNames.map((name) => {
      const notice = fixture.notices[name]
      if (notice === undefined) fail(`${vector.id} names an unknown notice "${name}"`)
      return notice
    }),
    prior_dealing_register: fixture.prior_dealing_register,
    counterparty,
    now,
  }
}

function matches(actual: Outcome, expected: ExpectedOutcome): boolean {
  return (
    actual.authority_verdict === expected.authority_verdict &&
    actual.authority_reason === expected.authority_reason &&
    actual.chain_state === expected.chain_state &&
    actual.chain_failure_code === expected.chain_failure_code &&
    actual.notice_state === expected.notice_state &&
    actual.notice_basis === expected.notice_basis &&
    actual.notice_reason === expected.notice_reason &&
    actual.held_grant_count === expected.held_grant_count
  )
}

function line(actual: Outcome): string {
  return (
    `authority="${actual.authority_verdict}"/${actual.authority_reason} chain=${actual.chain_state}/${actual.chain_failure_code}` +
    ` notice="${actual.notice_state}"/${actual.notice_reason} basis=${actual.notice_basis} counterparty=${actual.counterparty} held=${actual.held_grant_count}`
  )
}

function runBoundary(boundary: AuthorityBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  // Every vector is a fresh evaluation against its own status source. Nothing carries
  // between vectors: this family's state lives in the records, never in the boundary.
  for (const vector of vectors.vectors) results.set(vector.id, boundary.handle(toRequest(vector)))
  return results
}

const VERDICT_VOCABULARY = new Set(['valid', 'invalid', 'suspended', 'restricted', 'not established', 'not yet effective'])
const NOTICE_VOCABULARY = new Set(['established', 'not established'])

console.log(`lifecycle-third-party-reliance-notice: ${vectors.vectors.length} vectors, status label ${vectors.status_label}`)
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
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

console.log('')
console.log('structural checks')
let structuralOk = true
function check(label: string, ok: boolean, detail: string): void {
  if (!ok) structuralOk = false
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}: ${detail}`)
}

const verdicts = new Set([...referenceResults.values()].map((o) => o.authority_verdict))
check('authority verdict vocabulary', [...verdicts].every((v) => VERDICT_VOCABULARY.has(v)), `observed [${[...verdicts].sort().join(', ')}]`)
const noticeStates = new Set([...referenceResults.values()].map((o) => o.notice_state))
check('notice state vocabulary', [...noticeStates].every((v) => NOTICE_VOCABULARY.has(v)), `observed [${[...noticeStates].sort().join(', ')}]`)

// The load-bearing structural fact of this family: neither answer is a function of the other
// across the vector set. At least one authority verdict has to appear with both notice
// states, and at least one notice state with more than one authority verdict, or the two
// fields are interchangeable and the family has proved nothing.
const noticeByVerdict = new Map<string, Set<string>>()
const verdictByNotice = new Map<string, Set<string>>()
for (const outcome of referenceResults.values()) {
  if (!noticeByVerdict.has(outcome.authority_verdict)) noticeByVerdict.set(outcome.authority_verdict, new Set())
  noticeByVerdict.get(outcome.authority_verdict)!.add(outcome.notice_state)
  if (!verdictByNotice.has(outcome.notice_state)) verdictByNotice.set(outcome.notice_state, new Set())
  verdictByNotice.get(outcome.notice_state)!.add(outcome.authority_verdict)
}
const verdictWithBothNotices = [...noticeByVerdict.entries()].filter(([, states]) => states.size > 1).map(([v]) => v)
const noticeWithSeveralVerdicts = [...verdictByNotice.entries()].filter(([, vs]) => vs.size > 1).map(([n]) => n)
check(
  'notice state is not a function of the authority verdict',
  verdictWithBothNotices.length > 0,
  verdictWithBothNotices.length > 0 ? `verdict(s) appearing with both notice states: ${verdictWithBothNotices.map((v) => `"${v}"`).join(', ')}` : 'every verdict maps to one notice state',
)
check(
  'authority verdict is not a function of the notice state',
  noticeWithSeveralVerdicts.length > 0,
  noticeWithSeveralVerdicts.length > 0 ? `notice state(s) appearing with several verdicts: ${noticeWithSeveralVerdicts.map((n) => `"${n}"`).join(', ')}` : 'every notice state maps to one verdict',
)

// The publication record names no recipient at all, which is what makes the two-tier rule a
// question about the register rather than about the record's own contents.
check(
  'the publication record names no counterparty',
  fixture.notices.publication_all.counterparty === null && fixture.notices.publication_all.mode === 'publication',
  `mode=${fixture.notices.publication_all.mode} counterparty=${JSON.stringify(fixture.notices.publication_all.counterparty)}`,
)

// The newer grant is a genuinely different, later-issued, broader grant from the same issuer
// to the same subject, so the newest-wins control has a real target to misfire on.
const older = fixture.chains.older[0]
const newer = fixture.chains.newer[0]
check(
  'the newer grant is a distinct, later, broader grant from the same issuer to the same subject',
  older.delegation_id !== newer.delegation_id && older.issuer === newer.issuer && older.subject === newer.subject && newer.issued_at > older.issued_at,
  `older issued_at ${older.issued_at}, newer issued_at ${newer.issued_at}, newer grants ${JSON.stringify(newer.authority.scope.grants)}`,
)

let allDefectivesOk = true
for (const [name, factory] of [
  ['defective-boundary-single-notice-boolean', makeSingleNoticeBooleanBoundary],
  ['defective-boundary-publication-covers-everyone', makePublicationCoversEveryoneBoundary],
  ['defective-boundary-notice-without-standing', makeNoticeWithoutStandingBoundary],
  ['defective-boundary-newest-wins', makeNewestWinsBoundary],
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
  // The publication control is the one a naive checker passes: it reaches the same authority
  // verdict as the reference boundary on every vector and differs only on notice.
  const sameAuthorityEverywhere = vectors.vectors.every((vector) => {
    const actual = results.get(vector.id)!
    const reference = referenceResults.get(vector.id)!
    return actual.authority_verdict === reference.authority_verdict && actual.authority_reason === reference.authority_reason
  })
  console.log(`  ${boundary.name}: ${declared.length} declared, diverged on exactly its declared set: ${ok}, reaches the reference authority verdict on every vector: ${sameAuthorityEverywhere}`)
  if (!ok) allDefectivesOk = false
}

const SDK_SUPPORT: Array<[string, 'supported' | 'not_supported', string]> = [
  ['chain state, including time and root trust', 'supported', 'verifyAuthorityDelegationChain'],
  ['direct revocation by the delegation issuer', 'supported', 'issueAuthorityRevocation, verifyAuthorityRevocation, recordAuthorityRevocation'],
  ['revocation resolution, including unknown for a record that does not verify', 'supported', 'createAuthorityRevocationResolver over InMemoryAuthorityRevocationStore'],
  ['notice record and register signatures', 'supported', 'verify over canonicalizeJCS'],
  ['revocation by a party other than the issuer', 'not_supported', 'issueAuthorityRevocation refuses with REVOKER_NOT_ISSUER, see chain.json mint_time_sdk_observations'],
  ['notice record', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by this fixture'],
  ['notice state for a named counterparty', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
  ['prior-dealing register', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by this fixture'],
  ['two-tier notice sufficiency', 'not_supported', 'no export in agent-passport-system 7.1.0, supplied by harness.ts'],
]

console.log('')
console.log('TypeScript SDK support, agent-passport-system 7.1.0:')
for (const [concept, verdict, how] of SDK_SUPPORT) console.log(`  ${verdict.padEnd(14)} ${concept}  (${how})`)

console.log('')
console.log('recorded SDK observations from mint time:')
for (const [key, value] of Object.entries(fixture.mint_time_sdk_observations)) console.log(`  ${key}: ${JSON.stringify(value)}`)

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
