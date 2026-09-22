// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference runner for the key-rotation-historical fixture. Exercises
// draft-pidlisnyi-aps-03 section 2.4: a resolver MUST select the key version
// authorized at the artifact's issued_at, not the key current at
// verification time. Every delegation here shares one identifier and one
// verification_method across a rotation from K1 to K2 at rotation_boundary;
// what changes per record is issued_at and which key actually signed it.
//
// Two resolver policies are run against the four determinate vectors
// (KRH-01 through KRH-04), in both directions, the same way
// runtime-authority-denial-continuity checks its N1 and N2 negative
// controls: historical-key-resolution is the positive control and must
// match every vector; current-key-only is a deliberately wrong resolver that
// ignores issued_at and must fail exactly its declared set.
//
// KRH-05 is run separately. It is not scored pass/fail against either
// policy: see README "Known SDK gap".

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyAuthorityDelegationChain } from 'agent-passport-system'

// Not exported at the package's top level (only agent-passport-system's own
// v2/authority-delegation/types.js has it), so this mirrors its shape rather
// than importing it, the same way other fixtures in this suite type resolver
// callbacks that cross the same boundary.
type VerificationKeyResolver = (
  issuer: string,
  verificationMethod: string,
  issuedAt: string
) => string | null | { outcome: 'not_found' | 'ambiguous' | 'malformed' | 'unreachable' | 'unsupported_scheme' }

type Expected = {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failure_code: string | null
  failure_index: number | null
}

type VectorCase = {
  id: string
  description: string
  record: string
  signed_with: 'K1' | 'K2'
  expected?: Expected
  boundary_evidence?: null
  draft_required?: Expected
  known_sdk_gap?: boolean
  known_sdk_gap_reason?: string
  observed?: Expected
}

type PolicySpec = {
  name: string
  description: string
  runs_against: string[]
  expected_fail_ids: string[]
}

type Vectors = {
  profile: string
  description: string
  policies: { historical: PolicySpec; current_key_only: PolicySpec }
  cases: VectorCase[]
}

type Fixture = {
  _placeholder?: boolean
  now: string
  rotation_boundary: string
  verification_method: string
  issuer: string
  keys: { K1: string; K2: string }
  records: Record<string, any>
}

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<Fixture>('delegations.json')
const vectors = readJson<Vectors>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.now !== 'string' ||
  typeof fixture.rotation_boundary !== 'string' ||
  !fixture.keys ||
  typeof fixture.keys.K1 !== 'string' ||
  typeof fixture.keys.K2 !== 'string' ||
  !fixture.records
) {
  console.error(
    'key-rotation-historical delegations.json is still a placeholder. Mint the five ' +
    'root delegations with the SDK before running.'
  )
  process.exit(2)
}

// The correct resolver: pick the key authorized at the record's own
// issued_at against rotation_boundary. Draft lines 313-315: "A resolver MUST
// select the key version authorized at the artifact's issued_at."
function historicalResolver(): VerificationKeyResolver {
  return (_issuer, verificationMethod, issuedAt) => {
    if (verificationMethod !== fixture.verification_method) return { outcome: 'not_found' }
    return issuedAt < fixture.rotation_boundary ? fixture.keys.K1 : fixture.keys.K2
  }
}

// The deliberately wrong resolver: ignores issued_at entirely and always
// answers with the key that is current at verification time. Every vector
// here is verified at fixture.now, which is after rotation_boundary, so
// "current" is always K2. Draft lines 313-315: "selecting the key that is
// current at verification time is insufficient."
function currentKeyOnlyResolver(): VerificationKeyResolver {
  return (_issuer, verificationMethod) => {
    if (verificationMethod !== fixture.verification_method) return { outcome: 'not_found' }
    return fixture.keys.K2
  }
}

function actualFailure(result: any): { code: string | null; index: number | null } {
  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  return {
    code: first?.code ?? null,
    index: typeof first?.index === 'number' ? first.index : null,
  }
}

function matches(result: any, expected: Expected): boolean {
  const failure = actualFailure(result)
  return (
    result.state === expected.state &&
    result.valid === (expected.state === 'valid') &&
    failure.code === expected.failure_code &&
    failure.index === expected.failure_index &&
    (expected.failure_code !== null || (Array.isArray(result.failures) && result.failures.length === 0))
  )
}

function runOne(caseId: string, resolveVerificationKey: VerificationKeyResolver) {
  const vector = vectors.cases.find(c => c.id === caseId)
  if (!vector) throw new Error(`key-rotation-historical unknown case id ${caseId}`)
  const record = fixture.records[vector.record]
  if (!record) throw new Error(`key-rotation-historical unknown record ${vector.record}`)
  return verifyAuthorityDelegationChain([record], {
    now: fixture.now,
    resolveVerificationKey,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
}

function runPolicy(policy: PolicySpec, resolveVerificationKey: VerificationKeyResolver) {
  const observedFailIds: string[] = []
  let matched = 0
  console.log(`policy: ${policy.name}`)
  for (const caseId of policy.runs_against) {
    const vector = vectors.cases.find(c => c.id === caseId)!
    const result = runOne(caseId, resolveVerificationKey)
    const ok = matches(result, vector.expected!)
    if (ok) {
      matched += 1
      console.log(`  MATCH    ${caseId}  state=${result.state}`)
    } else {
      observedFailIds.push(caseId)
      const failure = actualFailure(result)
      console.log(`  MISMATCH ${caseId}`)
      console.log(`             expected: ${JSON.stringify(vector.expected)}`)
      console.log(
        `             actual:   ${JSON.stringify({ state: result.state, valid: result.valid, failure_code: failure.code, failure_index: failure.index })}`
      )
    }
  }
  return { matched, total: policy.runs_against.length, observedFailIds }
}

let ok = true

const historical = runPolicy(vectors.policies.historical, historicalResolver())
if (historical.matched !== historical.total) {
  ok = false
  console.error(`FAIL historical-key-resolution matched ${historical.matched}/${historical.total}, expected all`)
} else {
  console.log(`ok   historical-key-resolution matched all ${historical.total} cases`)
}

const currentOnly = runPolicy(vectors.policies.current_key_only, currentKeyOnlyResolver())
const declaredCurrentOnly = [...vectors.policies.current_key_only.expected_fail_ids].sort()
const observedCurrentOnly = [...currentOnly.observedFailIds].sort()
const currentOnlyMatches = JSON.stringify(declaredCurrentOnly) === JSON.stringify(observedCurrentOnly)
if (!currentOnlyMatches) {
  ok = false
  console.error(`FAIL current-key-only declared fail set ${JSON.stringify(declaredCurrentOnly)}, observed ${JSON.stringify(observedCurrentOnly)}`)
} else {
  console.log(`ok   current-key-only failed exactly the declared set: [${declaredCurrentOnly.join(', ')}]`)
}

// KRH-05: run and record the observed result. Not scored pass/fail: this
// vector documents a gap between draft-03 section 2.4's evidentiary
// requirement and what the reference SDKs' resolver surface can express.
// See README "Known SDK gap".
const gapVector = vectors.cases.find(c => c.id === 'KRH-05-indeterminate-boundary-no-evidence')!
const gapResult = runOne(gapVector.id, historicalResolver())
const gapFailure = actualFailure(gapResult)
const gapObserved: Expected = {
  state: gapResult.state,
  failure_code: gapFailure.code,
  failure_index: gapFailure.index,
}
const gapObservedMatchesRecorded = JSON.stringify(gapObserved) === JSON.stringify(gapVector.observed)
const gapDivergesFromDraft = JSON.stringify(gapObserved) !== JSON.stringify(gapVector.draft_required)
console.log(`gap  ${gapVector.id}  observed=${JSON.stringify(gapObserved)} draft_required=${JSON.stringify(gapVector.draft_required)}`)
if (!gapVector.known_sdk_gap || !gapObservedMatchesRecorded || !gapDivergesFromDraft) {
  ok = false
  console.error(
    'FAIL KRH-05 gap bookkeeping: expected known_sdk_gap true, observed result matching the recorded ' +
    'observed field, and observed diverging from draft_required'
  )
} else {
  console.log('ok   KRH-05 observed result matches the recorded known_sdk_gap, and diverges from draft_required as documented')
}

console.log(ok ? 'PASSED: historical-key-resolution matched every vector, current-key-only failed exactly the declared set' : 'FAILED')
process.exit(ok ? 0 : 1)
