// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference runner for the key-rotation-historical fixture. Exercises
// draft-pidlisnyi-aps-03 section 2.4: a resolver MUST select the key version
// authorized at the artifact's issued_at, not the key current at
// verification time. Every delegation here shares one identifier and one
// verification_method across a rotation from K1 to K2 at rotation_boundary;
// what changes per record is issued_at and which key actually signed it.
//
// Three resolver policies are run against all five vectors, in both
// directions, the same way runtime-authority-denial-continuity checks its N1
// and N2 negative controls: historical-key-resolution is the positive
// control and must match every vector. current-key-only and claim-trusting
// are deliberately wrong resolvers, each declared to fail exactly its own
// set.
//
// KRH-05 depends on the same issued_at-before-boundary, signed-with-K1
// relationship as KRH-01, with one difference: no boundary_evidence. Per
// draft-03 section 2.4's second paragraph (lines 317-323), issued_at is only
// an issuer claim, and without evidence placing signing before the boundary
// the key-authority result is indeterminate, even though the signature is
// cryptographically valid. historical-key-resolution reports that; the
// claim-trusting resolver below, which selects a key from the issued_at
// claim alone and never consults evidence, does not, and that is exactly
// the one vector it is declared to fail.

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
  expected: Expected
  boundary_evidence: 'present' | 'absent' | 'not_applicable'
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
  policies: { historical: PolicySpec; current_key_only: PolicySpec; claim_trusting: PolicySpec }
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
  boundary_evidence: Record<string, unknown>
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
  !fixture.records ||
  !fixture.boundary_evidence
) {
  console.error(
    'key-rotation-historical delegations.json is still a placeholder. Mint the five ' +
    'root delegations with the SDK before running.'
  )
  process.exit(2)
}

// The correct resolver: pick the key authorized at the record's own
// issued_at against rotation_boundary (draft lines 313-315: "A resolver MUST
// select the key version authorized at the artifact's issued_at"), and for
// K1's window additionally require boundary_evidence before trusting a
// before-boundary issued_at claim (draft lines 317-323: without evidence
// placing signing before the boundary, "the key-authority result is
// indeterminate, even when the artifact signature is cryptographically
// valid"). K2's window is not gated: K2 is the identifier's current key with
// no retirement boundary ahead of it, so no claim about issued_at relative
// to a closing window needs corroborating.
//
// Section 2.5 lines 360-364 fixes the resolver's outcome vocabulary at five
// entries (not_found, ambiguous, malformed, unreachable, unsupported_scheme)
// plus the unspecified case a raw null produces, and none of the five means
// "the claimed signing time could not be established." 'ambiguous' is the
// least-bad existing fit used here: which key epoch governs is exactly what
// is unresolved. See README "Findings".
function historicalResolver(): VerificationKeyResolver {
  return (_issuer, verificationMethod, issuedAt) => {
    if (verificationMethod !== fixture.verification_method) return { outcome: 'not_found' }
    if (issuedAt >= fixture.rotation_boundary) return fixture.keys.K2
    return fixture.boundary_evidence[issuedAt] ? fixture.keys.K1 : { outcome: 'ambiguous' }
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

// The other deliberately wrong resolver: performs the same before/after
// selection historicalResolver does, but never consults boundary_evidence,
// trusting the issued_at claim on its own. This is what historicalResolver
// used to do before this correction, and it is exactly the gap draft-03
// section 2.4's second paragraph identifies: an issuer claim about signing
// time, accepted with no evidence behind it.
function claimTrustingResolver(): VerificationKeyResolver {
  return (_issuer, verificationMethod, issuedAt) => {
    if (verificationMethod !== fixture.verification_method) return { outcome: 'not_found' }
    return issuedAt < fixture.rotation_boundary ? fixture.keys.K1 : fixture.keys.K2
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

function runNegativeControl(policy: PolicySpec, resolveVerificationKey: VerificationKeyResolver) {
  const observed = runPolicy(policy, resolveVerificationKey)
  const declared = [...policy.expected_fail_ids].sort()
  const actual = [...observed.observedFailIds].sort()
  const setsMatch = JSON.stringify(declared) === JSON.stringify(actual)
  if (!setsMatch) {
    ok = false
    console.error(`FAIL ${policy.name} declared fail set ${JSON.stringify(declared)}, observed ${JSON.stringify(actual)}`)
  } else {
    console.log(`ok   ${policy.name} failed exactly the declared set: [${declared.join(', ')}]`)
  }
}

runNegativeControl(vectors.policies.current_key_only, currentKeyOnlyResolver())
runNegativeControl(vectors.policies.claim_trusting, claimTrustingResolver())

console.log(ok ? 'PASSED: historical-key-resolution matched every vector, both negative controls failed exactly their declared sets' : 'FAILED')
process.exit(ok ? 0 : 1)
