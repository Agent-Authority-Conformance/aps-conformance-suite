// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the arap-binding candidate family.
//
// Replays every vector in vectors.json against the reference harness
// (harness.ts) and, where a negative control is declared, against a
// deliberately defective implementation:
//
//   Part D (denial binding, ARS)     correct: CORRECT_DENIAL_VERIFIER
//                                     control: BYTE_COMPARE_ARS_VERIFIER
//   Part A (approval, PDP)           correct: CORRECT_APPROVAL_VERIFIER
//                                     control: TRUSTING_PDP_APPROVAL_VERIFIER
//   Part P (PEP fallback)            a pure function, no control declared
//
// `correct` must match every non-indeterminate vector. Each control must fail
// exactly its declared set, checked in both directions: an undeclared failure
// appearing and a declared failure quietly starting to pass are both loud.
//
// D12 is a two-reading finding case, not an accept/reject vector: it computes
// both readings of the hash object the text leaves ambiguous, asserts they
// diverge, and is excluded from every tally.
//
// Run: npx tsx fixtures/arap-binding/verify.ts
// Exit 0 when every half holds, 1 otherwise.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  ApprovalLedger,
  BYTE_COMPARE_ARS_VERIFIER,
  CORRECT_APPROVAL_VERIFIER,
  CORRECT_DENIAL_VERIFIER,
  JwksRegistry,
  PolicyStub,
  SeenJtiLedger,
  TRUSTING_PDP_APPROVAL_VERIFIER,
  computeBindingHash,
  keyPairFromSeed,
  resolvePepNextAction,
  seedHex,
  signJWS,
  type ApprovalOutcome,
  type ApprovalRecord,
  type ApprovalVerifier,
  type AuthzenAction,
  type AuthzenContext,
  type AuthzenResource,
  type AuthzenSubject,
  type BindingTokenClaims,
  type CurrentEvaluation,
  type DenialBindingOutcome,
  type DenialBindingVerifier,
  type NextAction,
  type PresentedApproval,
  type Submission,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Vector schema
// ---------------------------------------------------------------------------

interface DenialClaimsSpec {
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context?: AuthzenContext
  iat: string
  exp: string
  denial_expires_at: string | null
  aud: string | null
  jti: string
}

interface DenialSubmissionSpec {
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context?: AuthzenContext
  denial_expires_at: string
}

interface DenialCase {
  id: string
  letter: string
  label: string
  section: string
  form: 'hashed' | 'inline'
  binding_context_members: string[] | null
  claims: DenialClaimsSpec
  submission: DenialSubmissionSpec
  now: string
  expected_outcome: DenialBindingOutcome
}

interface DenialFindingCase {
  id: string
  label: string
  section: string
  status: 'indeterminate'
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  note: string
}

interface ApprovalRecordSpec {
  id: string
  taskId: string
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  boundContextMembers: string[]
  approvedAt: string
  approvedUntil: string
  status: ApprovalRecord['status']
}

interface ApprovalPresentedSpec {
  id: string
  include_state: boolean
  state_aud: string
  state_approval_id: string
}

interface ApprovalEvaluationSpec {
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  now: string
  expected_outcome: ApprovalOutcome
  expected_next_action: NextAction | null
}

interface ApprovalCase {
  id: string
  label: string
  section: string
  note?: string
  record: ApprovalRecordSpec
  presented: ApprovalPresentedSpec
  policy_disable_subject: string | null
  evaluations: ApprovalEvaluationSpec[]
}

interface PepCase {
  id: string
  label: string
  section: string
  input: { next_action?: string; reason?: string; access_request_present: boolean }
  expected: NextAction
}

interface Vectors {
  family: string
  source: { pull_request: number; head_sha: string; file: string; kind: string }
  keys: {
    pdp_binding_seed_label: string
    ars_state_seed_label: string
    ars_identifier: string
    pdp_id: string
    other_pdp_id: string
    ars_state_iss: string
    ars_state_kid: string
  }
  denial_binding_cases: DenialCase[]
  denial_binding_finding_case: DenialFindingCase
  approval_cases: ApprovalCase[]
  pep_fallback_cases: PepCase[]
  negative_controls: {
    byte_compare_ars: { declared_to_fail: string[] }
    trusting_pdp: { declared_to_fail: string[] }
  }
}

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors

const pdpKeys = keyPairFromSeed(seedHex(vectors.keys.pdp_binding_seed_label))
const arsStateKeys = keyPairFromSeed(seedHex(vectors.keys.ars_state_seed_label))

const toEpochSeconds = (iso: string): number => Math.floor(Date.parse(iso) / 1000)

function pickMembers(context: AuthzenContext, members: readonly string[]): AuthzenContext {
  const out: AuthzenContext = {}
  for (const member of members) if (member in context) out[member] = context[member]
  return out
}

// ---------------------------------------------------------------------------
// Part D: denial binding
// ---------------------------------------------------------------------------

function buildDenialCompactJWS(testCase: DenialCase): string {
  const members = testCase.binding_context_members ?? undefined
  const payload: Record<string, unknown> = {
    iss: vectors.keys.pdp_id,
    iat: toEpochSeconds(testCase.claims.iat),
    exp: toEpochSeconds(testCase.claims.exp),
    jti: testCase.claims.jti,
    form: testCase.form,
  }
  if (testCase.claims.aud !== null) payload.aud = testCase.claims.aud
  if (testCase.claims.denial_expires_at !== null) payload.denial_expires_at = testCase.claims.denial_expires_at
  if (members !== undefined) payload.bindingContextMembers = members

  if (testCase.form === 'inline') {
    payload.subject = testCase.claims.subject
    payload.resource = testCase.claims.resource
    payload.action = testCase.claims.action
    if (members !== undefined) payload.context = pickMembers(testCase.claims.context ?? {}, members)
  } else {
    payload.binding_hash = computeBindingHash(
      testCase.claims.subject,
      testCase.claims.resource,
      testCase.claims.action,
      testCase.claims.context ?? {},
      members,
      true,
    )
  }

  return signJWS({ alg: 'EdDSA', kid: 'pdp-binding-key-1' }, payload, pdpKeys.privateKey)
}

function buildDenialSubmission(testCase: DenialCase): Submission {
  return {
    subject: testCase.submission.subject,
    resource: testCase.submission.resource,
    action: testCase.submission.action,
    context: testCase.submission.context ?? {},
    denialExpiresAt: testCase.submission.denial_expires_at,
  }
}

function runDenialCase(testCase: DenialCase, verifier: DenialBindingVerifier): DenialBindingOutcome {
  const compactJWS = buildDenialCompactJWS(testCase)
  const submission = buildDenialSubmission(testCase)
  const nowMs = Date.parse(testCase.now)
  return verifier.verify(compactJWS, submission, vectors.keys.ars_identifier, pdpKeys.publicKey, nowMs, new SeenJtiLedger())
}

function runDenialImplementation(verifier: DenialBindingVerifier): { id: string; ok: boolean; observed: DenialBindingOutcome; expected: DenialBindingOutcome }[] {
  console.log(`Part D, implementation: ${verifier.name}`)
  const results = vectors.denial_binding_cases.map(testCase => {
    const observed = runDenialCase(testCase, verifier)
    const ok = observed === testCase.expected_outcome
    console.log(`  ${ok ? 'MATCH   ' : 'MISMATCH'} ${testCase.id}  (${testCase.label})${ok ? '' : `  expected ${testCase.expected_outcome}, observed ${observed}`}`)
    return { id: testCase.id, ok, observed, expected: testCase.expected_outcome }
  })
  console.log()
  return results
}

function runDenialFindingCase(): boolean {
  const finding = vectors.denial_binding_finding_case
  const digestContextOmitted = computeBindingHash(finding.subject, finding.resource, finding.action, finding.context, undefined, true)
  const digestContextEmptyObject = computeBindingHash(finding.subject, finding.resource, finding.action, finding.context, undefined, false)
  const diverge = digestContextOmitted !== digestContextEmptyObject
  console.log(`Part D, finding case ${finding.id}: ${finding.label}`)
  console.log(`  reading A (context key omitted):    ${digestContextOmitted}`)
  console.log(`  reading B (context key is {}):       ${digestContextEmptyObject}`)
  console.log(`  ${diverge ? 'ok  ' : 'FAIL'} the two readings ${diverge ? 'diverge, as expected' : 'produced the same digest, which would collapse the finding'}`)
  console.log(`  status: indeterminate, excluded from both tallies`)
  console.log()
  return diverge
}

// ---------------------------------------------------------------------------
// Part A: approval verification
// ---------------------------------------------------------------------------

function buildApprovalStateJWS(testCase: ApprovalCase): string {
  const record = testCase.record
  const payload = {
    iss: vectors.keys.ars_state_iss,
    aud: testCase.presented.state_aud,
    approval_id: testCase.presented.state_approval_id,
    taskId: record.taskId,
    subject: record.subject,
    resource: record.resource,
    action: record.action,
    context: record.context,
    boundContextMembers: record.boundContextMembers,
    approvedAt: record.approvedAt,
    approvedUntil: record.approvedUntil,
  }
  return signJWS({ alg: 'EdDSA', kid: vectors.keys.ars_state_kid }, payload, arsStateKeys.privateKey)
}

function runApprovalCase(
  testCase: ApprovalCase,
  verifier: ApprovalVerifier,
): { evaluationIndex: number; ok: boolean; observedOutcome: ApprovalOutcome; observedNextAction: NextAction | undefined; expectedOutcome: ApprovalOutcome; expectedNextAction: NextAction | null }[] {
  const ledger = new ApprovalLedger()
  ledger.register({
    id: testCase.record.id,
    taskId: testCase.record.taskId,
    subject: testCase.record.subject,
    resource: testCase.record.resource,
    action: testCase.record.action,
    context: testCase.record.context,
    boundContextMembers: testCase.record.boundContextMembers,
    approvedAt: testCase.record.approvedAt,
    approvedUntil: testCase.record.approvedUntil,
    status: testCase.record.status,
  })

  const jwks = new JwksRegistry()
  jwks.publish(vectors.keys.ars_state_iss, vectors.keys.ars_state_kid, arsStateKeys.publicKey)

  const policy = new PolicyStub()
  if (testCase.policy_disable_subject !== null) policy.disableSubject(testCase.policy_disable_subject)

  const presented: PresentedApproval = {
    id: testCase.presented.id,
    state: testCase.presented.include_state ? buildApprovalStateJWS(testCase) : undefined,
  }

  return testCase.evaluations.map((evaluation, evaluationIndex) => {
    const currentEvaluation: CurrentEvaluation = {
      subject: evaluation.subject,
      resource: evaluation.resource,
      action: evaluation.action,
      context: evaluation.context,
    }
    const nowMs = Date.parse(evaluation.now)
    const result = verifier.verify(presented, currentEvaluation, nowMs, vectors.keys.pdp_id, ledger, jwks, policy)
    const ok = result.outcome === evaluation.expected_outcome && (result.nextAction ?? null) === evaluation.expected_next_action
    return {
      evaluationIndex,
      ok,
      observedOutcome: result.outcome,
      observedNextAction: result.nextAction,
      expectedOutcome: evaluation.expected_outcome,
      expectedNextAction: evaluation.expected_next_action,
    }
  })
}

function runApprovalImplementation(verifier: ApprovalVerifier): { id: string; ok: boolean }[] {
  console.log(`Part A, implementation: ${verifier.name}`)
  const results = vectors.approval_cases.map(testCase => {
    const evaluationResults = runApprovalCase(testCase, verifier)
    const ok = evaluationResults.every(r => r.ok)
    const suffix = evaluationResults.length > 1 ? ` (${evaluationResults.length} evaluations)` : ''
    if (ok) {
      console.log(`  MATCH    ${testCase.id}  (${testCase.label})${suffix}`)
    } else {
      console.log(`  MISMATCH ${testCase.id}  (${testCase.label})${suffix}`)
      for (const r of evaluationResults) {
        if (!r.ok) {
          console.log(
            `             evaluation ${r.evaluationIndex}: expected ${r.expectedOutcome}/${String(r.expectedNextAction)}, observed ${r.observedOutcome}/${String(r.observedNextAction ?? null)}`,
          )
        }
      }
    }
    return { id: testCase.id, ok }
  })
  console.log()
  return results
}

// ---------------------------------------------------------------------------
// Part P: PEP fallback
// ---------------------------------------------------------------------------

function runPepCases(): { id: string; ok: boolean }[] {
  console.log('Part P, PEP next-action fallback (no negative control declared)')
  const results = vectors.pep_fallback_cases.map(testCase => {
    const observed = resolvePepNextAction({
      nextAction: testCase.input.next_action,
      reason: testCase.input.reason,
      accessRequestPresent: testCase.input.access_request_present,
    })
    const ok = observed === testCase.expected
    console.log(`  ${ok ? 'MATCH   ' : 'MISMATCH'} ${testCase.id}  (${testCase.label})${ok ? '' : `  expected ${testCase.expected}, observed ${observed}`}`)
    return { id: testCase.id, ok }
  })
  console.log()
  return results
}

// ---------------------------------------------------------------------------
// Run everything
// ---------------------------------------------------------------------------

console.log(`arap-binding: ${vectors.denial_binding_cases.length} Part D cases, ${vectors.approval_cases.length} Part A cases, ${vectors.pep_fallback_cases.length} Part P cases, 1 Part D finding case`)
console.log(`source: ${vectors.source.kind}, ${vectors.source.file} at ${vectors.source.head_sha} (openid/authzen PR #${vectors.source.pull_request})`)
console.log()

let failed = 0

const denialCorrect = runDenialImplementation(CORRECT_DENIAL_VERIFIER)
const denialByteCompare = runDenialImplementation(BYTE_COMPARE_ARS_VERIFIER)
const findingDiverges = runDenialFindingCase()
if (!findingDiverges) failed += 1

const approvalCorrect = runApprovalImplementation(CORRECT_APPROVAL_VERIFIER)
const approvalTrusting = runApprovalImplementation(TRUSTING_PDP_APPROVAL_VERIFIER)

const pepResults = runPepCases()

// Half 1: correct matches everything (Part D, Part A, Part P).
const denialCorrectMismatches = denialCorrect.filter(r => !r.ok).map(r => r.id)
const approvalCorrectMismatches = approvalCorrect.filter(r => !r.ok).map(r => r.id)
const pepMismatches = pepResults.filter(r => !r.ok).map(r => r.id)

if (denialCorrectMismatches.length > 0) {
  failed += 1
  console.log(`FAIL correct denial-binding verifier did not match: [${denialCorrectMismatches.join(', ')}]`)
} else {
  console.log(`ok   correct denial-binding verifier matched all ${vectors.denial_binding_cases.length} Part D cases`)
}
if (approvalCorrectMismatches.length > 0) {
  failed += 1
  console.log(`FAIL correct approval verifier did not match: [${approvalCorrectMismatches.join(', ')}]`)
} else {
  console.log(`ok   correct approval verifier matched all ${vectors.approval_cases.length} Part A cases`)
}
if (pepMismatches.length > 0) {
  failed += 1
  console.log(`FAIL PEP fallback resolver did not match: [${pepMismatches.join(', ')}]`)
} else {
  console.log(`ok   PEP fallback resolver matched all ${vectors.pep_fallback_cases.length} Part P cases`)
}

// Half 2: each control fails exactly its declared set, in both directions.
function checkControl(name: string, results: { id: string; ok: boolean }[], declaredToFail: string[]): void {
  const observedToFail = results.filter(r => !r.ok).map(r => r.id)
  const undeclared = observedToFail.filter(id => !declaredToFail.includes(id))
  const stoppedFailing = declaredToFail.filter(id => !observedToFail.includes(id))
  if (undeclared.length > 0) {
    failed += 1
    console.log(`FAIL ${name} failed cases the fixture does not declare: [${undeclared.join(', ')}]`)
  }
  if (stoppedFailing.length > 0) {
    failed += 1
    console.log(`FAIL ${name} no longer fails declared cases: [${stoppedFailing.join(', ')}]`)
  }
  if (undeclared.length === 0 && stoppedFailing.length === 0) {
    console.log(`ok   ${name} failed exactly the declared set: [${declaredToFail.join(', ')}]`)
  }
}

checkControl('byte-compare-ars', denialByteCompare, vectors.negative_controls.byte_compare_ars.declared_to_fail)
checkControl('trusting-pdp', approvalTrusting, vectors.negative_controls.trusting_pdp.declared_to_fail)

console.log()
if (failed > 0) {
  console.log('FAILED')
  process.exit(1)
}
console.log('PASSED: correct matched every non-indeterminate vector, each control failed exactly its declared set')
process.exit(0)
