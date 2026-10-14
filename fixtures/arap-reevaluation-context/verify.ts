// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the arap-reevaluation-context candidate family (openid/authzen PR #745).
//
// Each case builds a re-evaluation request with the PEP the case names, checks
// the member-set comparison against an ordinary evaluation of the same
// operation, and, where a request is sent, runs the reference PDP verifier
// from fixtures/arap-binding. Seven negative controls must fail exactly their
// declared sets, in both directions: a PDP that skips absent bound members,
// the approval-only PEP swapped into every ordinary-rules case, four PEPs that
// drop or alter the approval, and a PEP whose first request differs from its
// later ones. Each run works on its own copies of the fixture. The ordinary
// construction is built before the PEP runs, the PEP is called once, and the
// member-set test and the PDP both see that one emitted request. The emitted
// approval is compared with a pristine copy of the one the PEP was given (822)
// and is what the PDP receives.
//
// Run: npx tsx fixtures/arap-reevaluation-context/verify.ts
// Exit 0 when every half holds, 1 otherwise.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  ApprovalLedger,
  CORRECT_APPROVAL_VERIFIER,
  JwksRegistry,
  PolicyStub,
  structurallyEqual,
  type ApprovalRecord,
  type ApprovalVerifier,
  type AuthzenContext,
} from '../arap-binding/harness.js'
import {
  APPROVAL_ONLY_PEP,
  CHANGED_ID_PEP,
  CHANGED_TIMESTAMP_PEP,
  DROP_APPROVAL_PEP,
  IN_PLACE_APPROVAL_PEP,
  ORDINARY_RULES_PEP,
  buildOrdinaryContext,
  makeAlternatingPep,
  memberSetsMatch,
  type BuildResult,
  presentOnlyVerifier,
  type ContextRule,
  type Inputs,
  type Pep,
} from './harness.js'

interface Expected {
  build: 'request' | 'stop'
  outcome: string | null
  next_action: string | null
  member_sets_match: boolean
  time?: string
  unreachable?: string
}
interface Case {
  id: string
  label: string
  pep: 'ordinary-rules' | 'approval-only'
  rules: ContextRule[]
  inputs: Inputs
  record: ApprovalRecord
  approval: Record<string, unknown>
  now: string
  expected: Expected
}
interface Vectors {
  pdp_id: string
  cases: Case[]
  negative_controls: Record<string, { declared_to_fail: string[] }>
}

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors
const PEPS: Record<string, Pep> = { 'ordinary-rules': ORDINARY_RULES_PEP, 'approval-only': APPROVAL_ONLY_PEP }

function run(c: Case, pep: Pep, verifier: (c: Case) => ApprovalVerifier): { ok: boolean; detail: string } {
  // The runner keeps pristine copies. The PEP gets its own copies, so nothing it
  // does to them can change what it is checked against. The ordinary
  // construction is built before the PEP runs, and the PEP is called once.
  const pristineApproval = structuredClone(c.approval)
  const ordinary = buildOrdinaryContext(structuredClone(c.rules), structuredClone(c.inputs))
  let built: BuildResult
  try {
    built = pep.buildReevaluation(structuredClone(c.rules), structuredClone(c.inputs), structuredClone(c.approval))
  } catch (e) {
    return { ok: false, detail: `PEP threw: ${(e as Error).message}` }
  }
  const members = memberSetsMatch(ordinary, built)
  const problems: string[] = []
  if (built.kind !== c.expected.build) problems.push(`build ${built.kind}, expected ${c.expected.build}`)
  if (members !== c.expected.member_sets_match) problems.push(`member sets match ${members}, expected ${c.expected.member_sets_match}`)
  if (built.kind === 'stop') {
    if (c.expected.unreachable !== undefined && built.unreachable !== c.expected.unreachable) problems.push(`unreachable ${built.unreachable}`)
    return { ok: problems.length === 0, detail: `stop (${built.unreachable})${problems.length ? ': ' + problems.join('; ') : ''}` }
  }
  if (c.expected.time !== undefined && built.context.time !== c.expected.time) problems.push(`time ${String(built.context.time)}`)
  const ledger = new ApprovalLedger()
  ledger.register(structuredClone(c.record))
  // 822: the approval the PEP emitted must be the one it was given, unchanged,
  // and that emitted approval, not the fixture's, is what the PDP sees.
  const emitted = built.context.approval
  if (!structurallyEqual(emitted, pristineApproval)) problems.push('emitted approval is missing or changed')
  const emittedId = emitted !== null && typeof emitted === 'object' && 'id' in emitted ? String((emitted as Record<string, unknown>).id) : undefined
  const presented = emittedId === undefined ? {} : { id: emittedId }
  const { approval: _a, ...ctx } = built.context
  const evaluation = { subject: c.record.subject, resource: c.record.resource, action: c.record.action, context: ctx }
  const r = verifier(c).verify(presented, evaluation, Date.parse(c.now), vectors.pdp_id, ledger, new JwksRegistry(), new PolicyStub())
  if (r.outcome !== c.expected.outcome) problems.push(`outcome ${r.outcome}, expected ${c.expected.outcome}`)
  if ((r.nextAction ?? null) !== c.expected.next_action) problems.push(`next_action ${String(r.nextAction ?? null)}`)
  return { ok: problems.length === 0, detail: `${r.outcome}${problems.length ? ': ' + problems.join('; ') : ''}` }
}

let failed = 0
const correct = () => CORRECT_APPROVAL_VERIFIER

console.log('Reference: each case with its named PEP and the reference PDP verifier')
for (const c of vectors.cases) {
  const r = run(c, PEPS[c.pep], correct)
  console.log(`  ${r.ok ? 'MATCH   ' : 'MISMATCH'} ${c.id.padEnd(4)} [${c.pep}] ${r.detail}  (${c.label})`)
  if (!r.ok) failed += 1
}
console.log()

function checkControl(name: string, results: { id: string; ok: boolean }[], declared: string[]): void {
  const observed = results.filter(r => !r.ok).map(r => r.id)
  const undeclared = observed.filter(id => !declared.includes(id))
  const stopped = declared.filter(id => !observed.includes(id))
  if (undeclared.length) { failed += 1; console.log(`FAIL ${name} failed undeclared cases: [${undeclared.join(', ')}]`) }
  if (stopped.length) { failed += 1; console.log(`FAIL ${name} no longer fails declared cases: [${stopped.join(', ')}]`) }
  if (!undeclared.length && !stopped.length) console.log(`ok   ${name} failed exactly the declared set: [${declared.join(', ')}]`)
}

// Control 1: the PDP that skips absent bound members, on every case that sends a request.
const lax = (c: Case) => presentOnlyVerifier(c.record.context, c.record.boundContextMembers)
const laxResults = vectors.cases.filter(c => c.expected.build === 'request').map(c => ({ id: c.id, ...run(c, PEPS[c.pep], lax) }))
checkControl('present-only-pdp', laxResults, vectors.negative_controls.present_only_pdp.declared_to_fail)

// Control 2: the approval-only PEP swapped into every ordinary-rules case.
const swapResults = vectors.cases.filter(c => c.pep === 'ordinary-rules').map(c => ({ id: c.id, ...run(c, APPROVAL_ONLY_PEP, correct) }))
checkControl('approval-only-pep', swapResults, vectors.negative_controls.approval_only_pep.declared_to_fail)

// Control 3: PEPs that drop or alter the approval, on every ordinary-rules case that sends a request.
const sending = vectors.cases.filter(c => c.pep === 'ordinary-rules' && c.expected.build === 'request')
for (const pep of [DROP_APPROVAL_PEP, CHANGED_ID_PEP, CHANGED_TIMESTAMP_PEP, IN_PLACE_APPROVAL_PEP]) {
  const r = sending.map(c => ({ id: c.id, ...run(c, pep, correct) }))
  checkControl(pep.name, r, vectors.negative_controls.approval_tampering_peps.declared_to_fail)
}

// Control 4: a PEP whose first request differs from its later ones, fresh per case.
const alternating = sending.map(c => ({ id: c.id, ...run(c, makeAlternatingPep(), correct) }))
checkControl('alternating-extra-member', alternating, vectors.negative_controls.alternating_pep.declared_to_fail)

console.log()
if (failed > 0) { console.log('FAILED'); process.exit(1) }
console.log('PASSED: every case matched, each control failed exactly its declared set')
process.exit(0)
