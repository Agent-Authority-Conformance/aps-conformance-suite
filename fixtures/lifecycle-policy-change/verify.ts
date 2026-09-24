// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs every presentation in vectors.json through the reference boundary and the
// declared defective negative control, and checks the control in both directions.
//
//     npm run verify:lifecycle-policy-change

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1, RevocationResolution } from 'agent-passport-system'

import {
  makeDefectiveBoundary,
  makeReferenceBoundary,
  type BoundaryOptions,
  type DecisionRecord,
  type Outcome,
  type PolicyChangeBoundary,
  type PolicyVersion,
  type Pointer,
  type Presentation,
} from './harness.ts'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<any>('chain.json')
const vectors = readJson<any>('vectors.json')

if (fixture._placeholder || !fixture.chains?.GRANT || !fixture.policy_versions || !fixture.pointers) {
  console.error(
    'lifecycle-policy-change chain.json is not minted. Run `npx tsx fixtures/lifecycle-policy-change/mint.ts` first.',
  )
  process.exit(2)
}

// The labelling contract. A vector that loses its candidate label, or names proposed
// text this file does not define, is a failure of the family and not of an
// implementation, so it stops the run before any boundary is built.
if (vectors.status !== 'candidate_against_proposed') {
  console.error('lifecycle-policy-change vectors.json must declare status candidate_against_proposed')
  process.exit(2)
}
const PROPOSED = new Set(Object.keys(vectors.proposed_text ?? {}))
for (const presentation of vectors.presentations) {
  if (presentation.status !== 'candidate_against_proposed') {
    console.error(`lifecycle-policy-change ${presentation.id} lost its candidate_against_proposed label`)
    process.exit(2)
  }
  if (!Array.isArray(presentation.tests_proposed_text) || presentation.tests_proposed_text.length === 0) {
    console.error(`lifecycle-policy-change ${presentation.id} names no proposed text`)
    process.exit(2)
  }
  for (const name of presentation.tests_proposed_text) {
    if (!PROPOSED.has(name)) {
      console.error(`lifecycle-policy-change ${presentation.id} names undefined proposed text ${name}`)
      process.exit(2)
    }
  }
  if (typeof presentation.case_id !== 'string' || !presentation.id.includes(presentation.case_id)) {
    console.error(`lifecycle-policy-change ${presentation.id} does not carry its CASES.md case id`)
    process.exit(2)
  }
}

const options: BoundaryOptions = {
  policyVersions: fixture.policy_versions as Record<string, PolicyVersion>,
  policyStanding: fixture.policy_standing as string[],
  recordKeys: fixture.record_keys as Record<string, string>,
  gateway: fixture.parties.gateway as string,
  resolveDelegationVerificationKey: (_issuer, method) => fixture.verification_keys[method] ?? null,
  trustRoot: () => true,
}

const grant = fixture.chains.GRANT[0] as AuthorityDelegationV1

function pointerSet(name: string): Pointer[] {
  const labels = vectors.pointer_sets[name] as string[]
  if (!Array.isArray(labels)) throw new Error(`unknown pointer set ${name}`)
  return labels.map((label) => {
    const pointer = fixture.pointers[label] as Pointer | undefined
    if (!pointer) throw new Error(`unknown pointer ${label}`)
    return pointer
  })
}

function presentationFor(vector: any): Presentation {
  if (vector.mode === 'action') {
    return {
      mode: 'action',
      label: vector.id,
      grant,
      pointerSet: pointerSet(vector.pointer_set),
      at: vector.at,
      amount: vector.amount,
      approvalPresented: vector.approval_presented,
      requiredGrant: 'ledger:export',
      resolveRevocation: () => vector.revocation as RevocationResolution,
    }
  }
  if (vector.mode === 'pointer') {
    const classify = fixture.pointers[vector.classify] as Pointer | undefined
    if (!classify) throw new Error(`unknown pointer ${vector.classify}`)
    return { mode: 'pointer', label: vector.id, pointerSet: pointerSet(vector.pointer_set), classify, at: vector.at }
  }
  const decision = fixture.decisions[vector.decision] as DecisionRecord | undefined
  if (!decision) throw new Error(`unknown decision ${vector.decision}`)
  return {
    mode: 'render',
    label: vector.id,
    pointerSet: pointerSet(vector.pointer_set),
    decision,
    readAt: vector.read_at,
  }
}

function matches(actual: Outcome, expected: any): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.reason !== expected.reason) return false
  if (expected.detail !== undefined && actual.detail !== expected.detail) return false
  if (expected.chain_state !== undefined && actual.chain_state !== expected.chain_state) return false
  if (
    Object.prototype.hasOwnProperty.call(expected, 'operative_version_id') &&
    (actual.operative_version_id ?? null) !== expected.operative_version_id
  ) {
    return false
  }
  if (
    Object.prototype.hasOwnProperty.call(expected, 'pointer_classification') &&
    (actual.pointer_classification ?? null) !== expected.pointer_classification
  ) {
    return false
  }
  return true
}

function render(outcome: Outcome): string {
  const parts = [`${outcome.verdict}/${outcome.reason}`]
  if (outcome.chain_state) parts.push(`chain=${outcome.chain_state}`)
  if (outcome.operative_version_id !== undefined) parts.push(`operative=${outcome.operative_version_id}`)
  if (outcome.pointer_classification !== undefined) parts.push(`class=${outcome.pointer_classification}`)
  if (outcome.detail) parts.push(`detail=${outcome.detail}`)
  return parts.join(' ')
}

function run(boundary: PolicyChangeBoundary): Map<string, boolean> {
  const results = new Map<string, boolean>()
  console.log(`\n${boundary.name}`)
  for (const vector of vectors.presentations) {
    const outcome = boundary.decide(presentationFor(vector))
    const ok = matches(outcome, vector.expected)
    results.set(vector.id, ok)
    console.log(`  ${ok ? 'MATCH        ' : 'DIVERGES     '} ${vector.id}  ${render(outcome)}`)
    if (!ok && boundary.name === 'reference-boundary') {
      console.error(`    expected: ${JSON.stringify(vector.expected)}`)
    }
  }
  return results
}

const reference = run(makeReferenceBoundary(options))
const defective = run(makeDefectiveBoundary(options))

const total = vectors.presentations.length
const referenceMatched = [...reference.values()].filter(Boolean).length
const declared: string[] = vectors.declared_defective_fail_set
const declaredSet = new Set(declared)

const undeclaredFailures = [...defective.entries()].filter(([id, ok]) => !ok && !declaredSet.has(id)).map(([id]) => id)
const declaredButPassing = declared.filter((id) => defective.get(id) === true)

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${total}`)
console.log(`defective-boundary declared failing set: ${declared.length}`)
if (undeclaredFailures.length > 0) console.error(`  undeclared divergence: ${undeclaredFailures.join(', ')}`)
if (declaredButPassing.length > 0) console.error(`  declared but matched: ${declaredButPassing.join(', ')}`)

const ok = referenceMatched === total && undeclaredFailures.length === 0 && declaredButPassing.length === 0
console.log(
  ok
    ? 'PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly the declared set'
    : 'FAILED',
)
process.exit(ok ? 0 : 1)
