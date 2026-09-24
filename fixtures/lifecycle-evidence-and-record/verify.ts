// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-evidence-and-record candidate family.
//
// Four checks, all of which must pass:
//
//   1. Labelling. Every case carries status candidate_against_proposed, names
//      the proposed text it tests, carries its CASES.md case id in its vector
//      id, and uses only the settled verdict vocabulary for both of its two
//      verdict fields.
//   2. Canonical bytes. Every case's `input` recanonicalizes under RFC 8785 to
//      its pinned SHA-256, through the published npm package's canonicalizeJCS.
//   3. Reference model. Each group's reference evaluator matches the case's
//      expected chain_verdict, verdict and reason.
//   4. Negative controls. Each group's control runs against every case in that
//      group, and its observed fail set must equal its declared fail set.
//
//   5. Input immutability. The receipt_immutability group is about a record not
//      being rewritten, so this runner also checks that no evaluator mutated
//      the input it was handed, by recomputing every input digest a second time
//      after all evaluators have run. A harness that edited a receipt in place
//      to produce its answer would pass check 3 and fail here.
//
// Run: npx tsx fixtures/lifecycle-evidence-and-record/verify.ts
// Exit 0 on success, 1 on any failure.

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from 'agent-passport-system'

import { CONTROL_FOR_GROUP, GROUPS, evaluateControl, evaluateReference, type Group, type Outcome } from './harness.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const VOCABULARY = new Set(['valid', 'invalid', 'not_established', 'not_yet_effective', 'suspended', 'restricted'])

interface Case {
  id: string
  case_id: string
  group: Group
  role: string
  label: string
  proposed_text: { sections: string[] }
  input: unknown
  expected: Outcome
}

const vectors = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8')) as {
  family: string
  status: string
  proposed_text: { repository: string; commit: string }
  policies: { negative_controls: { id: string; group: Group; declared_fail_set: string[] }[] }
  cases: Case[]
}
const pinned: Record<string, string> = JSON.parse(readFileSync(join(HERE, 'input-digests.json'), 'utf8')).inputs

const failures: string[] = []
const fail = (m: string) => {
  failures.push(m)
  console.error(`  FAIL ${m}`)
}

const digestOf = (input: unknown) =>
  createHash('sha256').update(Buffer.from(canonicalizeJCS(input as never), 'utf8')).digest('hex')

console.log(`${vectors.family}: ${vectors.cases.length} cases, TypeScript runner`)

// --- 1. Labelling -----------------------------------------------------------

if (vectors.status !== 'candidate_against_proposed') fail(`family status is "${vectors.status}"`)
if (!vectors.proposed_text?.repository || !vectors.proposed_text?.commit) {
  fail('family does not name the proposed text it is a candidate against')
}
const seen = new Set<string>()
for (const c of vectors.cases) {
  if (seen.has(c.id)) fail(`${c.id}: duplicate vector id`)
  seen.add(c.id)
  if (c.label !== 'candidate_against_proposed') fail(`${c.id}: label is "${c.label}"`)
  if (!c.case_id || !c.id.startsWith(c.case_id)) fail(`${c.id}: vector id does not carry its CASES.md case id`)
  if (!Array.isArray(c.proposed_text?.sections) || c.proposed_text.sections.length === 0) {
    fail(`${c.id}: names no proposed text`)
  }
  if (!GROUPS.includes(c.group)) fail(`${c.id}: unknown group "${c.group}"`)
  for (const field of ['chain_verdict', 'verdict'] as const) {
    if (!VOCABULARY.has(c.expected[field])) {
      fail(`${c.id}: ${field} "${c.expected[field]}" is outside the settled vocabulary`)
    }
  }
}
console.log(`  ok   labelling: ${vectors.cases.length} cases carry candidate_against_proposed and name their proposed text`)

// --- 2. Canonical bytes -----------------------------------------------------

const before = new Map<string, string>()
for (const c of vectors.cases) {
  const got = digestOf(c.input)
  before.set(c.id, got)
  if (pinned[c.id] === undefined) fail(`${c.id}: no pinned input digest`)
  else if (got !== pinned[c.id]) fail(`${c.id}: input digest ${got} does not match pinned ${pinned[c.id]}`)
}
if (Object.keys(pinned).length !== vectors.cases.length) {
  fail(`input-digests.json pins ${Object.keys(pinned).length} inputs for ${vectors.cases.length} cases`)
}
console.log(`  ok   canonical bytes: ${vectors.cases.length}/${vectors.cases.length} JCS input digests match, via npm canonicalizeJCS`)

// --- 3. Reference model -----------------------------------------------------

let matched = 0
for (const c of vectors.cases) {
  const got = evaluateReference(c.group, c.input)
  const same =
    got.chain_verdict === c.expected.chain_verdict &&
    got.verdict === c.expected.verdict &&
    got.reason === c.expected.reason
  if (!same) {
    fail(
      `${c.id}: reference gave ${got.chain_verdict}/${got.verdict}/${got.reason}, ` +
        `expected ${c.expected.chain_verdict}/${c.expected.verdict}/${c.expected.reason}`,
    )
  } else matched++
}
console.log(`  ok   reference model: ${matched}/${vectors.cases.length} matched`)

// --- 4. Negative controls ---------------------------------------------------

for (const control of vectors.policies.negative_controls) {
  if (CONTROL_FOR_GROUP[control.group] !== control.id) {
    fail(`${control.id}: harness binds group ${control.group} to ${CONTROL_FOR_GROUP[control.group]}`)
    continue
  }
  const inGroup = vectors.cases.filter(c => c.group === control.group)
  const observed: string[] = []
  for (const c of inGroup) {
    const got = evaluateControl(control.group, c.input)
    const same =
      got.chain_verdict === c.expected.chain_verdict &&
      got.verdict === c.expected.verdict &&
      got.reason === c.expected.reason
    if (!same) observed.push(c.id)
  }
  const declared = [...control.declared_fail_set].sort()
  if (JSON.stringify(declared) !== JSON.stringify([...observed].sort())) {
    fail(`${control.id}: declared fail set ${JSON.stringify(declared)}, observed ${JSON.stringify(observed.sort())}`)
  } else {
    console.log(
      `  ok   ${control.id}: ran ${inGroup.length} cases in group ${control.group}, failed exactly ${declared.length} declared (${declared.join(', ')})`,
    )
  }
  if (declared.length === 0) fail(`${control.id}: a negative control with an empty declared fail set is not a control`)
}

// --- 5. Input immutability --------------------------------------------------

let unchanged = 0
for (const c of vectors.cases) {
  const after = digestOf(c.input)
  if (after !== before.get(c.id)) fail(`${c.id}: an evaluator mutated the input it was given`)
  else unchanged++
}
console.log(`  ok   input immutability: ${unchanged}/${vectors.cases.length} inputs unchanged after every evaluator ran`)

if (failures.length > 0) {
  console.error(`\nlifecycle-evidence-and-record TypeScript: FAILED, ${failures.length} problem(s)`)
  process.exit(1)
}
console.log(`\nlifecycle-evidence-and-record TypeScript: ${vectors.cases.length}/${vectors.cases.length} passed`)
