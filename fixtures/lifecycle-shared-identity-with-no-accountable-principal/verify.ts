// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-shared-identity-with-no-accountable-principal
// candidate family.
//
// Five checks, all of which must pass:
//
//   1. Labelling. Every case carries status candidate_against_proposed, names
//      the proposed text it tests, carries its CASES.md case id in its vector
//      id, and uses only the settled verdict vocabulary for both verdict fields
//      and only a known value for the anomaly flag.
//   2. Canonical bytes. Every case's `input` recanonicalizes under RFC 8785 to
//      its pinned SHA-256, through the published npm package's canonicalizeJCS.
//   3. The authority axis is not the accountability axis. Every case in this
//      family has a valid chain, and at least one case must pair that valid
//      chain with accountability not_established. A family in which the two
//      axes never diverge would not be testing anything the section is about,
//      so this runner refuses to pass one.
//   4. Reference model. The reference evaluator matches each case's expected
//      authority verdict, accountability verdict, reason and anomaly.
//   5. Negative controls. Each control runs against every case, and its
//      observed fail set must equal its declared fail set.
//
// Run: npx tsx fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.ts
// Exit 0 on success, 1 on any failure.

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from 'agent-passport-system'

import { CONTROLS, evaluateReference, type Input, type Outcome } from './harness.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const VOCABULARY = new Set(['valid', 'invalid', 'not_established', 'not_yet_effective', 'suspended', 'restricted'])
const ANOMALIES = new Set(['not_applicable', 'on_enumerated_list', 'off_enumerated_list'])

interface Case {
  id: string
  case_id: string
  role: string
  label: string
  proposed_text: { sections: string[] }
  input: Input
  expected: Outcome
}

const vectors = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8')) as {
  family: string
  status: string
  proposed_text: { repository: string; commit: string }
  policies: { negative_controls: { id: string; declared_fail_set: string[] }[] }
  cases: Case[]
}
const pinned: Record<string, string> = JSON.parse(readFileSync(join(HERE, 'input-digests.json'), 'utf8')).inputs

const failures: string[] = []
const fail = (m: string) => {
  failures.push(m)
  console.error(`  FAIL ${m}`)
}

const same = (a: Outcome, b: Outcome) =>
  a.authority_verdict === b.authority_verdict &&
  a.accountability_verdict === b.accountability_verdict &&
  a.reason === b.reason &&
  a.anomaly === b.anomaly

const render = (o: Outcome) => `${o.authority_verdict}/${o.accountability_verdict}/${o.reason}/${o.anomaly}`

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
  for (const field of ['authority_verdict', 'accountability_verdict'] as const) {
    if (!VOCABULARY.has(c.expected[field])) {
      fail(`${c.id}: ${field} "${c.expected[field]}" is outside the settled vocabulary`)
    }
  }
  if (!ANOMALIES.has(c.expected.anomaly)) fail(`${c.id}: unknown anomaly value "${c.expected.anomaly}"`)
}
console.log(`  ok   labelling: ${vectors.cases.length} cases carry candidate_against_proposed and name their proposed text`)

// --- 2. Canonical bytes -----------------------------------------------------

for (const c of vectors.cases) {
  const got = createHash('sha256').update(Buffer.from(canonicalizeJCS(c.input as never), 'utf8')).digest('hex')
  if (pinned[c.id] === undefined) fail(`${c.id}: no pinned input digest`)
  else if (got !== pinned[c.id]) fail(`${c.id}: input digest ${got} does not match pinned ${pinned[c.id]}`)
}
if (Object.keys(pinned).length !== vectors.cases.length) {
  fail(`input-digests.json pins ${Object.keys(pinned).length} inputs for ${vectors.cases.length} cases`)
}
console.log(`  ok   canonical bytes: ${vectors.cases.length}/${vectors.cases.length} JCS input digests match, via npm canonicalizeJCS`)

// --- 3. The two axes must be capable of diverging ---------------------------

const allChainsValid = vectors.cases.every(c => c.input.chain_state === 'valid')
const diverging = vectors.cases.filter(
  c => c.expected.authority_verdict === 'valid' && c.expected.accountability_verdict === 'not_established',
)
if (!allChainsValid) fail('a case in this family has a chain that is not valid, which is not what the section is about')
if (diverging.length === 0) {
  fail('no case pairs a valid chain with accountability not_established, so the two axes never diverge')
}
console.log(
  `  ok   axis separation: all ${vectors.cases.length} chains valid, ${diverging.length} cases pair a valid chain with accountability not_established`,
)

// --- 4. Reference model -----------------------------------------------------

let matched = 0
for (const c of vectors.cases) {
  const got = evaluateReference(c.input)
  if (!same(got, c.expected)) fail(`${c.id}: reference gave ${render(got)}, expected ${render(c.expected)}`)
  else matched++
}
console.log(`  ok   reference model: ${matched}/${vectors.cases.length} matched`)

// --- 5. Negative controls ---------------------------------------------------

for (const control of vectors.policies.negative_controls) {
  const run = CONTROLS[control.id]
  if (run === undefined) {
    fail(`${control.id}: no control by that id in the harness`)
    continue
  }
  const observed = vectors.cases.filter(c => !same(run(c.input), c.expected)).map(c => c.id)
  const declared = [...control.declared_fail_set].sort()
  if (JSON.stringify(declared) !== JSON.stringify([...observed].sort())) {
    fail(`${control.id}: declared fail set ${JSON.stringify(declared)}, observed ${JSON.stringify(observed.sort())}`)
  } else {
    console.log(
      `  ok   ${control.id}: ran all ${vectors.cases.length} cases, failed exactly ${declared.length} declared (${declared.join(', ')})`,
    )
  }
  if (declared.length === 0) fail(`${control.id}: a negative control with an empty declared fail set is not a control`)
  if (declared.length === vectors.cases.length) {
    fail(`${control.id}: a control that fails every case has no passing baseline and isolates nothing`)
  }
}

if (failures.length > 0) {
  console.error(`\nlifecycle-shared-identity TypeScript: FAILED, ${failures.length} problem(s)`)
  process.exit(1)
}
console.log(`\nlifecycle-shared-identity TypeScript: ${vectors.cases.length}/${vectors.cases.length} passed`)
