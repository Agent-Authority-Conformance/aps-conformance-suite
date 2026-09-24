// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-infrastructure-failure candidate family.
//
// Three checks, all of which must pass:
//
//   1. Labelling. Every case carries status candidate_against_proposed, names
//      the proposed text it tests, names the CASES.md case id it was built
//      from, and uses only the settled verdict vocabulary. A vector that loses
//      its label or its proposed-text reference fails here, so the family
//      cannot quietly become a draft-03 conformance claim.
//   2. Reference model. The reference evaluator for each case's group matches
//      the case's expected verdict and reason.
//   3. Negative controls. Each group's control is run against every case in
//      that group, not only the ones predicted to fail, and its observed fail
//      set must equal its declared fail set exactly. An undeclared failure and
//      a declared failure that quietly starts passing are both errors.
//
// Canonical bytes. input-digests.json pins the SHA-256 of the RFC 8785 (JCS)
// canonicalization of every case's `input`. This runner recomputes each one
// through the published npm agent-passport-system's `canonicalizeJCS` and fails
// on a mismatch. verify.py does the same through the published PyPI package's
// `canonicalize_jcs`, so the pins are what the two implementations are compared
// against.
//
// Run: npx tsx fixtures/lifecycle-infrastructure-failure/verify.ts
// Exit 0 on success, 1 on any failure.

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from 'agent-passport-system'

import {
  CONTROL_FOR_GROUP,
  GROUPS,
  evaluateControl,
  evaluateReference,
  type Group,
  type Outcome,
} from './harness.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const VOCABULARY = new Set(['valid', 'invalid', 'not_established', 'not_yet_effective', 'suspended', 'restricted'])

interface Case {
  id: string
  case_id: string
  case_id_variant?: string
  group: Group
  role: string
  label: string
  title: string
  description: string
  proposed_text: { sections: string[] }
  input: unknown
  expected: Outcome
}

interface Vectors {
  family: string
  status: string
  proposed_text: { repository: string; commit: string }
  policies: { negative_controls: { id: string; group: Group; defect: string; declared_fail_set: string[] }[] }
  cases: Case[]
}

const vectors: Vectors = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8'))
const digests: Record<string, string> = JSON.parse(readFileSync(join(HERE, 'input-digests.json'), 'utf8')).inputs

const failures: string[] = []
const fail = (m: string) => {
  failures.push(m)
  console.error(`  FAIL ${m}`)
}

console.log(`${vectors.family}: ${vectors.cases.length} cases, TypeScript runner`)

// --- 1. Labelling -----------------------------------------------------------

if (vectors.status !== 'candidate_against_proposed') {
  fail(`family status is "${vectors.status}", expected candidate_against_proposed`)
}
if (!vectors.proposed_text?.repository || !vectors.proposed_text?.commit) {
  fail('family does not name the proposed text it is a candidate against')
}

const seen = new Set<string>()
for (const c of vectors.cases) {
  if (seen.has(c.id)) fail(`${c.id}: duplicate vector id`)
  seen.add(c.id)
  if (c.label !== 'candidate_against_proposed') fail(`${c.id}: label is "${c.label}"`)
  if (!c.case_id || !c.id.startsWith(c.case_id_variant ?? c.case_id)) {
    fail(`${c.id}: vector id does not carry its CASES.md case id`)
  }
  if (!Array.isArray(c.proposed_text?.sections) || c.proposed_text.sections.length === 0) {
    fail(`${c.id}: names no proposed text`)
  }
  if (!GROUPS.includes(c.group)) fail(`${c.id}: unknown group "${c.group}"`)
  if (!VOCABULARY.has(c.expected.verdict)) fail(`${c.id}: verdict "${c.expected.verdict}" is outside the settled vocabulary`)
}
console.log(`  ok   labelling: ${vectors.cases.length} cases carry candidate_against_proposed and name their proposed text`)

// --- 2. Canonical bytes -----------------------------------------------------

let digestChecked = 0
for (const c of vectors.cases) {
  const bytes = Buffer.from(canonicalizeJCS(c.input as never), 'utf8')
  const got = createHash('sha256').update(bytes).digest('hex')
  const want = digests[c.id]
  if (want === undefined) fail(`${c.id}: no pinned input digest`)
  else if (got !== want) fail(`${c.id}: input digest ${got} does not match pinned ${want}`)
  else digestChecked++
}
if (Object.keys(digests).length !== vectors.cases.length) {
  fail(`input-digests.json pins ${Object.keys(digests).length} inputs for ${vectors.cases.length} cases`)
}
console.log(`  ok   canonical bytes: ${digestChecked}/${vectors.cases.length} JCS input digests match, via npm canonicalizeJCS`)

// --- 3. Reference model -----------------------------------------------------

let refMatched = 0
for (const c of vectors.cases) {
  const got = evaluateReference(c.group, c.input)
  if (got.verdict !== c.expected.verdict || got.reason !== c.expected.reason) {
    fail(`${c.id}: reference gave ${got.verdict}/${got.reason}, expected ${c.expected.verdict}/${c.expected.reason}`)
  } else refMatched++
}
console.log(`  ok   reference model: ${refMatched}/${vectors.cases.length} matched`)

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
    if (got.verdict !== c.expected.verdict || got.reason !== c.expected.reason) observed.push(c.id)
  }
  const declared = [...control.declared_fail_set].sort()
  const sortedObserved = [...observed].sort()
  if (JSON.stringify(declared) !== JSON.stringify(sortedObserved)) {
    fail(`${control.id}: declared fail set ${JSON.stringify(declared)}, observed ${JSON.stringify(sortedObserved)}`)
  } else {
    console.log(
      `  ok   ${control.id}: ran ${inGroup.length} cases in group ${control.group}, failed exactly ${declared.length} declared (${declared.join(', ') || 'none'})`,
    )
  }
  if (declared.length === 0) {
    fail(`${control.id}: a negative control with an empty declared fail set is not a control`)
  }
}

// --- result -----------------------------------------------------------------

if (failures.length > 0) {
  console.error(`\nlifecycle-infrastructure-failure TypeScript: FAILED, ${failures.length} problem(s)`)
  process.exit(1)
}
console.log(`\nlifecycle-infrastructure-failure TypeScript: ${vectors.cases.length}/${vectors.cases.length} passed`)
