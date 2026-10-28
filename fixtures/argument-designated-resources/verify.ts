// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the argument-designated-resources candidate family.
//
// Checks, in order, and exits 1 if any group fails:
//
//   1. every presentation is labelled candidate_against_proposed and names only
//      proposed text that vectors.json defines (exit 2 if not)
//   2. structure: the required case roster is present exactly once, every
//      expected block has exactly its fields, every declared policy is
//      implemented and every implemented policy is declared
//   3. vectors.json is byte-identical to generate.ts's output, and every
//      decision's call_ref recomputes from its call
//   4. reference-boundary matches every expected decision, execution, trace and
//      final store, and no refused call touched the store
//   5. reference-boundary's outcomes do not change when the service gains every
//      credential, loses every credential its contracts do not declare, or the
//      requester gains unselected credentials over everything
//   6. each defective policy falls in exactly its declared category on every
//      vector: unsafe_admission, admission_without_forbidden_access,
//      false_refusal, wrong_diagnosis, wrong_effect or wrong_attribution
//
// Run: npx tsx fixtures/argument-designated-resources/verify.ts

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { serializeVectors } from './generate.js'
import {
  callRef,
  DEFECTIVE,
  evaluate,
  REFERENCE,
  type Access,
  type Credential,
  type Decision,
  type Execution,
  type Fixture,
  type Operation,
  type Outcome,
  type Policy,
  type Presentation,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

const ROSTER = [
  'ADR-01-admit-copy-source-and-destination-covered',
  'ADR-02-refuse-destination-not-covered',
  'ADR-03-refuse-deputy-holds-destination-caller-does-not',
  'ADR-04-refuse-nested-designation-not-covered',
  'ADR-04b-admit-nested-designation-covered',
  'ADR-04c-refuse-literal-dotted-key',
  'ADR-05-refuse-one-array-element-not-covered',
  'ADR-05b-admit-every-array-element-covered',
  'ADR-05c-admit-then-second-write-fails',
  'ADR-06-admit-resource-shaped-label-declared-data',
  'ADR-06b-admit-identifier-passed-by-value',
  'ADR-06c-refuse-identifier-passed-by-reference',
  'ADR-07-refuse-argument-not-classified-by-contract',
  'ADR-07b-refuse-empty-container-not-classified',
  'ADR-07c-refuse-required-operand-missing',
  'ADR-07d-refuse-resource-operand-not-a-string',
  'ADR-08-refuse-traversal-resolves-outside-credential',
  'ADR-08b-admit-cased-alias-resolves-inside-credential',
  'ADR-08c-refuse-traversal-above-root',
  'ADR-09-refuse-operation-not-granted-on-resource',
  'ADR-10-admit-capability-held-by-requester',
  'ADR-10b-refuse-capability-held-by-another-party',
  'ADR-10c-refuse-capability-wider-than-issuer-authority',
  'ADR-10d-refuse-capability-operation-narrower-than-tool-operation',
  'ADR-10e-admit-equal-authority-delegation',
  'ADR-10f-refuse-issuer-may-exercise-but-not-delegate',
  'ADR-10g-refuse-root-issuer-without-standing',
  'ADR-11-refuse-argument-changed-after-decision',
  'ADR-11b-admit-unchanged-call-under-decision',
  'ADR-12-refuse-read-credential-selected-for-destination',
  'ADR-12b-admit-write-credential-selected-for-destination',
  'ADR-12c-refuse-no-credential-selected-for-destination',
  'ADR-13-refuse-repeated-resource-sources-swapped',
  'ADR-13b-admit-repeated-resource-each-source-selected',
  'ADR-13c-refuse-repeated-resource-second-operation-uncovered',
  'ADR-14-admit-service-writes-own-statistics',
  'ADR-14b-refuse-destination-in-service-home',
  'ADR-14c-refuse-caller-selects-service-effect-credential',
]

const PROPOSED_KEYS = [
  'csr-closed-arguments',
  'csr-exact-call',
  'csr-holder-bound-credentials',
  'csr-operands',
  'csr-selected-authority',
  'csr-service-effects',
  'target-binding',
]

const CATEGORIES = [
  'unsafe_admission',
  'admission_without_forbidden_access',
  'false_refusal',
  'wrong_diagnosis',
  'wrong_effect',
  'wrong_attribution',
] as const
type Category = (typeof CATEGORIES)[number]

interface Expected {
  decision: Decision
  execution: Execution
  trace: Access[]
  store_changes: Record<string, string>
  forbidden_access: { operation: Operation; resource: string; path: string } | null
}

interface VectorPresentation extends Presentation {
  id: string
  status: string
  tests_proposed_text: string[]
  expected: Expected
}

interface Vectors extends Fixture {
  status: string
  proposed_text: Record<string, unknown>
  categories: string[]
  defective_policies: Array<{ name: string; stage: string; characteristic_cases: string[]; declared: Record<string, string[]> }>
  presentations: VectorPresentation[]
}

const raw = readFileSync(join(here, 'vectors.json'), 'utf8')
const vectors = JSON.parse(raw) as Vectors
const fixture: Fixture = { tools: vectors.tools, issuer_records: vectors.issuer_records, initial_store: vectors.initial_store }

const stable = (v: unknown): string => {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}
const sameJson = (a: unknown, b: unknown): boolean => stable(a) === stable(b)
const sortedKeys = (o: object): string => Object.keys(o).sort().join(',')

// 1. Labels.
const labelError = (message: string): never => {
  console.error(`argument-designated-resources: ${message}`)
  process.exit(2)
}
if (vectors.status !== 'candidate_against_proposed') labelError('vectors.json is not labelled candidate_against_proposed')
if (sortedKeys(vectors.proposed_text) !== PROPOSED_KEYS.join(',')) labelError(`proposed_text keys are [${sortedKeys(vectors.proposed_text)}]`)
for (const p of vectors.presentations) {
  if (p.status !== 'candidate_against_proposed') labelError(`${p.id} is not labelled candidate_against_proposed`)
  if (!Array.isArray(p.tests_proposed_text) || p.tests_proposed_text.length === 0) labelError(`${p.id} names no proposed text`)
  for (const key of p.tests_proposed_text) {
    if (!PROPOSED_KEYS.includes(key)) labelError(`${p.id} names unknown proposed text "${key}"`)
  }
}

console.log(`argument-designated-resources: ${vectors.presentations.length} presentations, status ${vectors.status}`)
console.log('')

let failed = 0
const fail = (message: string): void => {
  failed += 1
  console.log(`FAIL ${message}`)
}
const ok = (message: string): void => console.log(`ok   ${message}`)

// 2. Structure.
{
  const presented = vectors.presentations.map((p) => p.id)
  const duplicates = presented.filter((id, i) => presented.indexOf(id) !== i)
  const missing = ROSTER.filter((id) => !presented.includes(id))
  const extra = presented.filter((id) => !ROSTER.includes(id))
  const badExpected = vectors.presentations
    .filter((p) => sortedKeys(p.expected) !== 'decision,execution,forbidden_access,store_changes,trace')
    .map((p) => p.id)
  const badForbidden = vectors.presentations
    .filter((p) => p.expected.decision.verdict === 'admitted' && p.expected.forbidden_access !== null)
    .map((p) => p.id)
  if (duplicates.length + missing.length + extra.length > 0) {
    fail(`roster: duplicates [${duplicates}] missing [${missing}] unexpected [${extra}]`)
  } else ok(`roster: all ${ROSTER.length} required cases present exactly once`)
  if (badExpected.length + badForbidden.length > 0) fail(`expected blocks malformed: [${[...badExpected, ...badForbidden]}]`)
  else ok('every expected block has exactly decision, execution, trace, store_changes and forbidden_access')
  if (!sameJson(vectors.categories, CATEGORIES)) fail(`categories are [${vectors.categories}]`)
  const declaredNames = vectors.defective_policies.map((d) => d.name).sort()
  const implementedNames = DEFECTIVE.map((p) => p.name).sort()
  if (!sameJson(declaredNames, implementedNames)) fail(`declared policies [${declaredNames}] differ from implemented [${implementedNames}]`)
  else ok(`all ${implementedNames.length} defective policies declared and implemented`)
  for (const d of vectors.defective_policies) {
    if (sortedKeys(d.declared) !== [...CATEGORIES].sort().join(',')) fail(`${d.name} declares categories [${sortedKeys(d.declared)}]`)
    const named = [...Object.values(d.declared).flat(), ...d.characteristic_cases]
    const unknown = named.filter((id) => !ROSTER.includes(id))
    if (unknown.length > 0) fail(`${d.name} names unknown cases [${unknown}]`)
    const all = Object.values(d.declared).flat()
    if (new Set(all).size !== all.length) fail(`${d.name} declares a case in more than one category`)
    const uncharacteristic = d.characteristic_cases.filter((id) => !all.includes(id))
    if (uncharacteristic.length > 0) fail(`${d.name} characteristic cases not declared: [${uncharacteristic}]`)
  }
}
console.log('')

// 3. Determinism.
if (serializeVectors() !== raw) fail('vectors.json differs from generate.ts output; run npx tsx fixtures/argument-designated-resources/generate.ts')
else ok('vectors.json is byte-identical to generate.ts output')
{
  const badRefs = vectors.presentations.filter((p) => p.decision !== null && callRef(p.decision.call) !== p.decision.call_ref)
  if (badRefs.length > 0) fail(`decision.call_ref does not recompute: [${badRefs.map((p) => p.id)}]`)
  else ok('every decision call_ref recomputes from its call')
}
console.log('')

// Outcome comparison.
function expectedOutcome(p: VectorPresentation): Outcome {
  const store: Record<string, string> = { ...vectors.initial_store, ...p.expected.store_changes }
  const sorted: Record<string, string> = {}
  for (const k of Object.keys(store).sort()) sorted[k] = store[k]!
  return { decision: p.expected.decision, execution: p.expected.execution, trace: p.expected.trace, store: sorted }
}

const accesses = (t: Access[]): string[] => t.map((a) => `${a.operation} ${a.resource} ${a.path}`)

function classify(actual: Outcome, p: VectorPresentation): Category | 'match' {
  const expected = expectedOutcome(p)
  if (actual.decision.verdict !== expected.decision.verdict) {
    if (actual.decision.verdict === 'admitted') {
      const f = p.expected.forbidden_access
      const hit = f !== null && actual.trace.some((a) => a.operation === f.operation && a.resource === f.resource && a.path === f.path)
      return hit ? 'unsafe_admission' : 'admission_without_forbidden_access'
    }
    return 'false_refusal'
  }
  if (!sameJson(actual.decision, expected.decision)) return 'wrong_diagnosis'
  if (!sameJson(actual.execution, expected.execution) || !sameJson(accesses(actual.trace), accesses(expected.trace)) || !sameJson(actual.store, expected.store)) {
    return 'wrong_effect'
  }
  if (!sameJson(actual.trace, expected.trace)) return 'wrong_attribution'
  return 'match'
}

function show(o: Outcome): string {
  const d = o.decision
  const head = [d.verdict, d.reason, d.path, d.resource, d.operation].filter((x) => x !== undefined).join(' ')
  const exec = o.execution.status === 'partial' ? ` partial@${o.execution.stopped_at}:${o.execution.cause}` : ''
  const trace = o.trace.map((a) => `${a.operation} ${a.resource} ${a.path}@${a.authority ?? 'unchecked'}`).join(', ')
  return `${head}${exec}${trace === '' ? '' : ` | ${trace}`}`
}

function run(policy: Policy, mutate?: (p: VectorPresentation) => VectorPresentation): Map<string, Outcome> {
  const out = new Map<string, Outcome>()
  for (const p of vectors.presentations) out.set(p.id, evaluate(policy, fixture, mutate ? mutate(p) : p))
  return out
}

// 4. Reference.
console.log(`policy: ${REFERENCE.name}`)
const reference = run(REFERENCE)
{
  let matched = 0
  const touched: string[] = []
  for (const p of vectors.presentations) {
    const actual = reference.get(p.id)!
    const result = classify(actual, p)
    if (result === 'match') matched += 1
    console.log(`  ${result === 'match' ? 'MATCH   ' : 'MISMATCH'} ${p.id}  ${show(actual)}`)
    if (result !== 'match') console.log(`             expected ${show(expectedOutcome(p))}`)
    if (actual.decision.verdict === 'refused' && (actual.trace.length > 0 || !sameJson(actual.store, expectedOutcome(p).store) || actual.execution.status !== 'not_run')) {
      touched.push(p.id)
    }
  }
  if (matched !== vectors.presentations.length) fail(`reference-boundary matched ${matched}/${vectors.presentations.length}`)
  else ok(`reference-boundary matched ${matched}/${vectors.presentations.length} on decision, execution, trace and store`)
  const refused = vectors.presentations.filter((p) => reference.get(p.id)!.decision.verdict === 'refused').length
  if (touched.length > 0) fail(`refused calls touched the store: [${touched}]`)
  else ok(`all ${refused} refused calls performed no access and left the store unchanged`)
}
console.log('')

// 5. Invariance.
{
  const SVC = 'party:svc-tools'
  const ALL_OPS: Operation[] = ['read', 'write']
  const declaredServiceCreds = new Set(Object.values(vectors.tools).flatMap((t) => t.service_effects.map((e) => e.authority)))
  const extra = (id: string, holder: string, issuer: string, resource: string): Credential => ({
    id, holder, issuer, resource, operations: ALL_OPS, delegable: false, parent: null,
  })
  const withCreds = (p: VectorPresentation, creds: Credential[]): VectorPresentation => ({
    ...p,
    trusted_state: { credentials: creds },
  })
  const mutations: Array<[string, (p: VectorPresentation) => VectorPresentation]> = [
    ['the service holds every resource', (p) => withCreds(p, [...p.trusted_state.credentials, extra('cred:zz-svc-store', SVC, 'party:store-admin', 'res:/store')])],
    ['the service holds only its declared effect credentials', (p) => withCreds(p, p.trusted_state.credentials.filter((c) => c.holder !== SVC || declaredServiceCreds.has(c.id)))],
    ['the requester holds unselected credentials over everything', (p) => withCreds(p, [
      ...p.trusted_state.credentials,
      extra('cred:zz-requester-store', p.call.requester, 'party:store-admin', 'res:/store'),
      extra('cred:zz-requester-svc', p.call.requester, SVC, 'res:/svc'),
    ])],
  ]
  for (const [label, mutate] of mutations) {
    const mutated = run(REFERENCE, mutate)
    const changed = vectors.presentations.filter((p) => !sameJson(mutated.get(p.id), reference.get(p.id))).map((p) => p.id)
    if (changed.length > 0) fail(`reference-boundary changed when ${label}: [${changed}]`)
    else ok(`reference-boundary unchanged when ${label}`)
  }
}
console.log('')

// 6. Defective policies.
const summary: string[] = []
for (const policy of DEFECTIVE) {
  const declaration = vectors.defective_policies.find((d) => d.name === policy.name)
  if (declaration === undefined) continue
  console.log(`policy: ${policy.name} (stage ${declaration.stage})`)
  const results = run(policy)
  const observed: Record<Category, string[]> = Object.fromEntries(CATEGORIES.map((c) => [c, [] as string[]])) as Record<Category, string[]>
  for (const p of vectors.presentations) {
    const actual = results.get(p.id)!
    const category = classify(actual, p)
    if (category !== 'match') observed[category].push(p.id)
    console.log(`  ${category.padEnd(34)} ${p.id}  ${show(actual)}`)
  }
  let problems = 0
  for (const category of CATEGORIES) {
    const want = [...(declaration.declared[category] ?? [])].sort()
    const got = [...observed[category]].sort()
    if (!sameJson(want, got)) {
      problems += 1
      fail(`${policy.name} ${category}: declared [${want}] observed [${got}]`)
    }
  }
  const counts = CATEGORIES.map((c) => observed[c].length)
  summary.push(`${policy.name.padEnd(38)} ${counts.map((n) => String(n).padStart(3)).join(' ')}`)
  if (problems === 0) ok(`${policy.name} matches its declaration in every category`)
  console.log('')
}
console.log(`summary ${''.padEnd(30)} ${['uns', 'awf', 'fr', 'dia', 'eff', 'att'].map((s) => s.padStart(3)).join(' ')}`)
for (const line of summary) console.log(`  ${line}`)
console.log('')

if (failed > 0) {
  console.log('FAILED')
  process.exit(1)
}
console.log('PASSED: reference-boundary matched every presentation, every defective policy matched its declared categories')
process.exit(0)
