// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the teardown-accounting candidate family.
//
// Case files. dev-cases.json always runs. vectors.json runs too when it is
// present, under the same checks, and a present but malformed vectors.json is a
// failure, never a skip. Contributed vectors never replace the dev cases.
//
// Checks per case file, all of which must pass:
//
//   1. Proposed-text pin. The file's proposed_text.sha256 equals the SHA-256 of
//      the PROPOSED.md bytes it names. An edit to PROPOSED.md that was not
//      re-pinned fails here.
//   2. Labelling. Every case carries label candidate_against_proposed and group
//      teardown_accounting, and expects either a verdict and reason from the
//      settled vocabulary, paired as PROPOSED.md pairs them, or a fixture error
//      naming the exact JSON Pointers the validator must report.
//   3. Reference model. The reference evaluator reproduces every expectation,
//      refusals included.
//   4. Negative control. C1-ordering-taken-as-given runs against every case.
//      On a fixture-error case it must refuse identically. Elsewhere its
//      observed fail set must equal the declared fail set exactly, and an empty
//      declared fail set is a failure on its own.
//
// Then, once: direct unit checks of the element-wise sequence comparison.
//
// Run:  npx tsx fixtures/teardown-accounting/verify.ts
// Options:
//   --dev-cases PATH   read the dev cases from PATH (used by the mutation check)
//   --vectors PATH     read vectors from PATH instead of the default location
//   --results-only     print only one result line per case, for the parity diff
// Exit 0 on success, 1 on any failure.

import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CONTROL_ID,
  REASONS,
  VERDICTS,
  evaluateControl,
  evaluateReference,
  formatResult,
  sameSequence,
  type Result,
} from './harness.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..', '..')
const FAMILY = 'teardown-accounting'
const PROPOSED_PATH = 'fixtures/teardown-accounting/PROPOSED.md'
const DEV_PROVENANCE = 'author development cases, not contributed vectors and not independent evidence'

const args = process.argv.slice(2)
const option = (name: string): string | undefined => {
  const k = args.indexOf(name)
  return k === -1 ? undefined : args[k + 1]
}
const resultsOnly = args.includes('--results-only')
const devPath = option('--dev-cases') ?? join(HERE, 'dev-cases.json')
const vectorsPath = option('--vectors') ?? join(HERE, 'vectors.json')

const failures: string[] = []
const fail = (m: string) => {
  failures.push(m)
  console.error(`  FAIL ${m}`)
}
const say = (m: string) => {
  if (!resultsOnly) console.log(m)
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)
const exactMembers = (v: Record<string, unknown>, names: string[]) =>
  sameSequence(Object.keys(v).sort(), [...names].sort())

type Expected = { verdict: string; reason: string } | { fixture_error: string[] }

function checkExpected(id: string, e: unknown): Expected | null {
  if (!isObject(e)) {
    fail(`${id}: expected is not an object`)
    return null
  }
  if (exactMembers(e, ['verdict', 'reason'])) {
    if (!(VERDICTS as readonly unknown[]).includes(e.verdict)) {
      fail(`${id}: verdict ${JSON.stringify(e.verdict)} is outside the settled vocabulary`)
      return null
    }
    if (typeof e.reason !== 'string' || !Object.prototype.hasOwnProperty.call(REASONS, e.reason)) {
      fail(`${id}: reason ${JSON.stringify(e.reason)} is not a published reason code`)
      return null
    }
    if (REASONS[e.reason] !== e.verdict) {
      fail(`${id}: reason ${e.reason} does not accompany verdict ${e.verdict}`)
      return null
    }
    return { verdict: e.verdict as string, reason: e.reason }
  }
  if (exactMembers(e, ['fixture_error'])) {
    const p = e.fixture_error
    if (!Array.isArray(p) || p.length === 0 || !p.every(x => typeof x === 'string')) {
      fail(`${id}: fixture_error must be a non-empty array of JSON Pointers`)
      return null
    }
    const sorted = [...new Set(p as string[])].sort()
    if (!sameSequence(sorted, p as string[])) {
      fail(`${id}: fixture_error pointers must be sorted and unique`)
      return null
    }
    return { fixture_error: p as string[] }
  }
  fail(`${id}: expected must be exactly {verdict, reason} or exactly {fixture_error}`)
  return null
}

function matches(r: Result, e: Expected): boolean {
  if ('fixture_error' in e) return r.kind === 'fixture_error' && sameSequence(r.paths, e.fixture_error)
  return r.kind === 'verdict' && r.outcome.verdict === e.verdict && r.outcome.reason === e.reason
}

const formatExpected = (e: Expected) =>
  'fixture_error' in e ? `fixture_error[${e.fixture_error.join(',')}]` : `${e.verdict}/${e.reason}`

function runFile(label: string, path: string, isDev: boolean): void {
  let doc: unknown
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    fail(`${label}: cannot read or parse ${path}: ${(err as Error).message}`)
    return
  }
  say(`${label}: TypeScript runner`)
  if (!isObject(doc)) {
    fail(`${label}: top level is not an object`)
    return
  }
  const members = ['family', 'status', 'provenance', 'proposed_text', 'negative_control', 'cases']
  if (!exactMembers(doc, members)) {
    fail(`${label}: top-level members are ${JSON.stringify(Object.keys(doc).sort())}, expected ${JSON.stringify([...members].sort())}`)
    return
  }
  if (doc.family !== FAMILY) fail(`${label}: family is ${JSON.stringify(doc.family)}`)
  if (doc.status !== 'candidate_against_proposed') fail(`${label}: status is ${JSON.stringify(doc.status)}`)
  if (isDev) {
    if (doc.provenance !== DEV_PROVENANCE) fail(`${label}: provenance is ${JSON.stringify(doc.provenance)}`)
  } else if (typeof doc.provenance !== 'string' || doc.provenance.length === 0) {
    fail(`${label}: provenance must be a non-empty string`)
  }

  // 1. Proposed-text pin.
  const pt = doc.proposed_text
  if (!isObject(pt) || !exactMembers(pt, ['path', 'sha256']) || pt.path !== PROPOSED_PATH || typeof pt.sha256 !== 'string') {
    fail(`${label}: proposed_text must be exactly {path: "${PROPOSED_PATH}", sha256}`)
  } else {
    const got = createHash('sha256').update(readFileSync(join(ROOT, PROPOSED_PATH))).digest('hex')
    if (got !== pt.sha256) fail(`${label}: PROPOSED.md sha256 is ${got}, pinned ${pt.sha256}`)
    else say(`  ok   proposed text: PROPOSED.md matches the pin ${got}`)
  }

  // 2. Labelling.
  const nc = doc.negative_control
  const cases = doc.cases
  if (!Array.isArray(cases) || cases.length === 0) {
    fail(`${label}: cases must be a non-empty array`)
    return
  }
  const checked: { id: string; input: unknown; expected: Expected }[] = []
  const seen = new Set<string>()
  for (const [k, c] of cases.entries()) {
    if (!isObject(c) || !exactMembers(c, ['id', 'group', 'label', 'title', 'input', 'expected'])) {
      fail(`${label}: case ${k} must have exactly id, group, label, title, input, expected`)
      continue
    }
    const id = typeof c.id === 'string' && c.id.length > 0 ? c.id : `#${k}`
    if (id !== c.id) fail(`${label}: case ${k} has no id`)
    if (seen.has(id)) fail(`${id}: duplicate case id`)
    seen.add(id)
    if (c.label !== 'candidate_against_proposed') fail(`${id}: label is ${JSON.stringify(c.label)}`)
    if (c.group !== 'teardown_accounting') fail(`${id}: group is ${JSON.stringify(c.group)}`)
    if (typeof c.title !== 'string' || c.title.length === 0) fail(`${id}: title missing`)
    const e = checkExpected(id, c.expected)
    if (e) checked.push({ id, input: c.input, expected: e })
  }
  if (checked.length === cases.length) {
    say(`  ok   labelling: ${cases.length} cases carry candidate_against_proposed, group teardown_accounting and a well-formed expectation`)
  }

  // 3. Reference model.
  let refMatched = 0
  for (const c of checked) {
    const r = evaluateReference(c.input)
    const ctl = evaluateControl(c.input)
    if (resultsOnly) console.log(`${label}\t${c.id}\treference ${formatResult(r)}\tcontrol ${formatResult(ctl)}`)
    if (!matches(r, c.expected)) fail(`${c.id}: reference gave ${formatResult(r)}, expected ${formatExpected(c.expected)}`)
    else {
      refMatched++
      say(`  ok   ${c.id.padEnd(10)} ${formatResult(r)}`)
    }
  }
  say(`  ok   reference model: ${refMatched}/${checked.length} matched`)

  // 4. Negative control.
  if (!isObject(nc) || !exactMembers(nc, ['id', 'defect', 'declared_fail_set']) || nc.id !== CONTROL_ID ||
      !Array.isArray(nc.declared_fail_set) || !nc.declared_fail_set.every(x => typeof x === 'string')) {
    fail(`${label}: negative_control must be exactly {id: "${CONTROL_ID}", defect, declared_fail_set: string[]}`)
    return
  }
  const declared = [...(nc.declared_fail_set as string[])].sort()
  if (declared.length === 0) fail(`${CONTROL_ID}: a negative control with an empty declared fail set is not a control`)
  for (const d of declared) if (!seen.has(d)) fail(`${CONTROL_ID}: declared fail set names unknown case ${d}`)
  const observed: string[] = []
  let refusals = 0
  for (const c of checked) {
    const got = evaluateControl(c.input)
    if ('fixture_error' in c.expected) {
      if (!matches(got, c.expected)) fail(`${c.id}: control gave ${formatResult(got)} on a fixture-error case`)
      else refusals++
    } else if (!matches(got, c.expected)) observed.push(c.id)
  }
  observed.sort()
  if (!sameSequence(declared, observed)) {
    fail(`${CONTROL_ID}: declared fail set ${JSON.stringify(declared)}, observed ${JSON.stringify(observed)}`)
  } else {
    say(`  ok   ${CONTROL_ID}: ran ${checked.length} cases, refused the same ${refusals} fixture-error cases, failed exactly the declared ${declared.length} (${declared.join(', ')})`)
  }
}

runFile('dev-cases.json', devPath, true)
if (existsSync(vectorsPath)) runFile('vectors.json', vectorsPath, false)
else say('vectors.json: not present')

// Element-wise comparison, directly.
const unit: [string[], string[], boolean][] = [
  [['a,b', 'c'], ['a', 'b,c'], false],
  [['a', 'b'], ['a,b'], false],
  [['d1', 'd2'], ['d1', 'd2'], true],
  [[], [], true],
]
for (const [a, b, want] of unit) {
  const got = sameSequence(a, b)
  if (got !== want) fail(`sameSequence(${JSON.stringify(a)}, ${JSON.stringify(b)}) is ${got}, expected ${want}`)
  else say(`  ok   sameSequence(${JSON.stringify(a)}, ${JSON.stringify(b)}) is ${got}`)
}

if (failures.length > 0) {
  console.error(`\nteardown-accounting TypeScript: FAILED, ${failures.length} problem(s)`)
  process.exit(1)
}
say(`\nteardown-accounting TypeScript: passed`)
