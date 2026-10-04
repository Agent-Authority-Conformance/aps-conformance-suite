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
//   0. Duplicate member names. A case file with a duplicate JSON member name,
//      compared after string escape decoding, is refused as a whole before any
//      case is evaluated. The failure names the RFC 6901 pointer of the repeated
//      member. This is a rule of this family's proposed input contract (see
//      PROPOSED.md), not an APS requirement this family exercises.
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
// Then, once: direct unit checks of the element-wise sequence comparison and of
// the duplicate-name scanner.
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

// Duplicate member names. JSON.parse keeps the last value of a repeated name and
// gives no sign that there was a first one, so the raw text is scanned before it
// is parsed. The scanner follows object and array nesting, tells member names
// from value strings by position (the string after `{` or after `,` inside an
// object is a name), decodes each name with JSON string semantics and compares
// the decoded names exactly, with no Unicode normalization. A \u escape decodes
// to one UTF-16 code unit, so an escaped surrogate pair and the same astral
// character written literally decode to the same string. Grammar stays the job
// of JSON.parse. The scanner returns undefined when it cannot follow the text,
// and runFile reports JSON.parse's error first whenever the text is malformed.
type ScanFrame =
  | { kind: 'object'; pointer: string; names: Set<string>; state: 'name' | 'colon' | 'value' | 'comma'; current: string }
  | { kind: 'array'; pointer: string; index: number; state: 'value' | 'comma' }

const pointerToken = (name: string) => name.replace(/~/g, '~0').replace(/\//g, '~1')

const STRING_ESCAPES: Record<string, string> = {
  '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t',
}

function readJsonString(text: string, start: number): { value: string; end: number } | undefined {
  let out = ''
  let j = start + 1
  while (j < text.length) {
    const c = text[j]
    if (c === '"') return { value: out, end: j + 1 }
    if (c === '\\') {
      const e = text[j + 1]
      if (e === 'u') {
        const hex = text.slice(j + 2, j + 6)
        if (!/^[0-9A-Fa-f]{4}$/.test(hex)) return undefined
        out += String.fromCharCode(parseInt(hex, 16))
        j += 6
      } else if (e !== undefined && Object.prototype.hasOwnProperty.call(STRING_ESCAPES, e)) {
        out += STRING_ESCAPES[e]
        j += 2
      } else {
        return undefined
      }
      continue
    }
    if (c.charCodeAt(0) < 0x20) return undefined
    out += c
    j++
  }
  return undefined
}

/** RFC 6901 pointer of the first repeated member name in text order, null when
 *  there is none, undefined when the text cannot be followed. */
function findDuplicateMember(text: string): string | null | undefined {
  const stack: ScanFrame[] = []
  let rootDone = false
  const top = () => stack[stack.length - 1]
  const valueMayStart = (): boolean => {
    const t = top()
    return t === undefined ? !rootDone : t.state === 'value'
  }
  const valueEnded = () => {
    const t = top()
    if (t === undefined) rootDone = true
    else t.state = 'comma'
  }
  const childPointer = (): string => {
    const t = top()
    if (t === undefined) return ''
    return t.kind === 'object' ? `${t.pointer}/${pointerToken(t.current)}` : `${t.pointer}/${t.index}`
  }
  let i = 0
  while (i < text.length) {
    const ch = text[i]
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i++
    } else if (ch === '{' || ch === '[') {
      if (!valueMayStart()) return undefined
      const pointer = childPointer()
      stack.push(ch === '{'
        ? { kind: 'object', pointer, names: new Set(), state: 'name', current: '' }
        : { kind: 'array', pointer, index: 0, state: 'value' })
      i++
    } else if (ch === '}' || ch === ']') {
      const t = stack.pop()
      if (t === undefined) return undefined
      if (ch === '}') {
        if (t.kind !== 'object') return undefined
        if (!(t.state === 'comma' || (t.state === 'name' && t.names.size === 0))) return undefined
      } else {
        if (t.kind !== 'array') return undefined
        if (!(t.state === 'comma' || (t.state === 'value' && t.index === 0))) return undefined
      }
      valueEnded()
      i++
    } else if (ch === ',') {
      const t = top()
      if (t === undefined || t.state !== 'comma') return undefined
      if (t.kind === 'object') t.state = 'name'
      else {
        t.index++
        t.state = 'value'
      }
      i++
    } else if (ch === ':') {
      const t = top()
      if (t === undefined || t.kind !== 'object' || t.state !== 'colon') return undefined
      t.state = 'value'
      i++
    } else if (ch === '"') {
      const s = readJsonString(text, i)
      if (s === undefined) return undefined
      const t = top()
      if (t !== undefined && t.kind === 'object' && t.state === 'name') {
        if (t.names.has(s.value)) return `${t.pointer}/${pointerToken(s.value)}`
        t.names.add(s.value)
        t.current = s.value
        t.state = 'colon'
      } else {
        if (!valueMayStart()) return undefined
        valueEnded()
      }
      i = s.end
    } else {
      // A number or a literal. Its exact grammar is JSON.parse's to check.
      if (!valueMayStart()) return undefined
      let j = i
      while (j < text.length && !' \t\n\r,:[]{}"'.includes(text[j])) j++
      valueEnded()
      i = j
    }
  }
  return stack.length === 0 && rootDone ? null : undefined
}

// Pointers are printed as JSON strings with every code unit above U+007F
// escaped, the same bytes Python's json.dumps writes, so the two runners print
// identical refusals.
const printPointer = (p: string) =>
  JSON.stringify(p).replace(/[\u0080-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)

function runFile(label: string, path: string, isDev: boolean): void {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (err) {
    fail(`${label}: cannot read or parse ${path}: ${(err as Error).message}`)
    return
  }
  const duplicate = findDuplicateMember(text)
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch (err) {
    fail(`${label}: cannot read or parse ${path}: ${(err as Error).message}`)
    return
  }
  if (duplicate === undefined) {
    fail(`${label}: the duplicate-name scanner could not follow ${path}, which JSON.parse accepted`)
    return
  }
  if (duplicate !== null) {
    fail(`${label}: duplicate JSON member name at ${printPointer(duplicate)}, file refused before any case is evaluated`)
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

// Duplicate-name scanner, directly. Each literal is the raw JSON text, written
// as an ordinary string with doubled backslashes so that a \u escape reaches the
// scanner as six characters. Each must also parse, so a scanner verdict is never
// about malformed input. The same literals and expected pointers are in
// verify.py.
const ASTRAL = '\u{1D4B3}'
const duplicateUnit: [string, string | null][] = [
  ['{"a": 1, "b": 2, "a": 3}', '/a'],
  ['{"cases": [{"input": {"scope": {"epoch": "E0", "epoch": "E1"}}}]}', '/cases/0/input/scope/epoch'],
  ['{"x": [{"k": 1}, {"k": 1, "k": 2}]}', '/x/1/k'],
  ['{"a": 1, "\\u0061": 2}', '/a'],
  ['{"' + ASTRAL + '": 1, "\\ud835\\udcb3": 2}', '/' + ASTRAL],
  ['{"x/y~z": 1, "x/y~z": 2}', '/x~1y~0z'],
  ['{"q\\"": 1, "q\\u0022": 2}', '/q"'],
  ['{"b\\\\": 1, "b\\u005c": 2}', '/b\\'],
  ['{"p": {"a": 1}, "q": {"a": 2}}', null],
  ['{"a": {"a": {"a": 1}}}', null],
  ['{"s": [{"a": 1}, {"a": 1}], "t": [[{"a": 1}], [{"a": 2}]]}', null],
  ['{"t": "\\"a\\": 1", "a": 1}', null],
  ['{"t": "{\\"a\\": 1, \\"a\\": 2}", "u": ["\\"a\\"", "a"], "a": 1}', null],
  ['{"k\\"{[,:\\\\]}": "v\\"{[,:\\\\]}", "k\\"{[,:\\\\]}\\"": 1, "": 0, "\\\\": [], "\\"": {}}', null],
]
for (const [text, want] of duplicateUnit) {
  let parses = true
  try {
    JSON.parse(text)
  } catch {
    parses = false
  }
  const got = findDuplicateMember(text)
  const shown = printPointer(text)
  if (!parses) fail(`duplicate-name self-test literal does not parse: ${shown}`)
  else if (got !== want) fail(`findDuplicateMember(${shown}) is ${got === undefined ? 'unscannable' : got === null ? 'none' : printPointer(got)}, expected ${want === null ? 'none' : printPointer(want)}`)
  else say(`  ok   findDuplicateMember(${shown}) is ${want === null ? 'none' : printPointer(want)}`)
}

if (failures.length > 0) {
  console.error(`\nteardown-accounting TypeScript: FAILED, ${failures.length} problem(s)`)
  process.exit(1)
}
say(`\nteardown-accounting TypeScript: passed`)
