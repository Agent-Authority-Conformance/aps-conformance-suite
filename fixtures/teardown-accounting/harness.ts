// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the teardown-accounting candidate family.
//
// WHAT THIS IS. One input validator, one reference evaluator and one negative
// control for the proposed text in PROPOSED.md, which this file implements and
// does not extend. It is a reference model written to make that text
// executable. It is not APS, it speaks no protocol, and a result here is a
// statement about this model and nothing else.
//
// VALIDATION FIRST. validateInput runs over the whole input before any rule and
// returns every violation as an RFC 6901 JSON Pointer. A non-empty list is a
// fixture error: evaluate() returns it as a refusal and no rule runs, so a
// malformed input can never receive a verdict.
//
// INSTANTS. Date.parse is not used. It accepts strings without an offset and
// rolls invalid calendar dates forward, both of which PROPOSED.md makes errors.
// parseInstant applies the grammar in PROPOSED.md and computes the UTC instant
// exactly, as whole seconds plus the fraction's digits.
//
// DETERMINISM. Node builtins only, no imports. No randomness, no wall clock,
// no network. Every instant comes from the input.

export type Verdict = 'valid' | 'invalid' | 'not_established'

export interface Outcome {
  verdict: Verdict
  reason: string
}

export type Result = { kind: 'verdict'; outcome: Outcome } | { kind: 'fixture_error'; paths: string[] }

export const VERDICTS: readonly Verdict[] = ['valid', 'invalid', 'not_established']

/** Reason code to the only verdict it may accompany. */
export const REASONS: Readonly<Record<string, Verdict>> = {
  sink_configuration_not_established: 'not_established',
  runtime_binding_not_established: 'not_established',
  stop_admitting_not_established: 'not_established',
  cutoff_ordering_not_established: 'not_established',
  cutoff_ordering_independence_not_established: 'not_established',
  accepted_set_not_committed: 'not_established',
  accepted_descendant_missing_from_teardown: 'invalid',
  teardown_accounts_for_accepted_set_under_stipulated_basis: 'valid',
}

export const REQUIRED_STIPULATIONS: readonly string[] = [
  'sink configurations and runtime bindings are authentic',
  'admission sequence is append only',
  'distinct attestor identifiers denote distinct parties',
]

export const CONTROL_ID = 'C1-ordering-taken-as-given'

// ---------------------------------------------------------------------------
// Instants
// ---------------------------------------------------------------------------

/** A UTC instant: whole seconds since 1970-01-01T00:00:00Z plus the fraction's
 *  digits with trailing zeros removed. */
export interface Instant {
  seconds: number
  fraction: string
}

const INSTANT = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$/

function isLeap(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0
}

function daysInMonth(y: number, m: number): number {
  return [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
}

/** Days from 1970-01-01 to y-m-d in the proleptic Gregorian calendar. */
function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y
  const era = Math.floor(yy / 400)
  const yoe = yy - era * 400
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
}

/** Parses an instant under PROPOSED.md's grammar, or returns null. */
export function parseInstant(s: unknown): Instant | null {
  if (typeof s !== 'string') return null
  const m = INSTANT.exec(s)
  if (!m) return null
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number)
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo)) return null
  if (h > 23 || mi > 59 || se > 59) return null
  let offset = 0
  if (m[8] !== undefined) {
    const oh = Number(m[9])
    const om = Number(m[10])
    if (oh > 23 || om > 59) return null
    offset = (m[8] === '-' ? -1 : 1) * (oh * 3600 + om * 60)
  }
  const seconds = daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset
  return { seconds, fraction: (m[7] ?? '').replace(/0+$/, '') }
}

/** -1, 0 or 1. */
export function compareInstants(a: Instant, b: Instant): number {
  if (a.seconds !== b.seconds) return a.seconds < b.seconds ? -1 : 1
  const n = Math.max(a.fraction.length, b.fraction.length)
  const fa = a.fraction.padEnd(n, '0')
  const fb = b.fraction.padEnd(n, '0')
  return fa === fb ? 0 : fa < fb ? -1 : 1
}

function at(s: string): Instant {
  const v = parseInstant(s)
  // Unreachable after validation. Kept so a caller that skips validation fails
  // loudly instead of comparing garbage.
  if (v === null) throw new Error(`instant not validated: ${JSON.stringify(s)}`)
  return v
}

const le = (a: string, b: string) => compareInstants(at(a), at(b)) <= 0
const lt = (a: string, b: string) => compareInstants(at(a), at(b)) < 0

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

function pointer(base: string, token: string | number): string {
  return `${base}/${String(token).replace(/~/g, '~0').replace(/\//g, '~1')}`
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const isIdentifier = (v: unknown): v is string => typeof v === 'string' && v.length >= 1

const isInteger = (v: unknown): v is number =>
  typeof v === 'number' && Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER

type Check = (v: unknown, path: string, errors: string[]) => void

const identifier: Check = (v, p, e) => {
  if (!isIdentifier(v)) e.push(p)
}
const instant: Check = (v, p, e) => {
  if (parseInstant(v) === null) e.push(p)
}
const boolean: Check = (v, p, e) => {
  if (typeof v !== 'boolean') e.push(p)
}
const integerAtLeast = (min: number): Check => (v, p, e) => {
  if (!isInteger(v) || v < min) e.push(p)
}
const arrayOf = (item: Check): Check => (v, p, e) => {
  if (!Array.isArray(v)) {
    e.push(p)
    return
  }
  v.forEach((x, k) => item(x, pointer(p, k), e))
}
const closed = (members: Record<string, Check>): Check => (v, p, e) => {
  if (!isObject(v)) {
    e.push(p)
    return
  }
  for (const name of Object.keys(members)) {
    if (!Object.prototype.hasOwnProperty.call(v, name)) e.push(pointer(p, name))
    else members[name](v[name], pointer(p, name), e)
  }
  for (const name of Object.keys(v)) {
    if (!Object.prototype.hasOwnProperty.call(members, name)) e.push(pointer(p, name))
  }
}
const mapOf = (entry: Check): Check => (v, p, e) => {
  if (!isObject(v)) {
    e.push(p)
    return
  }
  for (const key of Object.keys(v)) {
    if (!isIdentifier(key)) e.push(pointer(p, key))
    else entry(v[key], pointer(p, key), e)
  }
}
const nullOr = (inner: Check): Check => (v, p, e) => {
  if (v !== null) inner(v, p, e)
}

const SCHEMA: Check = closed({
  stipulations: arrayOf(identifier),
  scope: closed({ declared_sinks: arrayOf(identifier), epoch: identifier, boundary: identifier }),
  sink_configurations: mapOf(closed({ epoch: identifier, accepts_only_through: identifier, digest: identifier })),
  runtime_bindings: mapOf(closed({ config_digest: identifier, from: instant, to: instant })),
  admissions: arrayOf(closed({ seq: integerAtLeast(1), descendant_id: identifier })),
  cutoff: closed({ at: instant, committed_final_seq: integerAtLeast(0), committed_members: arrayOf(identifier) }),
  cutoff_ordering_evidence: nullOr(closed({ attestor: identifier, covers_from: instant, covers_to: instant })),
  stop_admitting: closed({
    boundary: identifier,
    epoch: identifier,
    admits_epoch: boolean,
    asserted_by: identifier,
    observed_at: instant,
  }),
  teardown: closed({ processed: arrayOf(identifier) }),
})

/** Every violation, as sorted unique JSON Pointers. Empty means well formed. */
export function validateInput(input: unknown): string[] {
  const errors: string[] = []
  SCHEMA(input, '', errors)

  // Constraints across elements, checked where the shape allows.
  if (isObject(input)) {
    const stip = input.stipulations
    if (Array.isArray(stip)) {
      for (const s of REQUIRED_STIPULATIONS) if (!stip.includes(s)) errors.push('/stipulations')
    }
    const scope = input.scope
    if (isObject(scope) && Array.isArray(scope.declared_sinks)) {
      const sinks = scope.declared_sinks
      if (sinks.length === 0) errors.push('/scope/declared_sinks')
      sinks.forEach((s, k) => {
        if (isIdentifier(s) && sinks.indexOf(s) < k) errors.push(pointer('/scope/declared_sinks', k))
      })
    }
    const admissions = input.admissions
    if (Array.isArray(admissions)) {
      const ids = admissions.map(a => (isObject(a) && isIdentifier(a.descendant_id) ? a.descendant_id : undefined))
      ids.forEach((id, k) => {
        if (id !== undefined && ids.indexOf(id) < k) errors.push(`/admissions/${k}/descendant_id`)
      })
    }
  }
  return [...new Set(errors)].sort()
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface TeardownInput {
  stipulations: string[]
  scope: { declared_sinks: string[]; epoch: string; boundary: string }
  sink_configurations: Record<string, { epoch: string; accepts_only_through: string; digest: string }>
  runtime_bindings: Record<string, { config_digest: string; from: string; to: string }>
  admissions: { seq: number; descendant_id: string }[]
  cutoff: { at: string; committed_final_seq: number; committed_members: string[] }
  cutoff_ordering_evidence: null | { attestor: string; covers_from: string; covers_to: string }
  stop_admitting: { boundary: string; epoch: string; admits_epoch: boolean; asserted_by: string; observed_at: string }
  teardown: { processed: string[] }
}

/** Element-by-element equality: same length, then equal at every index. */
export function sameSequence(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false
  for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return false
  return true
}

const ne = (reason: string): Outcome => ({ verdict: 'not_established', reason })
const own = <T>(m: Record<string, T>, k: string): T | undefined =>
  Object.prototype.hasOwnProperty.call(m, k) ? m[k] : undefined

function rules(i: TeardownInput, checkOrdering: boolean): Outcome {
  const cut = i.cutoff.at

  // 1. Every declared sink: configuration, then runtime binding across the cutoff.
  for (const sink of i.scope.declared_sinks) {
    const c = own(i.sink_configurations, sink)
    if (!c || c.epoch !== i.scope.epoch || c.accepts_only_through !== i.scope.boundary) {
      return ne('sink_configuration_not_established')
    }
    const b = own(i.runtime_bindings, sink)
    if (!b || b.config_digest !== c.digest || !(le(b.from, cut) && le(cut, b.to))) {
      return ne('runtime_binding_not_established')
    }
  }

  // 2. The stop admitting observation, after the cutoff.
  const st = i.stop_admitting
  if (st.boundary !== i.scope.boundary || st.epoch !== i.scope.epoch || st.admits_epoch !== false || !lt(cut, st.observed_at)) {
    return ne('stop_admitting_not_established')
  }

  // 3. Cutoff ordering. The control takes present evidence as given.
  const ev = i.cutoff_ordering_evidence
  if (ev === null) return ne('cutoff_ordering_not_established')
  if (checkOrdering) {
    if (!(le(ev.covers_from, cut) && le(cut, ev.covers_to)) || !lt(ev.covers_to, st.observed_at)) {
      return ne('cutoff_ordering_not_established')
    }
    if (ev.attestor === st.asserted_by) return ne('cutoff_ordering_independence_not_established')
  }

  // 4. The cutoff commits to exactly the admission sequence.
  const ids = i.admissions.map(a => a.descendant_id)
  const numbered = i.admissions.every((a, k) => a.seq === k + 1)
  if (!numbered || i.cutoff.committed_final_seq !== ids.length || !sameSequence(i.cutoff.committed_members, ids)) {
    return ne('accepted_set_not_committed')
  }

  // 5. Every committed descendant appears in the teardown.
  const processed = new Set(i.teardown.processed)
  if (ids.some(d => !processed.has(d))) {
    return { verdict: 'invalid', reason: 'accepted_descendant_missing_from_teardown' }
  }

  // 6.
  return { verdict: 'valid', reason: 'teardown_accounts_for_accepted_set_under_stipulated_basis' }
}

function run(input: unknown, checkOrdering: boolean): Result {
  const paths = validateInput(input)
  if (paths.length > 0) return { kind: 'fixture_error', paths }
  return { kind: 'verdict', outcome: rules(input as TeardownInput, checkOrdering) }
}

/** The reference evaluator. */
export function evaluateReference(input: unknown): Result {
  return run(input, true)
}

/** C1-ordering-taken-as-given: identical validation and identical rules 1, 2,
 *  4, 5 and 6. Rule 3 returns cutoff_ordering_not_established for null
 *  evidence and otherwise skips the interval and attestor checks. */
export function evaluateControl(input: unknown): Result {
  return run(input, false)
}

/** One line per result, shared format with verify.py. */
export function formatResult(r: Result): string {
  return r.kind === 'verdict' ? `${r.outcome.verdict}/${r.outcome.reason}` : `fixture_error[${r.paths.join(',')}]`
}
