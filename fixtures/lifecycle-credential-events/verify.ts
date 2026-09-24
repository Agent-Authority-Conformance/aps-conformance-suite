// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the lifecycle-credential-events candidate family.
//
// Replays every boundary in vectors.json against the reference verifier and
// against fourteen negative controls, and checks:
//
//   1. the reference verifier reproduces the declared verdict and reason,
//   2. the record it writes is byte-identical to the pinned RFC 8785 canonical
//      bytes, checked by SHA-256 over those bytes and by byte length,
//   3. no boundary whose declared verdict is invalid or not established ever
//      comes out valid, stated as its own assertion rather than left implicit,
//   4. no check resolves to established_valid from a missing record: every
//      established_valid names a basis other than "no ... record", and every
//      declared check appears exactly once in the record,
//   5. the verdict is the declared join of the check results, recomputed from
//      the record's own check list rather than taken from the harness,
//   6. a later boundary references the earlier record by digest and the earlier
//      record is unchanged after the later one ran,
//   7. every vector carries the candidate_against_proposed label and names the
//      CASES.md case id and the proposed sections it tests,
//   8. each control fails exactly its declared record set and changes exactly
//      its declared verdict set, running against its whole declared scope and
//      not only the predicted entries.
//
// No network, no wall clock, no APS type. Everything is read from vectors.json
// and chain.json.
//
// From the suite root:
//
//     npm run verify:lifecycle-credential-events

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CHECK_IDS,
  CONTROL_POLICIES,
  REFERENCE_VERIFIER,
  canonicalRecordBytes,
  evaluateVector,
  recordDigest,
  type Boundary,
  type CheckId,
  type CredentialEventRecord,
  type PolicyProfile,
  type Verdict,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

interface VectorBoundary {
  boundary_id: string
  gateway_now: string
  credential: Boundary['credential']
  trust_policy: Boundary['trust_policy']
  events: Boundary['events']
  prior_record_sha256: string | null
  expected: {
    verdict: Verdict
    verdict_reason: string
    record: CredentialEventRecord
    canonical_bytes_len: number
    canonical_sha256: string
  }
}

interface VectorCase {
  id: string
  case_id: string | null
  group: string
  role: string
  label: string
  description: string
  proposed_text: { repository: string; commit: string; sections: string[]; case_id: string | null }
  draft_03: { states_the_rule: boolean; note: string }
  boundaries: VectorBoundary[]
}

interface Control {
  name: string
  axis: string
  scope: string[]
  must_fail: string[]
  must_change_verdict: string[]
}

interface Vectors {
  family: string
  label: string
  credential_ref: string
  check_ids: CheckId[]
  controls: Control[]
  cases: VectorCase[]
}

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors
const chain = JSON.parse(readFileSync(join(here, 'chain.json'), 'utf8')) as {
  chain: Array<{ delegation_id: string }>
}

const failures: string[] = []
const fail = (msg: string) => failures.push(msg)

if (chain.chain[1]?.delegation_id !== vectors.credential_ref) {
  fail(
    `credential_ref ${vectors.credential_ref} does not match chain.json leaf ` +
    `${chain.chain[1]?.delegation_id}. Re-run mint.py and the generator.`,
  )
}

const declaredCheckIds = [...vectors.check_ids].sort().join(',')
if (declaredCheckIds !== [...CHECK_IDS].sort().join(',')) {
  fail('vectors.json check_ids and harness.ts CHECK_IDS disagree')
}

function boundariesOf(c: VectorCase): Boundary[] {
  return c.boundaries.map(b => ({
    boundary_id: b.boundary_id,
    gateway_now: b.gateway_now,
    credential: b.credential,
    trust_policy: b.trust_policy,
    events: b.events,
    prior_record_sha256: b.prior_record_sha256,
  }))
}

/** Independently recompute the join from a record's own check list, so the
 *  verdict is checked against the stated rule and not only against the harness
 *  that produced it. */
function joinFromRecord(record: CredentialEventRecord): { verdict: Verdict; reason: string } {
  const inOrder = record.required_checks.map(id => {
    const entry = record.checks.find(c => c.check_id === id)
    if (!entry) throw new Error(`record for ${record.vector_id} has no entry for ${id}`)
    return entry
  })
  const invalid = inOrder.find(c => c.result === 'established_invalid')
  if (invalid) return { verdict: 'invalid', reason: `${invalid.check_id}:${invalid.reason}` }
  const unestablished = inOrder.find(c => c.result === 'not_established')
  if (unestablished) {
    return { verdict: 'not established', reason: `${unestablished.check_id}:${unestablished.reason}` }
  }
  return { verdict: 'valid', reason: 'every_declared_check_established' }
}

type Divergence = { record: boolean; verdict: boolean; lines: string[] }

function runCase(c: VectorCase, policy: PolicyProfile): Divergence {
  let records: CredentialEventRecord[]
  try {
    records = evaluateVector(boundariesOf(c), vectors.credential_ref, policy, c.id, c.case_id)
  } catch (err) {
    return { record: true, verdict: true, lines: [`${c.id}: threw under ${policy.name}: ${(err as Error).message}`] }
  }
  const out: Divergence = { record: false, verdict: false, lines: [] }
  for (let i = 0; i < c.boundaries.length; i++) {
    const want = c.boundaries[i].expected
    const got = records[i]
    const bytes = canonicalRecordBytes(got)
    const digest = recordDigest(got)
    const verdictDiffers = got.verdict !== want.verdict || got.verdict_reason !== want.verdict_reason
    const recordDiffers =
      verdictDiffers ||
      digest !== want.canonical_sha256 ||
      Buffer.byteLength(bytes, 'utf8') !== want.canonical_bytes_len
    if (verdictDiffers) out.verdict = true
    if (recordDiffers) {
      out.record = true
      out.lines.push(
        `${c.boundaries[i].boundary_id}: want ${want.verdict}/${want.verdict_reason} ` +
        `sha256=${want.canonical_sha256.slice(0, 16)}, got ${got.verdict}/${got.verdict_reason} ` +
        `sha256=${digest.slice(0, 16)}`,
      )
    }
  }
  return out
}

// ── 1 to 7: the reference verifier ────────────────────────────────────────

let boundaryCount = 0
const perVectorOk = new Map<string, boolean>()

for (const c of vectors.cases) {
  if (c.label !== 'candidate_against_proposed') {
    fail(`${c.id}: label is ${c.label}, every vector in this family is candidate_against_proposed`)
  }
  if (c.proposed_text.repository !== 'aeoess/agent-authority-lifecycle') {
    fail(`${c.id}: proposed_text.repository is ${c.proposed_text.repository}`)
  }
  if (!Array.isArray(c.proposed_text.sections) || c.proposed_text.sections.length === 0) {
    fail(`${c.id}: names no proposed text section`)
  }
  if (c.id !== 'CE-00-positive-control-every-check-established') {
    if (typeof c.case_id !== 'string' || !/^LC-[A-Z]-\d{3}$/.test(c.case_id)) {
      fail(`${c.id}: case_id ${String(c.case_id)} is not a CASES.md case id`)
    } else if (!c.id.startsWith(c.case_id)) {
      fail(`${c.id}: vector id does not carry its case id ${c.case_id}`)
    }
  }

  const diverged = runCase(c, REFERENCE_VERIFIER)
  perVectorOk.set(c.id, !diverged.record)
  for (const line of diverged.lines) fail(`reference-verifier ${line}`)

  const records = evaluateVector(
    boundariesOf(c),
    vectors.credential_ref,
    REFERENCE_VERIFIER,
    c.id,
    c.case_id,
  )

  for (let i = 0; i < c.boundaries.length; i++) {
    boundaryCount += 1
    const bid = c.boundaries[i].boundary_id
    const want = c.boundaries[i].expected
    const got = records[i]

    // (3) never valid where the vector declares otherwise.
    if (want.verdict !== 'valid' && got.verdict === 'valid') {
      fail(`${bid}: came out valid where the vector declares ${want.verdict}`)
    }

    // (4) every declared check appears exactly once, and no established_valid
    // rests on an absent record.
    const declared = got.required_checks
    if (new Set(declared).size !== declared.length) {
      fail(`${bid}: required_checks repeats a check id`)
    }
    for (const id of declared) {
      const entries = got.checks.filter(x => x.check_id === id)
      if (entries.length !== 1) {
        fail(`${bid}: ${id} appears ${entries.length} times in the record`)
      }
    }
    if (got.checks.length !== declared.length) {
      fail(`${bid}: record carries ${got.checks.length} checks for ${declared.length} declared`)
    }
    for (const entry of got.checks) {
      if (entry.result === 'established_valid' && /^no /.test(entry.basis)) {
        fail(
          `${bid}: ${entry.check_id} is established_valid on basis "${entry.basis}", ` +
          `which names an absent record`,
        )
      }
      if (entry.reason.endsWith('_treated_as_passed')) {
        fail(`${bid}: ${entry.check_id} carries a control-only reason under the reference verifier`)
      }
    }

    // (5) the verdict is the join, recomputed from the record itself.
    const rejoin = joinFromRecord(got)
    if (rejoin.verdict !== got.verdict || rejoin.reason !== got.verdict_reason) {
      fail(
        `${bid}: verdict ${got.verdict}/${got.verdict_reason} is not the join of its own ` +
        `check list (${rejoin.verdict}/${rejoin.reason})`,
      )
    }

    // (6) a later boundary references the earlier record and does not change it.
    if (i > 0) {
      const priorDigest = recordDigest(records[i - 1])
      if (got.prior_record_sha256 !== priorDigest) {
        fail(
          `${bid}: prior_record_sha256 ${String(got.prior_record_sha256)} is not the digest of ` +
          `the record written at ${records[i - 1].boundary_id ?? c.boundaries[i - 1].boundary_id}`,
        )
      }
      if (priorDigest !== c.boundaries[i - 1].expected.canonical_sha256) {
        fail(
          `${c.boundaries[i - 1].boundary_id}: record changed after a later boundary ran; ` +
          `pinned ${c.boundaries[i - 1].expected.canonical_sha256}, now ${priorDigest}`,
        )
      }
    }
  }
}

// ── 8: the negative controls ──────────────────────────────────────────────

const controlLines: string[] = []
for (const control of vectors.controls) {
  const policy = CONTROL_POLICIES[control.name]
  if (!policy) {
    fail(`control ${control.name} has no policy in harness.ts`)
    continue
  }
  const scope = vectors.cases.filter(c => control.scope.includes(c.id))
  if (scope.length !== control.scope.length) {
    fail(`control ${control.name}: scope names a vector id that is not in this family`)
  }
  if (scope.length === 0) {
    fail(`control ${control.name}: empty scope`)
  }
  const failed: string[] = []
  const changedVerdict: string[] = []
  for (const c of scope) {
    const d = runCase(c, policy)
    if (d.record) failed.push(c.id)
    if (d.verdict) changedVerdict.push(c.id)
  }
  const same = (a: string[], b: string[]) => {
    const x = [...a].sort()
    const y = [...b].sort()
    return x.length === y.length && x.every((v, i) => v === y[i])
  }
  if (!same(failed, control.must_fail)) {
    fail(
      `control ${control.name}: declared record-divergence set [${[...control.must_fail].sort().join(', ')}], ` +
      `observed [${[...failed].sort().join(', ')}]`,
    )
  }
  if (!same(changedVerdict, control.must_change_verdict)) {
    fail(
      `control ${control.name}: declared verdict-change set [${[...control.must_change_verdict].sort().join(', ')}], ` +
      `observed [${[...changedVerdict].sort().join(', ')}]`,
    )
  }
  if (!changedVerdict.every(id => failed.includes(id))) {
    fail(`control ${control.name}: a verdict change that is not also a record divergence`)
  }
  controlLines.push(
    `  ${control.name} (${control.axis}): ran ${scope.length}, ` +
    `record diverged on ${failed.length}, verdict changed on ${changedVerdict.length}`,
  )
}

// every control policy in the harness is declared in vectors.json
for (const name of Object.keys(CONTROL_POLICIES)) {
  if (!vectors.controls.some(c => c.name === name)) {
    fail(`harness.ts defines control ${name} which vectors.json does not declare`)
  }
}

for (const c of vectors.cases) {
  console.log(`${perVectorOk.get(c.id) ? 'PASS' : 'FAIL'} ${c.id}`)
}
console.log('controls:')
for (const line of controlLines) console.log(line)

if (failures.length > 0) {
  console.error('')
  for (const f of failures) console.error(`FAIL ${f}`)
  console.error(`\nlifecycle-credential-events TypeScript: ${failures.length} failure(s)`)
  process.exit(1)
}

console.log(
  `\nPASSED: lifecycle-credential-events TypeScript, ${vectors.cases.length} vectors, ` +
  `${boundaryCount} boundaries, reference verifier matched every pinned record, ` +
  `each of ${vectors.controls.length} controls diverged on exactly its declared set`,
)
