// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the conflicting-status-sources candidate family.
//
// Replays every boundary in vectors.json against the reference verifier and
// against three negative controls, and checks five things:
//
//   1. the reference verifier reproduces the declared decision and reason,
//   2. the record it writes is byte-identical to the pinned RFC 8785 canonical
//      bytes, checked by SHA-256 over those bytes,
//   3. no case whose declared decision is deny or not_established ever admits,
//      stated as its own assertion rather than left implicit in (1),
//   4. every offline admission carries the snapshot it admitted on and that
//      snapshot's age at the boundary, and a later boundary references the
//      earlier record by digest without changing it,
//   5. each negative control fails exactly the set the vectors declare for it,
//      running against every case of its property, not only the predicted ones.
//
// No network, no wall clock, no APS type. Everything is read from vectors.json
// and chain.json.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  DROP_STALE_THEN_DECIDE,
  LATEST_ANSWER_WINS,
  OFFLINE_ADMIT_WITHOUT_RECORDING,
  REFERENCE_VERIFIER,
  canonicalRecordBytes,
  evaluateCase,
  recordDigest,
  type Boundary,
  type PolicyProfile,
  type StatusObservationRecord,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

interface VectorBoundary {
  boundary_id: string
  evaluated_at: string
  trust_policy: Boundary['trust_policy']
  observations: Boundary['observations']
  prior_record_sha256: string | null
  expected: {
    decision: string
    reason: string
    record: StatusObservationRecord
    canonical_bytes_len: number
    canonical_sha256: string
  }
}

interface VectorCase {
  id: string
  property: 'C' | 'F' | 'O'
  role: string
  label: string
  boundaries: VectorBoundary[]
}

interface Control {
  name: string
  axis: string
  scope: string[]
  must_fail: string[]
}

interface Vectors {
  family: string
  label: string
  delegation_ref: string
  controls: Control[]
  cases: VectorCase[]
}

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors
const chain = JSON.parse(readFileSync(join(here, 'chain.json'), 'utf8')) as {
  chain: Array<{ delegation_id: string }>
}

const failures: string[] = []
const fail = (msg: string) => failures.push(msg)

if (chain.chain[0]?.delegation_id !== vectors.delegation_ref) {
  fail(
    `delegation_ref ${vectors.delegation_ref} does not match chain.json root ` +
    `${chain.chain[0]?.delegation_id}. Re-run mint.py and the generator.`,
  )
}

function boundariesOf(c: VectorCase): Boundary[] {
  return c.boundaries.map(b => ({
    boundary_id: b.boundary_id,
    evaluated_at: b.evaluated_at,
    trust_policy: b.trust_policy,
    observations: b.observations,
    prior_record_sha256: b.prior_record_sha256,
  }))
}

/** Run one case under one policy and report which boundaries diverged from
 *  the pinned record. A divergence in decision, reason or bytes all count. */
function runCase(c: VectorCase, policy: PolicyProfile): string[] {
  let records: StatusObservationRecord[]
  try {
    records = evaluateCase(boundariesOf(c), vectors.delegation_ref, policy)
  } catch (err) {
    return [`${c.id}: threw under ${policy.name}: ${(err as Error).message}`]
  }
  const diverged: string[] = []
  for (let i = 0; i < c.boundaries.length; i++) {
    const want = c.boundaries[i].expected
    const got = records[i]
    const bytes = canonicalRecordBytes(got)
    if (
      got.decision !== want.decision ||
      got.reason !== want.reason ||
      recordDigest(got) !== want.canonical_sha256 ||
      Buffer.byteLength(bytes, 'utf8') !== want.canonical_bytes_len
    ) {
      diverged.push(
        `${c.boundaries[i].boundary_id}: want ${want.decision}/${want.reason} ` +
        `sha256=${want.canonical_sha256.slice(0, 16)}, got ${got.decision}/${got.reason} ` +
        `sha256=${recordDigest(got).slice(0, 16)}`,
      )
    }
  }
  return diverged
}

// ── 1, 2, 3, 4: the reference verifier ────────────────────────────────────
let boundaryCount = 0
for (const c of vectors.cases) {
  if (c.label !== 'candidate_against_proposed') {
    fail(`${c.id}: label is ${c.label}, every case in this family is candidate_against_proposed`)
  }
  const diverged = runCase(c, REFERENCE_VERIFIER)
  for (const line of diverged) fail(`reference-verifier ${line}`)

  const records = evaluateCase(boundariesOf(c), vectors.delegation_ref, REFERENCE_VERIFIER)
  for (let i = 0; i < c.boundaries.length; i++) {
    boundaryCount += 1
    const want = c.boundaries[i].expected
    const got = records[i]

    // (3) never valid on a deny or a not_established.
    if (want.decision !== 'admit' && got.decision === 'admit') {
      fail(`${c.boundaries[i].boundary_id}: admitted where the vector declares ${want.decision}`)
    }

    // (4a) an offline admission records what it admitted on.
    if (got.verifier_mode === 'offline' && got.decision === 'admit') {
      const s = got.snapshot
      if (
        !s ||
        typeof s.source_id !== 'string' ||
        typeof s.as_of !== 'string' ||
        typeof s.age_s !== 'number' ||
        typeof s.declared_bound_s !== 'number'
      ) {
        fail(
          `${c.boundaries[i].boundary_id}: offline admission without a recorded snapshot ` +
          `source, as_of, age and declared bound`,
        )
      } else if (s.age_s > s.declared_bound_s) {
        fail(
          `${c.boundaries[i].boundary_id}: offline admission on a snapshot aged ${s.age_s}s ` +
          `past its declared bound ${s.declared_bound_s}s`,
        )
      }
    }

    // (4b) a conflict deny names the disagreeing states and sources.
    if (got.reason === 'status_sources_conflict') {
      if (!got.conflict || got.conflict.states.length < 2 || got.conflict.sources.length < 2) {
        fail(`${c.boundaries[i].boundary_id}: conflict deny without both states and sources named`)
      }
    }

    // (4c) a later boundary references the earlier record and does not change it.
    if (i > 0) {
      const priorDigest = recordDigest(records[i - 1])
      if (got.prior_record_sha256 !== priorDigest) {
        fail(
          `${c.boundaries[i].boundary_id}: prior_record_sha256 ${got.prior_record_sha256} ` +
          `is not the digest of the record written at ${records[i - 1].boundary_id}`,
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

// ── 5: the negative controls ──────────────────────────────────────────────
const POLICIES: Record<string, PolicyProfile> = {
  'latest-answer-wins': LATEST_ANSWER_WINS,
  'drop-stale-then-decide': DROP_STALE_THEN_DECIDE,
  'offline-admit-without-recording': OFFLINE_ADMIT_WITHOUT_RECORDING,
}

const controlLines: string[] = []
for (const control of vectors.controls) {
  const policy = POLICIES[control.name]
  if (!policy) {
    fail(`control ${control.name} has no policy in harness.ts`)
    continue
  }
  const scope = vectors.cases.filter(c => control.scope.includes(c.id))
  if (scope.length !== control.scope.length) {
    fail(`control ${control.name}: scope names a case id that is not in this family`)
  }
  const observed: string[] = []
  for (const c of scope) {
    if (runCase(c, policy).length > 0) observed.push(c.id)
  }
  const declared = [...control.must_fail].sort()
  const seen = [...observed].sort()
  const same = declared.length === seen.length && declared.every((v, i) => v === seen[i])
  if (!same) {
    fail(
      `control ${control.name}: declared fail set [${declared.join(', ')}], ` +
      `observed [${seen.join(', ')}]`,
    )
  }
  controlLines.push(
    `  ${control.name} (${control.axis}): ran ${scope.length} case(s), ` +
    `failed ${seen.length}, declared ${declared.length}`,
  )
}

for (const c of vectors.cases) {
  const ok = runCase(c, REFERENCE_VERIFIER).length === 0
  console.log(`${ok ? 'PASS' : 'FAIL'} ${c.id}`)
}
console.log('controls:')
for (const line of controlLines) console.log(line)

if (failures.length > 0) {
  console.error('')
  for (const f of failures) console.error(`FAIL ${f}`)
  console.error(`\nconflicting-status-sources TypeScript: ${failures.length} failure(s)`)
  process.exit(1)
}

console.log(
  `\nPASSED: conflicting-status-sources TypeScript, ${vectors.cases.length} cases, ` +
  `${boundaryCount} boundaries, reference verifier matched every pinned record, ` +
  `each control failed exactly its declared set`,
)
