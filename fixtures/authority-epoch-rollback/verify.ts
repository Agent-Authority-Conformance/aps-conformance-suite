// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the authority-epoch-rollback candidate family.
//
// Replays every case against the reference policy and against three negative
// controls, each of which removes exactly one gate:
//
//   reference               must match every case
//   latest-read (N1)        no epoch comparison, run on the epoch-rollback group
//   unfenced-writer (N2)    no fencing-token check, run on the write-fencing group
//   correction-as-deletion  an accepted withdrawal deletes the revocation, run on
//     (N3)                  the revocation-correction group
//
// Each control is run on its own group only. Running N1 against the fencing group
// would let its epoch defect answer for a fencing failure and the fixture would
// stop attributing anything. Each control is still run against every case in its
// group, not only the ones predicted to fail, so an undeclared failure and a
// declared failure that quietly starts passing are both loud.
//
// Before any case runs, every record's RFC 8785 JCS digest is recomputed and
// compared against chains.json. A vector result over bytes that drifted would be
// a statement about the wrong bytes.
//
// Run: npx tsx fixtures/authority-epoch-rollback/verify.ts
// Exit 0 when the reference matched every case and each control failed exactly
// its declared set, 1 otherwise, 2 on a broken fixture.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS, verifyAuthorityDelegationChain } from 'agent-passport-system'

import {
  CORRECTION_AS_DELETION_POLICY,
  EpochPublicationStore,
  LATEST_READ_POLICY,
  REFERENCE_POLICY,
  UNFENCED_WRITER_POLICY,
  epochGate,
  keyResolverFor,
  revocationStillVerifies,
  type ChainsFixture,
  type Policy,
  type RevocationAnswer,
  type WriteOutcome,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(join(here, name), 'utf8')) as T
}

interface ExpectedWrite {
  token: number
  view: string
  expected: { accepted: boolean; reason: string | null }
}

interface Expected {
  resolver_answer: RevocationAnswer
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failure_code: string | null
  failure_index: number | null
  high_water_mark_after?: number
  published_epoch_after?: number
  presented_view_answer_if_unfenced?: RevocationAnswer
  withdrawal?: { accepted: boolean; reason: string | null }
  revocation_still_held?: boolean
  revocation_still_verifies?: boolean
  unfenced_writer_would_return?: string
  correction_as_deletion_would_return?: string
}

interface VectorCase {
  id: string
  group: 'epoch_rollback' | 'write_fencing' | 'revocation_correction'
  status: string
  role: string
  description: string
  verifier: { observed_epoch: number | null; retained_records_from_view: string | null }
  publication: { seed: null; writes: ExpectedWrite[] } | null
  presented_view: string
  expected: Expected
  unconstrained_by_source: boolean
  establishes_epoch_property: boolean
}

interface ControlDeclaration {
  defect?: string
  axis: string
  groups: string[]
  declared_failures?: string[]
  must_match?: string
}

interface Vectors {
  profile: string
  status: string
  cases: VectorCase[]
  control_policies: Record<string, ControlDeclaration>
}

const fixture = readJson<ChainsFixture>('chains.json')
const vectors = readJson<Vectors>('vectors.json')

// ── Fixture integrity, before anything is verified ────────────────────────────

function jcsDigest(value: unknown): string {
  return createHash('sha256').update(canonicalizeJCS(value), 'utf8').digest('hex')
}

let integrityFailures = 0
for (let i = 0; i < fixture.chain.length; i++) {
  const actual = jcsDigest(fixture.chain[i])
  if (actual !== fixture.digests.chain[i]) {
    console.error(`FAIL digest chain[${i}] declared=${fixture.digests.chain[i]} actual=${actual}`)
    integrityFailures += 1
  }
}
for (const [name, declared] of Object.entries(fixture.digests.records)) {
  const actual = jcsDigest(fixture.records[name])
  if (actual !== declared) {
    console.error(`FAIL digest record ${name} declared=${declared} actual=${actual}`)
    integrityFailures += 1
  }
}
if (integrityFailures > 0) {
  console.error('authority-epoch-rollback: chains.json digests do not match its own bytes')
  process.exit(2)
}
console.log(
  `digests ok: ${fixture.chain.length} chain members and ` +
    `${Object.keys(fixture.digests.records).length} records match their declared JCS sha256`,
)

if (vectors.cases.some(c => c.status !== 'candidate_against_proposed')) {
  console.error('authority-epoch-rollback: every case must be labelled candidate_against_proposed')
  process.exit(2)
}

// ── One case under one policy ────────────────────────────────────────────────

interface Observed {
  resolver_answer: RevocationAnswer
  state: string
  failure_code: string | null
  failure_index: number | null
  high_water_mark_after: number
  published_epoch_after: number | null
  presented_view_answer_if_unfenced: RevocationAnswer
  withdrawals: { accepted: boolean; reason: string | null }[]
  revocation_still_held: boolean
  revocation_still_verifies: boolean
  writes: WriteOutcome[]
}

function runCase(testCase: VectorCase, policy: Policy): Observed {
  const writes: WriteOutcome[] = []
  let presentedViewName = testCase.presented_view

  if (testCase.publication !== null) {
    const store = new EpochPublicationStore(policy.checkFencingToken)
    for (const write of testCase.publication.writes) {
      writes.push(store.write(write.token, write.view))
    }
    if (presentedViewName !== '$published') {
      throw new Error(`fixture is broken: ${testCase.id} has writes but does not read $published`)
    }
    presentedViewName = store.published()
  } else if (presentedViewName === '$published') {
    throw new Error(`fixture is broken: ${testCase.id} reads $published with no writes`)
  }

  const gate = epochGate(fixture, {
    observedEpoch: testCase.verifier.observed_epoch,
    retainedViewName: testCase.verifier.retained_records_from_view,
    presentedViewName,
    policy,
  })

  const result = verifyAuthorityDelegationChain(fixture.chain, {
    now: fixture.now,
    resolveVerificationKey: keyResolverFor(fixture),
    trustRoot: () => true,
    resolveRevocation: gate.resolve,
  })

  const first = Array.isArray(result.failures) ? result.failures[0] : undefined

  return {
    resolver_answer: gate.resolve(fixture.chain[0]),
    state: result.state,
    failure_code: (first as any)?.code ?? null,
    failure_index: typeof (first as any)?.index === 'number' ? (first as any).index : null,
    high_water_mark_after: gate.highWaterMarkAfter,
    published_epoch_after: testCase.publication === null ? null : gate.presentedEpoch,
    presented_view_answer_if_unfenced: gate.presentedAnswerForRoot,
    withdrawals: gate.presentedView.withdrawals.map(w => ({ accepted: w.accepted, reason: w.reason })),
    revocation_still_held: gate.presentedView.heldRevocations.includes('root-revocation'),
    revocation_still_verifies: revocationStillVerifies(fixture, 'root-revocation'),
    writes,
  }
}

function diff(testCase: VectorCase, observed: Observed): string[] {
  const expected = testCase.expected
  const problems: string[] = []

  const check = (label: string, want: unknown, got: unknown) => {
    if (JSON.stringify(want) !== JSON.stringify(got)) {
      problems.push(`${label}: expected ${JSON.stringify(want)}, observed ${JSON.stringify(got)}`)
    }
  }

  check('state', expected.state, observed.state)
  check('failure_code', expected.failure_code, observed.failure_code)
  check('failure_index', expected.failure_index, observed.failure_index)
  check('resolver_answer', expected.resolver_answer, observed.resolver_answer)

  if (expected.high_water_mark_after !== undefined) {
    check('high_water_mark_after', expected.high_water_mark_after, observed.high_water_mark_after)
  }
  if (expected.published_epoch_after !== undefined) {
    check('published_epoch_after', expected.published_epoch_after, observed.published_epoch_after)
  }
  if (expected.presented_view_answer_if_unfenced !== undefined) {
    check(
      'presented_view_answer_if_unfenced',
      expected.presented_view_answer_if_unfenced,
      observed.presented_view_answer_if_unfenced,
    )
  }
  if (expected.withdrawal !== undefined) {
    check('withdrawal', [expected.withdrawal], observed.withdrawals)
  }
  if (expected.revocation_still_held !== undefined) {
    check('revocation_still_held', expected.revocation_still_held, observed.revocation_still_held)
  }
  if (expected.revocation_still_verifies !== undefined) {
    check(
      'revocation_still_verifies',
      expected.revocation_still_verifies,
      observed.revocation_still_verifies,
    )
  }
  if (testCase.publication !== null) {
    const want = testCase.publication.writes.map(w => ({
      token: w.token,
      view: w.view,
      accepted: w.expected.accepted,
      reason: w.expected.reason,
    }))
    check('writes', want, observed.writes)
  }

  return problems
}

// ── Reference run ────────────────────────────────────────────────────────────

let referenceMatched = 0
const observedByPolicy = new Map<string, Map<string, Observed>>()

console.log('')
console.log('reference')
for (const testCase of vectors.cases) {
  const observed = runCase(testCase, REFERENCE_POLICY)
  observedByPolicy.set('reference', (observedByPolicy.get('reference') ?? new Map()).set(testCase.id, observed))
  const problems = diff(testCase, observed)
  if (problems.length === 0) {
    referenceMatched += 1
    const suffix = observed.failure_code === null ? '' : ` code=${observed.failure_code} index=${observed.failure_index}`
    console.log(`  PASS ${testCase.id} answer=${observed.resolver_answer} state=${observed.state}${suffix}`)
  } else {
    console.error(`  FAIL ${testCase.id}`)
    for (const problem of problems) console.error(`       ${problem}`)
  }
}

// ── Negative controls ────────────────────────────────────────────────────────

const controls: { policy: Policy; declaration: ControlDeclaration }[] = [
  { policy: LATEST_READ_POLICY, declaration: vectors.control_policies['latest-read'] },
  { policy: UNFENCED_WRITER_POLICY, declaration: vectors.control_policies['unfenced-writer'] },
  { policy: CORRECTION_AS_DELETION_POLICY, declaration: vectors.control_policies['correction-as-deletion'] },
]

let controlProblems = 0
for (const { policy, declaration } of controls) {
  const declared = new Set(declaration.declared_failures ?? [])
  const observedFailures = new Set<string>()
  const perCase = new Map<string, Observed>()

  console.log('')
  console.log(`${policy.name} (${declaration.axis} removed), cases in group(s): ${declaration.groups.join(', ')}`)
  for (const testCase of vectors.cases) {
    if (!declaration.groups.includes(testCase.group)) continue
    const observed = runCase(testCase, policy)
    perCase.set(testCase.id, observed)
    const problems = diff(testCase, observed)
    if (problems.length > 0) {
      observedFailures.add(testCase.id)
      console.log(`  fails ${testCase.id} observed state=${observed.state} answer=${observed.resolver_answer}`)
    } else {
      console.log(`  matches ${testCase.id}`)
    }
  }
  observedByPolicy.set(policy.name, perCase)

  for (const id of declared) {
    if (!observedFailures.has(id)) {
      console.error(`  FAIL ${policy.name} was declared to fail ${id} and it matched instead`)
      controlProblems += 1
    }
  }
  for (const id of observedFailures) {
    if (!declared.has(id)) {
      console.error(`  FAIL ${policy.name} failed ${id}, which is not in its declared set`)
      controlProblems += 1
    }
  }
}

// ── Declared control outcomes named inside a case ─────────────────────────────

for (const testCase of vectors.cases) {
  const wantUnfenced = testCase.expected.unfenced_writer_would_return
  if (wantUnfenced !== undefined) {
    const got = observedByPolicy.get('unfenced-writer')?.get(testCase.id)?.state
    if (got !== wantUnfenced) {
      console.error(
        `  FAIL ${testCase.id} declares unfenced-writer would return ${wantUnfenced}, observed ${String(got)}`,
      )
      controlProblems += 1
    } else {
      console.log(`  ok   ${testCase.id}: unfenced-writer returned ${got}, as declared`)
    }
  }
  const wantDeletion = testCase.expected.correction_as_deletion_would_return
  if (wantDeletion !== undefined) {
    const got = observedByPolicy.get('correction-as-deletion')?.get(testCase.id)?.state
    if (got !== wantDeletion) {
      console.error(
        `  FAIL ${testCase.id} declares correction-as-deletion would return ${wantDeletion}, observed ${String(got)}`,
      )
      controlProblems += 1
    } else {
      console.log(`  ok   ${testCase.id}: correction-as-deletion returned ${got}, as declared`)
    }
  }
}

// ── Tallies ──────────────────────────────────────────────────────────────────

const total = vectors.cases.length
const epochProperty = vectors.cases.filter(c => c.establishes_epoch_property).length
const unconstrained = vectors.cases.filter(c => c.unconstrained_by_source).map(c => c.id)

console.log('')
console.log(`authority-epoch-rollback TypeScript: ${referenceMatched}/${total} matched under reference`)
console.log(
  `  ${epochProperty} of ${total} cases discriminate a fenced implementation from an unfenced one; ` +
    `the rest are controls`,
)
console.log(`  outcome not determined by the proposed text, excluded from that count: ${unconstrained.join(', ')}`)

if (referenceMatched === total && controlProblems === 0) {
  console.log(
    'PASSED: reference matched every case, latest-read, unfenced-writer and ' +
      'correction-as-deletion each failed exactly their declared set',
  )
  process.exit(0)
}
console.error(`FAILED: reference ${referenceMatched}/${total}, control problems ${controlProblems}`)
process.exit(1)
