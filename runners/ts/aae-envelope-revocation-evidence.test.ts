// Regression test for the aae-envelope adapter's fixture-supplied revocation state.
//
// interop/aae-envelope/verify.ts calls verifyDelegation with
// revocationCheckPolicy 'fail_closed'. Until 6fa874a it supplied
// cachedRevocationState only for a revoked status, so every node with status
// "active" had absent evidence, the SDK reported it valid=false with only the
// fail_closed missing-evidence error, and the runner still decided V1 ACCEPT
// and reported 4/4 because it never read `valid`. This test keeps that from
// coming back:
//
//   1. fixtureRevocationState maps explicit "active" to fresh {revoked:false},
//      "revoked" to {revoked:true}, and missing or unrecognized status to
//      absent evidence. fail_closed is never relaxed.
//   2. The old mapping (absent evidence for "active") is caught: decideChain
//      alone still says ACCEPT for V1 (the false ACCEPT the old runner
//      reported), the per-node guard flags both nodes, and the full verifyChain
//      rejects with NODE_INVALID.
//   3. Missing status, unknown status and explicit active, each on its own.
//   4. The per-node guard is independent of the chain verdict: V2's nodes are
//      both valid and the chain is still REJECT / SCOPE_WIDENING.
//
// Revocation state here is fixture-supplied, never live revocation resolution.
//
// Section 5 is a clock probe, not a conformance assertion. verifyDelegation
// reads Date.now() and has no evaluation-instant option, so V3 is evaluated at
// explicit instants by overriding Date.now in this process. It records that
// the adapter, which does not compare parent and child validity windows,
// ACCEPTS V3 at 2026-02-01T00:00:00Z. AAE -02 section 3 and section 5 step 9
// require the child window to nest in the parent's, and V3's does not. If the
// adapter gains a nesting check, this section fails and the README
// clarification must be updated with it.
//
// Run: npx tsx runners/ts/aae-envelope-revocation-evidence.test.ts

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  type AaeEnvelope,
  type FixtureRevocationState,
  aaeToApsDelegation,
  decideChain,
  fixtureRevocationState,
  validAgreement,
  verifyChain,
  verifyNodes,
} from '../../interop/aae-envelope/verify.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DIR = join(__dirname, '..', '..', 'interop', 'aae-envelope')
const load = (f: string): AaeEnvelope => JSON.parse(readFileSync(join(DIR, f), 'utf8'))
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v))

const MISSING = 'fail_closed: no revocation evidence supplied, revocation status unknown'

let failures = 0
function check(name: string, ok: boolean, detail?: unknown) {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}`)
  if (!ok) {
    failures++
    if (detail !== undefined) console.log(`       ${JSON.stringify(detail)}`)
  }
}

// The mapping before 6fa874a: evidence only for "revoked".
const oldMapping = (status: unknown, checkedAt: string): FixtureRevocationState =>
  status === 'revoked' ? { revoked: true, checkedAt } : undefined

function nodes(env: AaeEnvelope, mapping = fixtureRevocationState) {
  const cache = {}
  const dels = env.chain.map((c, i) =>
    aaeToApsDelegation(c, cache, i === 0 ? 0 : (c.depth ?? i), c.max_depth ?? 2),
  )
  const statuses = verifyNodes(env.chain, dels, new Date(Date.now()).toISOString(), mapping)
  return { dels, statuses }
}

const V1 = load('V1-narrowing-valid.json')
const V2 = load('V2-widened-scope-reject.json')
const V3 = load('V3-expired-parent-reject.json')
const V4 = load('V4-revoked-parent-cascade-reject.json')

console.log('aae-envelope fixture-supplied revocation state')

// ── 1. Mapping ──
console.log('1. mapping')
{
  const t = '2026-10-05T00:00:00.000Z'
  check('active -> {revoked:false, checkedAt}', JSON.stringify(fixtureRevocationState('active', t)) === JSON.stringify({ revoked: false, checkedAt: t }))
  check('revoked -> {revoked:true, checkedAt}', JSON.stringify(fixtureRevocationState('revoked', t)) === JSON.stringify({ revoked: true, checkedAt: t }))
  check('missing -> absent', fixtureRevocationState(undefined, t) === undefined)
  check('unknown "suspended" -> absent', fixtureRevocationState('suspended', t) === undefined)
  check('wrong case "ACTIVE" -> absent', fixtureRevocationState('ACTIVE', t) === undefined)
}

// ── 2. Old mapping is caught ──
console.log('2. old mapping (absent evidence for active) on V1')
{
  const { dels, statuses } = nodes(V1, oldMapping)
  for (let i = 0; i < statuses.length; i++) {
    const s = statuses[i]
    check(`node ${i}: SDK valid=false, evidence absent, only the missing-evidence error`,
      s.valid === false && s.revocationEvidence === 'absent' && JSON.stringify(s.errors) === JSON.stringify([MISSING]),
      { valid: s.valid, revocationEvidence: s.revocationEvidence, errors: s.errors })
  }
  const base = decideChain(V1.chain, dels, statuses)
  check('decideChain alone: ACCEPT (the false ACCEPT the old runner reported)', base.result === 'ACCEPT', base)
  const oldPass = base.result === V1.expected_result && (base.reason_code ?? null) === (V1.expected_reason_code ?? null)
  check('old pass criterion (result + reason code only) would have passed V1', oldPass)
  const g = validAgreement(statuses, V1.chain)
  check('per-node guard flags both nodes', g.disagreements.length === 2, g.disagreements)
  const d = verifyChain(V1, oldMapping)
  check('verifyChain with old mapping: REJECT / NODE_INVALID', d.result === 'REJECT' && d.reason_code === 'NODE_INVALID', d)
  check('runner pass criterion fails V1 under old mapping',
    !(d.result === V1.expected_result && (d.reason_code ?? null) === (V1.expected_reason_code ?? null) && d.disagreements.length === 0))
}

// ── 3. Missing, unknown, explicit active ──
console.log('3. per-status cases')
{
  const d = verifyChain(V1)
  const { statuses } = nodes(V1)
  check('explicit active (V1 as published): ACCEPT, valid [true,true], evidence fresh, no disagreement',
    d.result === 'ACCEPT' && d.valid.every(Boolean) && d.disagreements.length === 0 &&
      statuses.every((s) => s.revocationEvidence === 'fresh'), d)

  const missing = clone(V1)
  delete missing.chain[1].validity.revocation_check.status
  const dm = verifyChain(missing)
  check('missing status on child: REJECT / NODE_INVALID, node 1 invalid, guard flags node 1',
    dm.result === 'REJECT' && dm.reason_code === 'NODE_INVALID' &&
      dm.valid[0] === true && dm.valid[1] === false &&
      dm.disagreements.length === 1 && dm.disagreements[0].startsWith('node 1'), dm)

  const unknown = clone(V1)
  unknown.chain[0].validity.revocation_check.status = 'suspended'
  const du = verifyChain(unknown)
  check('unknown status "suspended" on parent: REJECT / NODE_INVALID, node 0 invalid, guard flags node 0',
    du.result === 'REJECT' && du.reason_code === 'NODE_INVALID' &&
      du.valid[0] === false && du.valid[1] === true &&
      du.disagreements.length === 1 && du.disagreements[0].startsWith('node 0'), du)

  const d4 = verifyChain(V4)
  check('explicit revoked (V4): REJECT / DELEGATION_REVOKED, no disagreement',
    d4.result === 'REJECT' && d4.reason_code === 'DELEGATION_REVOKED' && d4.disagreements.length === 0, d4)
}

// ── 4. Guard is per node, not compared with the chain verdict ──
console.log('4. per-node guard vs chain verdict')
{
  const d = verifyChain(V2)
  check('V2: both nodes valid, chain REJECT / SCOPE_WIDENING, no disagreement',
    d.valid.every(Boolean) && d.result === 'REJECT' && d.reason_code === 'SCOPE_WIDENING' && d.disagreements.length === 0, d)
}

// ── 5. V3 clock probe (documents the masked nesting gap) ──
console.log('5. V3 at explicit instants (Date.now override; clock probe, not a conformance assertion)')
{
  const realNow = Date.now
  const at = (iso: string) => {
    Date.now = () => Date.parse(iso)
    try {
      return verifyChain(V3)
    } finally {
      Date.now = realNow
    }
  }
  const before = at('2026-02-01T00:00:00Z')
  console.log(`       2026-02-01T00:00:00Z -> ${before.result}${before.reason_code ? ' / ' + before.reason_code : ''}, valid [${before.valid}]`)
  check('2026-02-01T00:00:00Z: adapter ACCEPTS V3 (no parent/child window nesting check)',
    before.result === 'ACCEPT' && before.valid.every(Boolean) && before.disagreements.length === 0, before)
  const after = at('2026-04-01T00:00:00Z')
  console.log(`       2026-04-01T00:00:00Z -> ${after.result}${after.reason_code ? ' / ' + after.reason_code : ''}, valid [${after.valid}]`)
  check('2026-04-01T00:00:00Z: REJECT / DELEGATION_EXPIRED',
    after.result === 'REJECT' && after.reason_code === 'DELEGATION_EXPIRED' && after.disagreements.length === 0, after)
  const early = at('2025-12-01T00:00:00Z')
  console.log(`       2025-12-01T00:00:00Z -> ${early.result}${early.reason_code ? ' / ' + early.reason_code : ''}, valid [${early.valid}]`)
  check('2025-12-01T00:00:00Z: REJECT / DELEGATION_NOT_YET_VALID',
    early.result === 'REJECT' && early.reason_code === 'DELEGATION_NOT_YET_VALID' && early.disagreements.length === 0, early)
}

if (failures > 0) {
  console.error(`\naae-envelope revocation-evidence: ${failures} check(s) FAILED`)
  process.exit(1)
}
console.log('\naae-envelope revocation-evidence: all checks passed')
