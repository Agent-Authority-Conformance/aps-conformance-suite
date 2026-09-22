// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// N1's different tool keys retain two live denials for one effect/context.
// This harness regression tests exact-ref release. A7 covers supersession.
import assert from 'node:assert/strict'
import { EnforcementPoint, FRESH_PATH_CONTROL, ResourceStore, type EffectIdentity } from '../../fixtures/runtime-authority-denial-continuity/harness.js'

const effect: EffectIdentity = { resource: 'record:44', transition: 'unavailable', domain: 'records' }
const context = 'ctx-n1-live'
const tools = ['delete_record', 'overwrite_record'] as const
let passed = 0
let failed = 0

function test(name: string, run: () => void): void {
  try {
    run()
    passed += 1
    console.log(`  ok   ${name}`)
  } catch (error) {
    failed += 1
    console.error(`  FAIL ${name}`, error)
  }
}

function fresh(): EnforcementPoint {
  const point = new EnforcementPoint(FRESH_PATH_CONTROL, new ResourceStore())
  point.deny('D1', tools[0], effect, context, 'insufficient_authority')
  point.deny('D2', tools[1], effect, context, 'insufficient_authority')
  assert.equal(point['ledger'].size, 2)
  assert.deepEqual([...point['ledger'].values()].map(r => [r.denialRef, r.resolved]), [['D1', false], ['D2', false]])
  return point
}

// Inspect private state without adding a production inspection API.
function state(point: EnforcementPoint): unknown {
  return structuredClone({ generation: point['generation'], records: [...point['ledger'].values()] })
}

function rejected(point: EnforcementPoint, target: EffectIdentity, ctx: string, ref: string | null, reason: string): void {
  const before = state(point)
  const audit = structuredClone(point.audit)
  assert.deepEqual(point.reauthorize('REJECT', target, ctx, ref, 'must_not_apply'), { decision: 'deny', reason })
  assert.deepEqual(state(point), before)
  assert.deepEqual(point.audit.slice(0, audit.length), audit)
  assert.deepEqual(point.audit.slice(audit.length), [{
    request: 'REJECT', kind: 'reauthorize', tool: null, effect: target,
    context: ctx, decision: 'deny', reason,
  }])
}

function stillDenied(point: EnforcementPoint): void {
  for (const tool of tools) {
    assert.deepEqual(point.attempt(`RETRY-${tool}`, tool, effect, context), {
      decision: 'deny', reason: 'denied_effect_continuity',
    })
  }
}

for (const [index, ref] of ['D1', 'D2'].entries()) {
  test(`release ${ref} only`, () => {
    const point = fresh()
    const other = structuredClone([...point['ledger'].values()][1 - index])
    assert.deepEqual(point.reauthorize('RELEASE', effect, context, ref, 'approved'), { decision: 'allow', reason: 'reauthorized' })
    assert.equal(point['generation'], 1)
    const records = [...point['ledger'].values()]
    assert.equal(records[index].resolved, true)
    assert.equal(records[index].resolvedAtGeneration, 1)
    assert.equal(records[index].resolvedBasis, 'approved')
    assert.deepEqual(records[1 - index], other)
    assert.deepEqual(point.attempt('RETRY-RELEASED', tools[index], effect, context), { decision: 'allow', reason: 'reauthorized' })
    assert.deepEqual(point.attempt('RETRY-SIBLING', tools[1 - index], effect, context), { decision: 'deny', reason: 'denied_effect_continuity' })
  })
}

for (const ref of ['wrong-ref', null]) {
  test(`reject ${String(ref)} with two live records`, () => {
    const point = fresh()
    rejected(point, effect, context, ref, ref === null ? 'reauthorize_denial_ref_required' : 'reauthorize_denial_ref_not_found')
    stillDenied(point)
  })
}

test('reject superseded D1 with two live records', () => {
  const point = fresh()
  point.deny('D1-new', tools[0], effect, context, 'new_denial')
  assert.equal(point['ledger'].size, 2)
  rejected(point, effect, context, 'D1', 'reauthorize_denial_ref_not_found')
  stillDenied(point)
})

for (const [name, target, ctx] of [
  ['resource', { ...effect, resource: 'record:45' }, context],
  ['transition', { ...effect, transition: 'updated' }, context],
  ['domain', { ...effect, domain: 'other' }, context],
  ['context', effect, 'other-context'],
] as const) {
  test(`reject D1 with wrong ${name}`, () => {
    const point = fresh()
    rejected(point, target, ctx, 'D1', 'reauthorize_denial_ref_not_found')
    stillDenied(point)
  })
}

test('reject already resolved ref without advancing generation', () => {
  const point = fresh()
  point.reauthorize('RELEASE', effect, context, 'D1', 'approved')
  rejected(point, effect, context, 'D1', 'reauthorize_denial_ref_not_found')
  assert.equal(point.attempt('RETRY-D2', tools[1], effect, context).decision, 'deny')
})

test('reject supplied ref on an empty ledger', () => {
  const point = new EnforcementPoint(FRESH_PATH_CONTROL, new ResourceStore())
  rejected(point, effect, context, 'D1', 'reauthorize_denial_ref_not_found')
})

test('allow A6 null-ref unrelated reauthorization without releasing either denial', () => {
  const point = fresh()
  const before = state(point)
  assert.deepEqual(point.reauthorize('A6', { ...effect, resource: 'record:45' }, context, null, 'unrelated'), { decision: 'allow', reason: 'reauthorized' })
  assert.deepEqual(state(point), before)
  stillDenied(point)
})

console.log(`${failed === 0 ? 'PASSED' : 'FAILED'}: N1 live-records regression, ${passed} passed, ${failed} failed`)
process.exitCode = failed === 0 ? 0 : 1
