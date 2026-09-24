// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records what the published npm `agent-passport-system` package does with each
// group in this family, so SDK-RUNS.md's entries are reproducible rather than
// asserted.
//
// It reports, it does not judge. Nothing in draft-pidlisnyi-aps-03 asks the SDK
// for either behaviour here, so a `not_supported` line is an absence of a named
// surface, not a defect report and not a conformance result.
//
// The retention group has the nearest thing to a surface, `isRetentionExpired`,
// and the run below is worth reading closely: it is a maximum-retention check
// pointing the other way from what LC-G-005 needs. The probe runs it on every
// retention vector and prints both answers side by side rather than claiming
// they mean the same thing.
//
// Run: node fixtures/lifecycle-evidence-and-record/sdk-probe.mjs
// Exit 0 always.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import * as aps from 'agent-passport-system'

const HERE = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8'))
const version = JSON.parse(
  readFileSync(join(HERE, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version
const exported = Object.keys(aps).sort()

console.log(`agent-passport-system (npm) ${version}, ${exported.length} exports`)
console.log('')

// --- retention_restriction --------------------------------------------------

console.log('group retention_restriction: isRetentionExpired')
console.log('  The package\'s RetentionPolicy declares maxRetentionMs, documented in')
console.log('  dist/src/types/data-lifecycle.d.ts as "Max retention in milliseconds", with')
console.log('  onExpiry one of delete, quarantine, renegotiate. That is a ceiling: data must')
console.log('  not be kept longer than the policy allows. LC-G-005 is a floor: a record must')
console.log('  not be destroyed before its duty runs out. The probe maps the vector\'s')
console.log('  retention_years onto maxRetentionMs so the call can be made at all, and prints')
console.log('  what came back next to the fixture\'s own verdict. They are not the same')
console.log('  question and the two columns are not offered as agreeing.')
console.log('')

for (const c of vectors.cases.filter(v => v.group === 'retention_restriction')) {
  const r = c.input.record
  if (r.trigger_occurred_at === null) {
    console.log(`  ${c.id}  fixture: ${c.expected.verdict}/${c.expected.reason}`)
    console.log('    isRetentionExpired: not called, the SDK policy has no trigger-not-yet-occurred state')
    continue
  }
  const policy = { maxRetentionMs: r.retention_years * 365 * 24 * 60 * 60 * 1000, onExpiry: 'delete' }
  // isRetentionExpired reads the process clock, so this probe cannot pin the
  // evaluation instant the way the fixture does. Every vector's evaluated_at is
  // 2026-09-20 and this probe runs later than that, so a "true" here is only
  // evidence about the relationship between the trigger date and the run date.
  const expired = aps.isRetentionExpired(r.trigger_occurred_at, policy, 'persistent')
  console.log(`  ${c.id}  fixture: ${c.expected.verdict}/${c.expected.reason}`)
  console.log(`    isRetentionExpired(trigger=${r.trigger_occurred_at}, maxRetentionMs=${policy.maxRetentionMs}): ${expired}`)
  console.log(`    reads as: ${expired ? 'the ceiling has passed, so the policy says destroy' : 'the ceiling has not passed, so the policy permits keeping'}`)
  console.log(`    what LC-G-005 needs instead: whether destroying is permitted yet`)
}
console.log('')
console.log('  verdict for the group: not_supported. The call runs, but it answers the')
console.log('  opposite question and takes no external hold, so no vector in this group has')
console.log('  an SDK behavioural result. No export takes a minimum retention duty, a')
console.log('  retention trigger event, or a set of composable holds:')
for (const p of [
  { need: 'a minimum retention duty (a floor, not a ceiling)', pattern: /(minRetention|retentionFloor|preservationDuty|mustRetainUntil)/i },
  { need: 'a retention trigger event distinct from the record instant', pattern: /(retentionTrigger|triggerEvent|retentionClock)/i },
  { need: 'composable external holds released independently', pattern: /(legalHold|externalHold|releaseHold|holds)/i },
]) {
  const hits = exported.filter(n => p.pattern.test(n))
  console.log(`    ${p.need}: ${hits.length === 0 ? 'not_supported' : `present: ${hits.join(', ')}`}`)
}
console.log('')

// --- receipt_immutability ---------------------------------------------------

console.log('group receipt_immutability:')
for (const p of [
  {
    need: 'a query distinguishing what a receipt decided at its decision instant from what is true now',
    pattern: /(verdictAtDecisionTime|asOfDecision|decisionTimeView|historicalVerdict)/i,
  },
  {
    need: 'a later record that references a prior receipt as a correction or supersession',
    pattern: /(supersedesReceipt|correctsReceipt|referencesPriorReceipt|amendReceipt)/i,
  },
  {
    need: 'distinguishing new-information from void-from-inception as reasons on a later record',
    pattern: /(voidFromInception|neverValidlyIssued|defectiveAtIssuance)/i,
  },
]) {
  const hits = exported.filter(n => p.pattern.test(n))
  console.log(`  ${p.need}: ${hits.length === 0 ? 'not_supported' : `present: ${hits.join(', ')}`}`)
}
console.log('')
console.log('  The package does hash and chain receipts (hashReceiptForChain,')
console.log('  canonicalizeReceiptForId, canonicalizeReceiptForSig), which is the machinery a')
console.log('  bytes-unchanged check would sit on, and this fixture\'s LC-G-006-f is that')
console.log('  check expressed as a vector. What it does not have is any notion of two')
console.log('  different questions being asked of one receipt, which is what the group is about.')
