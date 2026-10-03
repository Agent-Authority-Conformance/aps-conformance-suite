// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Usage: node checker/compare.ts <observed.json> <path to verax test-vectors> <out.json>
// Runs after run.ts. Reads each vector's expected.json and classifies the
// observation.
//
// Ordering rule: a vector's first failing stage can only be claimed as a
// MATCH when every stage earlier than it, in the vector set's twelve-stage
// order, was assessed. inputs-binding (stage 5) qualifies: stages 1 to 4 are
// all assessed. checkpoint-signature, checkpoint-coverage and
// checkpoint-totals (stages 9 to 11) do not: effect-binding, index and
// approval-signature (stages 6 to 8) sit in front of them and are not
// assessed. For those three, reaching the expected stage as the first
// failure among the stages this checker runs is reported as REACHED rather
// than MATCH, because a ledger that fails one of stages 6 to 8 first would
// read the same way here.

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { ASSESSED, STAGE_ORDER } from './verify.ts'

const [obsPath, root, out] = process.argv.slice(2)
const obs = JSON.parse(readFileSync(obsPath, 'utf8')).results
const assessedSet = new Set<string>(ASSESSED)
const orderIndex = new Map((STAGE_ORDER as readonly string[]).map((s, i) => [s, i]))
const earlierStagesAllAssessed = (stage: string): boolean => {
  const idx = orderIndex.get(stage)!
  for (let i = 0; i < idx; i++) if (!assessedSet.has(STAGE_ORDER[i])) return false
  return true
}

const rows = obs.map((r: any) => {
  const exp = JSON.parse(readFileSync(join(root, 'v1', r.id, 'expected.json'), 'utf8'))
  const stage: string | null = exp.first_failing_stage
  const inScope = stage !== null && assessedSet.has(stage)
  let cls: string
  if (inScope) {
    if (earlierStagesAllAssessed(stage)) {
      cls = r.firstFailingStage === stage ? 'MATCH' : 'MISMATCH'
    } else {
      cls = r.firstFailingStage === stage ? 'REACHED, earlier stages 6 to 8 not assessed' : 'MISMATCH'
    }
  } else {
    cls = r.outcome === 'NO_FAILURE_IN_ASSESSED_STAGES'
      ? (stage === null ? 'CONSISTENT, later stages not assessed' : `CONSISTENT, named stage ${stage} not assessed`)
      : 'MISMATCH'
  }
  const hashes = Array.isArray(exp.record_hashes)
    ? (JSON.stringify(exp.record_hashes) === JSON.stringify(r.recordHashes) ? 'equal' : 'DIFFER')
    : 'absent'
  return { id: r.id, expected: exp.expected_result, expectedStage: stage, observed: r.firstFailingStage, classification: cls, recordHashes: hashes }
})
for (const x of rows) console.log(`${x.id.padEnd(34)} exp ${String(x.expectedStage ?? 'VALID').padEnd(22)} obs ${String(x.observed ?? '-').padEnd(18)} ${x.classification}  hashes ${x.recordHashes}`)
const tally = rows.reduce((a: Record<string, number>, x: any) => { const k = x.classification.split(',')[0]; a[k] = (a[k] ?? 0) + 1; return a }, {})
console.log('tally', JSON.stringify(tally))
writeFileSync(out, JSON.stringify({ rows, tally }, null, 2) + '\n')
process.exit(rows.some((x: any) => x.classification === 'MISMATCH' || x.recordHashes === 'DIFFER') ? 1 : 0)
