// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Usage: node checker/compare.ts <observed.json> <path to verax test-vectors> <out.json>
// Runs after run.ts. Reads each vector's expected.json and classifies the
// observation. A vector whose named stage lies beyond `chain` can only be
// "consistent, named stage not assessed": this checker makes no claim there.

import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { ASSESSED } from './verify.ts'

const [obsPath, root, out] = process.argv.slice(2)
const obs = JSON.parse(readFileSync(obsPath, 'utf8')).results
const rows = obs.map((r: any) => {
  const exp = JSON.parse(readFileSync(join(root, 'v1', r.id, 'expected.json'), 'utf8'))
  const stage: string | null = exp.first_failing_stage
  const inScope = stage !== null && (ASSESSED as readonly string[]).includes(stage)
  let cls: string
  if (inScope) cls = r.firstFailingStage === stage ? 'MATCH' : 'MISMATCH'
  else cls = r.outcome === 'NO_FAILURE_IN_ASSESSED_STAGES'
    ? (stage === null ? 'CONSISTENT, later stages not assessed' : `CONSISTENT, named stage ${stage} not assessed`)
    : 'MISMATCH'
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
