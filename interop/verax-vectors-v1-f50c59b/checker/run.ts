// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Usage: node checker/run.ts <path to verax test-vectors> <out.json>
// Lists v1/<id> directories itself and never reads expected.json or
// manifest.json. Comparison with the published expectations is a separate,
// later step (compare.ts).

import { readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { runVector } from './verify.ts'

const [root, out] = process.argv.slice(2)
if (!root || !out) { console.error('usage: run.ts <test-vectors dir> <out.json>'); process.exit(2) }
const v1 = join(root, 'v1')
const ids = readdirSync(v1).filter(d => statSync(join(v1, d)).isDirectory()).sort()
const results = ids.map(id => runVector(join(v1, id), id))
for (const r of results) {
  const where = r.firstFailingStage ? `${r.firstFailingStage} (record ${r.findings[0].record}: ${r.findings[0].detail})` : 'none in assessed stages'
  console.log(`${r.id.padEnd(34)} ${r.outcome.padEnd(30)} ${where}${r.warnings.length ? ' WARN ' + r.warnings.join('; ') : ''}`)
}
writeFileSync(out, JSON.stringify({ vectors: results.length, results }, null, 2) + '\n')
