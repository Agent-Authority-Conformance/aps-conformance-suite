// Cold-clone verifier for the accountability-record fixture family.
//
// Run as:  npx tsx fixtures/accountability-record/verify.ts
//
// This is the family's composite runner. It executes every layer
// fixtures/manifest.json declares required for the family -- currently the
// cryptographic layer and the JSON Schema Draft 2020-12 layer -- reports each
// layer's own result for every vector, and prints one verdict per vector
// computed from those results by runners/ts/layered-gate.ts.
//
// It deliberately does NOT emit a verdict from any single layer. Two of this
// family's negatives are rejected by schema and by nothing else: their bytes
// are self-consistent and their signatures verify, so the cryptographic layer
// accepts them, correctly. This script used to print PASS for those vectors on
// the strength of that crypto accept, on the stated grounds that validate.py
// enforced the schema -- and validate.py was never run by `npm test`. The
// schema could be deleted outright and the suite stayed green. Now the schema
// layer runs here, inside the default command, and a schema-negative vector
// passes only when the schema actually produced the rejection the vector
// declares.
//
// A required layer that cannot run -- schema file missing, schema not valid
// Draft 2020-12, validator not installed, digest not matching the manifest pin
// -- fails every vector in the family. It never skips them.
//
// Exits 0 only if every vector's verdict passes.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readLayeredDecl } from '../../runners/ts/layered-gate.js'
import { evaluateFamily, type AccountabilityFixture } from './layers.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES_DIR = join(__dirname, '..')
const MANIFEST = join(FIXTURES_DIR, 'manifest.json')
const FIXTURE = join(__dirname, 'accountability-record-fixture-v1.json')
const CATEGORY = 'accountability-record'

const fx = JSON.parse(readFileSync(FIXTURE, 'utf8')) as AccountabilityFixture

interface ManifestEntry {
  category: string
  [k: string]: unknown
}
const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8')) as { fixtures: ManifestEntry[] }
const entry = manifest.fixtures.find((e) => e.category === CATEGORY)
if (!entry) {
  console.error(`no manifest entry for category "${CATEGORY}" in ${MANIFEST}`)
  process.exit(1)
}

// The family's layers are declared in the manifest, not here. A family whose
// declaration went missing is a failure: the set of layers that must decide it
// would otherwise be whatever this file happened to run.
const decl = readLayeredDecl(entry)
if (!decl) {
  console.error(`manifest entry for "${CATEGORY}" declares no required_layers; the layers that decide this family are unstated`)
  process.exit(1)
}

console.log(`accountability-record verifier — ${fx.vectors.length} vectors from ${FIXTURE}`)
console.log(`required layers: ${decl.required_layers.join(', ')} (declared in ${MANIFEST})\n`)

const { verdicts, reports } = await evaluateFamily(FIXTURES_DIR, fx, decl)

for (const r of reports) {
  if (!r.available) console.log(`  LAYER UNAVAILABLE  ${r.layer}: ${r.reason}`)
}
if (reports.some((r) => !r.available)) console.log()

let failures = 0
for (const v of fx.vectors) {
  const verdict = verdicts.find((x) => x.vector === v.name)
  if (!verdict) {
    failures++
    console.log(`  FAIL ${v.name.padEnd(34)} no verdict computed`)
    continue
  }
  if (!verdict.pass) failures++
  const tag = v.rejection_kind ? ` [${v.rejection_kind}]` : ''
  console.log(
    `  ${verdict.pass ? 'PASS' : 'FAIL'} ${v.name.padEnd(34)} expected=${v.expected_verification}${tag}` +
      `\n         layers: ${verdict.layerSummary}` +
      (verdict.problems.length ? `\n         ${verdict.problems.join('\n         ')}` : ''),
  )
}

console.log(`\n${failures === 0 ? 'ALL VECTORS PASS' : failures + ' VECTOR(S) FAILED'}`)
process.exit(failures === 0 ? 0 : 1)
