// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Manifest integrity for the APS-native corpus.
//
// fixtures/manifest.json is the declared inventory of this repository's own
// vectors. Counts printed anywhere in the repository are derived from it, so a
// manifest that disagrees with the files on disk turns every derived number
// into a claim nothing checks. This test is what makes the manifest usable as a
// source: it compares the declaration against the bytes.
//
// Node builtins only. No dependency, so this can run before anything else in
// the gate and cannot itself be the thing that is broken.
//
// Checked here:
//   totals.fixtures equals the number of entries
//   totals.vectors equals the sum of vector_count
//   every declared path exists, relative to fixtures/
//   every canonical_sha256 matches the file bytes
//   no duplicate (category, path) pair
//   vector_count is a positive integer
//   no fixtures/cross-stack path appears in the APS-native manifest
//
// The last check is a boundary, not a formality. fixtures/cross-stack/ holds
// external-system families, which are admitted and classified per family and
// are not APS-native vectors. Letting one into this manifest would fold a
// counterparty's corpus into this repository's own vector count.
//
// Run: npx tsx runners/ts/manifest-integrity.test.ts
// Exit 0 on full pass, 1 on any failure.

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const FIXTURES_DIR = join(REPO_ROOT, 'fixtures')
const MANIFEST_PATH = join(FIXTURES_DIR, 'manifest.json')

interface Entry {
  category: string
  path: string
  canonical_sha256: string
  vector_count: number
}
interface Manifest {
  totals?: { fixtures: number; vectors: number }
  fixtures: Entry[]
}

let failures = 0
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log(`  ok   ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL ${name}${detail ? `  ${detail}` : ''}`)
  }
}

console.log(`manifest integrity: ${MANIFEST_PATH}`)

const manifest: Manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'))
const entries = manifest.fixtures

check('manifest declares a fixtures array', Array.isArray(entries) && entries.length > 0)
if (!Array.isArray(entries) || entries.length === 0) process.exit(1)

// Totals, compared against the array rather than trusted.
const declared = manifest.totals
check('manifest declares totals', declared !== undefined)
if (declared) {
  check('totals.fixtures equals the entry count',
    declared.fixtures === entries.length,
    `declared ${declared.fixtures}, actual ${entries.length}`)
  const summed = entries.reduce((n, e) => n + (Number.isFinite(e.vector_count) ? e.vector_count : 0), 0)
  check('totals.vectors equals the sum of vector_count',
    declared.vectors === summed,
    `declared ${declared.vectors}, actual ${summed}`)
}

// Per entry: shape, existence, digest, boundary.
const seen = new Set<string>()
for (const entry of entries) {
  const label = `${entry.category} / ${entry.path}`

  check(`${label}: vector_count is a positive integer`,
    Number.isInteger(entry.vector_count) && entry.vector_count > 0,
    `got ${JSON.stringify(entry.vector_count)}`)

  const key = `${entry.category} ${entry.path}`
  check(`${label}: (category, path) is not a duplicate`, !seen.has(key))
  seen.add(key)

  // The boundary check runs on the declared path, before any file read, so a
  // cross-stack entry is refused even if its file happens to exist.
  check(`${label}: is not a fixtures/cross-stack path`,
    !entry.path.startsWith('cross-stack/') && !entry.path.includes('/cross-stack/'),
    'external-system families are admitted per family, not counted as APS-native vectors')

  const abs = join(FIXTURES_DIR, entry.path)
  const present = existsSync(abs) && statSync(abs).isFile()
  check(`${label}: file exists`, present, present ? '' : abs)
  if (!present) continue

  const actual = createHash('sha256').update(readFileSync(abs)).digest('hex')
  check(`${label}: canonical_sha256 matches the file bytes`,
    actual === entry.canonical_sha256,
    `declared ${String(entry.canonical_sha256).slice(0, 16)}, actual ${actual.slice(0, 16)}`)
}

console.log()
if (failures > 0) {
  console.error(`${failures} manifest integrity failure(s)`)
  process.exit(1)
}
console.log(`manifest integrity OK: ${entries.length} entries, ${entries.reduce((n, e) => n + e.vector_count, 0)} vectors`)
