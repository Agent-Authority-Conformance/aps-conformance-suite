// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// fixtures/cross-stack/index.json is the reviewed declaration of what each
// directory under fixtures/cross-stack/ is. This test holds it to the tree.
//
// WHY A DECLARATION AND NOT A RULE. Everything under cross-stack/ looks alike
// from the filesystem, and two of the things there are not the same kind of
// thing at all: most are external-system families ingested from a counterparty,
// and synthetic/ is lab-authored regression material whose placement there is
// historical. A generator that inferred the class from the path would call
// synthetic/ an external family forever, and would keep calling it that
// correctly-looking name in the README. Semantic class is a reviewed decision,
// so it is written down and this test checks the writing against the tree.
//
// Checked here:
//   every declared path exists and is a directory
//   every child of fixtures/cross-stack/ is declared exactly once
//   every declared kind is in the enum the file itself publishes
//
// Run: node tests/cross-stack-registry.test.mjs
// Exit 0 on full pass, 1 on any failure.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..')
const CROSS_STACK = join(REPO_ROOT, 'fixtures', 'cross-stack')
const INDEX_PATH = join(CROSS_STACK, 'index.json')

let failures = 0
function check(name, cond, detail = '') {
  if (cond) {
    console.log(`  ok   ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL ${name}${detail ? `  ${detail}` : ''}`)
  }
}

console.log(`cross-stack registry: ${INDEX_PATH}`)

const index = JSON.parse(readFileSync(INDEX_PATH, 'utf8'))
const kinds = new Set(index.kinds)
check('index declares a non-empty kind enum', kinds.size > 0)
check('index declares an entries array', Array.isArray(index.entries) && index.entries.length > 0)
if (!Array.isArray(index.entries)) process.exit(1)

// Declared paths must exist, be directories, and be declared once each.
const declared = new Set()
for (const entry of index.entries) {
  const label = entry.path
  check(`${label}: declared once`, !declared.has(entry.path))
  declared.add(entry.path)

  check(`${label}: kind is in the enum`, kinds.has(entry.kind), `got ${JSON.stringify(entry.kind)}`)

  const abs = join(CROSS_STACK, entry.path)
  let isDir = false
  try { isDir = statSync(abs).isDirectory() } catch { isDir = false }
  check(`${label}: directory exists`, isDir, isDir ? '' : abs)
}

// And every directory on disk must be declared. This is the direction that
// matters: an undeclared family would simply be missing from the inventory,
// which reads as absence rather than as an error.
const onDisk = readdirSync(CROSS_STACK, { withFileTypes: true })
  .filter(d => d.isDirectory())
  .map(d => d.name)
  .sort()

for (const name of onDisk) {
  check(`${name}: is declared in index.json`, declared.has(name),
    'add it with a reviewed kind; the class is never inferred from the path')
}

const stale = [...declared].filter(p => !onDisk.includes(p))
check('no declared path is missing from disk', stale.length === 0, stale.join(', '))

console.log()
if (failures > 0) {
  console.error(`${failures} cross-stack registry failure(s)`)
  process.exit(1)
}
console.log(`cross-stack registry OK: ${onDisk.length} directories, all declared`)
