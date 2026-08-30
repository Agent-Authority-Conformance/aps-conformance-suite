// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The README inventory is generated. This test fails when the committed README
// no longer matches what the generator produces from the manifest, the reviewed
// cross-stack registry and the interop tree.
//
// WHY IT IS A TEST AND NOT A HABIT. A generated block that nobody checks becomes
// a hand-maintained block within one release: someone adds a family, forgets to
// regenerate, and the front door quietly reports a smaller corpus than the
// repository holds. That is the failure the whole inventory exists to prevent,
// so the drift is a test failure rather than a note in a contributing guide.
//
// Fix a failure by running:
//   node scripts/readme-inventory.mjs --write
//
// Run: node tests/readme-inventory.test.mjs
// Exit 0 when the README matches, 1 on drift or missing markers.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { BEGIN, END, buildInventory, currentBlock } from '../scripts/readme-inventory.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const README = join(__dirname, '..', 'README.md')

console.log('README inventory drift check')

const text = readFileSync(README, 'utf8')
const present = text.includes(BEGIN) && text.includes(END)
if (!present) {
  console.error(`  FAIL README.md is missing the generated inventory markers`)
  console.error(`       ${BEGIN}`)
  console.error(`       ${END}`)
  process.exit(1)
}
console.log('  ok   markers present')

const committed = currentBlock(text)
const generated = buildInventory()

if (committed !== generated) {
  console.error('  FAIL README inventory has drifted from the generator')
  const a = committed.split('\n')
  const b = generated.split('\n')
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      console.error(`       first difference at line ${i + 1} of the block`)
      console.error(`       committed: ${a[i] ?? '(end of block)'}`)
      console.error(`       generated: ${b[i] ?? '(end of block)'}`)
      break
    }
  }
  console.error('       run: node scripts/readme-inventory.mjs --write')
  process.exit(1)
}

console.log('  ok   README inventory matches the generator')
console.log()
console.log('README inventory OK')
