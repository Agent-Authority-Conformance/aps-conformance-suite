// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs every executable cross-stack family declared in
// fixtures/cross-stack/index.json, in declaration order, and exits nonzero on
// the first failure.
//
// WHY THIS EXISTS AND NOT A LIST IN THE WORKFLOW. A hand-maintained list in the
// YAML drifts from the tree the first time a family lands, and the drift reads
// as "nothing to run" rather than as an error. The registry is already the
// reviewed declaration of what each directory is; this makes it the declaration
// of what each directory RUNS as well, and the CI job names no family at all.
//
// WHY SCRIPT NAMES AND NOT COMMANDS. The registry declares npm script names,
// never shell strings, and this runner spawns them with shell:false. A registry
// edit can therefore only select an npm script that already exists in
// package.json, reviewed there; it cannot introduce a command. That property is
// checked by scripts/check-cross-stack-wiring.mjs and is the reason the two
// files are separate: the check is a gate, this is an executor.
//
// Run: node scripts/run-cross-stack.mjs
// Exit 0 when every declared script exits 0.

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const index = JSON.parse(readFileSync(join(REPO_ROOT, 'fixtures', 'cross-stack', 'index.json'), 'utf8'))

/** The scripts the registry declares, in declaration order. Shared with the wiring check. */
export function declaredScripts(registry) {
  const out = []
  for (const entry of registry.entries) {
    const v = entry.verification ?? {}
    if (typeof v.verify === 'string') out.push({ path: entry.path, role: 'verify', script: v.verify })
    if (typeof v.falsify === 'string') out.push({ path: entry.path, role: 'falsify', script: v.falsify })
  }
  return out
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const scripts = declaredScripts(index)
  console.log(`cross-stack: ${scripts.length} declared script(s) from fixtures/cross-stack/index.json`)
  console.log('')
  let failed = 0
  for (const { path, role, script } of scripts) {
    console.log(`--- ${path} (${role}): npm run ${script}`)
    const r = spawnSync('npm', ['run', script], { cwd: REPO_ROOT, stdio: 'inherit', shell: false })
    if (r.status !== 0) {
      console.error(`\ncross-stack FAILED: ${path} (${role}) exited ${r.status === null ? r.signal : r.status}`)
      failed += 1
      break
    }
    console.log('')
  }
  if (failed > 0) process.exit(1)
  console.log(`cross-stack OK: ${scripts.length}/${scripts.length} declared scripts passed`)
}
