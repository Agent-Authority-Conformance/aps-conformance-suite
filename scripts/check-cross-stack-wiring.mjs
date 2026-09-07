// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The wiring invariant between fixtures/cross-stack/index.json, package.json and
// the cross-stack CI job. Three properties, each of which has failed somewhere
// before and each of which fails silently rather than loudly if unchecked:
//
//   P1  a family that exists must be classified. A directory under
//       fixtures/cross-stack/ with no registry entry runs nothing, and the
//       absence reads as "there was nothing to run".
//   P2  a declared executable must exist. A registry entry naming a script that
//       is not in package.json is a promise the repository does not keep, and a
//       non-executable declaration without a reason is an unexplained gap.
//   P3  the job cannot drift from the registry. The workflow names no family; it
//       runs one script that derives its work from this same file. This checks
//       that it still does, so nobody can quietly reintroduce a hand-kept list.
//
// Run: node scripts/check-cross-stack-wiring.mjs
// Exit 0 on full pass, 1 on any failure.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { declaredScripts } from './run-cross-stack.mjs'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const CROSS_STACK = join(REPO_ROOT, 'fixtures', 'cross-stack')
const WORKFLOW = join(REPO_ROOT, '.github', 'workflows', 'tests.yml')
const RUNNER_SCRIPT = 'verify:cross-stack'
const NON_EXECUTABLE = new Set(['none', 'blocked'])

let failures = 0
function check(name, cond, detail = '') {
  if (cond) console.log(`  ok   ${name}`)
  else { failures += 1; console.log(`  FAIL ${name}${detail ? `  ${detail}` : ''}`) }
}

const index = JSON.parse(readFileSync(join(CROSS_STACK, 'index.json'), 'utf8'))
const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'))
const scripts = pkg.scripts ?? {}

console.log('cross-stack wiring')
console.log('')
console.log('P1  every family directory is classified')
const onDisk = readdirSync(CROSS_STACK, { withFileTypes: true })
  .filter((d) => d.isDirectory()).map((d) => d.name).sort()
const declaredPaths = new Set(index.entries.map((e) => e.path))
for (const name of onDisk) {
  check(`${name}: has a registry entry`, declaredPaths.has(name),
    'add it to fixtures/cross-stack/index.json with a reviewed kind and a verification declaration')
}
for (const p of declaredPaths) {
  let isDir = false
  try { isDir = statSync(join(CROSS_STACK, p)).isDirectory() } catch { isDir = false }
  check(`${p}: declared path exists on disk`, isDir)
}

console.log('')
console.log('P2  every declaration is honoured')
for (const entry of index.entries) {
  const v = entry.verification
  check(`${entry.path}: declares verification`, v !== undefined && v !== null,
    'declare {verify, falsify?} script names, or {executable, reason}')
  if (!v) continue
  const hasScripts = typeof v.verify === 'string'
  const hasExecutable = typeof v.executable === 'string'
  check(`${entry.path}: declares scripts or a non-executable reason, not both`,
    hasScripts !== hasExecutable)
  if (hasScripts) {
    for (const role of ['verify', 'falsify']) {
      if (typeof v[role] !== 'string') continue
      check(`${entry.path}: ${role} script "${v[role]}" exists in package.json`,
        Object.prototype.hasOwnProperty.call(scripts, v[role]),
        'a registry entry may only name a script package.json already defines')
    }
  }
  if (hasExecutable) {
    check(`${entry.path}: executable "${v.executable}" is one of ${[...NON_EXECUTABLE].join(', ')}`,
      NON_EXECUTABLE.has(v.executable))
    check(`${entry.path}: non-executable declaration carries a reason`,
      typeof v.reason === 'string' && v.reason.trim().length > 0)
  }
}

console.log('')
console.log('P3  the CI job derives its work from the registry')
const workflow = readFileSync(WORKFLOW, 'utf8')
const jobMatch = workflow.match(/\n {2}cross-stack:\n([\s\S]*?)(?=\n {2}\S|\n*$)/)
check('tests.yml declares a cross-stack job', jobMatch !== null)
if (jobMatch) {
  const job = jobMatch[1]
  check(`the job runs "npm run ${RUNNER_SCRIPT}"`, job.includes(`npm run ${RUNNER_SCRIPT}`))
  const named = index.entries.map((e) => e.path).filter((p) => job.includes(p))
  check('the job names no individual family', named.length === 0,
    named.length ? `names ${named.join(', ')}; the registry is the only list` : '')
  const namedScripts = Object.keys(scripts).filter((s) => s.startsWith('cross-stack:') && job.includes(s))
  check('the job names no individual cross-stack script', namedScripts.length === 0,
    namedScripts.join(', '))
}
// `npm run x && npm run y` is the repository's own composition style, so the
// chain is expanded before it is read. One level is enough and the depth guard
// says so rather than recursing into whatever someone writes next.
function expand(name, depth = 0) {
  const body = scripts[name] ?? ''
  if (depth > 3) return body
  return body.replace(/npm run ([\w:-]+)/g, (m, ref) => (ref === name ? m : `${m} { ${expand(ref, depth + 1)} }`))
}
const runner = expand(RUNNER_SCRIPT)
check(`${RUNNER_SCRIPT} runs the wiring check`, runner.includes('check-cross-stack-wiring.mjs'))
check(`${RUNNER_SCRIPT} runs the cross-stack typecheck`, runner.includes('tsconfig.cross-stack.json'))
check(`${RUNNER_SCRIPT} runs the registry-driven runner`, runner.includes('run-cross-stack.mjs'))

// The two directions of the same set: what the registry declares, and what the
// runner would execute. They are computed from the same function, so this is a
// statement that nothing else can be smuggled into the run.
const declared = declaredScripts(index).map((s) => s.script).sort()
const wrappers = Object.keys(scripts).filter((s) => s.startsWith('cross-stack:')).sort()
const unused = wrappers.filter((s) => !declared.includes(s))
check('every cross-stack: script in package.json is declared by a family', unused.length === 0,
  unused.length ? `${unused.join(', ')} would never run` : '')

console.log('')
const executable = index.entries.filter((e) => typeof e.verification?.verify === 'string').length
const blocked = index.entries.filter((e) => e.verification?.executable === 'blocked').length
const none = index.entries.filter((e) => e.verification?.executable === 'none').length
console.log(`${onDisk.length} families: ${executable} executable, ${blocked} blocked, ${none} with no verifier; ${declared.length} declared scripts`)
if (failures > 0) {
  console.error(`${failures} cross-stack wiring failure(s)`)
  process.exit(1)
}
console.log('cross-stack wiring OK')
