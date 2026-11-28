// Asserts the canonical-bytes cross-run result of each named runner.
//
// `npm run crossrun:canonical-bytes` records a byte or digest mismatch as a
// result and exits 0, and it reports a missing toolchain as SKIP. That is the
// right behavior for a cross-run report, and it means the orchestrator's exit
// code says nothing about whether a given runner ran or matched. This check
// is for CI jobs that exist to exercise particular runners: each named runner
// must have a result file, must not be SKIP or ERROR, must cover every case in
// the fixture, and must match every case on bytes and on SHA-256.
//
// Usage: node scripts/check-crossrun-results.mjs <runner-id> [<runner-id> ...]
// Runner ids are the result file names under crossrun-results/, for example
// `rust` and `rust-jcs-admit`.
//
// Node builtins only.

import { readFileSync, existsSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const RESULTS = join(ROOT, 'fixtures', 'canonical-bytes', 'crossrun-results')
const FIXTURE = join(ROOT, 'fixtures', 'canonical-bytes', 'canonical-bytes-jcs-v2.json')

const ids = process.argv.slice(2)
if (ids.length === 0) {
  console.error('usage: check-crossrun-results.mjs <runner-id> [<runner-id> ...]')
  process.exit(2)
}

const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'))
const cases = Array.isArray(fixture) ? fixture : (fixture.cases || fixture.vectors)
if (!Array.isArray(cases) || cases.length === 0) {
  console.error(`cannot read the case list from ${FIXTURE}`)
  process.exit(2)
}
const expected = cases.length

let failed = 0
for (const id of ids) {
  const file = join(RESULTS, `${id}.json`)
  if (!existsSync(file)) {
    console.error(`FAIL ${id}: no result file at ${file}`)
    failed++
    continue
  }
  const r = JSON.parse(readFileSync(file, 'utf8'))
  if (r.status === 'SKIP' || r.status === 'ERROR') {
    console.error(`FAIL ${id}: status ${r.status}${r.reason ? `, ${r.reason}` : ''}`)
    failed++
    continue
  }
  const s = r.summary || {}
  const list = Array.isArray(r.cases) ? r.cases : []
  const n = list.length
  // The summary is checked against the per-case entries, not taken on trust.
  const perCase = list.filter(c => c.byte_match === true && c.sha256_match === true).length
  const ok = s.total === expected && n === expected && perCase === expected &&
    s.byte_match === expected && s.sha256_match === expected
  const line = `${id}: ${r.implementation} ${r.implementation_version}, bytes ${s.byte_match}/${s.total}, sha256 ${s.sha256_match}/${s.total}, cases ${n}, fixture ${expected}`
  if (ok) {
    console.log(`ok   ${line}`)
  } else {
    console.error(`FAIL ${line}`)
    failed++
  }
}
process.exit(failed ? 1 : 0)
