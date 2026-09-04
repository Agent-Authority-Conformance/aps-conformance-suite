// Fail-before / pass-after test for the fail-loud + wired-vector fix.
//
// Verifies two properties the runner used to violate:
//   1. WIRED ASSERTIONS: the actionref-canonical (6) and bilateral-pair (6)
//      vectors are actually asserted (real pass counts). Skips are governed by
//      a NAMED ALLOWLIST: the set of actually-skipped categories must equal the
//      declared allowlist EXACTLY, failing in BOTH directions — an unexpected
//      skip appearing and a declared skip quietly disappearing are both loud.
//      Every allowlisted name declares a dedicated verifier that runs in the
//      same `npm test` invocation. This allowlist governs only the APS-native
//      families the generic runner skips: a cross-stack family under
//      fixtures/cross-stack/ is outside the generic runner altogether (it is
//      declared in fixtures/cross-stack/index.json, not in the manifest) and is
//      not executed by `npm test` — it carries its own reproduction commands,
//      which is why no cross-stack verifier is spawned or asserted here.
//   2. FAIL LOUD: a vector that carries a corrupted expected value, and a vector
//      of an unrecognized shape, each make the runner EXIT NON-ZERO instead of
//      being silently downgraded to skip.
//
// On the pre-fix runner these vectors silently skip and the runner exits 0, so
// every assertion below fails: this test fails-before and passes-after.
//
// Run: npx tsx runners/ts/fail-loud-and-wire.test.ts

import { spawnSync } from 'node:child_process'
import { mkdtempSync, cpSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const VERIFY = join(REPO_ROOT, 'runners', 'ts', 'verify.ts')
// The tsx CLI module, launched with this process's own node binary. The
// node_modules/.bin/tsx entry is a shell shim, and on Windows it is tsx.cmd,
// which spawnSync cannot execute without shell: true. Spawning the .mjs with
// process.execPath removes the shim, the shell and the platform branch at once,
// so this test runs the same way on every platform.
// Reported by Stian Skogbrott (@darklordVirtual).
const TSX_CLI = join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs')

// The named allowlist. A category may be skipped by the generic runner ONLY if
// its name appears here. The guard (below) asserts the set of actually-skipped
// names equals this set exactly, failing in both directions; and asserts that
// each entry's dedicated verifier — and, where present, its mutation proof —
// runs inside the same `npm test` invocation.
interface AllowlistEntry {
  category: string
  // The dedicated verifier that deep-verifies the category inside the same
  // `npm test`. Omitted only when there is none, in which case `debt` must say
  // so: an entry with neither is an unexplained hole and fails below.
  verifier?: string
  mutation?: string
  debt?: string
}
const SKIP_ALLOWLIST: AllowlistEntry[] = [
  {
    category: 'canonical-bytes',
    verifier: 'test:canonical-bytes',
    // No mutation script yet: canonical-bytes predates the allowlist rule and
    // its falsifiability proof is the suite maintainers' outstanding debt, not
    // a condition of this PR (stated by the reviewer).
  },
  {
    category: 'inference-session',
    // Deliberately no verifier. Three of this family's vectors declare
    // expected_verification:false for a POLICY rejection -- expired validity
    // window, sequence gap, replayed sequence number -- and NOTHING in this
    // repository evaluates validity windows or sequence continuity. Their
    // canonical bytes and signatures are valid by construction, so the generic
    // runner used to report them as clean passes; it now reports them as skips
    // against the manifest's unasserted_negatives declaration.
    //
    // They carry neither rejection_kind nor expected_error_code, so there is
    // nothing for a gate to assert the rejection against, and supplying those
    // fields would change published vector expectations. Writing the missing
    // verifier is the fix; naming the debt here is what keeps it visible until
    // someone does.
    debt: 'no verifier evaluates inference-session validity windows or sequence continuity; three declared negatives are unasserted (fixtures/manifest.json unasserted_negatives)',
  },
]

let failures = 0
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log(`  ok   ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`)
  }
}

interface Run {
  code: number
  stdout: string
  stderr: string
}

function runVerify(fixturesDir?: string): Run {
  const env = { ...process.env }
  if (fixturesDir) env.APS_FIXTURES_DIR = fixturesDir
  const r = spawnSync(process.execPath, [TSX_CLI, VERIFY], { encoding: 'utf8', env, shell: false })
  return { code: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

function categoryCounts(stdout: string, category: string): { pass: number; fail: number; skip: number } | null {
  const re = new RegExp(`^\\s*${category}\\s+pass=(\\d+)\\s+fail=(\\d+)\\s+skip=(\\d+)`, 'm')
  const m = stdout.match(re)
  if (!m) return null
  return { pass: Number(m[1]), fail: Number(m[2]), skip: Number(m[3]) }
}

// Category summary lines look like: "  <name padded> pass=N  fail=N  skip=N".
// Return the names of every category that produced at least one skip (the
// TOTAL: summary line is not a category and is excluded).
function skippedCategories(stdout: string): string[] {
  const skipped: string[] = []
  const re = /^\s*(.+?)\s+pass=\d+\s+fail=\d+\s+skip=(\d+)/gm
  for (const m of stdout.matchAll(re)) {
    const name = m[1].trim()
    if (name.startsWith('TOTAL')) continue
    if (Number(m[2]) > 0) skipped.push(name)
  }
  return skipped
}

function sha256OfFile(path: string): string {
  return crypto.createHash('sha256').update(readFileSync(path)).digest('hex')
}

// Copy the whole fixtures tree into a temp dir and return its path. Callers
// mutate the copy and repair the copied manifest's file-level sha so the runner
// reaches the per-vector layer instead of failing at the manifest-sha gate.
function copyFixtures(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aps-faillod-'))
  const dest = join(dir, 'fixtures')
  cpSync(join(REPO_ROOT, 'fixtures'), dest, { recursive: true })
  return dest
}

function repairManifestSha(fixturesDir: string, fixturePath: string): void {
  const manifestPath = join(fixturesDir, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const entry = manifest.fixtures.find((e: { path: string }) => e.path === fixturePath)
  if (!entry) throw new Error(`manifest entry not found for ${fixturePath}`)
  entry.canonical_sha256 = sha256OfFile(join(fixturesDir, fixturePath))
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2))
}

console.log('fail-loud + wired-vector + allowlist test')
if (!existsSync(TSX_CLI)) {
  console.error(`tsx cli not found at ${TSX_CLI}`)
  process.exit(2)
}

// 1. Real fixtures: wired vectors are asserted; the set of skipped names equals
//    the named allowlist exactly (both directions); and every allowlisted name is
//    deep-verified by a dedicated script inside the same `npm test`.
{
  const r = runVerify()
  check('real fixtures exit 0', r.code === 0, `exit ${r.code}`)
  const ar = categoryCounts(r.stdout, 'actionref-canonical')
  check('actionref-canonical asserted (pass=6 fail=0 skip=0)', !!ar && ar.pass === 6 && ar.fail === 0 && ar.skip === 0, JSON.stringify(ar))
  const bp = categoryCounts(r.stdout, 'bilateral-pair')
  check('bilateral-pair asserted (pass=6 fail=0 skip=0)', !!bp && bp.pass === 6 && bp.fail === 0 && bp.skip === 0, JSON.stringify(bp))

  // Named allowlist, not a count: the set of skipped names must equal the
  // declared set EXACTLY, failing in BOTH directions. A count cannot see
  // identity — two unrelated vectors silently skipping would still satisfy
  // "skip === 2" — so the guard compares names.
  const allowlisted = SKIP_ALLOWLIST.map((e) => e.category)
  const skipped = skippedCategories(r.stdout)
  const unexpected = skipped.filter((c) => !allowlisted.includes(c))
  const missing = allowlisted.filter((c) => !skipped.includes(c))
  check(
    'skipped names == allowlist (no unexpected skip appearing)',
    unexpected.length === 0,
    `unexpected skips: [${unexpected.join(', ')}]`,
  )
  check(
    'skipped names == allowlist (no declared skip disappearing)',
    missing.length === 0,
    `missing skips: [${missing.join(', ')}]`,
  )
  check(
    'skipped set exactly matches the allowlist',
    unexpected.length === 0 && missing.length === 0,
    `skipped=[${skipped.join(', ')}] allowlist=[${allowlisted.join(', ')}]`,
  )

  // Every allowlisted name declares a dedicated verifier that runs in the same
  // `npm test` invocation; where a mutation script is declared, it must run in
  // the gate too (otherwise the falsifiability proof exists but never executes).
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { scripts: Record<string, string> }
  const testScript = pkg.scripts?.test ?? ''
  for (const e of SKIP_ALLOWLIST) {
    if (e.verifier) {
      check(`allowlist ${e.category}: dedicated verifier ${e.verifier} runs in npm test`, testScript.includes(`npm run ${e.verifier}`), 'missing from scripts.test')
    } else {
      // No verifier is allowed only when the entry states the debt. Silence
      // here would be the same hole the allowlist exists to close.
      check(`allowlist ${e.category}: has no verifier, and says why`,
        typeof e.debt === 'string' && e.debt.length > 0,
        'an allowlisted category with no verifier must declare `debt`')
    }
    if (e.mutation) {
      check(`allowlist ${e.category}: mutation proof ${e.mutation} runs in npm test`, testScript.includes(`npm run ${e.mutation}`), 'missing from scripts.test')
    }
  }

}

// 2. Fail loud on a corrupted expected value (wired assertion must reject it).
{
  const fixturesDir = copyFixtures()
  const rel = 'actionref-canonical/actionref-canonical-fixture-v1.json'
  const p = join(fixturesDir, rel)
  const fx = JSON.parse(readFileSync(p, 'utf8'))
  // Flip the last hex nibble of the first vector's expected action_ref.
  const ref: string = fx.vectors[0].action_ref
  const last = ref.slice(-1)
  fx.vectors[0].action_ref = ref.slice(0, -1) + (last === '0' ? '1' : '0')
  writeFileSync(p, JSON.stringify(fx, null, 2))
  repairManifestSha(fixturesDir, rel)
  const r = runVerify(fixturesDir)
  check('corrupted action_ref makes runner exit non-zero', r.code !== 0, `exit ${r.code}`)
  check('corruption is reported as a failure, not a skip', /actionref-canonical/.test(r.stdout) && /fail=/.test(r.stdout) && r.code !== 0)
}

// 3. Fail loud on an unrecognized vector shape (no verifiable data, no skip_reason).
{
  const fixturesDir = copyFixtures()
  const rel = 'bilateral-delegation/canonicalize-fixture-v1.json'
  const p = join(fixturesDir, rel)
  const fx = JSON.parse(readFileSync(p, 'utf8'))
  fx.vectors.push({ name: 'junk-unrecognized-shape', description: 'no verifiable data and no skip_reason' })
  writeFileSync(p, JSON.stringify(fx, null, 2))
  repairManifestSha(fixturesDir, rel)
  const r = runVerify(fixturesDir)
  check('unrecognized vector shape makes runner exit non-zero', r.code !== 0, `exit ${r.code}`)
  check('unrecognized shape names the offending vector', /junk-unrecognized-shape/.test(r.stdout), 'expected vector name in FAILURES')
}

console.log()
if (failures > 0) {
  console.log(`FAILED: ${failures} check(s) failed`)
  process.exit(1)
}
console.log('PASSED: fail-loud enforced, actionref-canonical + bilateral-pair wired, skips governed by the named allowlist')
process.exit(0)
