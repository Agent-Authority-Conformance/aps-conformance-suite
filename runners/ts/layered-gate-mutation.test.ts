// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Falsifiability proof for the layered gate. The audit's decisive check, made
// permanent.
//
// The defect this guards against was not that a check was wrong. It was that a
// check was absent and the suite could not tell. `npm test` printed ALL VECTORS
// PASS for two schema-negative vectors with the schema deleted. A gate that
// cannot fail is not a gate, so the property under test is failure: for each
// mutation below, the TOP-LEVEL COMMAND -- `npm test`, the same command
// .github/workflows/tests.yml runs -- must exit non-zero.
//
// Each case copies the repository into a temp directory, mutates the copy, and
// runs `npm test` inside it. Nothing in the working tree is touched. The copy's
// node_modules is a symlink to the real one (a junction on Windows), so a case
// costs a few megabytes and one npm test, not an install.
//
// Recursion. The inner `npm test` would otherwise run this file again. The copy
// is what changes, not the code: each scratch copy's package.json test chain has
// the single `npm run test:layered-gate-mutation` step removed before the inner
// run, so the inner run executes every other gate step, which is where the
// mutation must surface.
//
// There is deliberately no environment variable and no flag doing this. A guard
// the outside world can set is a way to switch the gate off, which is the shape
// of defect this file exists to catch. The only thing that can disable the step
// is editing a throwaway copy of package.json, and removeSelfFromTestChain
// below asserts that the edit removed that one step and left every other
// command in place and in order.
//
// The cases, and what each one distinguishes:
//
//   parser         schema is not parseable JSON
//   meta-schema    schema is parseable JSON but not a valid Draft 2020-12
//                  schema
//   weakened       the exact constraint each schema-negative vector exercises
//                  is removed, so the negative record becomes schema-valid.
//                  The gate must fail BECAUSE THE EXPECTED REJECTION WAS NOT
//                  OBSERVED. Deleting a random `required` entry would not prove
//                  this: a schema can weaken without changing any vector's
//                  verdict, and then the gate has no principled reason to fail.
//   wrong-error    the schema still rejects the negative, but with a different
//                  keyword than the vector's expected_error_code names. Proves
//                  the error binding is load-bearing and not satisfied by the
//                  bare fact of a rejection.
//   absent         the schema file is deleted
//   unpinned       the schema is edited without updating the manifest digest
//   undeclared     the manifest's required_layers declaration is removed, so
//                  the family would fall back to whatever layers happened to
//                  run
//   undebted       inference-session's unasserted_negatives declaration is
//                  removed. Those three vectors declare a policy rejection
//                  nothing in the repository evaluates; without the
//                  declaration they are negatives no layer asserts, and the
//                  runner must refuse them rather than pass them on byte
//                  parity
//
// The parser, meta-schema, weakened and wrong-error cases REPAIR the manifest's
// schema digest after mutating, so the gate reaches the layer it is being tested
// on instead of stopping at the digest pin. `unpinned` deliberately leaves the
// digest stale, to prove the pin itself bites; `absent` and `undeclared` have
// nothing left to re-pin.
//
// Run: npx tsx runners/ts/layered-gate-mutation.test.ts

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CATEGORY = 'accountability-record'
const SELF_STEP = 'npm run test:layered-gate-mutation'
const BANNER = 'layered-gate mutation test:'

let failures = 0
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log(`  ok   ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`)
  }
}

// npm is spawned through this process's own node binary and npm's cli.js, the
// same trick fail-loud-and-wire.test.ts uses for tsx: node_modules/.bin entries
// and `npm` itself are shell shims (npm.cmd on Windows) that spawnSync cannot
// execute without shell: true. npm sets npm_execpath when it runs a script, so
// inside `npm test` this is always available; the PATH fallback keeps the file
// runnable standalone.
const NPM_CLI = process.env.npm_execpath

interface Run {
  code: number
  out: string
}

function runNpmTest(cwd: string): Run {
  const r = NPM_CLI && NPM_CLI.endsWith('.js')
    ? spawnSync(process.execPath, [NPM_CLI, 'test'], { cwd, encoding: 'utf8', shell: false })
    : spawnSync('npm', ['test'], { cwd, encoding: 'utf8', shell: process.platform === 'win32' })
  return { code: r.status ?? -1, out: `${r.stdout ?? ''}${r.stderr ?? ''}` }
}

/**
 * Remove this file's own step from a scratch copy's `npm test` chain, and prove
 * the removal took out that step and nothing else.
 *
 * The chain is a `&&` list of commands. Splitting on `&&` and dropping the one
 * element that is exactly SELF_STEP leaves every other command untouched and in
 * its original order, which is asserted here rather than assumed: a rewrite that
 * quietly dropped a second step would make every mutation case below prove less
 * than it claims, and would do it silently.
 */
function removeSelfFromTestChain(repo: string, label: string): void {
  const pkgPath = join(repo, 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { scripts: Record<string, string> }
  const before = (pkg.scripts?.test ?? '').split('&&').map((c) => c.trim())
  const after = before.filter((c) => c !== SELF_STEP)

  check(`${label}: scratch chain drops exactly one step`,
    before.length - after.length === 1,
    `before ${before.length} steps, after ${after.length}`)
  check(`${label}: scratch chain no longer runs ${SELF_STEP}`, !after.includes(SELF_STEP))
  check(`${label}: every other step survives, in order`,
    JSON.stringify(before.filter((c) => c !== SELF_STEP)) === JSON.stringify(after),
    `before=${JSON.stringify(before)} after=${JSON.stringify(after)}`)

  pkg.scripts.test = after.join(' && ')
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`)
}

const tempRoots: string[] = []

/** Copy the repository (minus node_modules and .git) and link node_modules. */
function copyRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aps-layergate-'))
  tempRoots.push(dir)
  const dest = join(dir, 'repo')
  cpSync(REPO_ROOT, dest, {
    recursive: true,
    filter: (src) => {
      const rel = src.slice(REPO_ROOT.length + 1)
      const top = rel.split(/[\\/]/)[0]
      return top !== 'node_modules' && top !== '.git'
    },
  })
  symlinkSync(join(REPO_ROOT, 'node_modules'), join(dest, 'node_modules'), 'junction')
  return dest
}

function manifestPath(repo: string): string {
  return join(repo, 'fixtures', 'manifest.json')
}

interface LayerDecl {
  schema_path?: string
  schema_sha256?: string
}
interface Entry {
  category: string
  required_layers?: string[]
  layers?: Record<string, LayerDecl>
  unasserted_negatives?: unknown
}
interface SchemaInventoryEntry {
  path?: string
  sha256?: string
}
interface Manifest {
  schemas?: SchemaInventoryEntry[]
  fixtures: Entry[]
}

function readManifest(repo: string): Manifest {
  return JSON.parse(readFileSync(manifestPath(repo), 'utf8')) as Manifest
}
function writeManifest(repo: string, m: Manifest): void {
  writeFileSync(manifestPath(repo), `${JSON.stringify(m, null, 2)}\n`)
}
function entryOf(m: Manifest): Entry {
  const e = m.fixtures.find((x) => x.category === CATEGORY)
  if (!e) throw new Error(`no manifest entry for ${CATEGORY}`)
  return e
}
function schemaAbsPath(repo: string): string {
  const decl = entryOf(readManifest(repo)).layers?.schema
  if (!decl?.schema_path) throw new Error('manifest declares no schema layer schema_path')
  return join(repo, 'fixtures', decl.schema_path)
}

/**
 * Re-pin BOTH of the manifest's digests for the schema -- the layer's
 * schema_sha256 and the schema inventory's sha256 -- to the mutated bytes, so
 * the gate is tested on the layer under examination rather than stopping at a
 * pin. Missing either one would make every case below pass for the wrong
 * reason.
 */
function repairSchemaDigest(repo: string): void {
  const m = readManifest(repo)
  const decl = entryOf(m).layers?.schema
  if (!decl?.schema_path) throw new Error('manifest declares no schema layer schema_path')
  const digest = createHash('sha256').update(readFileSync(join(repo, 'fixtures', decl.schema_path))).digest('hex')
  decl.schema_sha256 = digest
  for (const s of m.schemas ?? []) {
    if (s.path === decl.schema_path) s.sha256 = digest
  }
  writeManifest(repo, m)
}

function readSchema(repo: string): Record<string, any> {
  return JSON.parse(readFileSync(schemaAbsPath(repo), 'utf8')) as Record<string, any>
}
function writeSchema(repo: string, schema: unknown): void {
  writeFileSync(schemaAbsPath(repo), JSON.stringify(schema, null, 2))
}

interface Case {
  name: string
  /** Mutate the copied repo. */
  mutate: (repo: string) => void
  /** Re-pin the schema digest after mutating. Default true. */
  repair?: boolean
  /**
   * Substrings, any one of which proves it failed for the right reason. More
   * than one because the mutation may be caught by whichever gate step reaches
   * it first -- the manifest-integrity declaration check or the runner's layer
   * loader -- and both are correct outcomes.
   */
  because: string[]
}

const CASES: Case[] = [
  {
    name: 'schema is not parseable JSON',
    mutate: (repo) => writeFileSync(schemaAbsPath(repo), '{ "type": "object",, '),
    because: ['is parseable JSON', 'not parseable JSON'],
  },
  {
    name: 'schema is valid JSON but not a valid Draft 2020-12 schema',
    mutate: (repo) =>
      writeSchema(repo, {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'obfuscated',
        required: 'not-an-array',
        properties: 42,
      }),
    because: ['not a valid Draft 2020-12 schema'],
  },
  {
    name: 'the constraint each schema-negative exercises is weakened away',
    mutate: (repo) => {
      const s = readSchema(repo)
      // negative-schema-decision turns on `decision` being an enum, and
      // negative-sig-alg-lowercase on `sig_alg` being a const. Remove exactly
      // those two constraints and both negative records become schema-valid.
      delete s.properties.decision.enum
      s.properties.decision.type = 'string'
      delete s.properties.sig_alg.const
      s.properties.sig_alg.type = 'string'
      writeSchema(repo, s)
    },
    because: ['was NOT observed'],
  },
  {
    name: 'schema rejects the negative for a different reason than declared',
    mutate: (repo) => {
      const s = readSchema(repo)
      // "permit" is still rejected -- but by maxLength, not by the enum the
      // vector's expected_error_code names.
      delete s.properties.decision.enum
      s.properties.decision.type = 'string'
      s.properties.decision.maxLength = 5
      writeSchema(repo, s)
    },
    because: ['not with the expected error'],
  },
  {
    name: 'schema file is absent',
    mutate: (repo) => unlinkSync(schemaAbsPath(repo)),
    // Nothing to re-pin: the file the digest covers no longer exists.
    repair: false,
    because: ['schema file exists', 'inventoried schema exists on disk', 'missing or unreadable'],
  },
  {
    name: 'schema is edited without re-pinning the manifest digest',
    mutate: (repo) => {
      const s = readSchema(repo)
      delete s.properties.decision.enum
      s.properties.decision.type = 'string'
      writeSchema(repo, s)
    },
    repair: false,
    because: ['schema_sha256 matches the schema bytes', 'sha256 matches the file bytes', 'digest mismatch'],
  },
  {
    name: 'a negative nothing asserts loses its declared-debt entry',
    mutate: (repo) => {
      const m = readManifest(repo)
      const e = m.fixtures.find((x) => x.category === 'inference-session')
      if (!e) throw new Error('no manifest entry for inference-session')
      delete e.unasserted_negatives
      writeManifest(repo, m)
    },
    because: ['nothing here evaluates the policy it declares'],
  },
  {
    name: 'the family stops declaring its required layers',
    mutate: (repo) => {
      const m = readManifest(repo)
      const e = entryOf(m)
      delete e.required_layers
      delete e.layers
      writeManifest(repo, m)
    },
    // The declaration that names the schema, and so the digest, is gone.
    repair: false,
    because: ['layered_families', 'declares no required_layers', 'inventory digest agrees'],
  },
]

console.log('layered-gate mutation test: `npm test` must fail for each mutation\n')

// Control: the unmutated copy must pass, otherwise a failure below proves
// nothing about the mutation.
{
  const repo = copyRepo()
  removeSelfFromTestChain(repo, 'control')
  const r = runNpmTest(repo)
  check('control: unmutated copy passes npm test', r.code === 0, `exit ${r.code}\n${r.out.slice(-2000)}`)
  check('control: inner run did not re-enter this file', !r.out.includes(BANNER), r.out.slice(-500))
}

for (const c of CASES) {
  const repo = copyRepo()
  removeSelfFromTestChain(repo, c.name)
  c.mutate(repo)
  if (c.repair !== false) repairSchemaDigest(repo)
  const r = runNpmTest(repo)
  check(`${c.name}: npm test exits non-zero`, r.code !== 0, `exit ${r.code}`)
  check(`${c.name}: inner run did not re-enter this file`, !r.out.includes(BANNER), r.out.slice(-500))
  check(
    `${c.name}: fails for a stated reason (${c.because.map((b) => JSON.stringify(b)).join(' | ')})`,
    c.because.some((b) => r.out.includes(b)),
    r.out.slice(-1500),
  )
}

// The mutation proof is only worth anything if the gate it mutates is in the
// default command. Assert the wiring rather than assuming it.
{
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { scripts: Record<string, string> }
  const testScript = pkg.scripts?.test ?? ''
  check('npm test runs the manifest runner', testScript.includes('npm run verify'), testScript)
  check('npm test runs the accountability-record family verifier', testScript.includes('npm run verify:accountability-record'), testScript)
  check('npm test runs this mutation proof', testScript.includes('npm run test:layered-gate-mutation'), testScript)
}

for (const dir of tempRoots) {
  try {
    rmSync(dir, { recursive: true, force: true })
  } catch {
    // A leftover temp directory is not a test result. Leave it to the OS.
  }
}

console.log()
if (failures > 0) {
  console.log(`FAILED: ${failures} check(s) failed`)
  process.exit(1)
}
console.log('PASSED: every layer mutation makes the top-level command fail, each for its own stated reason')
process.exit(0)
