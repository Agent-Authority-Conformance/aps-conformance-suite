#!/usr/bin/env node
// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Orchestrator for the RFC 8785 canonical-byte cross-run.
//
// Runs every language runner whose toolchain is present, validates each report
// against crossrun-result.schema.json, writes it to crossrun-results/<lang>.json
// and prints a table.
//
// EXIT STATUS. Non-zero only on a runner ERROR or a schema failure. A byte or
// digest MISMATCH is a recorded result, not a failed run: the whole point of
// this corpus is to publish where implementations differ, so a command that
// failed on difference would make the interesting outcome unreportable.
//
// Node is a prerequisite of this script rather than a skippable runner
// toolchain, so the TypeScript runner is required whenever this executes.
// Python, Go and Rust are optional: a missing toolchain produces a schema-valid
// SKIP and a SKIP line, never a pass.
//
// Usage:
//   npm run crossrun:canonical-bytes
//   npm run crossrun:canonical-bytes -- path/to/other-fixture.json

import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CROSSRUN_DIR = __dirname
const CANONICAL_DIR = join(__dirname, '..')
const REPO_ROOT = resolve(CANONICAL_DIR, '..', '..')
const RESULTS_DIR = join(CANONICAL_DIR, 'crossrun-results')
const SCHEMA_PATH = join(CANONICAL_DIR, 'crossrun-result.schema.json')
const DEFAULT_FIXTURE = join(CANONICAL_DIR, 'canonical-bytes-jcs-v2.json')

const fixturePath = resolve(process.argv[2] ?? DEFAULT_FIXTURE)

// ── A JSON Schema validator, deliberately a documented subset ────────────────
// The suite carries no schema library and this script adds no dependency, so
// the keywords actually used by crossrun-result.schema.json are implemented
// here and nothing else. Naming the subset matters: a validator that silently
// ignored a keyword would report "valid" for a document it never fully checked.
//
// Implemented: oneOf, type, enum, const, required, properties,
// additionalProperties, items, minItems, minLength, minimum, pattern.
// Not implemented, and not used by the schema: $ref, allOf, anyOf, not,
// dependent schemas, numeric multipleOf, format assertions.
const SUPPORTED_KEYWORDS = new Set([
  '$schema', '$id', 'title', 'description',
  'oneOf', 'type', 'enum', 'const', 'required', 'properties',
  'additionalProperties', 'items', 'minItems', 'minLength', 'minimum', 'pattern',
])

function assertSchemaIsWithinSubset(schema, path = '#') {
  if (schema === null || typeof schema !== 'object') return
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED_KEYWORDS.has(key)) {
      throw new Error(`schema uses keyword this validator does not implement: ${path}/${key}`)
    }
  }
  for (const sub of schema.oneOf ?? []) assertSchemaIsWithinSubset(sub, `${path}/oneOf`)
  for (const [name, sub] of Object.entries(schema.properties ?? {})) {
    assertSchemaIsWithinSubset(sub, `${path}/properties/${name}`)
  }
  if (schema.items) assertSchemaIsWithinSubset(schema.items, `${path}/items`)
}

function typeMatches(value, type) {
  const types = Array.isArray(type) ? type : [type]
  return types.some(t => {
    switch (t) {
      case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value)
      case 'array': return Array.isArray(value)
      case 'string': return typeof value === 'string'
      case 'boolean': return typeof value === 'boolean'
      case 'integer': return Number.isInteger(value)
      case 'number': return typeof value === 'number'
      case 'null': return value === null
      default: return false
    }
  })
}

function validate(value, schema, path = '') {
  const errors = []
  const where = path || '(root)'
  if (schema.oneOf) {
    const passing = schema.oneOf.filter(sub => validate(value, sub, path).length === 0)
    if (passing.length !== 1) {
      errors.push(`${where}: matched ${passing.length} of ${schema.oneOf.length} oneOf variants, expected exactly 1`)
    }
    return errors
  }
  if (schema.type && !typeMatches(value, schema.type)) {
    errors.push(`${where}: expected type ${JSON.stringify(schema.type)}, got ${Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value}`)
    return errors
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${where}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`)
  }
  if ('const' in schema && value !== schema.const) {
    errors.push(`${where}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`)
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${where}: shorter than minLength ${schema.minLength}`)
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${where}: does not match pattern ${schema.pattern}`)
    }
  }
  if (typeof value === 'number' && schema.minimum !== undefined && value < schema.minimum) {
    errors.push(`${where}: below minimum ${schema.minimum}`)
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${where}: fewer than minItems ${schema.minItems}`)
    }
    if (schema.items) value.forEach((item, i) => errors.push(...validate(item, schema.items, `${path}[${i}]`)))
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of schema.required ?? []) {
      if (!(key in value)) errors.push(`${where}: missing required property ${key}`)
    }
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties ?? {}))
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) errors.push(`${where}: unexpected property ${key}`)
      }
    }
    for (const [key, sub] of Object.entries(schema.properties ?? {})) {
      if (key in value) errors.push(...validate(value[key], sub, `${path}.${key}`))
    }
  }
  return errors
}

// ── Toolchain probing ────────────────────────────────────────────────────────
// Resolved against THIS process's PATH, so removing a toolchain from the
// orchestrator's PATH is enough to exercise the SKIP path.
//
// The probe RUNS the tool rather than only resolving its name, because on PATH
// is not the same as usable. `cargo` is normally a rustup shim: the shim
// resolves even when rustup has no default toolchain configured, and then every
// invocation fails. Treating that as a runner ERROR would be wrong twice, since
// it reports a failure of this suite for what is an absent toolchain, and it
// turns a machine without Rust configured into a non-zero exit. A tool that
// cannot answer `--version` is not present for our purposes.
function probeToolchain(command, versionArgs) {
  const resolved = spawnSync(process.platform === 'win32' ? 'where' : 'command',
    process.platform === 'win32' ? [command] : ['-v', command],
    { shell: process.platform !== 'win32', stdio: 'ignore' })
  if (resolved.status !== 0) return { present: false, reason: `toolchain not found on PATH: ${command}` }
  // The version arguments are per tool on purpose: `go` answers `go version`
  // and rejects `--version`, so a single hardcoded flag would report a working
  // Go toolchain as unusable.
  const ran = spawnSync(command, versionArgs, { encoding: 'utf8' })
  if (ran.status !== 0) {
    const detail = ((ran.stderr || '') + (ran.stdout || '')).trim().split('\n')[0] || `exit ${ran.status}`
    const invocation = [command, ...versionArgs].join(' ')
    return { present: false, reason: `toolchain on PATH but not usable: ${invocation} failed: ${detail}` }
  }
  return { present: true }
}

const ORCHESTRATOR = {
  node_version: process.version,
  platform: process.platform,
  arch: process.arch,
}

const RUNNERS = [
  {
    lang: 'ts',
    probe: null, // Node runs this script, so its own runtime is already present.
    run: () => execFileSync('npx', ['tsx', join(CROSSRUN_DIR, 'ts', 'runner.ts'), fixturePath],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
  },
  {
    lang: 'python',
    probe: 'python3',
    versionArgs: ['--version'],
    run: () => execFileSync('python3', [join(CROSSRUN_DIR, 'python', 'runner.py'), fixturePath],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
  },
  {
    lang: 'go',
    // -C keeps the nested module's own directory as the build context without
    // this script having to change its own working directory.
    probe: 'go',
    versionArgs: ['version'],
    run: () => execFileSync('go', ['-C', join(CROSSRUN_DIR, 'go'), 'run', '.', fixturePath],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
  },
  {
    lang: 'rust',
    probe: 'cargo',
    versionArgs: ['--version'],
    run: () => execFileSync('cargo', ['run', '--quiet',
      '--manifest-path', join(CROSSRUN_DIR, 'rust', 'Cargo.toml'), '--', fixturePath],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
  },
]

// ── Run ──────────────────────────────────────────────────────────────────────
const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'))
assertSchemaIsWithinSubset(schema)
mkdirSync(RESULTS_DIR, { recursive: true })

const fixtureSha = createHash('sha256').update(readFileSync(fixturePath)).digest('hex')
console.log('RFC 8785 canonical-byte cross-run')
console.log(`  fixture        ${relative(REPO_ROOT, fixturePath)}`)
console.log(`  fixture sha256 ${fixtureSha}`)
console.log(`  orchestrator   node ${process.version} on ${process.platform}/${process.arch}`)
console.log()

let errors = 0
const rows = []

for (const runner of RUNNERS) {
  let report
  const probed = runner.probe ? probeToolchain(runner.probe, runner.versionArgs) : { present: true }
  if (!probed.present) {
    report = {
      runner: runner.lang,
      status: 'SKIP',
      reason: probed.reason,
      orchestrator: ORCHESTRATOR,
      runtime: { probe: runner.probe, found: false },
    }
  } else {
    try {
      report = JSON.parse(runner.run())
    } catch (err) {
      errors++
      const detail = (err.stderr?.toString?.() || err.message || String(err)).trim().split('\n').slice(-4).join(' | ')
      rows.push({ lang: runner.lang, state: 'ERROR', detail })
      console.error(`ERROR ${runner.lang}: ${detail}`)
      continue
    }
    // Absolute paths are normalized to repo-relative before the artifact is
    // stored. These reports exist to be pasted into an issue, and a home
    // directory is both noise and something the author did not choose to
    // publish. The runner's own stdout is left alone.
    if (typeof report.fixture === 'string') {
      const rel = relative(REPO_ROOT, report.fixture)
      if (rel && !rel.startsWith('..')) report.fixture = rel
    }
  }

  const problems = validate(report, schema)
  const outPath = join(RESULTS_DIR, `${runner.lang}.json`)
  writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n')
  if (problems.length > 0) {
    errors++
    rows.push({ lang: runner.lang, state: 'SCHEMA', detail: problems[0] })
    console.error(`SCHEMA ${runner.lang}: ${problems.length} problem(s)`)
    for (const p of problems.slice(0, 5)) console.error(`  ${p}`)
    continue
  }
  rows.push(report.status === 'SKIP'
    ? { lang: runner.lang, state: 'SKIP', detail: report.reason }
    : { lang: runner.lang, state: 'OK', report })
}

// ── Table ────────────────────────────────────────────────────────────────────
const pad = (s, n) => String(s).padEnd(n)
console.log(pad('runner', 8) + pad('implementation', 52) + pad('kind', 22) + pad('version', 12) + pad('bytes', 8) + 'sha256')
console.log('-'.repeat(110))
for (const row of rows) {
  if (row.state === 'OK') {
    const r = row.report
    console.log(pad(r.runner, 8) + pad(r.implementation.slice(0, 50), 52) + pad(r.implementation_kind, 22) +
      pad(r.implementation_version, 12) +
      pad(`${r.summary.byte_match}/${r.summary.total}`, 8) + `${r.summary.sha256_match}/${r.summary.total}`)
  } else if (row.state === 'SKIP') {
    console.log(pad(row.lang, 8) + pad('SKIP: ' + row.detail, 52) + pad('-', 22) + pad('-', 12) + pad('-', 8) + '-')
  } else {
    console.log(pad(row.lang, 8) + pad(`${row.state}: ${row.detail.slice(0, 44)}`, 52) + pad('-', 22) + pad('-', 12) + pad('-', 8) + '-')
  }
}
console.log()

// Per-case divergences, so a mismatch is readable without opening the JSON.
for (const row of rows) {
  if (row.state !== 'OK') continue
  const diverged = row.report.cases.filter(c => !c.byte_match)
  if (diverged.length === 0) continue
  console.log(`${row.report.runner}: ${diverged.length} case(s) diverged`)
  for (const c of diverged) {
    console.log(`  ${pad(c.name, 32)} first differing byte at offset ${c.first_divergent_byte_offset}`)
  }
  console.log()
}

console.log(`results written to ${relative(REPO_ROOT, RESULTS_DIR)}/`)
console.log('A byte or digest mismatch is a recorded result, not a failure of this run.')
if (errors > 0) {
  console.error(`\n${errors} runner error(s) or schema failure(s).`)
  process.exit(1)
}
process.exit(0)
