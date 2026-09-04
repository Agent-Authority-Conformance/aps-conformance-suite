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
//   layer declarations: every required layer is declared, owns at least one
//     rejection_kind, and no rejection_kind is owned twice
//   schema layers: the dialect is Draft 2020-12, the schema file exists, its
//     bytes match the pinned schema_sha256, and the declared validator matches
//     the version package.json pins
//   error bindings: every expected_error_code any vector declares is bound to a
//     concrete error on the layer that owns its rejection_kind
//   layered_families names exactly the categories that carry a layer
//     declaration, checked in BOTH directions
//
// What the schema pin is and is not. It makes a schema change explicit and
// reviewable: the digest is in the manifest, so editing the schema without
// editing the manifest fails the gate, and editing both shows up as two
// changes in one diff. It is NOT tamper-proofing. A PR that changes the schema
// can update the digest in the same commit. Base-owned protection is
// governance work, not something this file provides.
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
const DRAFT_2020_12 = 'https://json-schema.org/draft/2020-12/schema'

interface ErrorBinding {
  instance_path?: unknown
  keyword?: unknown
}
interface LayerDecl {
  kind?: unknown
  owns_rejection_kinds?: unknown
  error_bindings?: Record<string, ErrorBinding>
  dialect?: unknown
  validator?: unknown
  schema_path?: unknown
  schema_sha256?: unknown
  instance_pointer?: unknown
}
interface Entry {
  category: string
  path: string
  canonical_sha256: string
  vector_count: number
  required_layers?: unknown
  layers?: Record<string, LayerDecl>
}
interface Manifest {
  totals?: { fixtures: number; vectors: number }
  layered_families?: unknown
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

  checkLayerDeclaration(label, entry, abs)
}

// A family decided by more than one validation layer declares those layers
// here. This block checks the declaration is complete and internally
// consistent, because the declaration is what the gate reads to decide which
// layers must run: a family that silently stops declaring a layer would stop
// running it, and every vector that layer decided would go unasserted.
function checkLayerDeclaration(label: string, entry: Entry, fixtureAbs: string): void {
  if (entry.required_layers === undefined && entry.layers === undefined) return

  const required = entry.required_layers
  check(`${label}: required_layers is a non-empty array`,
    Array.isArray(required) && required.length > 0 && required.every((n) => typeof n === 'string'),
    JSON.stringify(required))
  const layers = entry.layers
  check(`${label}: layers is an object`, layers !== undefined && layers !== null && typeof layers === 'object')
  if (!Array.isArray(required) || !layers) return

  // Every rejection_kind is owned by exactly one required layer. Unowned means
  // no layer is accountable for the rejection; owned twice means the verdict
  // has no single accountable layer.
  const ownerOf = new Map<string, string>()
  for (const name of required as string[]) {
    const decl = layers[name]
    check(`${label}: required layer "${name}" is declared`, decl !== undefined)
    if (!decl) continue

    const owns = decl.owns_rejection_kinds
    check(`${label}: layer "${name}" declares owns_rejection_kinds`,
      Array.isArray(owns) && owns.length > 0 && owns.every((k) => typeof k === 'string'),
      JSON.stringify(owns))
    if (Array.isArray(owns)) {
      for (const kind of owns as string[]) {
        check(`${label}: rejection_kind "${kind}" is owned by exactly one layer`,
          !ownerOf.has(kind),
          ownerOf.has(kind) ? `also owned by "${ownerOf.get(kind)}"` : '')
        ownerOf.set(kind, name)
      }
    }

    for (const [code, binding] of Object.entries(decl.error_bindings ?? {})) {
      check(`${label}: layer "${name}" error_binding ${code} names an instance path and keyword`,
        typeof binding?.instance_path === 'string' && typeof binding?.keyword === 'string',
        JSON.stringify(binding))
    }

    if (decl.kind === 'json-schema') checkSchemaLayer(label, name, decl)
  }

  // Every expected_error_code the fixture declares is bound on the layer that
  // owns its rejection_kind. An unbound code is a negative whose expected error
  // the gate cannot check -- it would pass on the bare fact of a rejection.
  let vectors: Array<Record<string, unknown>> = []
  try {
    const fx = JSON.parse(readFileSync(fixtureAbs, 'utf8')) as { vectors?: Array<Record<string, unknown>> }
    vectors = fx.vectors ?? []
  } catch {
    check(`${label}: fixture parses for the error-binding check`, false)
    return
  }
  for (const v of vectors) {
    const kind = v.rejection_kind
    const code = v.expected_error_code
    if (typeof kind !== 'string' || typeof code !== 'string') continue
    const owner = ownerOf.get(kind)
    check(`${label}: vector "${String(v.name)}" rejection_kind "${kind}" is owned by a required layer`,
      owner !== undefined)
    if (!owner) continue
    check(`${label}: vector "${String(v.name)}" expected_error_code ${code} is bound on layer "${owner}"`,
      layers[owner]?.error_bindings?.[code] !== undefined)
  }
}

function checkSchemaLayer(label: string, name: string, decl: LayerDecl): void {
  check(`${label}: schema layer "${name}" declares the Draft 2020-12 dialect`,
    decl.dialect === DRAFT_2020_12, String(decl.dialect))
  check(`${label}: schema layer "${name}" declares an instance_pointer`,
    typeof decl.instance_pointer === 'string')

  // The declared validator must be the one package.json actually pins, so a
  // dependency bump cannot silently change what the gate proves.
  const validator = decl.validator
  check(`${label}: schema layer "${name}" names its validator as name@version`,
    typeof validator === 'string' && /^[^@]+@[^@]+$/.test(validator), String(validator))
  if (typeof validator === 'string') {
    const [pkgName, version] = validator.split('@')
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
    }
    const pinned = pkg.devDependencies?.[pkgName] ?? pkg.dependencies?.[pkgName]
    check(`${label}: schema layer "${name}" validator ${validator} matches the version package.json pins`,
      pinned === version, `package.json pins ${String(pinned)}`)
  }

  const schemaPath = decl.schema_path
  check(`${label}: schema layer "${name}" declares a schema_path`, typeof schemaPath === 'string')
  if (typeof schemaPath !== 'string') return
  const schemaAbs = join(FIXTURES_DIR, schemaPath)
  const present = existsSync(schemaAbs) && statSync(schemaAbs).isFile()
  check(`${label}: schema layer "${name}" schema file exists`, present, present ? '' : schemaAbs)
  if (!present) return
  const actual = createHash('sha256').update(readFileSync(schemaAbs)).digest('hex')
  check(`${label}: schema layer "${name}" schema_sha256 matches the schema bytes`,
    actual === decl.schema_sha256,
    `declared ${String(decl.schema_sha256).slice(0, 16)}, actual ${actual.slice(0, 16)}`)
}

// layered_families is the named index of which categories are decided by more
// than one layer. A count cannot see identity, so this compares names and fails
// in BOTH directions: a listed family that stopped declaring its layers would
// otherwise stop running them silently, and a family that grew a declaration
// without being listed is a change nobody was asked to review.
{
  const listed = manifest.layered_families
  check('layered_families is an array of category names',
    Array.isArray(listed) && listed.every((n) => typeof n === 'string'),
    JSON.stringify(listed))
  if (Array.isArray(listed)) {
    const declaring = entries
      .filter((e) => e.required_layers !== undefined || e.layers !== undefined)
      .map((e) => e.category)
    const missing = (listed as string[]).filter((c) => !declaring.includes(c))
    const unlisted = declaring.filter((c) => !(listed as string[]).includes(c))
    check('every category in layered_families declares a layer declaration',
      missing.length === 0,
      `listed but not declaring: [${missing.join(', ')}]`)
    check('every category that declares layers is named in layered_families',
      unlisted.length === 0,
      `declaring but not listed: [${unlisted.join(', ')}]`)
  }
}

console.log()
if (failures > 0) {
  console.error(`${failures} manifest integrity failure(s)`)
  process.exit(1)
}
console.log(`manifest integrity OK: ${entries.length} entries, ${entries.reduce((n, e) => n + e.vector_count, 0)} vectors`)
