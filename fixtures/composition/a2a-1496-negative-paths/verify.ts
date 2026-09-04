// Verifier for the a2a-1496-negative-paths composition fixture. Run as:
//   npm run verify:a2a-1496-negative-paths
//
// Walks every *.fixture.json file in this directory, hands each fixture's
// `input` to validateNegativePathInput() from ./lib.js, and asserts the
// thrown NegativePathError's `code` equals the fixture's
// `expected_error_code`. A non-throw is a failure.
//
// The fixture set is DECLARED in generation-provenance.json, and the set on
// disk must equal it exactly, in both directions. This used to print "no
// fixtures present, nothing to verify" and exit 0 when the directory was empty,
// which was right while the scaffold predated any fixture PR. Four fixtures
// have since landed, and that branch had become a way for the whole set to
// vanish -- deleted, renamed, or never checked out -- with the gate still
// green. A vector that is not there is not a vector that passed.
//
// Fixture shape (see ./README.md for the full contract):
//   { name, description, input, expected_error_code }

import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { NegativePathError, validateNegativePathInput } from './lib.js'

interface NegativePathFixture {
  name: string
  description: string
  input: unknown
  expected_error_code: string
}

const __dirname = dirname(fileURLToPath(import.meta.url))

interface Provenance {
  fixtures: { file: string; expected_error_code: string }[]
}

const PROVENANCE = join(__dirname, 'generation-provenance.json')
const provenance = JSON.parse(readFileSync(PROVENANCE, 'utf-8')) as Provenance
const declared = provenance.fixtures
if (!Array.isArray(declared) || declared.length === 0) {
  console.log('a2a-1496-negative-paths: generation-provenance.json declares no fixtures')
  process.exit(1)
}

const onDisk = readdirSync(__dirname)
  .filter((f) => f.endsWith('.fixture.json'))
  .sort()
const declaredFiles = declared.map((d) => d.file).sort()

let failures = 0

// Both directions. A declared fixture missing from disk is the case that used
// to exit 0; an undeclared fixture appearing is a vector nobody reviewed.
const missing = declaredFiles.filter((f) => !onDisk.includes(f))
const undeclared = onDisk.filter((f) => !declaredFiles.includes(f))
for (const f of missing) {
  failures++
  console.log(`  FAIL  ${f}: declared in generation-provenance.json but not present on disk`)
}
for (const f of undeclared) {
  failures++
  console.log(`  FAIL  ${f}: present on disk but not declared in generation-provenance.json`)
}

const fixtures = onDisk.filter((f) => declaredFiles.includes(f))
console.log(`a2a-1496-negative-paths: running ${fixtures.length} of ${declaredFiles.length} declared fixture(s)`)

for (const file of fixtures) {
  let fx: NegativePathFixture
  try {
    fx = JSON.parse(readFileSync(join(__dirname, file), 'utf-8')) as NegativePathFixture
  } catch (e) {
    failures++
    console.log(`  FAIL  ${file}`)
    console.log(`    fixture parse error: ${(e as Error).message}`)
    continue
  }
  const label = `${file} [${fx.name}]`

  // The expected code is declared twice -- in the fixture and in the
  // provenance record -- and they must agree. A fixture quietly retargeted at
  // a different error code would otherwise still pass against itself.
  const declaredCode = declared.find((d) => d.file === file)?.expected_error_code
  if (declaredCode !== fx.expected_error_code) {
    failures++
    console.log(`  FAIL  ${label}`)
    console.log(`    fixture expects ${fx.expected_error_code}; generation-provenance.json declares ${String(declaredCode)}`)
    continue
  }

  try {
    validateNegativePathInput(fx.input)
    failures++
    console.log(`  FAIL  ${label}`)
    console.log(`    expected throw with code=${fx.expected_error_code}; got no throw`)
  } catch (e) {
    const code = e instanceof NegativePathError ? e.code : 'NON_NEGATIVE_PATH_ERROR'
    if (code === fx.expected_error_code) {
      console.log(`  PASS  ${label} (code=${code})`)
    } else {
      failures++
      console.log(`  FAIL  ${label}`)
      console.log(`    expected code: ${fx.expected_error_code}`)
      console.log(`    actual code:   ${code}`)
      if (!(e instanceof NegativePathError)) {
        console.log(`    detail:        ${(e as Error).message}`)
      }
    }
  }
}

console.log('')
if (failures === 0) {
  console.log(`a2a-1496-negative-paths: ALL PASS (${fixtures.length} of ${declaredFiles.length} declared fixture(s))`)
  process.exit(0)
} else {
  console.log(`a2a-1496-negative-paths: ${failures} FAIL of ${fixtures.length}`)
  process.exit(1)
}
