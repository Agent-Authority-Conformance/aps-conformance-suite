// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the RFC 8785 canonical-byte cross-run.
//
// Reports where this canonicalizer's bytes and SHA-256 agree with the pinned
// fixture. It is not a verdict on the implementation, and it is not APS
// conformance; it is a byte diff on ten cases.
//
// Canonicalizer under test: canonicalizeJCS from the published
// agent-passport-system npm package, resolved as a bare specifier so a clean
// checkout plus `npm ci` is self-contained. No sibling checkout, no $HOME, no
// path dependency.
//
// Every expected value is read from the fixture at run time. Nothing about the
// ten cases is transcribed into this file: a runner that embedded a byte string
// would still agree with itself after the fixture changed.
//
// Usage:
//   npx tsx runner.ts [fixture-path]
// Default fixture: ../../canonical-bytes-jcs-v2.json

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from 'agent-passport-system'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DEFAULT_FIXTURE = join(__dirname, '..', '..', 'canonical-bytes-jcs-v2.json')

const fixturePath = resolve(process.argv[2] ?? DEFAULT_FIXTURE)
const fixtureBytes = readFileSync(fixturePath)
const fixture = JSON.parse(fixtureBytes.toString('utf8')) as {
  vectors: { name: string; input: unknown; canonical_bytes_hex: string; canonical_sha256: string }[]
}

const sha256Hex = (buf: Buffer): string => createHash('sha256').update(buf).digest('hex')

/** Zero-based offset of the first differing byte. When one sequence is an exact
 *  prefix of the other there is no differing byte at all, so the answer is the
 *  length of the shorter one: that is the offset a reader would look at to see
 *  where the two stopped agreeing. Null when the bytes are equal. */
function firstDivergentByteOffset(a: Buffer, b: Buffer): number | null {
  const shared = Math.min(a.length, b.length)
  for (let i = 0; i < shared; i++) if (a[i] !== b[i]) return i
  return a.length === b.length ? null : shared
}

// The version is read from the manifest of the package that ACTUALLY loaded,
// rather than typed here or read from this repo's dependency pin, so it cannot
// drift from what was imported. Two details make this less direct than it looks:
// the package's exports map declares no ./package.json subpath, so the manifest
// cannot be imported, and it declares only an `import` condition, so
// require.resolve cannot see it either. import.meta.resolve is the ESM-native
// resolver that does, and the manifest is then found by walking up from the
// resolved entry point. The walk stays inside the resolved package; it never
// consults $HOME or a sibling checkout.
function loadedPackageVersion(specifier: string): string {
  let dir = dirname(fileURLToPath(import.meta.resolve(specifier)))
  for (;;) {
    const candidate = join(dir, 'package.json')
    try {
      const manifest = JSON.parse(readFileSync(candidate, 'utf8')) as { name?: string; version?: string }
      if (manifest.name === specifier && manifest.version) return manifest.version
    } catch { /* keep walking */ }
    const parent = dirname(dir)
    if (parent === dir) throw new Error(`could not find the manifest of ${specifier}`)
    dir = parent
  }
}
const sdkVersion = loadedPackageVersion('agent-passport-system')

const cases = fixture.vectors.map(v => {
  const actual = Buffer.from(canonicalizeJCS(v.input), 'utf8')
  const expected = Buffer.from(v.canonical_bytes_hex, 'hex')
  const actualSha = sha256Hex(actual)
  const byteMatch = actual.equals(expected)
  return {
    name: v.name,
    byte_match: byteMatch,
    sha256_match: actualSha === v.canonical_sha256,
    actual_bytes_hex: actual.toString('hex'),
    actual_sha256: actualSha,
    first_divergent_byte_offset: byteMatch ? null : firstDivergentByteOffset(actual, expected),
  }
})

process.stdout.write(JSON.stringify({
  runner: 'ts',
  implementation: 'agent-passport-system canonicalizeJCS',
  implementation_kind: 'first_party',
  implementation_version: sdkVersion,
  runtime_version: `node ${process.versions.node}`,
  fixture: fixturePath,
  fixture_sha256: sha256Hex(fixtureBytes),
  cases,
  summary: {
    total: cases.length,
    byte_match: cases.filter(c => c.byte_match).length,
    sha256_match: cases.filter(c => c.sha256_match).length,
  },
}, null, 2) + '\n')
