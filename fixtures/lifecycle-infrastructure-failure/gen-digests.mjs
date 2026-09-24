// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Regenerates input-digests.json: for each case in vectors.json, the SHA-256 of
// the RFC 8785 (JCS) canonicalization of that case's `input` object, computed
// through the published npm agent-passport-system's canonicalizeJCS.
//
// The file is a pin, not a derived convenience. verify.ts and verify.py both
// recompute every digest and fail on a mismatch, through two different
// implementations' JCS primitives, so editing a vector's input without
// regenerating is a test failure rather than a silent drift.
//
// Run: node fixtures/lifecycle-infrastructure-failure/gen-digests.mjs
// After regenerating, `git diff` on input-digests.json shows exactly which
// inputs changed.

import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS } from 'agent-passport-system'

const HERE = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8'))

const inputs = {}
for (const c of vectors.cases) {
  inputs[c.id] = createHash('sha256').update(Buffer.from(canonicalizeJCS(c.input), 'utf8')).digest('hex')
}

const out = {
  family: vectors.family,
  algorithm: 'sha256 over RFC 8785 (JCS) canonicalization of each case input',
  produced_by: 'fixtures/lifecycle-infrastructure-failure/gen-digests.mjs, via npm agent-passport-system canonicalizeJCS',
  inputs,
}

writeFileSync(join(HERE, 'input-digests.json'), JSON.stringify(out, null, 2) + '\n')
console.log(`input-digests.json: ${Object.keys(inputs).length} input digests written`)
