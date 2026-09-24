// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Prints, per vector, exactly what the npm reference SDK decided and what it
// has no API for. This is the evidence behind the README's "SDK support" table.
// It asserts nothing and always exits 0 unless a call throws: its job is to
// record, not to judge.
//
// Run: npx tsx fixtures/suspension-cause-composition/sdk-support.ts

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS, verifyAuthorityDelegationChain } from 'agent-passport-system'

import { signatureVerifies, type ChainFixture } from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))
// The package's exports map does not expose ./package.json, so the version is
// read from the installed file directly rather than imported.
const sdkVersion = (
  JSON.parse(
    fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
  ) as { version: string }
).version

const fixture = JSON.parse(fs.readFileSync(path.join(here, 'chain.json'), 'utf8')) as ChainFixture
const vectors = JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8')) as {
  cases: Array<{
    id: string
    grant: string
    evaluated_at: string
    revocation: 'active' | 'revoked' | 'unknown'
    presented_releases: string[]
  }>
}

// Named here so the reason travels with the record rather than living only in
// prose. The first entry is the one that decides the shape of this whole
// family: the SDK's revocation resolver has three answers and none of them is
// suspended, so there is nowhere to put one cause, let alone three.
const UNSUPPORTED_CONCEPTS = [
  'a suspended or restricted state of any arity (RevocationResolution is active, revoked or unknown)',
  'a lifecycle cause attached to a grant',
  'a release record, or a rule for when one takes effect',
  'lifecycle standing over a cause, or a registry that supplies it',
  'a verdict that names which causes remain',
]

console.log(`npm agent-passport-system ${sdkVersion}`)
console.log('JCS canonicalizer in use: canonicalizeJCS')
console.log(`  typeof canonicalizeJCS: ${typeof canonicalizeJCS}`)
console.log()

for (const vector of vectors.cases) {
  const evaluatedAt = fixture.clock[vector.evaluated_at]
  const chainResult = verifyAuthorityDelegationChain(fixture.chains[vector.grant] as never, {
    now: evaluatedAt,
    resolveVerificationKey: ((_i: string, m: string) => fixture.verification_keys[m] ?? null) as never,
    trustRoot: () => true,
    resolveRevocation: () => vector.revocation,
  })
  const code = chainResult.failures?.[0]?.code ?? 'none'
  const signatureResults = vector.presented_releases.map(label => {
    const release = fixture.releases[label] as unknown as Record<string, unknown>
    return `${label}=${signatureVerifies(fixture, release)}`
  })
  console.log(vector.id)
  console.log(`  verifyAuthorityDelegationChain: supported, state=${chainResult.state} code=${code}`)
  console.log(
    '  verify + canonicalizeJCS over release-record bytes: supported, ' +
      `${signatureResults.length > 0 ? signatureResults.join(' ') : 'no release presented'}`,
  )
  console.log(`  cause verdict: not_supported, no SDK API for: ${UNSUPPORTED_CONCEPTS.join('; ')}`)
}

console.log()
console.log(`suspension-cause-composition npm SDK observations: ${vectors.cases.length} vectors recorded`)
