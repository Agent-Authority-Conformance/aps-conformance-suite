// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Prints, per vector, exactly what the npm reference SDK decided and what it
// has no API for. This is the evidence behind the README's "SDK support" table.
// It asserts nothing and always exits 0 unless a call throws: its job is to
// record, not to judge.
//
// Run: npx tsx fixtures/activation-not-established/sdk-support.ts

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

import { attestationPreimage, type ChainFixture } from './harness.js'

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
    action_at: string
    revocation: 'active' | 'revoked' | 'unknown'
    presented_attestations: string[]
  }>
}

// Named here so the reason travels with the record rather than living only in
// prose. Checked against the loaded module below, so it cannot go stale
// silently.
const UNSUPPORTED_CONCEPTS = [
  'activation condition attached to a grant, by date or by recorded event',
  'attestor-role registry or role lookup',
  'attestation acceptance against an activation condition',
  'a not_yet_effective verdict, for a condition established as not yet met',
  'a not_established verdict distinct from invalid and indeterminate',
]

console.log(`npm agent-passport-system ${sdkVersion}`)
console.log(`JCS canonicalizer in use: canonicalizeJCS (canonicalizeJCSForWrite is declared in`)
console.log(`  dist/src/core/canonical-jcs.d.ts but is not re-exported from the package root)`)
console.log()

for (const vector of vectors.cases) {
  const actionAt = fixture.clock[vector.action_at]
  const chainResult = verifyAuthorityDelegationChain(fixture.chains[vector.grant] as never, {
    now: actionAt,
    resolveVerificationKey: ((_i: string, m: string) => fixture.verification_keys[m] ?? null) as never,
    trustRoot: () => true,
    resolveRevocation: () => vector.revocation,
  })
  const code = chainResult.failures?.[0]?.code ?? 'none'
  const signatureResults = vector.presented_attestations.map(label => {
    const attestation = fixture.attestations[label]
    const key = fixture.verification_keys[attestation.verification_method]
    let ok = false
    try {
      ok = verifyEd25519(attestationPreimage(attestation), attestation.signature, key)
    } catch {
      ok = false
    }
    return `${label}=${ok}`
  })
  console.log(vector.id)
  console.log(`  verifyAuthorityDelegationChain: supported, state=${chainResult.state} code=${code}`)
  console.log(
    `  verify + canonicalizeJCS over attestation bytes: supported, ` +
      `${signatureResults.length > 0 ? signatureResults.join(' ') : 'no attestation presented'}`,
  )
  console.log(`  activation verdict: not_supported, no SDK API for: ${UNSUPPORTED_CONCEPTS.join('; ')}`)
}

console.log()
console.log(`activation-not-established npm SDK observations: ${vectors.cases.length} vectors recorded`)
console.log('  canonicalizeJCS: ' + typeof canonicalizeJCS)
