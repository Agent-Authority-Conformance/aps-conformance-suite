// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the lifecycle-subdelegation-edges candidate family.
//
// Exit 0 when every vector matches its expected block under every declared
// policy, 1 on any mismatch, 2 when the fixture is not minted.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  type BoundaryRecord,
  type ChainsFixture,
  type PolicyName,
  recordDigest,
  runPolicy,
  writeRecord,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<ChainsFixture>('chains.json')
const vectors = readJson<any>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.mint_now !== 'string' ||
  !fixture.chains ||
  Object.keys(fixture.chains).length !== 6 ||
  !fixture.verification_keys ||
  !fixture.roles ||
  !fixture.refusals
) {
  console.error(
    'lifecycle-subdelegation-edges chains.json is not minted. Run ' +
    'python3 fixtures/lifecycle-subdelegation-edges/mint.py first.'
  )
  process.exit(2)
}

const POLICIES: PolicyName[] = ['reference', 'per-artifact-only', 'issuer-attestation-trusting']

const records = new Map<string, BoundaryRecord>()
const digests = new Map<string, string>()

let passed = 0
let failed = 0

for (const vector of vectors.cases) {
  const details: string[] = []
  let ok = true

  if (vector.kind === 'issuance') {
    const refusal = fixture.refusals[vector.refusal]
    ok =
      refusal !== undefined &&
      refusal.raised === vector.expected.raised &&
      refusal.code === vector.expected.code
    details.push(`raised=${refusal?.raised} code=${refusal?.code}`)
  } else if (vector.kind === 'record-continuity') {
    const earlier = records.get(vector.earlier)
    const later = records.get(vector.later)
    if (earlier === undefined || later === undefined) {
      ok = false
      details.push('a referenced record was never emitted')
    } else {
      // Recompute the earlier record's digest now, after the later finding was
      // made, from the object still held in this runner. If anything had
      // rewritten it, this would not match what it hashed to when it was
      // written.
      const earlierNow = recordDigest(earlier)
      const earlierThen = digests.get(vector.earlier)!
      const laterDigest = recordDigest(later)
      ok =
        earlierNow === earlierThen &&
        later.prior_record_sha256 === earlierThen &&
        vector.expected.earlier_record_rewritten === false &&
        vector.expected.earlier_record_sha256 === earlierThen &&
        vector.expected.later_record_prior_sha256 === earlierThen &&
        vector.expected.later_record_sha256 === laterDigest
      details.push(`earlier=${earlierThen.slice(0, 16)} later.prior=${String(later.prior_record_sha256).slice(0, 16)}`)
    }
  } else {
    for (const policy of POLICIES) {
      const outcome = runPolicy(fixture, policy, vector.chain, vector.now, vector.revocation ?? {})
      if (policy === 'reference') {
        const matches =
          outcome.authority_verdict === vector.expected.authority_verdict &&
          outcome.failure_code === vector.expected.failure_code &&
          outcome.failure_index === vector.expected.failure_index
        ok = ok && matches
        details.push(`reference=${outcome.authority_verdict}${outcome.failure_code ? `/${outcome.failure_code}@${outcome.failure_index}` : ''}`)
        if (vector.emits_record) {
          const prior = vector.prior_record_of ? (digests.get(vector.prior_record_of) ?? null) : null
          const record = writeRecord(vector.id, vector.now, vector.chain, outcome, prior)
          records.set(vector.id, record)
          digests.set(vector.id, recordDigest(record))
        }
      } else {
        const declared = vector.policy_expected?.[policy]
        if (declared === undefined) {
          ok = false
          details.push(`${policy}=undeclared`)
          continue
        }
        const reachedReference =
          outcome.authority_verdict === vector.expected.authority_verdict &&
          outcome.failure_code === vector.expected.failure_code &&
          outcome.failure_index === vector.expected.failure_index
        const matches =
          outcome.authority_verdict === declared.authority_verdict &&
          outcome.failure_code === declared.failure_code &&
          outcome.failure_index === declared.failure_index &&
          declared.agrees === reachedReference
        ok = ok && matches
        details.push(
          `${policy}=${outcome.authority_verdict}${outcome.failure_code ? `/${outcome.failure_code}@${outcome.failure_index}` : ''}(agrees=${declared.agrees})`
        )
      }
    }

    // A vector the family declares as a negative control must be one a
    // defective policy actually passes wrongly. This is checked, not asserted.
    if (vector.negative_control) {
      const failSets: Record<string, string[]> = vectors.declared_fail_sets
      const inAFailSet = Object.values(failSets).some(ids => ids.includes(vector.id))
      const someoneDisagrees = Object.values(vector.policy_expected ?? {}).some(
        (p: any) => p.agrees === false
      )
      ok = ok && inAFailSet && someoneDisagrees
      details.push(`negative_control=${inAFailSet && someoneDisagrees}`)
    }
  }

  if (ok) {
    passed += 1
    console.log(`PASS ${vector.id} ${details.join(' ')}`)
  } else {
    failed += 1
    console.error(`FAIL ${vector.id}`)
    console.error(`  expected: ${JSON.stringify(vector.expected)}`)
    console.error(`  actual:   ${details.join(' ')}`)
  }
}

// Every id a declared fail set names must exist, so a fail set cannot drift
// away from the vectors it describes.
const allIds = new Set(vectors.cases.map((c: any) => c.id))
for (const [policy, ids] of Object.entries(vectors.declared_fail_sets as Record<string, string[]>)) {
  for (const id of ids) {
    if (!allIds.has(id)) {
      console.error(`FAIL declared_fail_sets.${policy} names an unknown vector ${id}`)
      failed += 1
    }
  }
}

console.log(`lifecycle-subdelegation-edges TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(failed === 0 ? 0 : 1)
