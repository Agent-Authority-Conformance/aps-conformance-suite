import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  InMemoryAuthorityRevocationStore,
  recordAuthorityRevocation,
  verifyAuthorityRevocation,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

type RecordedFailure = { code: string; message: string }

type PartACase = {
  id: string
  role: string
  record: string
  changed_from_baseline: string | null
  defect: string | null
  expected: { state: string; valid: boolean; failures: RecordedFailure[] }
}

type PartBCase = {
  id: string
  role: string
  store: 'fresh' | 'same'
  offer: string
  changed_from_baseline: string | null
  expected: { recorded: boolean; inserted: boolean; stored_record: string }
}

type Vectors = {
  profile: string
  part_a_record_verification: { cases: PartACase[] }
  part_b_store_first_wins: { cases: PartBCase[] }
}

type ResolverEntry = {
  controller: string
  verification_method: string
  key_valid_from: string
  public_key_hex: string
  key_label: string
}

type Fixture = {
  _placeholder?: boolean
  key_resolver: { entries: ResolverEntry[] }
  target_delegation: any
  records: Record<string, any>
}

const fixture = readJson<Fixture>('fixture.json')
const vectors = readJson<Vectors>('vectors.json')

if (fixture._placeholder || !fixture.records || !fixture.target_delegation) {
  console.error('authority-revocation-record fixture.json is still a placeholder. Run mint.py first.')
  process.exit(2)
}

const delegation = fixture.target_delegation

/** The resolver the fixture describes, rebuilt from its own committed table. */
function resolveVerificationKey(controller: string, verificationMethod: string, at: string): any {
  const entry = fixture.key_resolver.entries.find(
    item => item.controller === controller && item.verification_method === verificationMethod,
  )
  if (!entry) return { outcome: 'not_found' }
  if (at < entry.key_valid_from) return { outcome: 'not_found' }
  return entry.public_key_hex
}

let passed = 0
let total = 0

console.log('authority-revocation-record Part A: record verification')
for (const vector of vectors.part_a_record_verification.cases) {
  total += 1
  const result = verifyAuthorityRevocation(fixture.records[vector.record], delegation, {
    resolveVerificationKey,
  })
  const actual = {
    state: result.state,
    valid: result.valid,
    failures: result.failures.map(item => ({ code: item.code, message: item.message })),
  }
  const ok = JSON.stringify(actual) === JSON.stringify(vector.expected)

  if (ok) {
    passed += 1
    const codes = actual.failures.map(item => item.code).join(',') || '-'
    console.log(`PASS ${vector.id} state=${actual.state} failures=${codes}`)
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error('  expected:', JSON.stringify(vector.expected))
    console.error('  actual:  ', JSON.stringify(actual))
  }
}

console.log()
console.log('authority-revocation-record Part B: store first-wins')
let store = new InMemoryAuthorityRevocationStore()
for (const vector of vectors.part_b_store_first_wins.cases) {
  total += 1
  if (vector.store === 'fresh') store = new InMemoryAuthorityRevocationStore()
  const outcome = recordAuthorityRevocation(
    store,
    delegation,
    fixture.records[vector.offer],
    { resolveVerificationKey },
  )
  const actual = {
    recorded: outcome.recorded,
    inserted: outcome.inserted,
    stored_revocation_id: outcome.stored ? outcome.stored.revocation_id : null,
  }
  const expectedId = fixture.records[vector.expected.stored_record].revocation_id
  const ok =
    actual.recorded === vector.expected.recorded &&
    actual.inserted === vector.expected.inserted &&
    actual.stored_revocation_id === expectedId

  if (ok) {
    passed += 1
    console.log(
      `PASS ${vector.id} recorded=${actual.recorded} inserted=${actual.inserted} ` +
      `stored=${actual.stored_revocation_id}`,
    )
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error('  expected:', JSON.stringify({
      recorded: vector.expected.recorded,
      inserted: vector.expected.inserted,
      stored_revocation_id: expectedId,
    }))
    console.error('  actual:  ', JSON.stringify(actual))
  }
}

console.log()
console.log(`authority-revocation-record TypeScript: ${passed}/${total} passed`)
process.exit(passed === total ? 0 : 1)
