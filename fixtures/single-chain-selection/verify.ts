import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyAuthorityDelegationChain } from 'agent-passport-system'

type Expected = {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failure_code: string | null
  failure_index: number | null
}

type VectorCase = {
  id: string
  presented_chain: string
  // Documentation only, matching what mint.py baked into the named presented
  // chain's second hop. Never read below: the runner only reads
  // vector.presented_chain to look up the pre-minted array in chains.json.
  action: Record<string, unknown>
  expected: Expected
}

type Vectors = {
  profile: string
  description: string
  cases: VectorCase[]
}

type ChainFixture = {
  _placeholder?: boolean
  now: string
  verification_keys: Record<string, string>
  chain_1: any[]
  chain_2: any[]
  presented: Record<string, any[]>
}

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<ChainFixture>('chains.json')
const vectors = readJson<Vectors>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.now !== 'string' ||
  fixture.now.length === 0 ||
  !Array.isArray(fixture.chain_1) ||
  !Array.isArray(fixture.chain_2) ||
  !fixture.verification_keys ||
  Object.keys(fixture.verification_keys).length === 0 ||
  !fixture.presented ||
  Object.keys(fixture.presented).length === 0
) {
  console.error(
    'single-chain-selection chains.json is still a placeholder. Mint it with the SDK ' +
    'and populate now, verification_keys, chain_1, chain_2 and presented before running.'
  )
  process.exit(2)
}

function actualFailure(result: any): { code: string | null; index: number | null } {
  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  return {
    code: first?.code ?? null,
    index: typeof first?.index === 'number' ? first.index : null,
  }
}

let passed = 0

for (const vector of vectors.cases) {
  const presentedChain = fixture.presented[vector.presented_chain]
  if (!presentedChain) {
    console.error(`FAIL ${vector.id}: no presented chain named ${vector.presented_chain} in chains.json`)
    continue
  }

  const result = verifyAuthorityDelegationChain(presentedChain, {
    now: fixture.now,
    resolveVerificationKey: (_issuer, verificationMethod) =>
      fixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })

  const failure = actualFailure(result)

  const ok =
    result.state === vector.expected.state &&
    result.valid === (vector.expected.state === 'valid') &&
    failure.code === vector.expected.failure_code &&
    failure.index === vector.expected.failure_index &&
    (
      vector.expected.failure_code !== null ||
      (Array.isArray(result.failures) && result.failures.length === 0)
    )

  if (ok) {
    passed += 1
    console.log(
      `PASS ${vector.id} state=${result.state}` +
      (failure.code ? ` code=${failure.code} index=${failure.index}` : '')
    )
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error('  expected:', JSON.stringify(vector.expected))
    console.error(
      '  actual:  ',
      JSON.stringify({
        state: result.state,
        valid: result.valid,
        failure_code: failure.code,
        failure_index: failure.index,
        failures: result.failures,
      })
    )
  }
}

console.log(`single-chain-selection TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(passed === vectors.cases.length ? 0 : 1)
