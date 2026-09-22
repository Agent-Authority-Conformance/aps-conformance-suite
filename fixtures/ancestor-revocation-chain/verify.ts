import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyAuthorityDelegationChain } from 'agent-passport-system'

type Expected = {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failure_code: string | null
  failure_index: number | null
}

type ResolverSpec =
  | { mode: 'constant'; value: unknown }
  | { mode: 'by_index'; values: unknown[] }

type VectorCase = {
  id: string
  resolver: ResolverSpec
  // Present only on AAC-03. Never read by resolverFor or by the pass/fail
  // check below: it documents an external, non-exhaustive children list and
  // must not be able to change the expected result. See README "Vector 3".
  context?: Record<string, unknown>
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
  chain: any[]
}

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.now !== 'string' ||
  fixture.now.length === 0 ||
  !Array.isArray(fixture.chain) ||
  fixture.chain.length !== 3 ||
  !fixture.verification_keys ||
  Object.keys(fixture.verification_keys).length === 0
) {
  console.error(
    'ancestor-revocation-chain chain.json is still a placeholder. Mint a valid three-hop ' +
    'root->leaf chain with the SDK and populate now, verification_keys, and chain before running.'
  )
  process.exit(2)
}

const indexById = new Map<string, number>()
for (let i = 0; i < fixture.chain.length; i++) {
  const id = fixture.chain[i]?.delegation_id
  if (typeof id !== 'string') {
    console.error(`ancestor-revocation-chain chain member ${i} has no delegation_id`)
    process.exit(2)
  }
  indexById.set(id, i)
}

// Deliberately takes only vector.resolver. vector.context (AAC-03) is never
// passed in here, so it structurally cannot affect the resolver's answers.
function resolverFor(spec: ResolverSpec) {
  if (spec.mode === 'constant') {
    return (() => spec.value) as any
  }

  return ((delegation: any) => {
    const index = indexById.get(delegation?.delegation_id)
    if (index === undefined) {
      throw new Error('ancestor-revocation-chain resolver received an unknown delegation')
    }
    return spec.values[index]
  }) as any
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
  const result = verifyAuthorityDelegationChain(fixture.chain, {
    now: fixture.now,
    resolveVerificationKey: (_issuer, verificationMethod) =>
      fixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: resolverFor(vector.resolver),
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

console.log(`ancestor-revocation-chain TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(passed === vectors.cases.length ? 0 : 1)
