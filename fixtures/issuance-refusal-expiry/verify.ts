import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  issueSubAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

type RevocationAnswer = 'active' | 'revoked'

type PartACase = {
  id: string
  role: string
  now: string
  parent: 'parent' | 'parent_signature_tampered'
  resolver: RevocationAnswer
  changed_from_baseline: string | null
  expected: { outcome: 'issued' } | { outcome: 'refused'; code: string }
}

type ResolverSpec =
  | { mode: 'constant'; value: unknown }
  | { mode: 'by_index'; values: unknown[] }

type PartBCase = {
  id: string
  role: string
  now: string
  resolver: ResolverSpec
  changed_from_baseline: string | null
  expected: { state: string; failure_code: string | null; failure_index: number | null }
}

type Vectors = {
  profile: string
  part_a_issuance: { cases: PartACase[] }
  part_b_verification: { cases: PartBCase[] }
}

type Fixture = {
  _placeholder?: boolean
  principal_priv: string
  agent_a_priv: string
  verification_keys: Record<string, string>
  parent: any
  parent_signature_tampered: any
  child_body: any
  chain: any[]
  now: Record<string, string>
}

const fixture = readJson<Fixture>('fixture.json')
const vectors = readJson<Vectors>('vectors.json')

if (fixture._placeholder || !Array.isArray(fixture.chain) || fixture.chain.length !== 2) {
  console.error('issuance-refusal-expiry fixture.json is still a placeholder. Run mint.py first.')
  process.exit(2)
}

function resolveVerificationKey(_issuer: string, verificationMethod: string): string | null {
  return fixture.verification_keys[verificationMethod] ?? null
}

/** Extracts the SDK's failure code from an issuance Error's message, which
 * every thrown message in issue.ts ends with in parentheses, e.g. "...(EXPIRED)". */
function codeFromError(err: unknown): string | null {
  if (!(err instanceof Error)) return null
  const match = err.message.match(/\(([A-Z_]+)\)\s*$/)
  return match ? match[1] : null
}

let passed = 0
let total = 0

console.log('issuance-refusal-expiry Part A: issuance refusal')
for (const vector of vectors.part_a_issuance.cases) {
  total += 1
  const parent = vector.parent === 'parent' ? fixture.parent : fixture.parent_signature_tampered
  const now = fixture.now[vector.now]
  const resolveRevocation = () => vector.resolver

  let outcome: { outcome: 'issued'; delegationId: string } | { outcome: 'refused'; code: string | null; message: string }
  try {
    const child = issueSubAuthorityDelegation(parent, fixture.child_body, fixture.agent_a_priv, {
      now,
      resolveVerificationKey,
      resolveRevocation,
    })
    outcome = { outcome: 'issued', delegationId: child.delegation_id }
  } catch (err) {
    outcome = { outcome: 'refused', code: codeFromError(err), message: err instanceof Error ? err.message : String(err) }
  }

  const ok =
    outcome.outcome === vector.expected.outcome &&
    (vector.expected.outcome === 'issued' || (outcome.outcome === 'refused' && outcome.code === vector.expected.code))

  if (ok) {
    passed += 1
    console.log(
      `PASS ${vector.id} outcome=${outcome.outcome}` +
      (outcome.outcome === 'refused' ? ` code=${outcome.code}` : ''),
    )
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error('  expected:', JSON.stringify(vector.expected))
    console.error('  actual:  ', JSON.stringify(outcome))
  }
}

function resolverFor(spec: ResolverSpec, indexById: Map<string, number>) {
  if (spec.mode === 'constant') {
    return (() => spec.value) as any
  }
  return ((delegation: any) => {
    const index = indexById.get(delegation?.delegation_id)
    if (index === undefined) {
      throw new Error('issuance-refusal-expiry resolver received an unknown delegation')
    }
    return spec.values[index]
  }) as any
}

const indexById = new Map<string, number>()
for (let i = 0; i < fixture.chain.length; i++) {
  indexById.set(fixture.chain[i].delegation_id, i)
}

console.log()
console.log('issuance-refusal-expiry Part B: verification codes')
for (const vector of vectors.part_b_verification.cases) {
  total += 1
  const result = verifyAuthorityDelegationChain(fixture.chain, {
    now: fixture.now[vector.now],
    resolveVerificationKey,
    trustRoot: () => true,
    resolveRevocation: resolverFor(vector.resolver, indexById),
  })

  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  const failureCode = first?.code ?? null
  const failureIndex = typeof first?.index === 'number' ? first.index : null

  const ok =
    result.state === vector.expected.state &&
    failureCode === vector.expected.failure_code &&
    failureIndex === vector.expected.failure_index

  if (ok) {
    passed += 1
    console.log(
      `PASS ${vector.id} state=${result.state}` +
      (failureCode ? ` code=${failureCode} index=${failureIndex}` : ''),
    )
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error('  expected:', JSON.stringify(vector.expected))
    console.error('  actual:  ', JSON.stringify({ state: result.state, failure_code: failureCode, failure_index: failureIndex, failures: result.failures }))
  }
}

console.log()
console.log(`issuance-refusal-expiry TypeScript: ${passed}/${total} passed`)
process.exit(passed === total ? 0 : 1)
