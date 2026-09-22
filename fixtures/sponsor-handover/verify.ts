import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { verifyAuthorityDelegationChain } from 'agent-passport-system'

type Expected = {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failure_code: string | null
  failure_index: number | null
}

type ResolverSpec = { mode: 'by_role'; values: Record<string, unknown> }

type VectorCase = {
  id: string
  available_chains: string[]
  resolver: ResolverSpec
  expected: Record<string, Expected>
  assert_no_valid_chain?: boolean
  structural_independence_check?: boolean
}

type Vectors = {
  profile: string
  description: string
  cases: VectorCase[]
}

type ChainsFixture = {
  _placeholder?: boolean
  now: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chains: Record<string, any[]>
}

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

const fixture = readJson<ChainsFixture>('chains.json')
const vectors = readJson<Vectors>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.now !== 'string' ||
  fixture.now.length === 0 ||
  !fixture.chains ||
  !fixture.chains.OLD ||
  !fixture.chains.NEW ||
  !fixture.chains.OTHER ||
  !fixture.verification_keys ||
  Object.keys(fixture.verification_keys).length === 0 ||
  !fixture.roles
) {
  console.error(
    'sponsor-handover chains.json is still a placeholder or missing chains/roles. ' +
    'Mint OLD, NEW and OTHER with the SDK and populate now, verification_keys, roles and chains before running.'
  )
  process.exit(2)
}

const roleByDelegationId = new Map<string, string>()
for (const [role, id] of Object.entries(fixture.roles)) {
  roleByDelegationId.set(id, role)
}

for (const [chainName, chain] of Object.entries(fixture.chains)) {
  for (const member of chain) {
    if (typeof member?.delegation_id !== 'string' || !roleByDelegationId.has(member.delegation_id)) {
      console.error(`sponsor-handover chain ${chainName} has a member with no registered role`)
      process.exit(2)
    }
  }
}

function resolverFor(spec: ResolverSpec) {
  return ((delegation: any) => {
    const role = roleByDelegationId.get(delegation?.delegation_id)
    if (role === undefined || !(role in spec.values)) {
      throw new Error('sponsor-handover resolver received a delegation with no answer for its role')
    }
    return spec.values[role]
  }) as any
}

function actualFailure(result: any): { code: string | null; index: number | null } {
  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  return {
    code: first?.code ?? null,
    index: typeof first?.index === 'number' ? first.index : null,
  }
}

// Checked once, not derived from any vector's resolver answers: NEW is built
// from an independent root delegation, so no member of NEW should share a
// delegation_id with, or name as parent, any member of OLD.
function structuralIndependence(): { ok: boolean; detail: string } {
  const oldIds = new Set(fixture.chains.OLD.map((m: any) => m.delegation_id))
  const sharedId = fixture.chains.NEW.find((m: any) => oldIds.has(m.delegation_id))
  const sharedParent = fixture.chains.NEW.find(
    (m: any) => m.parent_delegation_id !== null && oldIds.has(m.parent_delegation_id)
  )
  const ok = !sharedId && !sharedParent
  return {
    ok,
    detail: `shared_delegation_id=${Boolean(sharedId)} new_member_parents_old_member=${Boolean(sharedParent)}`,
  }
}

let passed = 0

for (const vector of vectors.cases) {
  const resolveRevocation = resolverFor(vector.resolver)
  const results: Record<string, any> = {}

  for (const chainName of vector.available_chains) {
    results[chainName] = verifyAuthorityDelegationChain(fixture.chains[chainName], {
      now: fixture.now,
      resolveVerificationKey: (_issuer, verificationMethod) =>
        fixture.verification_keys[verificationMethod] ?? null,
      trustRoot: () => true,
      resolveRevocation,
    })
  }

  let ok = true
  const details: string[] = []

  for (const [chainName, expected] of Object.entries(vector.expected)) {
    const result = results[chainName]
    const failure = actualFailure(result)
    const chainOk =
      result.state === expected.state &&
      result.valid === (expected.state === 'valid') &&
      failure.code === expected.failure_code &&
      failure.index === expected.failure_index &&
      (expected.failure_code !== null || (Array.isArray(result.failures) && result.failures.length === 0))
    ok = ok && chainOk
    details.push(`${chainName}=${result.state}${failure.code ? `/${failure.code}@${failure.index}` : ''}`)
  }

  if (vector.assert_no_valid_chain) {
    const anyValid = vector.available_chains.some((name) => results[name].state === 'valid')
    ok = ok && !anyValid
    details.push(`no_valid_chain=${!anyValid}`)
  }

  if (vector.structural_independence_check) {
    const structural = structuralIndependence()
    ok = ok && structural.ok
    details.push(structural.detail)
  }

  if (ok) {
    passed += 1
    console.log(`PASS ${vector.id} ${details.join(' ')}`)
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error(`  expected: ${JSON.stringify(vector.expected)}`)
    console.error(`  actual:   ${details.join(' ')}`)
  }
}

console.log(`sponsor-handover TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(passed === vectors.cases.length ? 0 : 1)
