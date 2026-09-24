// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// chain-selection-no-union, TypeScript runner.
//
// Decides every vector under the four policies vectors.json names, and fails if
// any of them departs from its declared result. Only the single_chain column is
// a claim about the reference SDK: it is built entirely out of
// verifyAuthorityDelegationChain, isValidScopeGrant, scopeGrantCovers and
// InMemoryAuthorityBudgetLedger, on the one chain each vector selected. The
// other three policies are this fixture's own models of specific
// non-conformant behaviors, and their declared results are what make each
// negative control a control rather than a vector a wrong implementation would
// also pass. See README.md, "Decision policies".
//
// No network. Run from the suite root:
//   npm run verify:chain-selection-no-union

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  InMemoryAuthorityBudgetLedger,
  canonicalizeJCS,
  isValidScopeGrant,
  scopeGrantCovers,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

type Decision = { state: 'valid' | 'invalid'; reason: string }
type FallbackDecision = Decision & { chain: string; switched: boolean }

type VectorCase = {
  id: string
  status: string
  tests: string[]
  stored_chains: string[]
  selected_chain: string
  revocation: Record<string, 'active' | 'revoked'>
  action: { scope_needed: string[]; unit: string; amount: string }
  expected: {
    single_chain: Decision
    union_pooled: Decision
    union_axis: Decision
    silent_fallback: FallbackDecision
  }
}

type Vectors = {
  profile: string
  status: string
  description: string
  policies: Record<string, string>
  cases: VectorCase[]
}

type ChainFixture = {
  _placeholder?: boolean
  now: string
  seeds: Record<string, unknown>
  verification_keys: Record<string, string>
  chains: Record<string, any[]>
  canonical_sha256: Record<string, string>
  delegation_ids: Record<string, string>
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
  !fixture.chains ||
  Object.keys(fixture.chains).length === 0 ||
  !fixture.verification_keys ||
  Object.keys(fixture.verification_keys).length === 0 ||
  !fixture.canonical_sha256 ||
  Object.keys(fixture.canonical_sha256).length === 0 ||
  !fixture.delegation_ids ||
  Object.keys(fixture.delegation_ids).length === 0
) {
  console.error(
    'chain-selection-no-union chains.json is still a placeholder. Mint it with the SDK ' +
    'and populate now, seeds, verification_keys, chains and delegation_ids before running.'
  )
  process.exit(2)
}

// Recompute the published RFC 8785 JCS digest of every record before any vector
// is decided, so a verdict is never reported against bytes that drifted from the
// ones mint.py pinned.
for (const [name, chain] of Object.entries(fixture.chains)) {
  if (chain.length !== 1) {
    console.error(`chain-selection-no-union: ${name} is ${chain.length} records, every chain here is one root`)
    process.exit(2)
  }
  const digest = crypto.createHash('sha256').update(canonicalizeJCS(chain[0]), 'utf8').digest('hex')
  if (digest !== fixture.canonical_sha256[name]) {
    console.error(
      `chain-selection-no-union: JCS canonical digest mismatch for ${name}\n` +
      `  declared:   ${fixture.canonical_sha256[name]}\n` +
      `  recomputed: ${digest}`
    )
    process.exit(2)
  }
}
console.log(`chain-selection-no-union: ${Object.keys(fixture.chains).length} JCS canonical digests recomputed and matched`)

// Reverse the published name -> delegation id map so a resolver answer keyed by
// chain name can be given back to the SDK, which hands the resolver a
// delegation record and not a name.
const chainNameByDelegationId = new Map<string, string>()
for (const [name, id] of Object.entries(fixture.delegation_ids)) {
  chainNameByDelegationId.set(id, name)
}

const resolveVerificationKey = (_issuer: string, verificationMethod: string) =>
  fixture.verification_keys[verificationMethod] ?? null

// Fail loud: a vector that forgot to state an answer for a chain it presents
// must not silently read as active.
function resolverFor(vector: VectorCase) {
  return ((delegation: any) => {
    const name = chainNameByDelegationId.get(delegation?.delegation_id)
    if (name === undefined || !(name in vector.revocation)) {
      throw new Error(
        `chain-selection-no-union resolver received a delegation with no declared answer (vector ${vector.id})`
      )
    }
    return vector.revocation[name]
  }) as any
}

function firstFailureCode(result: any): string | null {
  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  return first?.code ?? null
}

function actionRefFor(id: string): string {
  return crypto.createHash('sha256').update(id).digest('hex')
}

function leafGrants(chain: any[]): string[] {
  return chain[chain.length - 1].authority.scope.grants as string[]
}

function verifyChain(vector: VectorCase, chainName: string) {
  return verifyAuthorityDelegationChain(fixture.chains[chainName], {
    now: fixture.now,
    resolveVerificationKey,
    trustRoot: () => true,
    resolveRevocation: resolverFor(vector),
  })
}

// ---------------------------------------------------------------------------
// Policy 1, single_chain. The conformant one, and the only one below whose
// result is a claim about the SDK.
// ---------------------------------------------------------------------------
function singleChain(vector: VectorCase, chainName: string): Decision {
  const chain = fixture.chains[chainName]

  const chainResult = verifyChain(vector, chainName)
  if (chainResult.state !== 'valid') {
    return { state: 'invalid', reason: firstFailureCode(chainResult) ?? chainResult.state }
  }

  const grants = leafGrants(chain)
  const covered = vector.action.scope_needed.every(
    (needed) => isValidScopeGrant(needed) && grants.some((grant) => scopeGrantCovers(grant, needed))
  )
  if (!covered) return { state: 'invalid', reason: 'scope_not_covered' }

  const ledger = new InMemoryAuthorityBudgetLedger()
  const reservation = ledger.reserve(
    chain,
    actionRefFor(vector.id),
    vector.action.unit,
    vector.action.amount
  )
  return { state: reservation.ok ? 'valid' : 'invalid', reason: reservation.code }
}

// ---------------------------------------------------------------------------
// Policies 2 and 3, the union models. Authored here, not by the SDK: no SDK
// entry point takes more than one chain, so a pooled budget has to be computed
// by this file's own arithmetic. That absence is part of the finding, not a
// workaround. See README.md, "What the SDKs do not support".
// ---------------------------------------------------------------------------
function pooledGrantsAndCeiling(vector: VectorCase): { grants: string[]; ceiling: bigint } | null {
  const grants: string[] = []
  let ceiling = 0n
  let any = false
  for (const name of vector.stored_chains) {
    if (verifyChain(vector, name).state !== 'valid') continue
    any = true
    const chain = fixture.chains[name]
    for (const grant of leafGrants(chain)) {
      if (!grants.includes(grant)) grants.push(grant)
    }
    const spend = chain[chain.length - 1].authority.spend
    if (spend.mode === 'bounded' && spend.unit === vector.action.unit) {
      ceiling += BigInt(spend.per_action)
    }
  }
  return any ? { grants, ceiling } : null
}

function unionDecision(vector: VectorCase, covers: (pooled: string[], needed: string) => boolean): Decision {
  const pool = pooledGrantsAndCeiling(vector)
  if (pool === null) return { state: 'invalid', reason: 'no_valid_chain' }

  const covered = vector.action.scope_needed.every(
    (needed) => isValidScopeGrant(needed) && covers(pool.grants, needed)
  )
  if (!covered) return { state: 'invalid', reason: 'scope_not_covered' }

  if (BigInt(vector.action.amount) > pool.ceiling) {
    return { state: 'invalid', reason: 'PER_ACTION_EXCEEDED_POOLED' }
  }
  return { state: 'valid', reason: 'RESERVED_POOLED' }
}

const unionPooled = (vector: VectorCase): Decision =>
  unionDecision(vector, (pooled, needed) => pooled.some((grant) => scopeGrantCovers(grant, needed)))

// Split at the last colon: everything before it is the resource, the final
// segment is the action. Unioning the two axes independently is the bug this
// models: it admits a resource-and-action pair that no single grant carried.
function splitGrant(grant: string): { resource: string; action: string } {
  const i = grant.lastIndexOf(':')
  return { resource: grant.slice(0, i), action: grant.slice(i + 1) }
}

const unionAxis = (vector: VectorCase): Decision =>
  unionDecision(vector, (pooled, needed) => {
    const resources = new Set(pooled.map((grant) => splitGrant(grant).resource))
    const actions = new Set(pooled.map((grant) => splitGrant(grant).action))
    const want = splitGrant(needed)
    return resources.has(want.resource) && actions.has(want.action)
  })

// ---------------------------------------------------------------------------
// Policy 4, silent_fallback. Also authored here. It reports no switch of its
// own: the only way to see the switch is to compare its chosen chain against
// the chain the action selected, which is what this runner asserts.
// ---------------------------------------------------------------------------
function silentFallback(vector: VectorCase): FallbackDecision {
  const selected = singleChain(vector, vector.selected_chain)
  if (selected.state === 'valid') {
    return { ...selected, chain: vector.selected_chain, switched: false }
  }
  for (const name of vector.stored_chains) {
    if (name === vector.selected_chain) continue
    const other = singleChain(vector, name)
    if (other.state === 'valid') {
      return { ...other, chain: name, switched: true }
    }
  }
  return { ...selected, chain: vector.selected_chain, switched: false }
}

// ---------------------------------------------------------------------------

function sameDecision(actual: Decision, expected: Decision): boolean {
  return actual.state === expected.state && actual.reason === expected.reason
}

let passed = 0

for (const vector of vectors.cases) {
  const problems: string[] = []

  if (vector.status !== 'candidate_against_proposed') {
    problems.push(`status is ${vector.status}, every vector in this family is candidate_against_proposed`)
  }
  for (const name of vector.stored_chains) {
    if (!fixture.chains[name]) problems.push(`no chain named ${name} in chains.json`)
  }
  if (!vector.stored_chains.includes(vector.selected_chain)) {
    problems.push(`selected_chain ${vector.selected_chain} is not among stored_chains`)
  }

  const actual = {
    single_chain: problems.length === 0 ? singleChain(vector, vector.selected_chain) : null,
    union_pooled: problems.length === 0 ? unionPooled(vector) : null,
    union_axis: problems.length === 0 ? unionAxis(vector) : null,
    silent_fallback: problems.length === 0 ? silentFallback(vector) : null,
  }

  if (problems.length === 0) {
    for (const policy of ['single_chain', 'union_pooled', 'union_axis'] as const) {
      if (!sameDecision(actual[policy]!, vector.expected[policy])) {
        problems.push(
          `${policy}: expected ${JSON.stringify(vector.expected[policy])}, got ${JSON.stringify(actual[policy])}`
        )
      }
    }
    const fb = actual.silent_fallback!
    const fbExpected = vector.expected.silent_fallback
    if (!sameDecision(fb, fbExpected) || fb.chain !== fbExpected.chain || fb.switched !== fbExpected.switched) {
      problems.push(
        `silent_fallback: expected ${JSON.stringify(fbExpected)}, got ${JSON.stringify(fb)}`
      )
    }
    // The property the L11 vectors turn on: the fallback model reports a valid
    // result only by acting under a chain the action did not select.
    if (fb.switched !== (fb.chain !== vector.selected_chain)) {
      problems.push(
        `silent_fallback switched flag ${fb.switched} disagrees with chain ${fb.chain} against selected ${vector.selected_chain}`
      )
    }
  }

  if (problems.length === 0) {
    passed += 1
    const fb = actual.silent_fallback!
    console.log(
      `PASS ${vector.id} [${vector.tests.join(',')}] single_chain=${actual.single_chain!.state}(${actual.single_chain!.reason})` +
      ` union_pooled=${actual.union_pooled!.state} union_axis=${actual.union_axis!.state}` +
      ` silent_fallback=${fb.state} via ${fb.chain}${fb.switched ? ' (SWITCHED)' : ''}`
    )
  } else {
    console.error(`FAIL ${vector.id}`)
    for (const problem of problems) console.error(`  ${problem}`)
  }
}

console.log(`chain-selection-no-union TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(passed === vectors.cases.length ? 0 : 1)
