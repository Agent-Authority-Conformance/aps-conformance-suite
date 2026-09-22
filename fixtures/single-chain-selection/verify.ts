import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  InMemoryAuthorityBudgetLedger,
  isValidScopeGrant,
  scopeGrantCovers,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

type Expected = {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failure_code: string | null
  failure_index: number | null
}

type PrimaryExpected = {
  state: 'valid' | 'invalid'
  reason: string
}

type VectorCase = {
  id: string
  presented_chain: string
  // Which of chains.json's chain_1 / chain_2 (the single presented chain, no
  // synthetic hop) the primary path runs against. Absent for SCS-06, which has
  // no single chain to select: it is a concatenation, decided only by the
  // synthetic-hop cross-check below.
  primary_chain?: 'chain_1' | 'chain_2'
  primary_expected?: PrimaryExpected
  // Documentation only, matching what mint.py baked into the named presented
  // chain's second hop. Never read below for the synthetic-hop path: that path
  // only reads vector.presented_chain to look up the pre-minted array in
  // chains.json. The primary path reads action.scope_needed, action.unit and
  // action.amount directly, since it has no synthetic hop to decide those for it.
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

function actionRefFor(id: string): string {
  return crypto.createHash('sha256').update(id).digest('hex')
}

// The primary path: decide chain state, scope coverage and spend headroom with
// the SDK's own real primitives, on the one chain the action presents, no
// synthetic hop involved. See the README's "Primary path" section for why each
// step below is the one that decides it.
function runPrimaryPath(vector: VectorCase): { state: 'valid' | 'invalid'; reason: string } | null {
  if (!vector.primary_chain) return null
  const chain = fixture[vector.primary_chain]

  const chainResult = verifyAuthorityDelegationChain(chain, {
    now: fixture.now,
    resolveVerificationKey: (_issuer, verificationMethod) =>
      fixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
  if (chainResult.state !== 'valid') {
    const failure = actualFailure(chainResult)
    return { state: 'invalid', reason: failure.code ?? chainResult.state }
  }

  const leafGrants: string[] = chain[chain.length - 1].authority.scope.grants
  const neededGrants = vector.action.scope_needed as string[]
  const scopeCovered = neededGrants.every(
    (needed) => isValidScopeGrant(needed) && leafGrants.some((grant) => scopeGrantCovers(grant, needed))
  )
  if (!scopeCovered) {
    return { state: 'invalid', reason: 'scope_not_covered' }
  }

  const ledger = new InMemoryAuthorityBudgetLedger()
  const reservation = ledger.reserve(
    chain,
    actionRefFor(vector.id),
    vector.action.unit as string,
    vector.action.amount as string
  )
  return { state: reservation.ok ? 'valid' : 'invalid', reason: reservation.code }
}

let passed = 0

for (const vector of vectors.cases) {
  const presentedChain = fixture.presented[vector.presented_chain]
  if (!presentedChain) {
    console.error(`FAIL ${vector.id}: no presented chain named ${vector.presented_chain} in chains.json`)
    continue
  }

  // Synthetic-hop cross-check: the action's requirement modeled as a second,
  // signed AuthorityDelegationV1 hop, decided entirely by chain verification's
  // own phase 9 narrowing check. Unchanged from before the primary path existed.
  const result = verifyAuthorityDelegationChain(presentedChain, {
    now: fixture.now,
    resolveVerificationKey: (_issuer, verificationMethod) =>
      fixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })

  const failure = actualFailure(result)

  const syntheticOk =
    result.state === vector.expected.state &&
    result.valid === (vector.expected.state === 'valid') &&
    failure.code === vector.expected.failure_code &&
    failure.index === vector.expected.failure_index &&
    (
      vector.expected.failure_code !== null ||
      (Array.isArray(result.failures) && result.failures.length === 0)
    )

  const primary = runPrimaryPath(vector)

  const primaryOk =
    primary === null ||
    vector.primary_expected === undefined ||
    (primary.state === vector.primary_expected.state && primary.reason === vector.primary_expected.reason)

  const agreementOk = primary === null || primary.state === result.state

  const ok = syntheticOk && primaryOk && agreementOk

  if (ok) {
    passed += 1
    const primaryNote = primary ? ` primary=${primary.state}(${primary.reason})` : ''
    console.log(
      `PASS ${vector.id} state=${result.state}` +
      (failure.code ? ` code=${failure.code} index=${failure.index}` : '') +
      primaryNote
    )
  } else {
    console.error(`FAIL ${vector.id}`)
    console.error('  synthetic expected:', JSON.stringify(vector.expected))
    console.error(
      '  synthetic actual:  ',
      JSON.stringify({
        state: result.state,
        valid: result.valid,
        failure_code: failure.code,
        failure_index: failure.index,
        failures: result.failures,
      })
    )
    if (vector.primary_expected !== undefined) {
      console.error('  primary expected:', JSON.stringify(vector.primary_expected))
    }
    if (primary !== null) {
      console.error('  primary actual:  ', JSON.stringify(primary))
    }
    if (!agreementOk) {
      console.error(`  primary/synthetic disagreement: primary=${primary?.state} synthetic=${result.state}`)
    }
  }
}

console.log(`single-chain-selection TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(passed === vectors.cases.length ? 0 : 1)
