// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-conferral-without-authority family, byte for byte.
//
// WHAT THIS FAMILY TESTS. Holding a scope is not the right to confer it. An agent can
// hold a grant that is valid, unrevoked, inside its time window and wide in scope, and
// still have no authority to create a child from it. The proposed text is
// aeoess/agent-authority-lifecycle at commit 2bf5c7e (later than 5c1bf09), section
// "Lifecycle concepts are separate" > "Authority and dependencies", entry "Delegated
// authority", read against invariant "L5. Independent chains are not combined". Every
// vector in this family is labelled candidate_against_proposed. See README.md for the
// verbatim quotes, and for the two vector groups where draft-pidlisnyi-aps-03 Section
// 3.2 does state a rule of its own.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and facet values are
// pinned constants: no clock is read and no randomness is drawn.
//
// WHY SOME CHILDREN ARE SIGNED WITHOUT issueSubAuthorityDelegation. The SDK's
// cooperative issuance entry point runs the section 3.6 parent checks before signing, so
// it refuses to mint a child from a parent with zero remaining depth. That refusal is
// itself recorded below, under mint_time_sdk_observations. What this family tests is the
// VERIFIER's refusal of a syntactically valid, correctly signed child that a cooperating
// issuer would never have produced, so the reject children are signed through the lower
// level computeAuthorityDelegationId and signAuthorityDelegation primitives instead. The
// same technique, and the same reasoning, is used by
// fixtures/single-chain-selection/mint.py.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-conferral-without-authority/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  compareAuthority,
  computeAuthorityDelegationId,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  publicKeyFromPrivate,
  scopeGrantCovers,
  signAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-conferral-without-authority:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

function nonce(label: string): string {
  return seed('nonce:' + label).slice(0, 32)
}

// The principal is a scheduling office, not a named person. This family says nothing
// about what happens when an individual issuer leaves, which the proposed text leaves
// open under "Office vacancy and succession".
const PRINCIPAL = 'did:aps:example:cwa-scheduling-principal'
const AGENT = 'did:aps:example:cwa-calendar-agent'
const SUBAGENT = 'did:aps:example:cwa-subagent'
const WORKER = 'did:aps:example:cwa-worker'

const PRINCIPAL_KEY_ID = `${PRINCIPAL}#key-1`
const AGENT_KEY_ID = `${AGENT}#key-1`
const SUBAGENT_KEY_ID = `${SUBAGENT}#key-1`

const principalPrivate = seed('principal:v1')
const agentPrivate = seed('agent:v1')
const subagentPrivate = seed('subagent:v1')

const VERIFICATION_KEYS: Record<string, string> = {
  [PRINCIPAL_KEY_ID]: publicKeyFromPrivate(principalPrivate),
  [AGENT_KEY_ID]: publicKeyFromPrivate(agentPrivate),
  [SUBAGENT_KEY_ID]: publicKeyFromPrivate(subagentPrivate),
}

// ---------------------------------------------------------------------------
// One clock. Roots are issued Monday and run to Friday. Every child is issued Tuesday
// 09:00Z and every grandchild Tuesday 10:00Z, so every record in every presented chain
// is inside its parent's window and valid at the single verification instant NOW.
// ---------------------------------------------------------------------------

const MONDAY = '2026-09-21T00:00:00.000Z'
const TUESDAY_09 = '2026-09-22T09:00:00.000Z'
const TUESDAY_10 = '2026-09-22T10:00:00.000Z'
const NOW = '2026-09-22T12:00:00.000Z'
const WEDNESDAY = '2026-09-23T00:00:00.000Z'
const THURSDAY = '2026-09-24T00:00:00.000Z'
const FRIDAY = '2026-09-25T00:00:00.000Z'

const UNIT = 'iso4217:USD:minor'

// ---------------------------------------------------------------------------
// Facet vectors. Three tiers, root-wide, child-narrow and grandchild-narrower, so that
// every reject vector differs from a positive control by exactly one stated change.
// ---------------------------------------------------------------------------

type Depth = { remaining: number }

function authorityVector(opts: {
  grants: string[]
  perAction: string
  cumulative: string
  depth: number
  notBefore: string
  notAfter: string
  reputation: number
  values: string[]
  reversibility: 'tentative' | 'compensable' | 'irreversible'
}) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: opts.grants },
    spend: {
      mode: 'bounded' as const,
      unit: UNIT,
      per_action: opts.perAction,
      cumulative: opts.cumulative,
    },
    depth: { remaining: opts.depth } as Depth,
    time: { not_before: opts.notBefore, not_after: opts.notAfter },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: opts.reputation },
    values: { profile: 'aps-values-identifiers-v1' as const, required: opts.values },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: opts.reversibility },
  }
}

/** Root tier: wide scope, the full week, the widest ceilings this family uses. */
function rootAuthority(depth: number) {
  return authorityVector({
    grants: ['calendar:*'],
    perAction: '6000',
    cumulative: '60000',
    depth,
    notBefore: MONDAY,
    notAfter: FRIDAY,
    reputation: 80,
    values: ['F-001'],
    reversibility: 'compensable',
  })
}

/** Child tier: strictly narrower than the root tier in all six non-depth facets. */
function childAuthority(depth: number, grants: string[] = ['calendar:write']) {
  return authorityVector({
    grants,
    perAction: '1000',
    cumulative: '10000',
    depth,
    notBefore: TUESDAY_09,
    notAfter: THURSDAY,
    reputation: 40,
    values: ['F-001', 'F-002'],
    reversibility: 'tentative',
  })
}

/** Grandchild tier: strictly narrower again than the child tier. */
function grandchildAuthority(depth: number) {
  return authorityVector({
    grants: ['calendar:write'],
    perAction: '500',
    cumulative: '5000',
    depth,
    notBefore: TUESDAY_10,
    notAfter: WEDNESDAY,
    reputation: 30,
    values: ['F-001', 'F-002', 'F-003'],
    reversibility: 'tentative',
  })
}

// ---------------------------------------------------------------------------
// Minting.
// ---------------------------------------------------------------------------

type Body = Parameters<typeof issueAuthorityDelegation>[0]
type Record_ = ReturnType<typeof issueAuthorityDelegation>

function rootBody(nonceLabel: string, authority: unknown): Body {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject: AGENT,
    verification_method: PRINCIPAL_KEY_ID,
    issued_at: MONDAY,
    nonce: nonce(nonceLabel),
    authority,
  } as Body
}

function childBody(opts: {
  nonceLabel: string
  parent: Record_
  issuer: string
  subject: string
  verificationMethod: string
  issuedAt: string
  authority: unknown
}): Body {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: opts.parent.delegation_id,
    issuer: opts.issuer,
    subject: opts.subject,
    verification_method: opts.verificationMethod,
    issued_at: opts.issuedAt,
    nonce: nonce(opts.nonceLabel),
    authority: opts.authority,
  } as Body
}

/**
 * Compute delegation_id and sign, without the issuer-side narrowing check
 * issueSubAuthorityDelegation performs. The record this returns is byte-for-byte what a
 * conforming issuer would have produced had it been willing to produce it: same id
 * derivation, same signature domain, same canonical bytes. Only the issuer's own refusal
 * is bypassed, never the verifier's.
 */
function signWithoutIssuerNarrowingCheck(body: Body, privateKey: string): Record_ {
  const delegationId = computeAuthorityDelegationId(body)
  const unsigned = { ...(body as object), delegation_id: delegationId }
  const signature = signAuthorityDelegation(unsigned as never, privateKey)
  return { ...unsigned, signature } as Record_
}

// --- Roots: the same principal, the same agent, the same scope, three conferral rights.

const rootConfersTwo = issueAuthorityDelegation(rootBody('root-confers-two', rootAuthority(2)), principalPrivate)
const rootConfersOne = issueAuthorityDelegation(rootBody('root-confers-one', rootAuthority(1)), principalPrivate)
const rootConfersNone = issueAuthorityDelegation(rootBody('root-confers-none', rootAuthority(0)), principalPrivate)

// --- Children issued by the agent.

const issueOptions = {
  now: TUESDAY_09,
  resolveVerificationKey: (_issuer: string, verificationMethod: string) =>
    VERIFICATION_KEYS[verificationMethod] ?? null,
  resolveRevocation: () => 'active' as const,
}

// CWA-01 and CWA-09: conferral authority is declared, so the child is minted through the
// SDK's own cooperative issuance path, narrowing check and all.
const childOk = issueSubAuthorityDelegation(
  rootConfersTwo,
  childBody({
    nonceLabel: 'child-ok',
    parent: rootConfersTwo,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthority(1),
  }),
  agentPrivate,
  issueOptions as never,
)

const grandchildOk = issueSubAuthorityDelegation(
  childOk,
  childBody({
    nonceLabel: 'grandchild-ok',
    parent: childOk,
    issuer: SUBAGENT,
    subject: WORKER,
    verificationMethod: SUBAGENT_KEY_ID,
    issuedAt: TUESDAY_10,
    authority: grandchildAuthority(0),
  }),
  subagentPrivate,
  { ...issueOptions, now: TUESDAY_10 } as never,
)

// CWA-10: the last declared hop, spent legitimately.
const childConsumesLastHop = issueSubAuthorityDelegation(
  rootConfersOne,
  childBody({
    nonceLabel: 'child-consumes-last-hop',
    parent: rootConfersOne,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthority(0),
  }),
  agentPrivate,
  issueOptions as never,
)

// CWA-02: the headline. The agent holds calendar:* and confers exactly what it holds.
const childSameScopeFromNone = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'child-same-scope-from-none',
    parent: rootConfersNone,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: authorityVector({
      grants: ['calendar:*'],
      perAction: '6000',
      cumulative: '60000',
      depth: 0,
      notBefore: TUESDAY_09,
      notAfter: THURSDAY,
      reputation: 80,
      values: ['F-001'],
      reversibility: 'compensable',
    }),
  }),
  agentPrivate,
)

// CWA-03: the naive-pass trap. Strictly narrower in every facet a narrowing checker
// knows how to compare, and still not conferrable.
const childStrictlyNarrowerFromNone = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'child-strictly-narrower-from-none',
    parent: rootConfersNone,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthority(0),
  }),
  agentPrivate,
)

// CWA-04: the hop is consumed by the act of conferring, not by the scope conferred.
const grandchildFromExhausted = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'grandchild-from-exhausted',
    parent: childConsumesLastHop,
    issuer: SUBAGENT,
    subject: WORKER,
    verificationMethod: SUBAGENT_KEY_ID,
    issuedAt: TUESDAY_10,
    authority: grandchildAuthority(0),
  }),
  subagentPrivate,
)

// CWA-05: conferral authority is declared, and the child keeps all of it.
const childNoHopConsumed = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'child-no-hop-consumed',
    parent: rootConfersTwo,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthority(2),
  }),
  agentPrivate,
)

// CWA-06: conferral authority is declared, and is not a licence to widen.
const childWidensScope = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'child-widens-scope',
    parent: rootConfersTwo,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthority(1, ['calendar:*', 'payments:refund']),
  }),
  agentPrivate,
)

// CWA-07: the undeclared case. The depth facet is absent, not zero. See README.md,
// "Where the proposed text was too vague to test", item 1.
const childAuthorityWithoutDepth = (() => {
  const full = childAuthority(1) as Record<string, unknown>
  const { depth: _dropped, ...rest } = full
  return rest
})()

const childDepthAbsent = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'child-depth-absent',
    parent: rootConfersTwo,
    issuer: AGENT,
    subject: SUBAGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthorityWithoutDepth,
  }),
  agentPrivate,
)

// CWA-08: a copy of itself. The proposed text names this case explicitly.
const selfChildFromNone = signWithoutIssuerNarrowingCheck(
  childBody({
    nonceLabel: 'self-child-from-none',
    parent: rootConfersNone,
    issuer: AGENT,
    subject: AGENT,
    verificationMethod: AGENT_KEY_ID,
    issuedAt: TUESDAY_09,
    authority: childAuthority(0),
  }),
  agentPrivate,
)

// ---------------------------------------------------------------------------
// Presented chains, one per vector.
// ---------------------------------------------------------------------------

const presented: Record<string, unknown[]> = {
  'CWA-01': [rootConfersTwo, childOk],
  'CWA-02': [rootConfersNone, childSameScopeFromNone],
  'CWA-03': [rootConfersNone, childStrictlyNarrowerFromNone],
  'CWA-04': [rootConfersOne, childConsumesLastHop, grandchildFromExhausted],
  'CWA-05': [rootConfersTwo, childNoHopConsumed],
  'CWA-06': [rootConfersTwo, childWidensScope],
  'CWA-07': [rootConfersTwo, childDepthAbsent],
  'CWA-08': [rootConfersNone, selfChildFromNone],
  'CWA-09': [rootConfersTwo, childOk, grandchildOk],
  'CWA-10': [rootConfersOne, childConsumesLastHop],
}

// ---------------------------------------------------------------------------
// Mint-time assertions. Nothing is written if any of these fails.
// ---------------------------------------------------------------------------

function die(message: string): never {
  console.error(`mint.ts: ${message}`)
  process.exit(1)
}

const verifyOptions = {
  now: NOW,
  resolveVerificationKey: (_issuer: string, verificationMethod: string) =>
    VERIFICATION_KEYS[verificationMethod] ?? null,
  trustRoot: (root: { issuer: string }) => root.issuer === PRINCIPAL,
  resolveRevocation: () => 'active' as const,
}

const allRecords = [
  rootConfersTwo, rootConfersOne, rootConfersNone,
  childOk, grandchildOk, childConsumesLastHop,
  childSameScopeFromNone, childStrictlyNarrowerFromNone, grandchildFromExhausted,
  childNoHopConsumed, childWidensScope, childDepthAbsent, selfChildFromNone,
]
const ids = new Set(allRecords.map((r) => r.delegation_id))
if (ids.size !== allRecords.length) die('two minted records share a delegation_id')

// Every root, presented alone, verifies valid at NOW. The three roots differ only in
// their declared conferral right, so nothing else can explain a reject below.
for (const [label, root] of [
  ['root_confers_two', rootConfersTwo],
  ['root_confers_one', rootConfersOne],
  ['root_confers_none', rootConfersNone],
] as const) {
  const result = verifyAuthorityDelegationChain([root], verifyOptions as never)
  if (result.state !== 'valid') die(`${label} alone is ${result.state}, expected valid`)
}

// The agent's held scope is identical across all three roots.
const heldGrants = JSON.stringify(rootConfersNone.authority.scope.grants)
if (heldGrants !== JSON.stringify(rootConfersTwo.authority.scope.grants)) {
  die('the depth-0 root does not hold the same scope as the depth-2 root')
}

// The conferred scope in CWA-02 is exactly what the agent holds, and is covered by it.
if (!scopeGrantCovers('calendar:*', 'calendar:*')) die('scopeGrantCovers self-coverage failed')
if (!scopeGrantCovers('calendar:*', 'calendar:write')) die('scopeGrantCovers narrowing failed')

// compareAuthority on the CWA-03 pair returns DEPTH_EXHAUSTED and nothing else: the
// child is narrower in every other facet, which is what makes it the naive-pass trap.
const cwa03Failures = compareAuthority(
  rootConfersNone.authority as never,
  childStrictlyNarrowerFromNone.authority as never,
)
if (cwa03Failures.length !== 1 || cwa03Failures[0].code !== 'DEPTH_EXHAUSTED') {
  die(`CWA-03 compareAuthority returned ${JSON.stringify(cwa03Failures)}, expected exactly DEPTH_EXHAUSTED`)
}

// The SDK's cooperative issuance path refuses to mint CWA-03's child at all.
let cooperativeIssuanceRefusal = ''
try {
  issueSubAuthorityDelegation(
    rootConfersNone,
    childBody({
      nonceLabel: 'child-strictly-narrower-from-none',
      parent: rootConfersNone,
      issuer: AGENT,
      subject: SUBAGENT,
      verificationMethod: AGENT_KEY_ID,
      issuedAt: TUESDAY_09,
      authority: childAuthority(0),
    }),
    agentPrivate,
    issueOptions as never,
  )
  die('issueSubAuthorityDelegation minted a child from a zero-depth parent')
} catch (error) {
  cooperativeIssuanceRefusal = (error as Error).message
}
if (!cooperativeIssuanceRefusal.includes('DEPTH_EXHAUSTED')) {
  die(`cooperative issuance refused for the wrong reason: ${cooperativeIssuanceRefusal}`)
}

// Each reject child is correctly signed. A reject here must come from the verifier's
// conferral check, never from a broken signature.
for (const [label, record, key] of [
  ['child_same_scope_from_none', childSameScopeFromNone, AGENT_KEY_ID],
  ['child_strictly_narrower_from_none', childStrictlyNarrowerFromNone, AGENT_KEY_ID],
  ['grandchild_from_exhausted', grandchildFromExhausted, SUBAGENT_KEY_ID],
  ['child_no_hop_consumed', childNoHopConsumed, AGENT_KEY_ID],
  ['child_widens_scope', childWidensScope, AGENT_KEY_ID],
  ['self_child_from_none', selfChildFromNone, AGENT_KEY_ID],
] as const) {
  const { delegation_id: _id, signature: _sig, ...body } = record as unknown as Record<string, unknown>
  const recomputed = computeAuthorityDelegationId(body as never)
  if (recomputed !== record.delegation_id) die(`${label} delegation_id does not recompute`)
  if (!VERIFICATION_KEYS[key]) die(`${label} names an unknown verification method`)
}

// The two positive controls verify valid, end to end, at NOW.
for (const id of ['CWA-01', 'CWA-09', 'CWA-10']) {
  const result = verifyAuthorityDelegationChain(presented[id] as never, verifyOptions as never)
  if (result.state !== 'valid') {
    die(`${id} is ${result.state} (${JSON.stringify(result.failures)}), expected valid`)
  }
}

// Record what the SDK actually answered for every presented chain, so the README quotes
// a recorded value rather than a remembered one.
const mintTimeSdkObservations: Record<string, unknown> = {
  cooperative_issuance_refusal_from_zero_depth_parent: cooperativeIssuanceRefusal,
  compare_authority_cwa_03: cwa03Failures,
}
for (const [id, chain] of Object.entries(presented)) {
  const result = verifyAuthorityDelegationChain(chain as never, verifyOptions as never)
  mintTimeSdkObservations[`verify_chain_${id}`] = {
    state: result.state,
    failures: result.failures,
  }
}

// ---------------------------------------------------------------------------
// Write chain.json with keys sorted at every depth, so the file is a function of its
// content and not of insertion order.
// ---------------------------------------------------------------------------

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep)
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as object).sort()) {
      out[key] = sortDeep((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

const chainFile = {
  family: 'lifecycle-conferral-without-authority',
  seed_label_prefix: SEED_PREFIX,
  generated_by: 'fixtures/lifecycle-conferral-without-authority/mint.ts',
  sdk: 'agent-passport-system 7.1.0 (npm)',
  now: NOW,
  identities: {
    principal: PRINCIPAL,
    agent: AGENT,
    subagent: SUBAGENT,
    worker: WORKER,
  },
  verification_keys: VERIFICATION_KEYS,
  trusted_root_issuer: PRINCIPAL,
  delegations: {
    root_confers_two: rootConfersTwo,
    root_confers_one: rootConfersOne,
    root_confers_none: rootConfersNone,
    child_ok: childOk,
    grandchild_ok: grandchildOk,
    child_consumes_last_hop: childConsumesLastHop,
    child_same_scope_from_none: childSameScopeFromNone,
    child_strictly_narrower_from_none: childStrictlyNarrowerFromNone,
    grandchild_from_exhausted: grandchildFromExhausted,
    child_no_hop_consumed: childNoHopConsumed,
    child_widens_scope: childWidensScope,
    child_depth_absent: childDepthAbsent,
    self_child_from_none: selfChildFromNone,
  },
  presented,
  mint_time_sdk_observations: mintTimeSdkObservations,
}

const sorted = sortDeep(chainFile)
const out = JSON.stringify(sorted, null, 2) + '\n'

// JCS is the canonical form the protocol signs over. It is computed here as a check that
// every record round-trips through the SDK's own canonicalizer, and its digest is
// recorded so a reviewer can pin the canonical bytes without re-running the SDK.
const jcsDigest = createHash('sha256').update(canonicalizeJCS(sorted as never), 'utf8').digest('hex')

fs.writeFileSync(path.join(here, 'chain.json'), out)

console.log(`wrote chain.json, ${out.length} bytes`)
console.log(`sha256(chain.json)            ${createHash('sha256').update(out, 'utf8').digest('hex')}`)
console.log(`sha256(JCS(chain.json content)) ${jcsDigest}`)
