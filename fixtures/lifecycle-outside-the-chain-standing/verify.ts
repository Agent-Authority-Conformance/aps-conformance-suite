// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the lifecycle-outside-the-chain-standing candidate family.
//
// Replays every vector in vectors.json against the reference boundary and against each
// declared negative control. The reference boundary must match every vector. Each control
// runs against every vector for the concepts it covers, not only the ones predicted to
// diverge, so an undeclared divergence and a declared divergence that stops happening are
// both loud.
//
// Where an SDK API exists for a layer, this runner calls it rather than reimplementing
// the check:
//
//   verifyAuthorityDelegationChain   every chain_state claim in every vector
//   checkQuorum                      the office holder count behind LC-H-004
//   canonicalizeJCS                  the RFC 8785 canonical bytes the digests pin
//
// Where no API exists, the vector records not_supported with a reason and this runner
// prints that reason instead of a result. It never substitutes its own answer for an
// SDK result.
//
// Run: npx tsx fixtures/lifecycle-outside-the-chain-standing/verify.ts
// Exit 0 when the reference matches every vector, every control diverges on exactly its
// declared set, and every supported SDK probe matches. 1 on any mismatch, 2 on a
// malformed fixture. No network.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  checkQuorum,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

import {
  BYLAW_NUMBER_WINS,
  FORCED_BINARY,
  REFERENCE,
  REVIVAL_RESTORES,
  WELL_FORMED_RECORD_SUFFICES,
  decideDisputedRoot,
  decideExternalReinstatement,
  decideIssuingBodyQuorum,
  majorityFloor,
  type BodyRecord,
  type BoundaryProfile,
  type DepositRecord,
  type DeterminationRecord,
  type OrderRecord,
  type SuspensionRecord,
  type Verdict,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

interface ChainFixture {
  _placeholder?: boolean
  now: string
  seed_prefix: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chains: Record<string, Array<Record<string, any>>>
}

interface SdkProbe {
  supported: boolean
  layer: string
  reason?: string
  api?: string
  chain?: string
  note?: string
  expected?: Record<string, unknown>
}

interface AlsoRun {
  layer: string
  claim: string
  npm: SdkProbe
  pypi: SdkProbe
}

interface Vector {
  id: string
  case: string
  concept: 'issuing_body_quorum' | 'external_reinstatement_grant' | 'disputed_root_held'
  label: string
  polarity: string
  proposed_text: string
  description: string
  at: string
  records: Record<string, any>
  expected: Record<string, any>
  sdk: { npm: SdkProbe; pypi: SdkProbe }
  also_runs: AlsoRun[]
  control_fails: string[]
}

interface Control {
  name: string
  defect: string
  runs_against_concepts: string[]
  expected_fail_ids: string[]
}

interface Vectors {
  family: string
  profile: string
  label: string
  proposed_text_source: Record<string, string>
  verdict_vocabulary: string[]
  description: string
  controls: Record<string, Control>
  vectors: Vector[]
}

const chainFixture = JSON.parse(readFileSync(join(here, 'chain.json'), 'utf8')) as ChainFixture
const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as Vectors

if (
  chainFixture._placeholder === true ||
  typeof chainFixture.now !== 'string' ||
  Object.keys(chainFixture.chains ?? {}).length === 0 ||
  Object.keys(chainFixture.verification_keys ?? {}).length === 0 ||
  Object.keys(chainFixture.roles ?? {}).length === 0
) {
  console.error('chain.json is a placeholder or missing chains, keys or roles. Run mint.py.')
  process.exit(2)
}

const roleByDelegationId = new Map<string, string>()
for (const [role, id] of Object.entries(chainFixture.roles)) roleByDelegationId.set(id, role)

for (const [name, chain] of Object.entries(chainFixture.chains)) {
  for (const member of chain) {
    if (typeof member?.delegation_id !== 'string' || !roleByDelegationId.has(member.delegation_id)) {
      console.error(`chain ${name} has a member with no registered role`)
      process.exit(2)
    }
  }
}

const VOCAB = new Set(vectors.verdict_vocabulary)

// --- SDK layer ------------------------------------------------------------------

interface ChainResult {
  state: string
  failureCode: string | null
  failureIndex: number | null
}

/** One call to the SDK chain verifier, with revocation answered by role. */
function verifyChain(name: string, revokedRoles: string[]): ChainResult {
  const revoked = new Set(revokedRoles)
  const result = verifyAuthorityDelegationChain(chainFixture.chains[name], {
    now: chainFixture.now,
    resolveVerificationKey: (_issuer: string, verificationMethod: string) =>
      chainFixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: (delegation: any) =>
      revoked.has(roleByDelegationId.get(delegation?.delegation_id) ?? '') ? 'revoked' : 'active',
  } as any) as any
  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  return {
    state: result.state,
    failureCode: first?.code ?? null,
    failureIndex: typeof first?.index === 'number' ? first.index : null,
  }
}

/** The scope grants a chain's leaf record carries, read off the minted bytes. */
function leafGrants(name: string): string[] {
  const chain = chainFixture.chains[name]
  return [...(chain[chain.length - 1].authority.scope.grants as string[])].sort()
}

function rootIssuer(name: string): string {
  return chainFixture.chains[name][0].issuer as string
}

function rootIssuedAt(name: string): string {
  return chainFixture.chains[name][0].issued_at as string
}

/** All grants any record of a chain carries, for the absent-from-old comparison. */
function allGrants(name: string): string[] {
  const out = new Set<string>()
  for (const member of chainFixture.chains[name]) {
    for (const g of member.authority.scope.grants as string[]) out.add(g)
  }
  return [...out].sort()
}

// --- Reference and control replay -----------------------------------------------

interface Divergence {
  field: string
  expected: unknown
  observed: unknown
}

/**
 * JSON with object keys sorted, recursively. Used so a comparison of two record maps is a
 * comparison of their contents and not of the order a decider happened to build them in.
 * Arrays keep their order, because order is meaningful in every array compared here.
 */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value as Record<string, unknown>)
      .sort()
      .map(k => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`)
    return `{${entries.join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}

function compare(expected: Record<string, any>, observed: Record<string, any>): Divergence[] {
  const out: Divergence[] = []
  for (const [field, want] of Object.entries(expected)) {
    if (want === undefined) continue
    const got = observed[field]
    if (stableStringify(got) !== stableStringify(want)) {
      out.push({ field, expected: want, observed: got })
    }
  }
  return out
}

function runVector(vector: Vector, profile: BoundaryProfile): Divergence[] {
  switch (vector.concept) {
    case 'issuing_body_quorum': {
      const body = vector.records.body as BodyRecord
      const suspension = vector.records.suspension as SuspensionRecord
      const chainVerdict = verifyChain(vector.records.target_chain, []).state as Verdict
      const decision = decideIssuingBodyQuorum(body, suspension, chainVerdict, profile)
      return compare(
        {
          verdict: vector.expected.verdict,
          code: vector.expected.code,
          target_chain_verdict: vector.expected.target_chain_verdict,
          body_action_exists: vector.expected.body_action_exists,
        },
        decision as unknown as Record<string, any>,
      )
    }
    case 'external_reinstatement_grant': {
      const order = vector.records.order as OrderRecord | null
      const newChainName = vector.records.new_chain as string | null
      const old = verifyChain(vector.records.old_chain, vector.records.revoked_roles)
      const decision = decideExternalReinstatement(
        order,
        newChainName !== null,
        vector.records.registry,
        {
          verdict: old.state as Verdict,
          failureCode: old.failureCode,
          rootIssuer: rootIssuer(vector.records.old_chain),
          grants: allGrants(vector.records.old_chain),
        },
        newChainName === null
          ? null
          : {
              verdict: verifyChain(newChainName, []).state as Verdict,
              rootIssuer: rootIssuer(newChainName),
              grants: leafGrants(newChainName),
            },
        profile,
      )
      return compare(
        {
          verdict: vector.expected.verdict,
          code: vector.expected.code,
          old_chain_verdict: vector.expected.old_chain_verdict,
          old_chain_failure_code: vector.expected.old_chain_failure_code,
          old_chain_verdict_unchanged_by_order:
            vector.expected.old_chain_verdict_unchanged_by_order,
          new_chain_verdict: vector.expected.new_chain_verdict,
          new_chain_root_issuer_differs: vector.expected.new_chain_root_issuer_differs,
          new_chain_carries_grant_absent_from_old:
            vector.expected.new_chain_carries_grant_absent_from_old,
        },
        decision as unknown as Record<string, any>,
      )
    }
    case 'disputed_root_held': {
      const claims = vector.records.claims as Array<{ claimant: string; chain: string }>
      const issuedAt: Record<string, string> = {}
      for (const c of claims) issuedAt[c.chain] = rootIssuedAt(c.chain)
      const decision = decideDisputedRoot(
        claims,
        vector.records.deposit as DepositRecord | null,
        vector.records.determination as DeterminationRecord | null,
        profile,
        issuedAt,
      )
      return compare(
        {
          verdict: vector.expected.verdict,
          code: vector.expected.code,
          per_chain: vector.expected.per_chain,
          holder_must_choose: vector.expected.holder_must_choose,
        },
        decision as unknown as Record<string, any>,
      )
    }
  }
}

// --- Run ------------------------------------------------------------------------

console.log(`${vectors.family}: ${vectors.vectors.length} vectors, all ${vectors.label}`)
console.log(
  `proposed text: ${vectors.proposed_text_source.repo} at or after ${vectors.proposed_text_source.commit_floor}, ` +
    `cases from ${vectors.proposed_text_source.cases_version}, section "${vectors.proposed_text_source.section}"`,
)
console.log(`npm agent-passport-system: ${process.env.APS_NPM_VERSION ?? '7.1.0 (package.json dependency)'}`)
console.log()

let failed = 0

// Every vector's verdict must come from the settled vocabulary. A typo in an expected
// verdict would otherwise pass silently as long as the harness produced the same typo.
for (const vector of vectors.vectors) {
  if (vector.label !== 'candidate_against_proposed') {
    console.log(`FAIL ${vector.id} is not labelled candidate_against_proposed`)
    failed += 1
  }
  if (typeof vector.proposed_text !== 'string' || vector.proposed_text.length === 0) {
    console.log(`FAIL ${vector.id} names no proposed text`)
    failed += 1
  }
  if (!vector.id.includes(vector.case)) {
    console.log(`FAIL ${vector.id} does not carry its case id`)
    failed += 1
  }
  const declared: string[] = [vector.expected.verdict]
  for (const v of Object.values(vector.expected.per_chain ?? {})) declared.push(v as string)
  for (const v of [vector.expected.target_chain_verdict, vector.expected.old_chain_verdict, vector.expected.new_chain_verdict]) {
    if (typeof v === 'string') declared.push(v)
  }
  for (const v of declared) {
    if (!VOCAB.has(v)) {
      console.log(`FAIL ${vector.id} uses verdict "${v}", outside the settled vocabulary`)
      failed += 1
    }
  }
}

console.log('reference boundary')
const referenceFails: string[] = []
for (const vector of vectors.vectors) {
  const divergences = runVector(vector, REFERENCE)
  if (divergences.length === 0) {
    console.log(`  MATCH    ${vector.id}  ${vector.expected.verdict}/${vector.expected.code}`)
  } else {
    referenceFails.push(vector.id)
    console.log(`  MISMATCH ${vector.id}`)
    for (const d of divergences) {
      console.log(`             ${d.field}: expected ${JSON.stringify(d.expected)}, observed ${JSON.stringify(d.observed)}`)
    }
  }
}
if (referenceFails.length > 0) {
  failed += 1
  console.log(`FAIL reference boundary did not match: [${referenceFails.join(', ')}]`)
} else {
  console.log(`ok   reference boundary matched all ${vectors.vectors.length} vectors`)
}
console.log()

const PROFILES: Record<string, BoundaryProfile> = {
  'well-formed-record-suffices': WELL_FORMED_RECORD_SUFFICES,
  'bylaw-number-wins': BYLAW_NUMBER_WINS,
  'revival-restores': REVIVAL_RESTORES,
  'forced-binary': FORCED_BINARY,
}

for (const control of Object.values(vectors.controls)) {
  const profile = PROFILES[control.name]
  if (profile === undefined) {
    console.log(`FAIL control ${control.name} has no profile in harness.ts`)
    failed += 1
    continue
  }
  const scope = vectors.vectors.filter(v => control.runs_against_concepts.includes(v.concept))
  const observedFails = scope.filter(v => runVector(v, profile).length > 0).map(v => v.id)
  const undeclared = observedFails.filter(id => !control.expected_fail_ids.includes(id))
  const stopped = control.expected_fail_ids.filter(id => !observedFails.includes(id))
  if (undeclared.length > 0) {
    failed += 1
    console.log(`FAIL ${control.name} diverged on vectors the fixture does not declare: [${undeclared.join(', ')}]`)
  }
  if (stopped.length > 0) {
    failed += 1
    console.log(`FAIL ${control.name} no longer diverges on declared vectors: [${stopped.join(', ')}]`)
  }
  if (undeclared.length === 0 && stopped.length === 0) {
    console.log(
      `ok   ${control.name} ran ${scope.length} vectors and diverged on exactly [${control.expected_fail_ids.join(', ')}]`,
    )
  }
}
console.log()

// --- SDK probes -----------------------------------------------------------------

console.log('SDK probes, npm agent-passport-system')
let probes = 0
let probeFails = 0
const notSupported = new Map<string, string>()

for (const vector of vectors.vectors) {
  const probe = vector.sdk.npm
  if (!probe.supported) {
    notSupported.set(`${vector.concept}/${probe.layer}`, probe.reason ?? '(no reason recorded)')
  } else if (probe.layer === 'office_holder_count') {
    const body = vector.records.body as BodyRecord
    const seated = new Set(body.seated_directors)
    const counted = body.participants.filter(p => seated.has(p))
    const effective = Math.max(majorityFloor(body.total_seats), body.bylaw_quorum ?? 0)
    const office = {
      officeId: body.body_id,
      name: 'Board',
      holderMode: 'threshold' as const,
      holderSet: counted.map(publicKey => ({
        publicKey,
        appointedAt: '2026-09-01T00:00:00.000Z',
        appointedBy: 'charter_founding',
        isInterim: false,
      })),
      delegationPolicy: { allowedScopes: ['payroll:*'], maxSpendPerAction: 0, maxDelegationDepth: 1 },
      successionOrder: [] as string[],
      status: 'active' as const,
      effectiveAt: '2026-09-01T00:00:00.000Z',
    }
    const observed = checkQuorum(office as any, {
      officeId: body.body_id,
      minimumHolders: effective,
      onQuorumLoss: 'freeze_office',
      maxFreezeDurationSeconds: 86400,
    } as any)
    probes += 1
    const divergences = compare(probe.expected as Record<string, any>, observed as unknown as Record<string, any>)
    if (divergences.length === 0) {
      console.log(`  MATCH    ${vector.id} checkQuorum ${JSON.stringify(observed)}`)
    } else {
      probeFails += 1
      console.log(`  MISMATCH ${vector.id} checkQuorum expected ${JSON.stringify(probe.expected)} observed ${JSON.stringify(observed)}`)
    }
  } else {
    probeFails += 1
    console.log(`  MISMATCH ${vector.id} declares a supported npm layer "${probe.layer}" this runner does not call`)
  }

  for (const also of vector.also_runs) {
    const p = also.npm
    if (!p.supported) {
      notSupported.set(`${vector.concept}/${p.layer}`, p.reason ?? '(no reason recorded)')
      continue
    }
    if (p.layer !== 'chain_state' || typeof p.chain !== 'string') {
      probeFails += 1
      console.log(`  MISMATCH ${vector.id} also_runs layer "${p.layer}" is not one this runner calls`)
      continue
    }
    const revoked = (vector.records.revoked_roles as string[] | undefined) ?? []
    // The chain the terminated case revokes is the only one with revoked roles; every
    // other chain_state claim is asserted on the records with nothing revoked.
    const applies = p.chain === vector.records.old_chain ? revoked : []
    const observed = verifyChain(p.chain, applies)
    probes += 1
    const want = p.expected as { state: string; failure_code: string | null; failure_index: number | null }
    const ok =
      observed.state === want.state &&
      observed.failureCode === want.failure_code &&
      observed.failureIndex === want.failure_index
    if (ok) {
      console.log(`  MATCH    ${vector.id} chain ${p.chain} ${observed.state}${observed.failureCode ? `/${observed.failureCode}@${observed.failureIndex}` : ''}`)
    } else {
      probeFails += 1
      console.log(`  MISMATCH ${vector.id} chain ${p.chain} expected ${JSON.stringify(want)} observed ${JSON.stringify(observed)}`)
    }
  }
}

console.log(`  ${probes - probeFails}/${probes} supported npm probes matched`)
if (probeFails > 0) failed += 1
console.log()

console.log('layers with no npm API, recorded not_supported rather than faked')
for (const [layer, reason] of [...notSupported.entries()].sort()) {
  console.log(`  ${layer}: ${reason}`)
}
console.log()

// --- The verdict vocabulary against the SDK's own -------------------------------

// LC-H-004's verdict is `suspended`, which no SDK state expresses. Rather than assert
// that in prose, the claim is produced by the run: a resolver answering "suspended" for
// a chain member yields `indeterminate` under REVOCATION_UNKNOWN, not a suspended state.
// A later SDK release that adds one makes this fail loudly rather than leaving a stale
// line in the README.
console.log('settled verdict vocabulary against the npm chain verifier')
{
  const result = verifyAuthorityDelegationChain(chainFixture.chains.OFFICER, {
    now: chainFixture.now,
    resolveVerificationKey: (_issuer: string, verificationMethod: string) =>
      chainFixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: () => 'suspended',
  } as any) as any
  const code = Array.isArray(result.failures) ? result.failures[0]?.code : undefined
  const asExpected = result.state === 'indeterminate' && code === 'REVOCATION_UNKNOWN'
  console.log(`  resolveRevocation answering "suspended" -> state ${result.state}, code ${code}`)
  if (asExpected) {
    console.log('  ok   4 of the 6 settled verdicts have no SDK state: not_established, not_yet_effective, suspended, restricted')
  } else {
    failed += 1
    console.log('  FAIL the SDK no longer answers indeterminate/REVOCATION_UNKNOWN for an unrecognized resolver answer. Update "Where the proposed text was too vague to test".')
  }
}
console.log()

// --- Canonical bytes ------------------------------------------------------------

// The digests in CHECKSUMS.sha256 pin the exact committed bytes of chain.json and
// vectors.json. This is the separate claim that every signed record inside chain.json
// canonicalizes under RFC 8785 JCS, recomputed here by the SDK's own canonicalizer.
console.log('RFC 8785 JCS canonical digests of the signed records')
let records = 0
for (const [name, chain] of Object.entries(chainFixture.chains)) {
  for (const member of chain) {
    const body = { ...member }
    delete (body as any).signature
    delete (body as any).delegation_id
    const canonical = canonicalizeJCS(body)
    const digest = createHash('sha256').update(canonical, 'utf8').digest('hex')
    records += 1
    console.log(`  ${name} ${roleByDelegationId.get(member.delegation_id)} jcs-sha256 ${digest}`)
  }
}
console.log(`  ${records} records canonicalized`)
console.log()

if (failed > 0) {
  console.log('FAILED')
  process.exit(1)
}
console.log(
  'PASSED: reference matched every vector, every control diverged on exactly its declared set, ' +
    'every supported npm probe matched',
)
process.exit(0)
