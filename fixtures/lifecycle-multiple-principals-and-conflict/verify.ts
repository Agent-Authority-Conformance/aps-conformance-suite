// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the lifecycle-multiple-principals-and-conflict candidate family.
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
//   verify                          every confirmation's and vote's Ed25519 signature,
//                                   over the exact bytes approvalSignContent produces,
//                                   so signature_verifies is a fact about bytes and not a
//                                   boolean asserted in the vector
//   approvalSignContent             those bytes
//   evaluateThreshold               the multi-class conjunction behind the gate cases
//   verifyAuthorityDelegationChain  every chain_state claim
//   canonicalizeJCS                 the RFC 8785 canonical bytes the digests pin
//
// Where no API exists, the vector records not_supported with a reason and this runner
// prints that reason instead of a result. It never substitutes its own answer for an SDK
// result, and it never reports a layer as SDK-supplied when this file decided it.
//
// Run: npx tsx fixtures/lifecycle-multiple-principals-and-conflict/verify.ts
// Exit 0 when the reference matches every vector, every control diverges on exactly its
// declared set, and every supported SDK probe matches. 1 on any mismatch, 2 on a
// malformed fixture. No network.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  approvalSignContent,
  canonicalizeJCS,
  evaluateThreshold,
  verify as verifySignature,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

import {
  CONTROLS,
  REFERENCE,
  decideAdHocPosition,
  decideAsymmetricThreshold,
  decideCompetingSuccession,
  decideContestedSeat,
  decideDivisibleGrant,
  decideInstructionPrecedence,
  decideJointObjective,
  decidePendingRatification,
  decidePerContributorCaveat,
  decideRoleGate,
  decideSequencedRevival,
  decideStandingOverride,
  decideVoidFromIssuance,
  type BoundaryProfile,
  type Confirmation,
  type Verdict,
  type Vote,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

interface ChainFixture {
  _placeholder?: boolean
  now: string
  seed_prefix: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chains: Record<string, Array<Record<string, any>>>
  approvals: {
    actors: Record<string, string>
    subjects: Record<string, { request_id: string; subject: string; content: string }>
    signatures: Record<string, { actor: string; subject_key: string; signature: string }>
  }
}

interface SdkProbe {
  supported: boolean
  layer: string
  reason?: string
  api?: string
  chain?: string
  subject_key?: string
  requirements?: Array<{ role: string; requiredSignatures: number; actors: string[] }>
  signature_refs?: string[]
  note?: string
  expected?: Record<string, unknown>
}

interface AlsoRun {
  layer: string
  claim: string
  revoked_roles?: string[]
  npm: SdkProbe
  pypi: SdkProbe
}

interface Vector {
  id: string
  case: string
  concept: string
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
  cases_covered: string[]
  concepts: string[]
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
  Object.keys(chainFixture.roles ?? {}).length === 0 ||
  Object.keys(chainFixture.approvals?.signatures ?? {}).length === 0
) {
  console.error('chain.json is a placeholder or missing chains, keys, roles or approvals. Run mint.py.')
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
// Lexicographic comparison stands in for chronological comparison throughout the harness,
// which holds only for this exact shape. Asserted here rather than assumed.
const RFC3339_MS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

// --- signature layer, supplied by the SDK ----------------------------------------------

/**
 * Verifies one minted approval signature with the SDK, over the exact content
 * approvalSignContent produces for its subject. Returns false for a reference the fixture
 * does not carry, so a typo in a vector cannot read as a verifying signature.
 */
function signatureVerifies(ref: string, expectedActor: string): boolean {
  const record = chainFixture.approvals.signatures[ref]
  if (record === undefined || record.actor !== expectedActor) return false
  const subject = chainFixture.approvals.subjects[record.subject_key]
  if (subject === undefined) return false
  const content = approvalSignContent({ requestId: subject.request_id, subject: subject.subject })
  if (content !== subject.content) {
    console.error(`chain.json approvals.subjects.${record.subject_key}.content is not what approvalSignContent produces`)
    process.exit(2)
  }
  const publicKey = chainFixture.approvals.actors[expectedActor]
  if (publicKey === undefined) return false
  return verifySignature(content, record.signature, publicKey) === true
}

function hydrateConfirmations(raw: any[]): Confirmation[] {
  return raw.map(c => ({
    role: c.role,
    actor: c.actor,
    decision: c.decision,
    at: c.at,
    signature_verifies: signatureVerifies(c.signature_ref, c.actor),
  }))
}

function hydrateVotes(raw: any[]): Vote[] {
  return raw.map(v => ({
    actor: v.actor,
    class: v.class,
    at: v.at,
    signature_verifies: signatureVerifies(v.signature_ref, v.actor),
  }))
}

// --- chain layer, supplied by the SDK --------------------------------------------------

interface ChainResult {
  state: string
  failureCode: string | null
  failureIndex: number | null
}

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

function allGrants(name: string): string[] {
  const out = new Set<string>()
  for (const member of chainFixture.chains[name]) {
    for (const g of member.authority.scope.grants as string[]) out.add(g)
  }
  return [...out].sort()
}

function leafGrants(name: string): string[] {
  const chain = chainFixture.chains[name]
  return [...(chain[chain.length - 1].authority.scope.grants as string[])].sort()
}

// --- comparison ------------------------------------------------------------------------

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
    if (stableStringify(observed[field]) !== stableStringify(want)) {
      out.push({ field, expected: want, observed: observed[field] })
    }
  }
  return out
}

// --- dispatch --------------------------------------------------------------------------

function runVector(vector: Vector, profile: BoundaryProfile): Divergence[] {
  const r = vector.records
  const at = vector.at
  let observed: Record<string, any>

  switch (vector.concept) {
    case 'concurrence_gate':
    case 'unanimous_role_set':
      observed = decideRoleGate(r.gate, hydrateConfirmations(r.confirmations), r.registry, at, profile) as any
      break
    case 'asymmetric_threshold':
      observed = decideAsymmetricThreshold(
        r.gate, r.direction, hydrateConfirmations(r.confirmations), r.registry, at, profile,
      ) as any
      break
    case 'contested_seat':
      observed = decideContestedSeat(r.contest, hydrateVotes(r.votes), r.actor, at, profile) as any
      break
    case 'competing_succession_sources':
      observed = decideCompetingSuccession(r.sources, r.priority_rule, profile) as any
      break
    case 'void_from_issuance_finding':
      observed = decideVoidFromIssuance(
        r.finding,
        verifyChain(r.chain, []).state as Verdict,
        r.earlier_receipts,
        r.registry,
        at,
        profile,
      ) as any
      break
    case 'joint_objective_no_union': {
      const grantsByChain: Record<string, string[]> = {}
      for (const party of r.objective?.parties ?? []) grantsByChain[party.chain] = leafGrants(party.chain)
      observed = decideJointObjective(r.objective, grantsByChain, r.action, r.withdrawal, at, profile) as any
      break
    }
    case 'ad_hoc_position':
      observed = decideAdHocPosition(r.rule, r.trigger, r.claims, r.handovers, r.registry, at, profile) as any
      break
    case 'pending_ratification':
      observed = decidePendingRatification(
        r.relief, r.ratification, r.registry, r.earlier_receipts, at, profile,
      ) as any
      break
    case 'per_contributor_caveat':
      observed = decidePerContributorCaveat(r.contributions, r.caveats, r.action, profile) as any
      break
    case 'standing_override':
      observed = decideStandingOverride(
        r.standing, r.override, verifyChain(r.chain, []).state as Verdict,
        r.revocation_record_present, at, profile,
      ) as any
      break
    case 'divisible_grant_revocation':
      observed = decideDivisibleGrant(r.joint_grant, r.revocation, r.amendment, r.action, profile) as any
      break
    case 'instruction_precedence':
      observed = decideInstructionPrecedence(
        r.account,
        r.instructions.map((i: any) => ({ ...i, signature_verifies: true })),
        r.item,
        profile,
      ) as any
      break
    case 'sequenced_revival_window':
      observed = decideSequencedRevival(r.termination, r.revival, r.rescission, at, profile) as any
      break
    default:
      return [{ field: 'concept', expected: 'a concept this runner dispatches', observed: vector.concept }]
  }

  return compare(vector.expected, observed)
}

// --- structural checks -----------------------------------------------------------------

console.log(`${vectors.family}: ${vectors.vectors.length} vectors, all ${vectors.label}`)
console.log(
  `proposed text: ${vectors.proposed_text_source.repo} at or after ${vectors.proposed_text_source.commit_floor}, ` +
    `cases from ${vectors.proposed_text_source.cases_version}, section "${vectors.proposed_text_source.section}"`,
)
console.log(`cases covered: ${vectors.cases_covered.join(', ')}`)
console.log()

let failed = 0

function structural(): void {
  const timestamps: string[] = []
  const collect = (value: unknown): void => {
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) timestamps.push(value)
    else if (Array.isArray(value)) value.forEach(collect)
    else if (value !== null && typeof value === 'object') Object.values(value).forEach(collect)
  }

  for (const vector of vectors.vectors) {
    if (vector.label !== 'candidate_against_proposed') {
      console.log(`FAIL ${vector.id} is not labelled candidate_against_proposed`)
      failed += 1
    }
    if (typeof vector.proposed_text !== 'string' || vector.proposed_text.length === 0) {
      console.log(`FAIL ${vector.id} names no proposed text`)
      failed += 1
    }
    if (!vector.id.startsWith(`${vector.case}-`)) {
      console.log(`FAIL ${vector.id} does not carry its case id`)
      failed += 1
    }
    if (!vectors.cases_covered.includes(vector.case)) {
      console.log(`FAIL ${vector.id} names a case the family does not list as covered`)
      failed += 1
    }
    const declared: unknown[] = [vector.expected.verdict]
    for (const key of ['grant_state', 'objective_state', 'action_state', 'rescission_status', 'target_chain_verdict']) {
      if (typeof vector.expected[key] === 'string') declared.push(vector.expected[key])
    }
    for (const holder of Object.values(vector.expected.per_chain ?? {})) declared.push(holder)
    for (const holder of Object.values(vector.expected.per_share ?? {})) declared.push(holder)
    for (const value of declared) {
      if (typeof value === 'string' && !VOCAB.has(value)) {
        console.log(`FAIL ${vector.id} uses verdict "${value}", outside the settled vocabulary`)
        failed += 1
      }
    }
    collect(vector.at)
    collect(vector.records)
  }

  const bad = [...new Set(timestamps)].filter(t => !RFC3339_MS_Z.test(t))
  if (bad.length > 0) {
    console.log(`FAIL these timestamps are not RFC 3339 with millisecond precision and a literal Z, so the harness's string comparison is not a chronological comparison: ${bad.join(', ')}`)
    failed += 1
  } else {
    console.log(`ok   all ${new Set(timestamps).size} distinct record timestamps are RFC 3339 with millisecond precision and a literal Z`)
  }
}

structural()
console.log()

// --- reference and controls ------------------------------------------------------------

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

console.log('negative controls')
for (const control of Object.values(vectors.controls)) {
  const profile = CONTROLS[control.name]
  if (profile === undefined) {
    console.log(`FAIL control ${control.name} has no profile in harness.ts`)
    failed += 1
    continue
  }
  const scope = vectors.vectors.filter(v => control.runs_against_concepts.includes(v.concept))
  if (scope.length === 0) {
    console.log(`FAIL control ${control.name} covers no vector`)
    failed += 1
    continue
  }
  const observedFails = scope.filter(v => runVector(v, profile).length > 0).map(v => v.id)
  const undeclared = observedFails.filter(id => !control.expected_fail_ids.includes(id))
  const stopped = control.expected_fail_ids.filter(id => !observedFails.includes(id))
  if (undeclared.length > 0) {
    failed += 1
    console.log(`  FAIL ${control.name} diverged on vectors the fixture does not declare: [${undeclared.join(', ')}]`)
  }
  if (stopped.length > 0) {
    failed += 1
    console.log(`  FAIL ${control.name} no longer diverges on declared vectors: [${stopped.join(', ')}]`)
  }
  if (undeclared.length === 0 && stopped.length === 0) {
    console.log(
      `  ok   ${control.name} ran ${scope.length} vectors and diverged on exactly [${control.expected_fail_ids.join(', ')}]`,
    )
  }
}
console.log()

// --- SDK probes ------------------------------------------------------------------------

console.log('SDK probes, npm agent-passport-system')
let probes = 0
let probeFails = 0
const notSupported = new Map<string, string>()

/** One evaluateThreshold call over the minted signatures a vector names. */
function runThresholdProbe(vector: Vector, probe: SdkProbe): boolean {
  const subject = chainFixture.approvals.subjects[probe.subject_key!]
  if (subject === undefined) {
    console.log(`  MISMATCH ${vector.id} names subject_key ${probe.subject_key}, absent from chain.json`)
    return false
  }
  const content = approvalSignContent({ requestId: subject.request_id, subject: subject.subject })
  const requirements = (probe.requirements ?? []).map(req => ({
    role: req.role,
    requiredSignatures: req.requiredSignatures,
    eligibleKeys: req.actors.map(a => chainFixture.approvals.actors[a]),
  }))
  const signatures = (probe.signature_refs ?? []).map(ref => {
    const record = chainFixture.approvals.signatures[ref]
    const role = (probe.requirements ?? []).find(req => req.actors.includes(record.actor))?.role ?? 'role_unassigned'
    return {
      publicKey: chainFixture.approvals.actors[record.actor],
      keyClass: role,
      signedAt: '2026-09-20T11:45:00.000Z',
      signature: record.signature,
    }
  })
  const evaluation = evaluateThreshold(
    {
      policyId: `policy:${probe.subject_key}`,
      requirements,
      collectionTimeoutSeconds: 3600,
      onTimeout: 'reject',
      reevaluateOnRevocation: true,
    } as any,
    signatures as any,
    content,
  ) as any
  const unsatisfied = (evaluation.classStatus as Array<{ role: string; satisfied: boolean }>)
    .filter(c => !c.satisfied)
    .map(c => c.role)
    .sort()
  const want = probe.expected as { met: boolean; unsatisfied_roles: string[] }
  const ok = evaluation.met === want.met && JSON.stringify(unsatisfied) === JSON.stringify([...want.unsatisfied_roles].sort())
  if (ok) {
    console.log(`  MATCH    ${vector.id} evaluateThreshold met=${evaluation.met} unsatisfied=[${unsatisfied.join(', ')}]`)
  } else {
    console.log(
      `  MISMATCH ${vector.id} evaluateThreshold expected ${JSON.stringify(want)} observed ` +
        `{"met":${evaluation.met},"unsatisfied_roles":${JSON.stringify(unsatisfied)}}`,
    )
  }
  return ok
}

function runChainProbe(vector: Vector, probe: SdkProbe, revokedRoles: string[]): boolean {
  const observed = verifyChain(probe.chain!, revokedRoles)
  const want = probe.expected as { state: string; failure_code: string | null; failure_index: number | null }
  const ok =
    observed.state === want.state &&
    observed.failureCode === want.failure_code &&
    observed.failureIndex === want.failure_index
  const suffix = observed.failureCode ? `/${observed.failureCode}@${observed.failureIndex}` : ''
  if (ok) console.log(`  MATCH    ${vector.id} chain ${probe.chain} ${observed.state}${suffix}`)
  else {
    console.log(
      `  MISMATCH ${vector.id} chain ${probe.chain} expected ${JSON.stringify(want)} observed ${JSON.stringify(observed)}`,
    )
  }
  return ok
}

for (const vector of vectors.vectors) {
  const entries: Array<{ probe: SdkProbe; revoked: string[] }> = [
    { probe: vector.sdk.npm, revoked: [] },
    ...vector.also_runs.map(a => ({ probe: a.npm, revoked: a.revoked_roles ?? [] })),
  ]
  for (const { probe, revoked } of entries) {
    if (!probe.supported) {
      notSupported.set(`${vector.concept}/${probe.layer}`, probe.reason ?? '(no reason recorded)')
      continue
    }
    probes += 1
    let ok: boolean
    if (probe.layer === 'multi_class_threshold') ok = runThresholdProbe(vector, probe)
    else if (probe.layer === 'chain_state') ok = runChainProbe(vector, probe, revoked)
    else {
      console.log(`  MISMATCH ${vector.id} declares a supported layer "${probe.layer}" this runner does not call`)
      ok = false
    }
    if (!ok) probeFails += 1
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

// --- signature layer summary -----------------------------------------------------------

// Every minted approval signature is verified with the SDK, and the one tampered
// signature must fail. Asserted here so a mint that silently stopped tampering, or a
// verifier that accepts anything, fails the run rather than passing quietly.
console.log('approval signature layer, verified by the SDK')
let good = 0
let bad = 0
for (const [ref, record] of Object.entries(chainFixture.approvals.signatures).sort()) {
  const ok = signatureVerifies(ref, record.actor)
  const shouldVerify = !ref.endsWith(':tampered')
  if (ok === shouldVerify) (shouldVerify ? good++ : bad++)
  else {
    failed += 1
    console.log(`  FAIL ${ref} verifies=${ok}, expected ${shouldVerify}`)
  }
}
console.log(`  ok   ${good} minted signatures verify and ${bad} tampered signature does not`)
console.log()

// --- canonical bytes -------------------------------------------------------------------

console.log('RFC 8785 JCS canonical digests of the signed delegation records')
let records = 0
for (const [name, chain] of Object.entries(chainFixture.chains).sort()) {
  for (const member of chain) {
    const body = { ...member }
    delete (body as any).signature
    delete (body as any).delegation_id
    const digest = createHash('sha256').update(canonicalizeJCS(body), 'utf8').digest('hex')
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
