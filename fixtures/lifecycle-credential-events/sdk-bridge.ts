// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs this family's vectors against the npm reference SDK, agent-passport-system,
// and records per claim whether the SDK has an API for the behaviour the claim
// needs. Where it does not, the claim is recorded not_supported with the reason
// and the nearest surface named, and nothing is simulated in its place.
//
// The family's model is protocol neutral. This bridge is the one place it
// touches APS.
//
// From the suite root:
//
//     npm run verify:lifecycle-credential-events:sdk-ts

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CompositionCheckV0,
  assertKeyPurpose,
  checkAudience,
  compareTimestamps,
  createHybridTimestampAt,
  publicKeyFromPrivate,
  scopeCovers,
  sign,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(
  readFileSync(join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
) as { name: string; version: string }

const vectors = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8')) as any
const chainFixture = JSON.parse(readFileSync(join(here, 'chain.json'), 'utf8')) as {
  now: string
  verification_keys: Record<string, string>
  chain: any[]
}

console.log(`implementation: ${pkg.name} ${pkg.version} (npm)`)
console.log(`node: ${process.version}`)
console.log('')

const failures: string[] = []
const allBoundaries: any[] = vectors.cases.flatMap((c: any) =>
  c.boundaries.map((b: any) => ({ ...b, vector_id: c.id, case_id: c.case_id })),
)

// ── claim 1 ───────────────────────────────────────────────────────────────
//
// The SDK's resolveRevocation returns one answer per delegation. This family's
// verdict vocabulary is wider, so every verdict projects onto the narrowest SDK
// answer that does not overstate it: valid -> active, invalid -> revoked, and
// not established -> unknown, which is the SDK's indeterminate input. The claim
// being tested is that an implementation whose only status vocabulary is
// active/revoked/unknown never answers valid for a boundary this family does
// not call valid.

type Projection = { answer: string; expect_state: string; expect_code: string | null }

function project(verdict: string): Projection {
  if (verdict === 'valid') return { answer: 'active', expect_state: 'valid', expect_code: null }
  if (verdict === 'invalid') {
    return { answer: 'revoked', expect_state: 'invalid', expect_code: 'REVOKED' }
  }
  return { answer: 'unknown', expect_state: 'indeterminate', expect_code: 'REVOCATION_UNKNOWN' }
}

console.log('claim 1  chain verdict under the projected single revocation answer: SUPPORTED')
console.log('         api: verifyAuthorityDelegationChain({ resolveRevocation })')
let claim1 = 0
for (const b of allBoundaries) {
  const p = project(b.expected.verdict)
  const result: any = verifyAuthorityDelegationChain(chainFixture.chain, {
    now: chainFixture.now,
    resolveVerificationKey: (_issuer: string, method: string) =>
      chainFixture.verification_keys[method] ?? null,
    trustRoot: () => true,
    resolveRevocation: (() => p.answer) as any,
  })
  const code = Array.isArray(result.failures) && result.failures[0] ? result.failures[0].code : null
  const neverValid = b.expected.verdict === 'valid' || result.state !== 'valid'
  if (result.state === p.expect_state && code === p.expect_code && neverValid) claim1 += 1
  else {
    failures.push(
      `claim 1 ${b.boundary_id}: projected ${p.answer}, wanted ${p.expect_state}/${p.expect_code}, ` +
      `got ${result.state}/${code}`,
    )
  }
}
console.log(`         ${claim1}/${allBoundaries.length} boundaries matched the projection`)
console.log('')

// ── claim 2 ───────────────────────────────────────────────────────────────

console.log(
  'claim 2  a declared recipient scope checked as its own facet, separately from the ' +
  'signature: SUPPORTED, with one projection divergence recorded',
)
console.log('         api: checkAudience(proof, policy), four-valued AudienceCheckResult')
const G004 = vectors.cases.filter((c: any) => c.case_id === 'LC-G-004')
let claim2 = 0
const claim2Notes: string[] = []
for (const c of G004) {
  const b = c.boundaries[0]
  const keyScope = b.events.find((e: any) => e.type === 'key_scope')
  const proof = keyScope
    ? { aud: { profile: 'aps:audience-binding:v1' as const, recipients: keyScope.populations } }
    : {}
  const result = checkAudience(proof as any, {
    recipientId: b.credential.claimed_audience,
    requireAudience: true,
  })
  const familyCheck = b.expected.record.checks.find(
    (x: any) => x.check_id === 'key_scope_containment',
  )
  const agree =
    (familyCheck.result === 'established_valid' && result.status === 'pass') ||
    (familyCheck.result === 'established_invalid' && result.status === 'fail') ||
    (familyCheck.result === 'not_established' && result.status === 'unknown')
  console.log(
    `         ${c.id.padEnd(58)} family ${familyCheck.result.padEnd(20)} SDK ${result.status}/${result.reason}`,
  )
  if (agree) claim2 += 1
  else {
    claim2Notes.push(
      `${c.id}: family ${familyCheck.result}, SDK ${result.status}/${result.reason}`,
    )
  }
}
console.log(`         ${claim2}/${G004.length} key-scope outcomes projected exactly`)
for (const note of claim2Notes) {
  console.log(`         divergence recorded, not a failure: ${note}`)
}
console.log(
  '         reason for the divergence: AudienceCheckResult reserves `unknown` for a policy\n' +
  '         carrying no recipientId, and maps "binding required and absent" to `fail`. This\n' +
  '         family returns not established there. The SDK has a four-valued lattice and uses\n' +
  '         its fourth value for a different condition, so the two are not interchangeable.',
)
if (claim2Notes.length !== 1) {
  failures.push(`claim 2: expected exactly 1 recorded divergence, saw ${claim2Notes.length}`)
}
console.log('')

// ── claim 3 ───────────────────────────────────────────────────────────────

console.log('claim 3  scope containment arithmetic for the enforced-scope check: SUPPORTED')
console.log('         api: scopeCovers(granted, required)')
const D009 = vectors.cases.filter((c: any) => c.case_id === 'LC-D-009')
let claim3 = 0
let claim3Total = 0
for (const c of D009) {
  const b = c.boundaries[0]
  const attested = b.events.find((e: any) => e.type === 'reachable_scope_attestation')
  if (!attested) continue
  claim3Total += 1
  const declared: string[] = b.credential.declared_scope
  const contained = (attested.grants as string[]).every(g =>
    declared.some(d => scopeCovers(d, g)),
  )
  const familyCheck = b.expected.record.checks.find(
    (x: any) => x.check_id === 'enforced_scope_containment',
  )
  const want = familyCheck.result === 'established_valid'
  console.log(
    `         ${c.id.padEnd(58)} SDK contained=${String(contained).padEnd(5)} family ${familyCheck.result}`,
  )
  if (contained === want) claim3 += 1
  else {
    failures.push(
      `claim 3 ${c.id}: scopeCovers says contained=${contained}, family says ${familyCheck.result}`,
    )
  }
}
console.log(`         ${claim3}/${claim3Total} attested-scope vectors matched`)
console.log('')

// ── claim 4 ───────────────────────────────────────────────────────────────

console.log(
  'claim 4  per-check results in a fixed enum with a separate indeterminate, and attestor\n' +
  '         independence corroborated from trust context rather than self-declaration: SUPPORTED',
)
console.log(
  '         api: CompositionCheckV0.verifyCompositionCheck, ' +
  'compositionCheckSigningPayload, COMPOSITION_CHECK_RESULTS',
)
const { verifyCompositionCheck, compositionCheckSigningPayload, COMPOSITION_CHECK_PROFILE } =
  CompositionCheckV0
console.log(
  `         COMPOSITION_CHECK_RESULTS = ${JSON.stringify(CompositionCheckV0.COMPOSITION_CHECK_RESULTS)}`,
)
console.log(
  `         ATTESTOR_INDEPENDENCE_CLASSES = ` +
  `${JSON.stringify(CompositionCheckV0.ATTESTOR_INDEPENDENCE_CLASSES)}`,
)

/** This family's three check results projected onto the SDK's fixed enum. The
 *  SDK enum has a fourth member, not_checked, which this family does not need
 *  because a check outside required_checks is simply absent from the record. */
function projectCheck(result: string): string {
  if (result === 'established_valid') return 'pass'
  if (result === 'established_invalid') return 'fail'
  return 'indeterminate'
}

const attestorPriv = createHash('sha256')
  .update(`${vectors.determinism.seed_input}:sdk-bridge-attestor:v1`, 'utf8')
  .digest('hex')
const attestorPub = publicKeyFromPrivate(attestorPriv)
const ATTESTOR_KEY_ID = 'did:aps:example:lce-sdk-bridge-attestor#key-1'

function receiptFor(b: any, independenceClass: string) {
  const checks = b.expected.record.checks
  const receipt: Record<string, unknown> = {
    profile: COMPOSITION_CHECK_PROFILE,
    attestor_key_id: ATTESTOR_KEY_ID,
    attestor_independence_class: independenceClass,
    chain_hash: vectors.credential_ref,
    action_ref: b.boundary_id,
    context_hash: b.expected.canonical_sha256,
    policy_profile_ids: ['aac-lifecycle-credential-events-v0'],
    checks_run: checks.map((c: any) => c.check_id),
    result_per_check: checks.map((c: any) => projectCheck(c.result)),
    issued_at: b.gateway_now,
    expires_at: '2026-09-30T00:00:00Z',
  }
  receipt.signature = sign(compositionCheckSigningPayload(receipt), attestorPriv)
  return receipt
}

function ctxFor(b: any, registeredByOperator: boolean) {
  return {
    trusted_attestors: {
      [ATTESTOR_KEY_ID]: {
        publicKey: attestorPub,
        profiles: ['aac-lifecycle-credential-events-v0'],
        registered_by_operator: registeredByOperator,
      },
    },
    expected_chain_hash: vectors.credential_ref,
    expected_action_ref: b.boundary_id,
    expected_context_hash: b.expected.canonical_sha256,
    now_ms: Date.parse(b.gateway_now),
  }
}

let claim4 = 0
for (const b of allBoundaries) {
  const receipt = receiptFor(b, 'independent_registered')
  const verified: any = verifyCompositionCheck(receipt as any, ctxFor(b, false) as any)
  const echoed: string[] = verified.result_per_check
  const projected: string[] = b.expected.record.checks.map((c: any) => projectCheck(c.result))
  const sameOrder =
    echoed.length === projected.length && echoed.every((v, i) => v === projected[i])
  const noAggregateVerdict = !('safe' in verified) && !('verdict' in verified)
  if (verified.anchor_verified && sameOrder && noAggregateVerdict) claim4 += 1
  else {
    failures.push(
      `claim 4 ${b.boundary_id}: anchor_verified=${verified.anchor_verified}, ` +
      `violations=${JSON.stringify(verified.violations)}, per-check echo same=${sameOrder}`,
    )
  }
}
console.log(
  `         ${claim4}/${allBoundaries.length} boundaries: the SDK verified the anchor, echoed the\n` +
  `         per-check results in order, and returned no aggregate verdict of its own`,
)

// the independence property this family's LC-D-029-b turns on
const sampleBoundary = allBoundaries[0]
const selfDeclared: any = verifyCompositionCheck(
  receiptFor(sampleBoundary, 'independent_registered') as any,
  ctxFor(sampleBoundary, true) as any,
)
const corroborated: any = verifyCompositionCheck(
  receiptFor(sampleBoundary, 'independent_registered') as any,
  ctxFor(sampleBoundary, false) as any,
)
console.log(
  `         self-declared independent, context says registered_by_operator=true  -> ` +
  `independence_is_second_anchor=${selfDeclared.independence_is_second_anchor}`,
)
console.log(
  `         self-declared independent, context says registered_by_operator=false -> ` +
  `independence_is_second_anchor=${corroborated.independence_is_second_anchor}`,
)
if (selfDeclared.independence_is_second_anchor !== false) {
  failures.push('claim 4: the SDK accepted a self-declared independence the context did not back')
}
if (corroborated.independence_is_second_anchor !== true) {
  failures.push('claim 4: the SDK did not corroborate an independence the context backs')
}
console.log(
  '         this is the same property LC-D-029-b turns on: an attestation that restates the\n' +
  '         signer\'s own claim is not a second anchor. The SDK downgrades, never upgrades.',
)

// One pinned cross-language constant. Both bridges build the same receipt from
// vectors.json and sign it with the same derived key. The signature is over the
// composition-check tag plus RFC 8785 JCS of the receipt without its signature,
// so if the two packages' canonicalizers or tags ever diverge, both runs fail
// here rather than silently disagreeing.
const CROSS_LANG_SIGNATURE =
  'fc2acb57697994cc1edbf39f90270f6022b25717fcecb8c5818ed069613ad9a58f71fc41796aae686374397b4ec47f20ad9d873ea701beb28c60924ecf5aa50f'
const pinnedReceipt = receiptFor(allBoundaries[0], 'independent_registered') as any
console.log(
  `         cross-language signature over ${allBoundaries[0].boundary_id}: ` +
  `${String(pinnedReceipt.signature).slice(0, 24)}...`,
)
if (pinnedReceipt.signature !== CROSS_LANG_SIGNATURE) {
  failures.push(
    `claim 4: the signature over the pinned receipt is ${pinnedReceipt.signature}, ` +
    `not the pinned ${CROSS_LANG_SIGNATURE}`,
  )
}
console.log('')

// ── claim 5 ───────────────────────────────────────────────────────────────

console.log('claim 5  a signing key checked for the purpose it was authorized for: SUPPORTED')
console.log('         api: assertKeyPurpose(keyId, didDoc, requiredPurpose)')
const keyId = 'did:aps:example:lce-principal#key-1'
const didDocScoped = { assertionMethod: [keyId] }
let claim5ok = true
try {
  assertKeyPurpose(keyId, didDocScoped, 'assertionMethod')
  console.log('         key authorized for assertionMethod: accepted')
} catch (err) {
  claim5ok = false
  failures.push(`claim 5: rejected a key the DID document authorizes: ${(err as Error).message}`)
}
try {
  assertKeyPurpose(keyId, didDocScoped, 'capabilityDelegation')
  claim5ok = false
  failures.push('claim 5: accepted a key for a purpose the DID document does not authorize')
} catch (err) {
  const reason = (err as any).reason
  console.log(`         same key for capabilityDelegation: rejected, reason=${reason}`)
  if (reason !== 'key_purpose_violation') {
    failures.push(`claim 5: rejection reason was ${reason}`)
  }
}
console.log(
  '         scope: the SDK\'s purposes are DID verification relationships, not issuer-defined\n' +
  '         populations. It establishes that a key scope is checked as its own step, which is\n' +
  '         LC-G-004\'s shape. It does not carry the population vocabulary the case needs.',
)
if (!claim5ok) failures.push('claim 5: see above')
console.log('')

// ── claim 6 ───────────────────────────────────────────────────────────────

console.log('claim 6  clock disagreement as an outcome distinct from expiry: PARTIAL')
const skewBoundary = allBoundaries.find(
  (b: any) => b.expected.record.clock && b.expected.record.clock.within_tolerance === false,
)
if (!skewBoundary) {
  failures.push('claim 6: no boundary in vectors.json records a skew beyond tolerance')
} else {
  const clock = skewBoundary.expected.record.clock
  const driftMs = clock.tolerance_s * 1000
  const gateway = createHybridTimestampAt('gateway', 1, driftMs)
  const reference = createHybridTimestampAt('reference-attestor', 1, driftMs)
  // Place the two readings skew_s apart, keeping the uncertainty bound the
  // boundary declared, so the SDK's own comparison decides the ordering.
  const shift = clock.skew_s * 1000
  const shifted = {
    ...gateway,
    wallClockEarliest: gateway.wallClockEarliest + shift,
    wallClockLatest: gateway.wallClockLatest + shift,
  }
  const ordering = compareTimestamps(shifted, reference)
  console.log(`         boundary: ${skewBoundary.boundary_id}`)
  console.log(`         declared tolerance ${clock.tolerance_s}s, observed skew ${clock.skew_s}s`)
  console.log(`         compareTimestamps(gatewayReading, referenceReading) = ${ordering}`)
  const near = compareTimestamps(
    { ...gateway, wallClockEarliest: gateway.wallClockEarliest + 1000, wallClockLatest: gateway.wallClockLatest + 1000 },
    reference,
  )
  console.log(`         the same comparison one second apart              = ${near}`)
  console.log(
    '         supported: HybridTimestamp carries an explicit wall-clock uncertainty band and\n' +
    '         compareTimestamps returns a non-definite ordering while the bands overlap, so\n' +
    '         "these two readings cannot be definitely ordered" is expressible.\n' +
    '         not supported: no API returns a denial category for a clock disagreement.\n' +
    '         validateTemporalRights answers validity and expiry; a skew rejection would be\n' +
    '         recorded as the same expiry LC-F-013-b records, which is what the case says\n' +
    '         must not happen. Nothing was simulated in its place.',
  )
  if (ordering !== 'definitely_after') {
    failures.push(`claim 6: a ${clock.skew_s}s gap did not order definitely, got ${ordering}`)
  }
  if (near !== 'concurrent' && near !== 'incomparable') {
    failures.push(`claim 6: a 1s gap inside the drift band ordered definitely, got ${near}`)
  }
}
console.log('')

// ── claims 7 to 10, recorded absences ─────────────────────────────────────

const ABSENT: Array<{ n: number; title: string; reason: string }> = [
  {
    n: 7,
    title: 'compromise reach computed over a declared authority graph',
    reason:
      'No exported function takes a set of authority edges and a compromised subject and\n' +
      '         returns the reachable set. The nearest surface is evaluateRevocationImpact,\n' +
      '         which walks DerivationReceipt records in a receipt store: an impact set over\n' +
      '         what was recorded, which is the `enumerated-reach-basis` control in this\n' +
      '         family, not the reference basis. cascadeRevoke walks delegation descendants\n' +
      '         and has no notion of a "could mint credentials for" edge.',
  },
  {
    n: 8,
    title: 'revocation effectiveness as a property of the credential class',
    reason:
      'A revocation record and a revocation observation both name one delegation. No\n' +
      '         exported API takes a credential class and returns when a recorded revocation\n' +
      '         becomes effective for it, so LC-F-035\'s "not yet effective" has no SDK\n' +
      '         counterpart and the two boundaries in that case are indistinguishable.',
  },
  {
    n: 9,
    title: 'an issuance-window integrity finding, or trust in an issuer population',
    reason:
      'buildTrustRootPolicy and verifyTrustRootPolicy carry accepted roots. Nothing takes\n' +
      '         a finding about an issuer\'s own issuance records over a window, and nothing\n' +
      '         expresses "this issuer\'s whole population is in question" as distinct from\n' +
      '         revoking named artifacts.',
  },
  {
    n: 10,
    title: 'a coverage basis for what was exercised under a credential',
    reason:
      'The suite\'s accountability and attribution surfaces record individual actions.\n' +
      '         No exported API states or checks a completeness claim over an interval, which\n' +
      '         is the separate second claim LC-D-025 turns on.',
  },
]
for (const a of ABSENT) {
  console.log(`claim ${a.n}  ${a.title}: NOT_SUPPORTED`)
  console.log(`         reason: ${a.reason}`)
  console.log('')
}

// Assert the absences against the installed package, so a later release that
// adds the surface turns this run into a failure rather than a stale note.
const sdk: any = await import('agent-passport-system')
const MUST_BE_ABSENT = [
  'reachableAuthoritySubjects',
  'computeCompromiseReach',
  'revocationEffectiveFrom',
  'credentialClassRevocability',
  'verifyIssuanceWindowIntegrity',
  'issuerPopulationTrust',
  'exercisedAuthorityCoverage',
  'verifyCoverageBasis',
]
for (const name of MUST_BE_ABSENT) {
  if (name in sdk) {
    failures.push(
      `claims 7 to 10: ${pkg.name} ${pkg.version} now exports ${name}. Re-run this bridge and ` +
      `move the claim out of the recorded absences.`,
    )
  }
}

if (failures.length > 0) {
  for (const f of failures) console.error(`FAIL ${f}`)
  console.error(`\nlifecycle-credential-events SDK bridge (TypeScript): ${failures.length} failure(s)`)
  process.exit(1)
}
console.log(
  `PASSED: lifecycle-credential-events SDK bridge (TypeScript), ${pkg.name} ${pkg.version}. ` +
  `4 claims supported and matched, 1 supported with a recorded projection divergence, ` +
  `1 partial, 4 recorded not_supported.`,
)
