// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs this family's vectors against the npm reference SDK, agent-passport-system,
// and records per claim whether the SDK has an API for the behaviour the claim
// needs. Where it does not, the claim is recorded not_supported with the reason,
// and nothing is simulated in its place.
//
// The family's model is protocol neutral. This bridge is the one place where it
// touches APS, and it touches it in two ways only:
//
//   claim 1  project the reference decision onto the single revocation answer
//            verifyAuthorityDelegationChain accepts, and check the chain verdict,
//   claim 2  re-derive each source line's within_bound using the SDK freshness
//            primitives rather than the harness arithmetic.
//
// Claims 3 to 6 are recorded, not run, because the SDK has no API for them.
//
// From the suite root:
//
//     npm run verify:conflicting-status-sources:sdk-ts

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildRevocationObservation,
  createLocalSigner,
  createSnapshotFreshness,
  enforceFreshnessPolicy,
  verifyAuthorityDelegationChain,
  verifyRevocationObservation,
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

// ── claim 1: chain verdict under the projected single answer ──────────────
//
// The SDK's resolveRevocation returns one answer for one delegation. A
// conflict has no representation in that vocabulary, so it projects to
// 'unknown', which is the SDK's indeterminate input. The projection is the
// claim being tested: an implementation whose only status vocabulary is
// active/revoked/unknown must not answer valid for anything this family
// denies or leaves unestablished.
type Projection = { answer: string; expect_state: string; expect_code: string | null }

function project(decision: string, reason: string): Projection {
  if (decision === 'admit') return { answer: 'active', expect_state: 'valid', expect_code: null }
  if (decision === 'deny' && reason === 'status_revoked') {
    return { answer: 'revoked', expect_state: 'invalid', expect_code: 'REVOKED' }
  }
  // conflict and every not_established reason: the SDK has no value for either,
  // so both project to unknown.
  return { answer: 'unknown', expect_state: 'indeterminate', expect_code: 'REVOCATION_UNKNOWN' }
}

console.log('claim 1  chain verdict under the projected single revocation answer: SUPPORTED')
console.log('         api: verifyAuthorityDelegationChain({ resolveRevocation })')
let claim1 = 0
let claim1Total = 0
for (const c of vectors.cases) {
  for (const b of c.boundaries) {
    claim1Total += 1
    const p = project(b.expected.decision, b.expected.reason)
    const result: any = verifyAuthorityDelegationChain(chainFixture.chain, {
      now: chainFixture.now,
      resolveVerificationKey: (_issuer: string, method: string) =>
        chainFixture.verification_keys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: (() => p.answer) as any,
    })
    const code = Array.isArray(result.failures) && result.failures[0] ? result.failures[0].code : null
    const ok = result.state === p.expect_state && code === p.expect_code
    const neverValid = b.expected.decision === 'admit' || result.state !== 'valid'
    if (ok && neverValid) claim1 += 1
    else {
      failures.push(
        `claim 1 ${b.boundary_id}: projected ${p.answer}, wanted ${p.expect_state}/${p.expect_code}, ` +
        `got ${result.state}/${code}`,
      )
    }
    console.log(
      `         ${b.boundary_id.padEnd(12)} ${b.expected.decision.padEnd(16)}` +
      `-> resolveRevocation '${p.answer}' -> ${result.state}` +
      (code ? `/${code}` : ''),
    )
  }
}
console.log(`         ${claim1}/${claim1Total} boundaries matched`)
console.log('')

// ── claim 2: per-source freshness boundary ────────────────────────────────
console.log('claim 2  per-source freshness bound, answer inside or past it: SUPPORTED')
console.log('         api: enforceFreshnessPolicy, mode bounded_staleness')
console.log(
  '         note: recordRevocationFreshness, which builds the underlying record, is not\n' +
  '         exported from the package root; the composition is.',
)
let claim2 = 0
let claim2Total = 0
for (const c of vectors.cases) {
  for (const b of c.boundaries) {
    for (const line of b.expected.record.sources_consulted) {
      if (line.as_of === null) continue // an unavailable answer dates nothing
      claim2Total += 1
      const boundMs = line.freshness_bound_s * 1000
      const decision = enforceFreshnessPolicy(
        {
          source: line.source_id,
          maxStalenessMs: boundMs,
          checkedAt: new Date(b.evaluated_at),
          freshness: createSnapshotFreshness(line.as_of, line.freshness_bound_s),
        },
        { mode: 'bounded_staleness', boundedStalenessMs: boundMs, action_on_stale: 'deny' },
      )
      const sdkWithinBound = decision.effect === 'allow'
      if (sdkWithinBound === line.within_bound) claim2 += 1
      else {
        failures.push(
          `claim 2 ${b.boundary_id}/${line.source_id}: harness within_bound=${line.within_bound}, ` +
          `SDK effect=${decision.effect} (${decision.reason})`,
        )
      }
    }
  }
}
console.log(`         ${claim2}/${claim2Total} source lines matched the harness freshness boundary`)
console.log('')

// ── claim 3: two sources compared for conflict ────────────────────────────
console.log('claim 3  two status sources compared for conflict about one delegation: NOT_SUPPORTED')
console.log(
  '         reason: a RevocationObservation carries exactly one status_source, and\n' +
  '         decideFreshness takes exactly one RevocationFreshnessRecord. No exported\n' +
  '         function takes two answers about one authority_ref and returns a conflict.\n' +
  '         Nothing was simulated in its place.',
)
console.log('')

// ── claim 4: coverage over a declared source set ──────────────────────────
console.log('claim 4  coverage over a declared required-source set: NOT_SUPPORTED')
console.log(
  '         reason: no exported API takes a list of sources a verifier requires, so\n' +
  '         "every required source answered" is not expressible. The suite\'s\n' +
  '         status_coverage_incomplete reason has no SDK counterpart.',
)
console.log('')

// ── claim 5: a third verdict at the observation layer ─────────────────────
console.log('claim 5  not_established as an observation-layer outcome: NOT_SUPPORTED')
console.log(
  '         reason: FreshnessDecision.effect is allow | deny, and the SDK types say of\n' +
  '         RevocationObservationDecision that "No third verdict value exists". The\n' +
  '         chain layer does carry indeterminate, which claim 1 exercises; the two\n' +
  '         layers do not share a vocabulary.',
)
console.log('')

// ── claim 6: what an offline admission records ────────────────────────────
console.log('claim 6  an offline admission records the snapshot and the age it used: PARTIAL')
const offline = vectors.cases
  .flatMap((c: any) => c.boundaries)
  .find((b: any) => b.expected.record.verifier_mode === 'offline' && b.expected.decision === 'admit')
if (!offline) {
  failures.push('claim 6: no offline admit boundary in vectors.json')
} else {
  const snap = offline.expected.record.snapshot
  const boundMs = snap.declared_bound_s * 1000
  const decision = enforceFreshnessPolicy(
    {
      source: snap.source_id,
      maxStalenessMs: boundMs,
      checkedAt: new Date(offline.evaluated_at),
      freshness: createSnapshotFreshness(snap.as_of, snap.declared_bound_s),
    },
    { mode: 'bounded_staleness', boundedStalenessMs: boundMs },
  )
  const record = decision.record
  const signerKey = createHash('sha256')
    .update(`${vectors.determinism.seed_input}:sdk-bridge-observer:v1`, 'utf8')
    .digest('hex')
  const signed = await buildRevocationObservation(
    {
      authority_ref: vectors.delegation_ref,
      status_source: { kind: 'source', id: snap.source_id },
      observed_at: new Date(offline.evaluated_at),
      maximum_staleness_ms: boundMs,
      decision: { effect: decision.effect === 'allow' ? 'allow' : 'deny' },
    },
    createLocalSigner({ privateKeyHex: signerKey }),
  )
  const verified = verifyRevocationObservation(signed)
  console.log(`         boundary: ${offline.boundary_id}`)
  console.log(`         decideFreshness effect=${decision.effect}`)
  console.log(`         decideFreshness reason="${decision.reason}"`)
  console.log(
    `         RevocationFreshnessRecord carries: source=${record.source}, ` +
    `freshness.validAt=${record.freshness?.validAt}, maxStalenessMs=${record.maxStalenessMs}`,
  )
  console.log(
    `         SignedRevocationObservation fields: ${Object.keys(signed).sort().join(', ')}`,
  )
  console.log(`         verifyRevocationObservation: valid=${verified.valid}`)
  console.log(
    '         supported: the source identity and the tolerated staleness are structured\n' +
    '         fields on the signed observation, and the snapshot\'s own as_of is a\n' +
    '         structured field on the unsigned freshness record.\n' +
    '         not supported: the signed observation carries neither the snapshot as_of\n' +
    '         nor the age it admitted on, so a reader of the signed record alone cannot\n' +
    '         recompute either. On this path the decision short-circuits on result\n' +
    '         \'fresh\' and its reason carries no age at all; an age appears in the\n' +
    '         reason string only on the bounded-staleness branch, which is reached only\n' +
    '         after the source\'s own maxAge has already expired, and even there it is\n' +
    '         prose rather than a field.',
  )
  if (!verified.valid) failures.push('claim 6: the SDK did not verify its own observation')
  if (decision.effect !== 'allow') {
    failures.push(`claim 6: SDK denied a snapshot the fixture admits (${decision.reason})`)
  }
}
console.log('')

if (failures.length > 0) {
  for (const f of failures) console.error(`FAIL ${f}`)
  console.error(`\nconflicting-status-sources SDK bridge (TypeScript): ${failures.length} failure(s)`)
  process.exit(1)
}
console.log(
  `PASSED: conflicting-status-sources SDK bridge (TypeScript), ${pkg.name} ${pkg.version}. ` +
  `2 claims supported and matched, 1 partial, 3 recorded not_supported.`,
)
