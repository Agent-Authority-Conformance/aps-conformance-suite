// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records what the published npm `agent-passport-system` package does with each
// group in this family, so SDK-RUNS.md's entries are reproducible rather than
// asserted.
//
// This probe reports. It does not judge. Nothing in draft-pidlisnyi-aps-03 asks
// the SDK for any of these six behaviours, so a `not_supported` line here is an
// absence of a named surface, not a defect report and not a conformance result.
//
// One group does have a real surface. `enforceFreshnessPolicy` takes an
// `AttestationFreshness` carrying the source's own `validAt` and `ttl` plus the
// verifier's own `maxStalenessMs`, which is exactly the two-window shape the
// status_artifact group is about. This probe runs every status_artifact vector
// through it under two of the SDK's documented policy modes and prints what
// came back next to what the fixture expects. Disagreement is reported as
// disagreement; the probe never rewrites either side.
//
// Run: node fixtures/lifecycle-infrastructure-failure/sdk-probe.mjs
// Exit 0 always.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import * as aps from 'agent-passport-system'

const HERE = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(readFileSync(join(HERE, 'vectors.json'), 'utf8'))

// The package does not export ./package.json, so the version is read from the
// installed tree rather than imported.
const version = JSON.parse(readFileSync(join(HERE, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8')).version
const exported = Object.keys(aps).sort()

console.log(`agent-passport-system (npm) ${version}, ${exported.length} exports`)
console.log('')

// --- status_artifact: a real surface, run per vector ------------------------

console.log('group status_artifact: enforceFreshnessPolicy + isEvidenceFresh')
console.log('  mapping: AttestationFreshness {type: rotating, validAt: this_update,')
console.log('           ttl: next_update - this_update}, maxStalenessMs: the verifier bound.')
console.log('  The artifact\'s own declared refresh window becomes the evidence ttl and the')
console.log('  verifier\'s bound stays the verifier\'s bound, so both windows reach the SDK.')
console.log('')

for (const c of vectors.cases.filter(v => v.group === 'status_artifact')) {
  const a = c.input.artifact
  const ttlSeconds = (Date.parse(a.next_update) - Date.parse(a.this_update)) / 1000
  const freshness = aps.createRotatingFreshness(a.this_update, ttlSeconds)
  const now = new Date(c.input.evaluated_at)
  const opts = {
    source: a.list_id,
    maxStalenessMs: c.input.verifier_freshness_bound_s * 1000,
    checkedAt: now,
    freshness,
  }
  const own = aps.isEvidenceFresh(freshness, now)
  const closed = aps.enforceFreshnessPolicy(opts, { mode: 'fail_closed' })
  const bounded = aps.enforceFreshnessPolicy(opts, {
    mode: 'bounded_staleness',
    boundedStalenessMs: c.input.verifier_freshness_bound_s * 1000,
  })
  console.log(`  ${c.id}  fixture expects ${c.expected.verdict}`)
  console.log(`    isEvidenceFresh(own window)   : ${own}`)
  console.log(`    fail_closed                   : result=${closed.result} effect=${closed.effect} reason="${closed.reason}"`)
  console.log(`    bounded_staleness(bound=verifier): result=${bounded.result} effect=${bounded.effect} reason="${bounded.reason}"`)
}
console.log('')

// --- the other five groups: probe for a named surface -----------------------

const probes = [
  {
    group: 'status_correction',
    concept: 'retraction of an erroneous status publication, distinct from a revocation withdrawal',
    pattern: /(publicationError|retract|correctStatus|correctRevocation|unrevoke|withdrawRevocation)/i,
    reason:
      'no export names a publication-error retraction, and no export takes a list version range. The correction/withdrawal names the package does export (withdrawProvisional, withdrawalPayload) belong to the provisional-decision surface, not to a status publisher retracting its own published entry.',
  },
  {
    group: 'issuer_time_evidence',
    concept: 'independent time evidence covering an issuer-claimed issued_at',
    // Deliberately not matching a bare /timeAttestation/i: the export
    // `verifyRuntimeAttestation` contains that substring ("runTimeAttestation")
    // and is about runtime attestation, not about time. It is the only near-name
    // in the package and it is unrelated.
    pattern: /(timestampAuthority|trustedTimestamp|timeSourceDisagreement|rfc3161|externalTimeEvidence)/i,
    reason:
      'the package canonicalizes and asserts timestamps (assertCanonicalTimestamp, compareCanonicalTimestamps) but has no surface that takes evidence about a timestamp from a party other than the issuer, and none that takes a declared time-source-disagreement window.',
  },
  {
    group: 'history_reconciliation',
    concept: 'merging two divergent authority write histories with a reconciliation record',
    pattern: /(reconcileHistory|mergeHistories|splitBrain|partitionMerge|discardedWrites)/i,
    reason:
      'the revocation store is a single in-memory set (InMemoryAuthorityRevocationStore) with no notion of two histories, no merge entry point and no record of what a merge kept or discarded. reconcileBilateralPair is about a bilateral delegation pair, not about a partitioned authority store.',
  },
  {
    group: 'causal_read',
    concept: 'a required-observation token binding a read to a specific prior write',
    pattern: /(consistencyToken|zookie|zedToken|requiredObservation|readAfterWrite|appliedThrough)/i,
    reason:
      'the resolveRevocation callback the chain verifier accepts takes the delegation and nothing else, so there is no argument through which a request could name a write the answer must reflect.',
  },
  {
    group: 'evidence_coverage',
    concept: 'coverage of an evidence interval against a declared delivery lag and a consumer set',
    pattern: /(coverageOfInterval|evidenceCoverage|deliveryLag|deliveredThrough|intervalComplete)/i,
    reason:
      'capabilityCoverage is scope coverage, not interval coverage. Nothing takes a query interval, a declared delivery-lag bound, or a set of consumers with delivery positions.',
  },
]

for (const p of probes) {
  const hits = exported.filter(n => p.pattern.test(n))
  const verdict = hits.length === 0 ? 'not_supported' : `present: ${hits.join(', ')}`
  console.log(`group ${p.group}: ${verdict}`)
  console.log(`  needed: ${p.concept}`)
  console.log(`  reason: ${p.reason}`)
}
