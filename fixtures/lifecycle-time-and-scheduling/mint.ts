// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-time-and-scheduling family, byte for byte.
//
// WHAT THIS FAMILY TESTS. The "Time and scheduling" section of CASES.md in
// aeoess/agent-authority-lifecycle, cases LC-C-008, LC-C-014, LC-C-015, LC-C-017,
// LC-C-025, LC-E-008, LC-E-014, LC-E-018, LC-E-019, LC-E-020, LC-E-034, LC-G-007,
// LC-G-008 and LC-G-009, against the proposed text in AUTHORITY-LIFECYCLE.md at commit
// 7796e22 or later. Every vector is labelled candidate_against_proposed. Nothing here is
// a draft-pidlisnyi-aps-03 conformance result for the lifecycle rule under test, because
// draft-03 states no rule for any of the fourteen. Where draft-03 does decide a step
// (chain shape, signature, time facet, revocation state, scope narrowing) the SDK decides
// it and the result is recorded separately from this family's lifecycle verdict.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are
// pinned constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-time-and-scheduling/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  computeActionRefV2,
  computeAuthorityDelegationId,
  computePayloadRefV1,
  createActionReferenceInputV2,
  isPurposePermitted,
  publicKeyFromPrivate,
  sign,
  signAuthorityDelegation,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-time-and-scheduling:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

// The principal is an office, not a named person. This family says nothing about what
// happens when an individual issuer leaves: office vacancy and succession are open in
// OPEN-QUESTIONS.md and this fixture tests only what a recorded instrument declares.
const OFFICE = 'did:aps:example:lts-operations-office'
const AGENT = 'did:aps:example:lts-reconciliation-agent'
const ORG_AGENT = 'did:aps:example:lts-organizational-agent'
const OUTGOING = 'did:aps:example:lts-outgoing-holder'
const INCOMING = 'did:aps:example:lts-incoming-holder'
const REGISTRAR = 'did:aps:example:lts-registrar'
const BOUNDARY = 'did:aps:example:lts-enforcement-boundary'
// A party with a real key and no recorded standing for anything in this family.
const OUTSIDER = 'did:aps:example:lts-outsider'

const IDS = { OFFICE, AGENT, ORG_AGENT, OUTGOING, INCOMING, REGISTRAR, BOUNDARY, OUTSIDER }

const KEY_ID: Record<string, string> = Object.fromEntries(
  Object.values(IDS).map((d) => [d, `${d}#key-1`]),
)
const PRIVATE: Record<string, string> = Object.fromEntries(
  Object.entries(IDS).map(([label, d]) => [d, seed(`identity:${label.toLowerCase()}:v1`)]),
)
const PUBLIC: Record<string, string> = Object.fromEntries(
  Object.entries(PRIVATE).map(([d, k]) => [d, publicKeyFromPrivate(k)]),
)
const VERIFICATION_KEYS: Record<string, string> = Object.fromEntries(
  Object.values(IDS).map((d) => [KEY_ID[d], PUBLIC[d]]),
)

// ---------------------------------------------------------------------------
// The timeline. One pinned day inside one pinned grant window. No clock is read.
// ---------------------------------------------------------------------------

const ISSUED = '2026-09-01T00:00:00.000Z'
const NOT_AFTER = '2026-10-01T00:00:00.000Z'
const T1 = '2026-09-10T08:00:00.000Z'
const T2 = '2026-09-10T09:00:00.000Z'
const T3 = '2026-09-10T10:00:00.000Z'
const T4 = '2026-09-10T11:00:00.000Z'
const T5 = '2026-09-10T12:00:00.000Z'
const T6 = '2026-09-10T13:00:00.000Z'
const AFTER_END = '2026-10-05T00:00:00.000Z'

// The short window the clock cases (LC-G-007, LC-G-008, LC-G-009) are checked against.
const TB_NOT_BEFORE = T2
const TB_NOT_AFTER = T4

// 1024 weeks is the legacy GPS week counter's period. The wrapped reading below is the
// pinned reading T3 moved back by exactly that many weeks, computed here rather than
// written by hand, so the number in chain.json is a function of the constant above it.
const GPS_ROLLOVER_WEEKS = 1024
const WRAPPED_READING = new Date(
  Date.parse(T3) - GPS_ROLLOVER_WEEKS * 7 * 24 * 60 * 60 * 1000,
).toISOString()

// ---------------------------------------------------------------------------
// Grants. Root AuthorityDelegationV1 records, office to agent, minted with the SDK.
//
// Note what is NOT here. draft-pidlisnyi-aps-03 section 3.2's authority vector is a
// closed set of seven facets. It has no facet for a handover acknowledgment, a rotation
// schedule, a pinned policy version, an occurrence template, a wind-down grace bound, a
// queue, or a clock attestation. None of the fourteen bounds this family tests can live
// inside a signed delegation at all, which is why they are minted below as separate
// signed records. That gap is a finding, recorded in README.md under "Where the proposed
// text was too vague to test".
// ---------------------------------------------------------------------------

function authorityVector(grants: string[], notBefore: string, notAfter: string, depth = 0) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: depth },
    time: { not_before: notBefore, not_after: notAfter },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] as string[] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

function mintGrant(
  label: string,
  subject: string,
  grants: string[],
  notBefore = ISSUED,
  notAfter = NOT_AFTER,
) {
  const body = {
    record_type: 'aps:authority-delegation:v1' as const,
    version: '1.0' as const,
    parent_delegation_id: null,
    issuer: OFFICE,
    subject,
    verification_method: KEY_ID[OFFICE],
    issued_at: ISSUED,
    nonce: seed(`grant-nonce:${label}:v1`).slice(0, 32),
    authority: authorityVector(grants, notBefore, notAfter),
  }
  const delegation_id = computeAuthorityDelegationId(body)
  const draft = { ...body, delegation_id }
  return { ...draft, signature: signAuthorityDelegation(draft, PRIVATE[OFFICE]) }
}

const GRANTS = {
  // LC-C-008. An office-issued grant whose exercise this family gates on a direction
  // record from whoever currently acts for the office.
  office: mintGrant('office', AGENT, ['ops:office:*']),
  // LC-C-014, LC-C-017, LC-C-025. One control position, held by one holder at a time.
  position_outgoing: mintGrant('position-outgoing', OUTGOING, ['ops:position:*']),
  position_incoming: mintGrant('position-incoming', INCOMING, ['ops:position:*']),
  // LC-C-015. Live-directed work, with a narrower pre-authorized fallback.
  directed: mintGrant('directed', AGENT, ['ops:reconcile:*']),
  // LC-E-008. A durable workflow instance.
  workflow: mintGrant('workflow', AGENT, ['ops:workflow:*']),
  // LC-E-014. A recurring series owner, and the organizational principal a recorded
  // disposition can reassign the series to.
  series_owner: mintGrant('series-owner', AGENT, ['ops:series:*']),
  series_fallback: mintGrant('series-fallback', ORG_AGENT, ['ops:series:*']),
  // LC-E-018. A recurring job whose occurrence template is edited between occurrences.
  job: mintGrant('job', AGENT, ['ops:job:*']),
  // LC-E-019. A workload that receives a termination signal mid-request.
  workload: mintGrant('workload', AGENT, ['ops:workload:*']),
  // LC-E-020. The creator identity's broad grant, and the narrower grant that replaces
  // it while the job definition itself sits untouched between occurrences.
  creator_broad: mintGrant('creator-broad', AGENT, ['ops:batch:*']),
  creator_narrow: mintGrant('creator-narrow', AGENT, ['ops:batch:read']),
  // LC-E-034. A queued action that outlasts a suspension.
  queued: mintGrant('queued', AGENT, ['ops:queue:*']),
  // LC-G-007, LC-G-008, LC-G-009. A two-hour window, so a checking party's own clock
  // decides the answer.
  timebound: mintGrant('timebound', AGENT, ['ops:timed:*'], TB_NOT_BEFORE, TB_NOT_AFTER),
} as const

type GrantKey = keyof typeof GRANTS

// ---------------------------------------------------------------------------
// Fixture-local signed records. One envelope, one `kind` discriminator.
//
// This shape is this fixture's invention. Neither AUTHORITY-LIFECYCLE.md nor draft-03
// defines a wire shape for any of it. The envelope exists so that every lifecycle input
// this family reasons over is a signed statement by a named party, checkable the same
// way, rather than a bare JSON blob the harness trusts.
// ---------------------------------------------------------------------------

const RECORD_PROFILE = 'aps-conformance-suite:lifecycle-time-and-scheduling:record-v0'
const RECORD_SIG_DOMAIN = 'APS-CONFORMANCE-LIFECYCLE-TIME-RECORD-V0'

interface SignedRecord {
  profile: string
  kind: string
  record_id: string
  issuer: string
  verification_method: string
  issued_at: string
  body: Record<string, unknown>
  signature: string
}

function mintRecord(
  recordId: string,
  kind: string,
  issuer: string,
  issuedAt: string,
  body: Record<string, unknown>,
): SignedRecord {
  const unsigned = {
    profile: RECORD_PROFILE,
    kind,
    record_id: recordId,
    issuer,
    verification_method: KEY_ID[issuer],
    issued_at: issuedAt,
    body,
  }
  const payload = `${RECORD_SIG_DOMAIN} ${canonicalizeJCS(unsigned)}`
  return { ...unsigned, signature: sign(payload, PRIVATE[issuer]) }
}

// Who may say what. A signature establishes who signed. It does not establish standing,
// so standing is its own signed statement by the office, and the harness reads it from
// here rather than from the record making the claim about itself.
const STANDING_REGISTRY = mintRecord('standing_registry', 'standing_registry', OFFICE, ISSUED, {
  // role -> the identities the office recognizes in that role
  succession_rule_author: [OFFICE],
  tenure_attestor: [REGISTRAR],
  vacancy_attestor: [REGISTRAR],
  rest_attestor: [REGISTRAR],
  qualification_attestor: [REGISTRAR],
  identity_removal_attestor: [REGISTRAR],
  schedule_author: [OFFICE],
  policy_author: [OFFICE],
  template_author: [OFFICE],
  series_author: [OFFICE],
  job_author: [OFFICE],
  suspension_author: [OFFICE],
  fallback_author: [OFFICE],
  relief_author: [OFFICE],
  observation_attestor: [BOUNDARY],
  instance_attestor: [BOUNDARY],
  occurrence_attestor: [BOUNDARY],
  wind_down_attestor: [BOUNDARY],
  queue_attestor: [BOUNDARY],
})

const R: Record<string, SignedRecord> = { standing_registry: STANDING_REGISTRY }
function add(rec: SignedRecord): SignedRecord {
  R[rec.record_id] = rec
  return rec
}

// --- LC-C-008. Vacancy with and without a declared default successor -------

add(mintRecord('c008_vacancy', 'vacancy', REGISTRAR, T1, { office: OFFICE, vacant_from: T1 }))
add(
  mintRecord('c008_default_rule', 'succession_default', OFFICE, ISSUED, {
    office: OFFICE,
    default_successor_role: 'first_assistant',
    minimum_tenure_days: 90,
  }),
)
// The same rule, asserted by the candidate about itself. Real signature, no standing.
add(
  mintRecord('c008_default_rule_self_declared', 'succession_default', OUTSIDER, ISSUED, {
    office: OFFICE,
    default_successor_role: 'first_assistant',
    minimum_tenure_days: 90,
  }),
)
add(
  mintRecord('c008_tenure_eligible', 'role_tenure', REGISTRAR, ISSUED, {
    holder: INCOMING,
    office: OFFICE,
    role: 'first_assistant',
    held_since: '2026-01-01T00:00:00.000Z',
  }),
)
add(
  mintRecord('c008_tenure_short', 'role_tenure', REGISTRAR, ISSUED, {
    holder: INCOMING,
    office: OFFICE,
    role: 'first_assistant',
    held_since: '2026-08-20T00:00:00.000Z',
  }),
)
add(
  mintRecord('c008_direction', 'direction', INCOMING, T2, {
    grant: GRANTS.office.delegation_id,
    office: OFFICE,
    requested_scope: 'ops:office:direct',
  }),
)
// The same direction record, self-declared by a party with no tenure record at all.
add(
  mintRecord('c008_direction_outsider', 'direction', OUTSIDER, T2, {
    grant: GRANTS.office.delegation_id,
    office: OFFICE,
    requested_scope: 'ops:office:direct',
  }),
)

// --- LC-C-014. Acknowledgment-gated handover -------------------------------

add(
  mintRecord('c014_offer', 'handover_offer', OUTGOING, T2, {
    position: 'ops:position',
    outgoing: OUTGOING,
    incoming: INCOMING,
    offered_at: T2,
    briefing_digest: seed('c014-briefing:v1'),
  }),
)
add(
  mintRecord('c014_ack', 'handover_ack', INCOMING, T3, {
    offer_id: 'c014_offer',
    acknowledged_at: T3,
    briefing_digest: seed('c014-briefing:v1'),
  }),
)
// An acknowledgment for the same offer, signed by someone other than the named incoming
// holder. The signature verifies. The signer is not the party the offer names.
add(
  mintRecord('c014_ack_wrong_signer', 'handover_ack', OUTSIDER, T3, {
    offer_id: 'c014_offer',
    acknowledged_at: T3,
    briefing_digest: seed('c014-briefing:v1'),
  }),
)

// --- LC-C-015. Loss of the live directing channel --------------------------

add(
  mintRecord('c015_fallback', 'fallback_authorization', OFFICE, ISSUED, {
    grant: GRANTS.directed.delegation_id,
    fallback_scope: ['ops:reconcile:read'],
    contact_loss_threshold_seconds: 900,
  }),
)
add(
  mintRecord('c015_contact_live', 'contact_observation', BOUNDARY, T3, {
    agent: AGENT,
    last_contact_at: T3,
    restored_at: null,
  }),
)
// Last contact two hours before the presentation, well past the declared threshold.
add(
  mintRecord('c015_contact_lost', 'contact_observation', BOUNDARY, T3, {
    agent: AGENT,
    last_contact_at: T1,
    restored_at: null,
  }),
)
add(
  mintRecord('c015_contact_restored', 'contact_observation', BOUNDARY, T4, {
    agent: AGENT,
    last_contact_at: T1,
    restored_at: T4,
  }),
)

// --- LC-C-017. A standing rotation schedule --------------------------------

add(
  mintRecord('c017_schedule', 'rotation_schedule', OFFICE, ISSUED, {
    position: 'ops:position',
    minimum_rest_seconds: 7200,
    slots: [
      { at: T3, outgoing: OUTGOING, incoming: INCOMING },
      { at: T5, outgoing: INCOMING, incoming: OUTGOING },
    ],
  }),
)
add(
  mintRecord('c017_rest_complete', 'rest_ledger', REGISTRAR, T3, {
    holder: INCOMING,
    rest_started_at: '2026-09-10T00:00:00.000Z',
    rest_ended_at: T2,
  }),
)
add(
  mintRecord('c017_rest_incomplete', 'rest_ledger', REGISTRAR, T3, {
    holder: INCOMING,
    rest_started_at: T2,
    rest_ended_at: null,
  }),
)

// --- LC-C-025. Continuous coverage -----------------------------------------

add(
  mintRecord('c025_atomic_relief', 'atomic_relief', OFFICE, T2, {
    position: 'ops:position',
    departing: OUTGOING,
    designated: INCOMING,
    effective_at: T2,
  }),
)
add(mintRecord('c025_departure', 'departure', OFFICE, T2, { position: 'ops:position', departing: OUTGOING, effective_at: T2 }))
add(
  mintRecord('c025_designation', 'designation', OFFICE, T4, {
    position: 'ops:position',
    designated: INCOMING,
    effective_at: T4,
  }),
)
add(
  mintRecord('c025_designation_unqualified', 'designation', OFFICE, T4, {
    position: 'ops:position',
    designated: OUTSIDER,
    effective_at: T4,
  }),
)
add(
  mintRecord('c025_qualification', 'qualification', REGISTRAR, ISSUED, {
    holder: INCOMING,
    position: 'ops:position',
    qualification: 'senior-operator',
  }),
)

// --- LC-E-008. Policy version pinned at instance start ---------------------

add(
  mintRecord('e008_policy_v1', 'policy', OFFICE, ISSUED, {
    policy_id: 'workflow-spend-v1',
    policy_version: '1.0.0',
    effective_from: ISSUED,
    denied_scopes: [] as string[],
  }),
)
add(
  mintRecord('e008_policy_v2', 'policy', OFFICE, T2, {
    policy_id: 'workflow-spend-v1',
    policy_version: '2.0.0',
    effective_from: T2,
    denied_scopes: ['ops:workflow:commit'],
  }),
)
add(
  mintRecord('e008_instance_pinned_v1', 'instance_start', BOUNDARY, T1, {
    instance_id: 'wf-0001',
    grant: GRANTS.workflow.delegation_id,
    pinned_policy_version: '1.0.0',
    started_at: T1,
  }),
)
add(
  mintRecord('e008_instance_pinned_v2', 'instance_start', BOUNDARY, T3, {
    instance_id: 'wf-0002',
    grant: GRANTS.workflow.delegation_id,
    pinned_policy_version: '2.0.0',
    started_at: T3,
  }),
)
add(
  mintRecord('e008_instance_unpinned', 'instance_start', BOUNDARY, T1, {
    instance_id: 'wf-0003',
    grant: GRANTS.workflow.delegation_id,
    pinned_policy_version: null,
    started_at: T1,
  }),
)
add(
  mintRecord('e008_instance_pinned_missing', 'instance_start', BOUNDARY, T1, {
    instance_id: 'wf-0004',
    grant: GRANTS.workflow.delegation_id,
    pinned_policy_version: '9.9.9',
    started_at: T1,
  }),
)

// --- LC-E-014. A recurring series and a removed owner ----------------------

add(
  mintRecord('e014_series', 'series', OFFICE, ISSUED, {
    series_id: 'nightly-reconciliation',
    grant: GRANTS.series_owner.delegation_id,
    owner: AGENT,
    action_scope: 'ops:series:reconcile',
    disposition_on_owner_removal: null,
  }),
)
add(
  mintRecord('e014_series_with_disposition', 'series', OFFICE, ISSUED, {
    series_id: 'nightly-reconciliation-b',
    grant: GRANTS.series_owner.delegation_id,
    owner: AGENT,
    action_scope: 'ops:series:reconcile',
    disposition_on_owner_removal: {
      mode: 'reassign',
      reassign_to: ORG_AGENT,
      grant: GRANTS.series_fallback.delegation_id,
    },
  }),
)
add(mintRecord('e014_owner_removed', 'identity_removal', REGISTRAR, T2, { identity: AGENT, removed_at: T2 }))

// --- LC-E-018. Occurrence template versus running occurrence ---------------

add(
  mintRecord('e018_template_v1', 'occurrence_template', OFFICE, ISSUED, {
    job_id: 'hourly-export',
    template_version: '1',
    effective_from: ISSUED,
    scope: ['ops:job:*'],
  }),
)
add(
  mintRecord('e018_template_v2', 'occurrence_template', OFFICE, T3, {
    job_id: 'hourly-export',
    template_version: '2',
    effective_from: T3,
    scope: ['ops:job:read'],
  }),
)
add(
  mintRecord('e018_occurrence_under_v1', 'occurrence', BOUNDARY, T2, {
    occurrence_id: 'hourly-export-0007',
    job_id: 'hourly-export',
    created_at: T2,
    created_under_template_version: '1',
  }),
)
add(
  mintRecord('e018_occurrence_under_v2', 'occurrence', BOUNDARY, T4, {
    occurrence_id: 'hourly-export-0008',
    job_id: 'hourly-export',
    created_at: T4,
    created_under_template_version: '2',
  }),
)
add(
  mintRecord('e018_occurrence_unrecorded', 'occurrence', BOUNDARY, T2, {
    occurrence_id: 'hourly-export-0009',
    job_id: 'hourly-export',
    created_at: T2,
    created_under_template_version: null,
  }),
)

// --- LC-E-019. Scheduled wind-down -----------------------------------------

add(
  mintRecord('e019_wind_down', 'wind_down', BOUNDARY, T3, {
    workload: AGENT,
    grant: GRANTS.workload.delegation_id,
    termination_started_at: T3,
    grace_seconds: 1800,
  }),
)
add(
  mintRecord('e019_wind_down_no_bound', 'wind_down', BOUNDARY, T3, {
    workload: AGENT,
    grant: GRANTS.workload.delegation_id,
    termination_started_at: T3,
    grace_seconds: null,
  }),
)

// --- LC-E-020. A dormant scheduled job whose creator is downgraded ---------

add(
  mintRecord('e020_job_broad', 'scheduled_job', OFFICE, ISSUED, {
    job_id: 'batch-writer',
    creator: AGENT,
    creator_grant: GRANTS.creator_broad.delegation_id,
    action_scope: 'ops:batch:write',
  }),
)
add(
  mintRecord('e020_job_narrowed', 'scheduled_job', OFFICE, ISSUED, {
    job_id: 'batch-writer-b',
    creator: AGENT,
    creator_grant: GRANTS.creator_narrow.delegation_id,
    action_scope: 'ops:batch:write',
  }),
)
add(
  mintRecord('e020_job_reader', 'scheduled_job', OFFICE, ISSUED, {
    job_id: 'batch-reader',
    creator: AGENT,
    creator_grant: GRANTS.creator_narrow.delegation_id,
    action_scope: 'ops:batch:read',
  }),
)
add(
  mintRecord('e020_job_no_creator_grant', 'scheduled_job', OFFICE, ISSUED, {
    job_id: 'batch-orphan',
    creator: AGENT,
    creator_grant: null,
    action_scope: 'ops:batch:read',
  }),
)

// --- LC-E-034. A queued action that outlasts a suspension ------------------

add(
  mintRecord('e034_queued', 'queued_action', BOUNDARY, T1, {
    queue_id: 'q-0001',
    grant: GRANTS.queued.delegation_id,
    queued_at: T1,
    fires_at: T5,
    action_scope: 'ops:queue:settle',
    requires_live_suspension_source: true,
  }),
)
// Suspension lifted before the queued action fires. The benign timeline.
add(
  mintRecord('e034_suspension_released', 'suspension', OFFICE, T2, {
    grant: GRANTS.queued.delegation_id,
    cause: 'investigation-4711',
    suspended_at: T2,
    released_at: T4,
  }),
)
// The same suspension, still in force at fire time. Nothing else changes.
add(
  mintRecord('e034_suspension_active', 'suspension', OFFICE, T2, {
    grant: GRANTS.queued.delegation_id,
    cause: 'investigation-4711',
    suspended_at: T2,
    released_at: null,
  }),
)

// --- LC-G-007, LC-G-008, LC-G-009. Clock attestations ----------------------

function clockAttestation(
  recordId: string,
  issuer: string,
  reading: string,
  source: string,
  crossCheck: { source: string; reading: string; bound_ms: number } | null,
  smearPolicy: { window_start: string; window_end: string; bound_ms: number } | null,
) {
  return add(
    mintRecord(recordId, 'clock_attestation', issuer, ISSUED, {
      verifier: issuer,
      reading,
      source,
      cross_check: crossCheck,
      smear_policy: smearPolicy,
    }),
  )
}

const CROSS_OK = { source: 'ntp:pool-b', reading: T3, bound_ms: 500 }
clockAttestation('g007_clock_inside', BOUNDARY, T3, 'ntp:pool-a', CROSS_OK, null)
clockAttestation('g007_clock_after', REGISTRAR, '2026-09-10T11:30:00.000Z', 'ntp:pool-a', { source: 'ntp:pool-b', reading: '2026-09-10T11:30:00.000Z', bound_ms: 500 }, null)
clockAttestation('g007_clock_before', OUTGOING, '2026-09-10T08:30:00.000Z', 'ntp:pool-a', { source: 'ntp:pool-b', reading: '2026-09-10T08:30:00.000Z', bound_ms: 500 }, null)
// LC-G-008. One source, no cross-check, wrapped back by the legacy GPS counter period.
clockAttestation('g008_wrapped_single_source', BOUNDARY, WRAPPED_READING, 'gnss:legacy-week-counter', null, null)
clockAttestation('g008_cross_checked', BOUNDARY, T3, 'gnss:legacy-week-counter', CROSS_OK, null)
clockAttestation('g008_cross_check_disagrees', BOUNDARY, T3, 'gnss:legacy-week-counter', { source: 'ntp:pool-b', reading: '2026-09-10T10:00:05.000Z', bound_ms: 500 }, null)
clockAttestation('g008_no_source', BOUNDARY, T3, '', CROSS_OK, null)
// LC-G-009. A declared smear window, and two readings taken inside it.
const SMEAR = { window_start: TB_NOT_BEFORE, window_end: TB_NOT_AFTER, bound_ms: 500 }
clockAttestation('g009_smeared', BOUNDARY, '2026-09-10T10:00:00.000Z', 'ntp:smeared', CROSS_OK, SMEAR)
clockAttestation('g009_unsmeared', REGISTRAR, '2026-09-10T10:00:00.400Z', 'ntp:unsmeared', { source: 'ntp:pool-b', reading: '2026-09-10T10:00:00.400Z', bound_ms: 500 }, SMEAR)
clockAttestation('g009_unsmeared_no_window', REGISTRAR, '2026-09-10T10:00:00.400Z', 'ntp:unsmeared', { source: 'ntp:pool-b', reading: '2026-09-10T10:00:00.400Z', bound_ms: 500 }, null)
clockAttestation('g009_smeared_no_window', BOUNDARY, '2026-09-10T10:00:00.000Z', 'ntp:smeared', CROSS_OK, null)
// Two correctly run clocks that happen to read the same instant. The match control for
// the boundary that reads any mismatch as a fault.
clockAttestation('g009_smeared_twin', REGISTRAR, '2026-09-10T10:00:00.000Z', 'ntp:unsmeared', { source: 'ntp:pool-b', reading: '2026-09-10T10:00:00.000Z', bound_ms: 500 }, SMEAR)
clockAttestation('g009_far_apart', REGISTRAR, '2026-09-10T10:00:05.000Z', 'ntp:unsmeared', { source: 'ntp:pool-b', reading: '2026-09-10T10:00:05.000Z', bound_ms: 500 }, SMEAR)

// ---------------------------------------------------------------------------
// Actions. One action_ref per distinct proposed action, so no two attempts share an
// identity and a vector's action is a real draft-03 section 4 action reference rather
// than a bare string.
// ---------------------------------------------------------------------------

// `issued_at` is the issuer-side time the action reference itself claims. It is a claim
// by the party that built the reference, not a reading by the party checking it, and
// LC-G-007 turns on exactly that difference: the defective issuer-clock boundary reads
// this field where the reference boundary reads its own clock attestation.
const ACTION_SPECS: Array<[string, string, string, string]> = [
  ['office_direct', 'ops:office:direct', 'office.direct', ISSUED],
  ['position_control', 'ops:position:control', 'position.control', ISSUED],
  ['reconcile_read', 'ops:reconcile:read', 'reconcile.read', ISSUED],
  ['reconcile_write', 'ops:reconcile:write', 'reconcile.write', ISSUED],
  ['workflow_commit', 'ops:workflow:commit', 'workflow.commit', ISSUED],
  ['workflow_read', 'ops:workflow:read', 'workflow.read', ISSUED],
  ['series_reconcile', 'ops:series:reconcile', 'series.reconcile', ISSUED],
  ['job_write', 'ops:job:write', 'job.write', ISSUED],
  ['job_read', 'ops:job:read', 'job.read', ISSUED],
  ['workload_call', 'ops:workload:call', 'workload.call', ISSUED],
  ['batch_write', 'ops:batch:write', 'batch.write', ISSUED],
  ['batch_read', 'ops:batch:read', 'batch.read', ISSUED],
  ['queue_settle', 'ops:queue:settle', 'queue.settle', ISSUED],
  ['timed_call', 'ops:timed:call', 'timed.call', T3],
]

const ACTIONS = Object.fromEntries(
  ACTION_SPECS.map(([label, scope, type, actionIssuedAt]) => {
    const input = createActionReferenceInputV2({
      agent_id: AGENT,
      action_type: type,
      target: `https://ops.example/api/v1/${label.replace(/_/g, '/')}`,
      payload_ref: computePayloadRefV1({ action: label }),
      scope_required: [scope],
      issued_at: actionIssuedAt,
      nonce: seed(`action-nonce:${label}:v1`).slice(0, 32),
    })
    return [label, { input, action_ref: computeActionRefV2(input), requested_scope: scope, issued_at: actionIssuedAt }]
  }),
) as Record<string, { input: unknown; action_ref: string; requested_scope: string; issued_at: string }>

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written. Every claim this family
// makes about what the SDK returns is checked here and recorded in chain.json, so the
// README quotes a recorded value rather than a remembered one.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

const grantIds = Object.values(GRANTS).map((g) => g.delegation_id)
assert(new Set(grantIds).size === grantIds.length, 'two grants share a delegation_id')

const actionRefs = Object.values(ACTIONS).map((a) => a.action_ref)
assert(new Set(actionRefs).size === actionRefs.length, 'two actions share an action_ref')

// Every fixture-local record verifies under exactly the rule harness.ts applies.
for (const [label, rec] of Object.entries(R)) {
  const { signature, ...unsigned } = rec
  const payload = `${RECORD_SIG_DOMAIN} ${canonicalizeJCS(unsigned)}`
  assert(verifyEd25519(payload, signature, PUBLIC[rec.issuer]), `${label} does not verify under the harness rule`)
}

const resolveDelegationKey = (_issuer: string, method: string) => VERIFICATION_KEYS[method] ?? null
const chainOpts = (now: string, revocation: 'active' | 'revoked' = 'active') => ({
  now,
  resolveVerificationKey: resolveDelegationKey,
  trustRoot: (root: { issuer?: string }) => root.issuer === OFFICE,
  resolveRevocation: () => revocation as 'active' | 'revoked',
})

// Every grant except the two-hour timebound one verifies valid at every pinned instant on
// the fixture's day. This is the load-bearing fact of the whole family: the SDK answers
// `valid` for a grant whose handover is unacknowledged, whose owner has been removed from
// the registry, whose policy has been tightened, and whose workload is winding down. None
// of the fourteen bounds is visible to chain verification at all.
const chainStates: Record<string, Record<string, string>> = {}
for (const [label, grant] of Object.entries(GRANTS)) {
  chainStates[label] = {}
  for (const [instant, now] of Object.entries({ T1, T2, T3, T4, T5, T6 })) {
    const r = verifyAuthorityDelegationChain([grant], chainOpts(now))
    chainStates[label][instant] = r.state
    if (label !== 'timebound') {
      assert(r.state === 'valid', `${label} is not valid at ${instant}: ${JSON.stringify(r)}`)
    }
  }
}

// The timebound grant is the one the clock cases turn on. Recorded, not assumed.
const clockProbe: Record<string, { state: string; code: string | null }> = {}
for (const [label, now] of Object.entries({
  inside: T3,
  after: '2026-09-10T11:30:00.000Z',
  before: '2026-09-10T08:30:00.000Z',
  wrapped: WRAPPED_READING,
})) {
  const r = verifyAuthorityDelegationChain([GRANTS.timebound], chainOpts(now))
  clockProbe[label] = { state: r.state, code: r.failures[0]?.code ?? null }
}
assert(clockProbe.inside.state === 'valid', 'timebound grant is not valid inside its window')
assert(clockProbe.after.code === 'EXPIRED', 'past not_after did not give EXPIRED')
assert(clockProbe.before.code === 'NOT_YET_VALID', 'before not_before did not give NOT_YET_VALID')
assert(clockProbe.wrapped.code === 'NOT_YET_VALID', 'the wrapped reading did not give NOT_YET_VALID')

// A revoked grant, so LC-E-014 and LC-E-034 can separate revocation from removal and
// from suspension with the SDK's own code rather than with an assertion of ours.
const revokedProbe = verifyAuthorityDelegationChain([GRANTS.series_owner], chainOpts(T3, 'revoked'))
assert(revokedProbe.state === 'invalid' && revokedProbe.failures[0]?.code === 'REVOKED', 'revoked resolution did not give REVOKED')

// The SDK's purpose check answers membership and nothing else. It answers the same for a
// queued action fired during a suspension as for one fired outside it, which is why
// membership can never decide any of the fourteen bounds.
const membership = {
  reconcile_read_in_fallback: isPurposePermitted('ops:reconcile:read', ['ops:reconcile:read']),
  reconcile_write_in_fallback: isPurposePermitted('ops:reconcile:write', ['ops:reconcile:read']),
  batch_write_in_narrow_grant: isPurposePermitted('ops:batch:write', ['ops:batch:read']),
  job_write_in_template_v2: isPurposePermitted('ops:job:write', ['ops:job:read']),
}
assert(membership.reconcile_read_in_fallback === true, 'fallback scope does not permit the read action')
assert(membership.reconcile_write_in_fallback === false, 'fallback scope wrongly permits the write action')
assert(membership.batch_write_in_narrow_grant === false, 'narrowed creator grant wrongly permits the write action')
assert(membership.job_write_in_template_v2 === false, 'template v2 wrongly permits the write action')

// ---------------------------------------------------------------------------
// Write. Keys are sorted at every depth so the file is a function of its content.
// ---------------------------------------------------------------------------

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

const chain = {
  profile: 'aps-lifecycle-time-and-scheduling-v0',
  description:
    'Fourteen time and scheduling lifecycle cases. Twelve root AuthorityDelegationV1 ' +
    'grants, one signed standing registry, forty-odd fixture-local signed lifecycle ' +
    'records (a fixture-local profile, not a protocol object) and thirteen draft-03 ' +
    'action references, minted and verified with agent-passport-system 7.1.0.',
  minted_by: 'fixtures/lifecycle-time-and-scheduling/mint.ts',
  seed_label_prefix: SEED_PREFIX,
  sdk: { typescript: 'agent-passport-system@7.1.0' },
  identities: IDS,
  verification_keys: VERIFICATION_KEYS,
  record_profile: RECORD_PROFILE,
  record_signature_domain: RECORD_SIG_DOMAIN,
  timeline: {
    issued: ISSUED,
    not_after: NOT_AFTER,
    T1, T2, T3, T4, T5, T6,
    after_end: AFTER_END,
    timebound_not_before: TB_NOT_BEFORE,
    timebound_not_after: TB_NOT_AFTER,
    gps_rollover_weeks: GPS_ROLLOVER_WEEKS,
    wrapped_reading: WRAPPED_READING,
  },
  grants: GRANTS,
  records: R,
  actions: ACTIONS,
  // Recorded SDK observations, taken at mint time from the pinned SDK rather than written
  // by hand. README.md and the handoff quote these values.
  mint_time_sdk_observations: {
    chain_state_by_grant_and_instant: chainStates,
    timebound_chain_probe: clockProbe,
    revoked_resolution: { state: revokedProbe.state, code: revokedProbe.failures[0]?.code ?? null },
    is_purpose_permitted: membership,
  },
}

fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('lifecycle-time-and-scheduling: chain.json minted')
console.log(`  grants: ${Object.keys(GRANTS).length}, records: ${Object.keys(R).length}, actions: ${Object.keys(ACTIONS).length}`)
console.log(`  timebound chain probe: ${JSON.stringify(clockProbe)}`)
console.log(`  wrapped reading: ${WRAPPED_READING}`)
console.log(`  isPurposePermitted: ${JSON.stringify(membership)}`)
