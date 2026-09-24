// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the lifecycle-credential-events candidate family.
//
// WHAT THIS IS. A synthetic verifier that resolves a declared set of required
// checks about one credential, at one authorization boundary, from the event
// records available at that boundary, and writes a credential-event record. It
// is protocol neutral: no APS type, no APS receipt, no network call, no
// wall-clock read. Every instant comes from the vector.
//
// THE ONE IDEA the whole family turns on. A boundary declares which checks its
// policy requires. Each required check resolves from its own input records to
// established_valid, established_invalid or not_established. No check's answer
// is ever inferred from another check's answer, and a check with no input
// record is not_established rather than passed. The boundary verdict is the
// join of the check results under a fixed precedence, in the settled verdict
// vocabulary.
//
// WHAT IT MODELS, in the vocabulary of the proposed text it is written against
// (aeoess/agent-authority-lifecycle, AUTHORITY-LIFECYCLE.md at commit 7796e22
// or later):
//
//   Status observation     what a verifier could establish, from which record.
//   Verifier trust policy  which roots, attestors and required checks the
//                          verifier accepts, and its clock tolerance.
//   Evidence attestor      who produced a record and in what role, kept
//                          separate from whether the record's claim holds.
//   Coverage/completeness  which set a claim about "everything reachable" or
//                          "everything that happened" was computed over.
//   Authority epoch        the suspect window a compromise finding opens, and
//                          which side of it an artifact is independently dated.
//
// THE AXES the control policies differ along are named in PolicyProfile below.
// Everything else -- the check functions, the join, the record writer, the
// digest -- is shared, so a divergence between two policies is attributable to
// the declared axis and to nothing else.
//
// Node builtins only, except for the suite's vendored RFC 8785 canonicalizer,
// which produces the pinned record bytes.

import { canonicalizeJCS } from '../../runners/ts/canonicalize.js'
import { createHash } from 'node:crypto'

// ── vocabulary ────────────────────────────────────────────────────────────

/** What one required check resolves to. There is no fourth value, and a check
 *  with no input record never resolves to established_valid. */
export type CheckResult = 'established_valid' | 'established_invalid' | 'not_established'

/** The settled verdict vocabulary. This family reaches `valid`, `invalid` and
 *  `not established`. `not yet effective`, `suspended` and `restricted` are in
 *  the vocabulary and are used for the state of a revocation record rather than
 *  of the credential; see revocation_effectiveness. */
export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not established'
  | 'not yet effective'
  | 'suspended'
  | 'restricted'

export type CheckId =
  | 'signature_and_key_version'
  | 'key_scope_containment'
  | 'enforced_scope_containment'
  | 'artifact_provenance'
  | 'authorizer_addition_provenance'
  | 'compromise_reach'
  | 'issuance_log_integrity'
  | 'issuer_population_trust'
  | 'suspect_window_partition'
  | 'revocation_effectiveness'
  | 'clock_agreement'
  | 'inherited_root_reattestation'
  | 'exercised_authority_accounting'

export const CHECK_IDS: CheckId[] = [
  'signature_and_key_version',
  'key_scope_containment',
  'enforced_scope_containment',
  'artifact_provenance',
  'authorizer_addition_provenance',
  'compromise_reach',
  'issuance_log_integrity',
  'issuer_population_trust',
  'suspect_window_partition',
  'revocation_effectiveness',
  'clock_agreement',
  'inherited_root_reattestation',
  'exercised_authority_accounting',
]

// ── inputs ────────────────────────────────────────────────────────────────

/** An event record known at the boundary. `attestor_standing` is whether the
 *  trust policy declares this attestor as having standing to make this kind of
 *  statement. A valid signature would establish who signed; it would not
 *  establish standing, so standing is carried as its own field. */
export interface EventRecord {
  event_id: string
  type: string
  attestor: string
  attestor_standing: 'declared' | 'not_declared'
  [key: string]: unknown
}

export interface CredentialFacts {
  /** The issuer's own claimed issuance instant. An issuer claim, not evidence. */
  issued_at: string
  not_before: string
  not_after: string
  /** The population or audience this artifact claims to be usable for. */
  claimed_audience: string
  /** The scope the delegation declares on its face. */
  declared_scope: string[]
  /** Whether a verifier at this boundary performs a server-side status lookup
   *  for this credential class at all. A stateless bearer artifact verified by
   *  signature alone does not. */
  status_lookup: boolean
  /** The subject the credential was issued to. */
  subject: string
}

export interface RootDeclaration {
  root_id: string
  /** Set when this root entered the verifier's trust policy by inheriting
   *  another organization's root rather than by the verifier establishing it. */
  inherited_at?: string
  /** The instant by which the trust policy requires the inherited root to be
   *  re-established under the inheriting party's own root. */
  reattestation_deadline?: string
}

export interface TrustPolicy {
  roots: RootDeclaration[]
  /** Maximum tolerated disagreement, in seconds, between this boundary's clock
   *  and an attested reference clock. */
  clock_tolerance_s: number
  /** Directed edges of the authority graph the policy declares: from a subject
   *  that can issue or mint for, to a subject it can reach. Reachability is
   *  computed over the transitive closure of these edges. */
  authority_graph: Array<{ from: string; to: string; relation: string }>
  /** The list a deployment maintains of grants it believes are live under a
   *  given subject. Documentation for the reference policy, and the reach basis
   *  for the `enumerated-reach-basis` control. */
  enumerated_reach_list: string[]
  /** Authorizers (devices, keys) currently attached to the credential's
   *  identity. Presence here is a fact about a list, not about an authorization. */
  authorizers: string[]
  /** Checks this policy requires at this boundary, in precedence order. */
  required_checks: CheckId[]
}

export interface Boundary {
  boundary_id: string
  /** The instant this boundary's own clock reports. Possibly wrong; that is
   *  what clock_agreement is for. Nothing here reads a wall clock. */
  gateway_now: string
  credential: CredentialFacts
  trust_policy: TrustPolicy
  events: EventRecord[]
  /** Digest of the record written at an earlier boundary, when this boundary
   *  follows one. A later finding is a NEW record that references the earlier
   *  one. It never rewrites it. */
  prior_record_sha256: string | null
}

// ── record ────────────────────────────────────────────────────────────────

export interface RecordedCheck {
  check_id: CheckId
  result: CheckResult
  reason: string
  /** Which record or declared input the check read, so a reader can tell an
   *  answer established from evidence from an answer established from nothing. */
  basis: string
}

export interface CompromiseReachBlock {
  trigger_event_id: string
  trigger_accepted: boolean
  reach_basis: 'authority_graph' | 'enumerated_list'
  reached: string[]
  credential_in_reach: boolean
  reattested: boolean
}

export interface SuspectWindowBlock {
  finding_event_id: string
  /** null means the finding opens no suspect window at all. */
  start: string | null
  start_basis: 'exposure' | 'discovery' | 'compromise_point' | 'none'
  partition_timestamp_source: 'independent_attestation' | 'issuer_claim' | 'none'
  artifact_position: 'before_window' | 'inside_window' | 'not_established'
}

export interface ClockBlock {
  gateway_now: string
  reference_now: string | null
  skew_s: number | null
  tolerance_s: number
  within_tolerance: boolean
}

export interface RevocationEffectivenessBlock {
  revocation_event_id: string
  /** The state of the revocation record itself, in the settled vocabulary. */
  status: 'valid' | 'not yet effective'
  effective_from: string
  basis: string
}

export interface CredentialEventRecord {
  record_type: 'aac.credential-event-record.v0'
  vector_id: string
  /** The case id in CASES.md this record is written against, or null for the
   *  family-level control. */
  case_id: string | null
  credential_ref: string
  evaluated_at: string
  verdict: Verdict
  verdict_reason: string
  required_checks: CheckId[]
  checks: RecordedCheck[]
  compromise_reach: CompromiseReachBlock | null
  suspect_window: SuspectWindowBlock | null
  clock: ClockBlock | null
  revocation_effectiveness: RevocationEffectivenessBlock | null
  prior_record_sha256: string | null
}

// ── policy axes ───────────────────────────────────────────────────────────

/**
 * The axes a policy can differ along. The reference policy sets all of them the
 * way the proposed text reads. Each control changes exactly one.
 */
export interface PolicyProfile {
  name: string
  /** Whether a compromise disclosure from a party other than the credential's
   *  own issuing organization is ingested as a trigger at all. */
  ingest_third_party_triggers: boolean
  /** What reachability from a compromised subject is computed over. */
  reach_basis: 'authority_graph' | 'enumerated_list'
  /** Whether a valid signature is treated as satisfying key_scope_containment,
   *  enforced_scope_containment and artifact_provenance. */
  signature_satisfies_other_checks: boolean
  /** Whether a root that entered the policy by inheritance needs its own
   *  re-establishment record. */
  inherited_root_needs_reattestation: boolean
  /** Whether per-artifact revocation records settle a finding about the
   *  issuer's own issuance-log integrity. */
  log_integrity_settled_by_per_artifact_revocation: boolean
  /** Whether a systemic issuer-misbehaviour finding is answered chain by chain
   *  instead of over the issuer's whole population. */
  issuer_population_per_chain: boolean
  /** Whether the accounting of what was done under a credential is inferred
   *  from the credential's current authority status. */
  accounting_from_authority_status: boolean
  /** Whether presence on the authorizer list establishes that the addition was
   *  itself authorized. */
  presence_implies_authorized_addition: boolean
  /** How a clock disagreement beyond tolerance is categorized. */
  skew_category: 'clock_disagreement' | 'expiry'
  /** Whether a recorded revocation is treated as effective for every credential
   *  class regardless of whether the boundary looks status up. */
  revocation_universal: boolean
  /** Whether a planned rotation at the end of a declared cryptoperiod opens a
   *  suspect window. */
  planned_rotation_opens_window: boolean
  /** Where a suspect window starts when exposure and discovery differ. */
  window_start: 'exposure' | 'discovery'
  /** Which timestamp partitions artifacts around a compromise point. */
  partition_timestamp: 'independent' | 'claimed'
  /** What a declared check with no input record resolves to. */
  missing_record_result: 'not_established' | 'established_valid'
}

export const REFERENCE_VERIFIER: PolicyProfile = {
  name: 'reference-verifier',
  ingest_third_party_triggers: true,
  reach_basis: 'authority_graph',
  signature_satisfies_other_checks: false,
  inherited_root_needs_reattestation: true,
  log_integrity_settled_by_per_artifact_revocation: false,
  issuer_population_per_chain: false,
  accounting_from_authority_status: false,
  presence_implies_authorized_addition: false,
  skew_category: 'clock_disagreement',
  revocation_universal: false,
  planned_rotation_opens_window: false,
  window_start: 'exposure',
  partition_timestamp: 'independent',
  missing_record_result: 'not_established',
}

function control(name: string, patch: Partial<PolicyProfile>): PolicyProfile {
  return { ...REFERENCE_VERIFIER, name, ...patch }
}

export const CONTROL_POLICIES: Record<string, PolicyProfile> = {
  'self-initiated-triggers-only': control('self-initiated-triggers-only', {
    ingest_third_party_triggers: false,
  }),
  'enumerated-reach-basis': control('enumerated-reach-basis', {
    reach_basis: 'enumerated_list',
  }),
  'signature-satisfies-other-checks': control('signature-satisfies-other-checks', {
    signature_satisfies_other_checks: true,
  }),
  'grandfather-inherited-root': control('grandfather-inherited-root', {
    inherited_root_needs_reattestation: false,
  }),
  'per-artifact-revocation-settles-log-integrity': control(
    'per-artifact-revocation-settles-log-integrity',
    { log_integrity_settled_by_per_artifact_revocation: true },
  ),
  'issuer-population-from-caught-chains': control('issuer-population-from-caught-chains', {
    issuer_population_per_chain: true,
  }),
  'revocation-closes-accounting': control('revocation-closes-accounting', {
    accounting_from_authority_status: true,
  }),
  'presence-implies-authorized-addition': control('presence-implies-authorized-addition', {
    presence_implies_authorized_addition: true,
  }),
  'skew-is-expiry': control('skew-is-expiry', { skew_category: 'expiry' }),
  'revocation-is-universal': control('revocation-is-universal', { revocation_universal: true }),
  'every-rotation-is-a-trigger': control('every-rotation-is-a-trigger', {
    planned_rotation_opens_window: true,
  }),
  'discovery-dated-window': control('discovery-dated-window', { window_start: 'discovery' }),
  'trust-claimed-issued-at': control('trust-claimed-issued-at', {
    partition_timestamp: 'claimed',
  }),
  'skip-unestablished-checks': control('skip-unestablished-checks', {
    missing_record_result: 'established_valid',
  }),
}

// ── helpers ───────────────────────────────────────────────────────────────

function parseInstant(value: string): number {
  const ms = Date.parse(value)
  if (Number.isNaN(ms)) throw new Error(`not an instant: ${value}`)
  return ms
}

function eventsOfType(boundary: Boundary, type: string): EventRecord[] {
  return boundary.events.filter(e => e.type === type)
}

function firstEvent(boundary: Boundary, type: string): EventRecord | undefined {
  return eventsOfType(boundary, type)[0]
}

/** Transitive closure of the declared authority graph from one subject. */
function reachableFrom(
  edges: Array<{ from: string; to: string; relation: string }>,
  start: string,
): string[] {
  const seen = new Set<string>()
  const stack = [start]
  while (stack.length > 0) {
    const node = stack.pop() as string
    for (const edge of edges) {
      if (edge.from === node && !seen.has(edge.to)) {
        seen.add(edge.to)
        stack.push(edge.to)
      }
    }
  }
  return [...seen].sort()
}

type CheckOutcome = {
  result: CheckResult
  reason: string
  basis: string
}

/** A declared check with no input record. Routed through the policy so the one
 *  control that passes an unestablished check differs on exactly that. */
function missing(policy: PolicyProfile, reason: string, basis: string): CheckOutcome {
  return policy.missing_record_result === 'established_valid'
    ? { result: 'established_valid', reason: `${reason}_treated_as_passed`, basis }
    : { result: 'not_established', reason, basis }
}

// ── the checks ────────────────────────────────────────────────────────────
//
// Each check reads only its own declared inputs. No check reads another
// check's outcome. Blocks a check contributes to the record are returned
// alongside it, never written by another check.

export interface CheckContext {
  boundary: Boundary
  policy: PolicyProfile
  blocks: {
    compromise_reach: CompromiseReachBlock | null
    suspect_window: SuspectWindowBlock | null
    clock: ClockBlock | null
    revocation_effectiveness: RevocationEffectivenessBlock | null
  }
}

function checkSignatureAndKeyVersion(ctx: CheckContext): CheckOutcome {
  // This family is not about signature correctness. Every vector presents an
  // artifact whose signature verifies under the key version authorized at its
  // own issued_at, so this check is the family's constant positive input and
  // exists to be the thing other checks are NOT allowed to be satisfied by.
  return {
    result: 'established_valid',
    reason: 'signature_verifies_under_key_version_at_issued_at',
    basis: 'chain.json',
  }
}

function checkKeyScopeContainment(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  if (policy.signature_satisfies_other_checks) {
    return {
      result: 'established_valid',
      reason: 'signature_verified_so_key_scope_assumed',
      basis: 'chain.json',
    }
  }
  const scope = firstEvent(boundary, 'key_scope')
  if (!scope) {
    return missing(policy, 'key_scope_not_declared', 'no key_scope record')
  }
  if (scope.attestor_standing !== 'declared') {
    return missing(
      policy,
      'key_scope_attestor_standing_not_established',
      `key_scope ${scope.event_id} attestor ${scope.attestor}`,
    )
  }
  const populations = (scope.populations as string[]) ?? []
  const claimed = boundary.credential.claimed_audience
  if (populations.includes(claimed)) {
    return {
      result: 'established_valid',
      reason: 'key_scope_covers_claimed_audience',
      basis: scope.event_id,
    }
  }
  return {
    result: 'established_invalid',
    reason: 'key_scope_does_not_cover_claimed_audience',
    basis: scope.event_id,
  }
}

function checkEnforcedScopeContainment(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  if (policy.signature_satisfies_other_checks) {
    return {
      result: 'established_valid',
      reason: 'signature_verified_so_declared_scope_assumed_enforced',
      basis: 'chain.json',
    }
  }
  const attested = firstEvent(boundary, 'reachable_scope_attestation')
  if (!attested) {
    return missing(
      policy,
      'enforced_scope_not_attested',
      'no reachable_scope_attestation record',
    )
  }
  if (attested.attestor_standing !== 'declared') {
    return missing(
      policy,
      'reachable_scope_attestor_standing_not_established',
      `reachable_scope_attestation ${attested.event_id} attestor ${attested.attestor}`,
    )
  }
  const declared = new Set(boundary.credential.declared_scope)
  const reachable = ((attested.grants as string[]) ?? []).slice().sort()
  const outside = reachable.filter(g => !declared.has(g))
  if (outside.length > 0) {
    return {
      result: 'established_invalid',
      reason: 'enforced_scope_exceeds_declared_scope',
      basis: `${attested.event_id} reaches ${outside.join(',')}`,
    }
  }
  return {
    result: 'established_valid',
    reason: 'enforced_scope_contained_in_declared_scope',
    basis: attested.event_id,
  }
}

function checkArtifactProvenance(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  if (policy.signature_satisfies_other_checks) {
    return {
      result: 'established_valid',
      reason: 'signature_verified_so_provenance_assumed',
      basis: 'chain.json',
    }
  }
  const prov = firstEvent(boundary, 'provenance_attestation')
  if (!prov) {
    return missing(policy, 'artifact_provenance_not_attested', 'no provenance_attestation record')
  }
  if (prov.independent_of_signing_key !== true) {
    return missing(
      policy,
      'provenance_attestor_not_independent_of_signing_key',
      `provenance_attestation ${prov.event_id} attestor ${prov.attestor}`,
    )
  }
  if (prov.attestor_standing !== 'declared') {
    return missing(
      policy,
      'provenance_attestor_standing_not_established',
      `provenance_attestation ${prov.event_id} attestor ${prov.attestor}`,
    )
  }
  return {
    result: 'established_valid',
    reason: 'provenance_attested_by_independent_attestor',
    basis: prov.event_id,
  }
}

function checkAuthorizerAdditionProvenance(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const authorizers = boundary.trust_policy.authorizers
  if (policy.presence_implies_authorized_addition) {
    return {
      result: 'established_valid',
      reason: 'present_on_authorizer_list',
      basis: `authorizers ${authorizers.join(',')}`,
    }
  }
  const additions = eventsOfType(boundary, 'authorizer_addition')
  const byAuthorizer = new Map<string, EventRecord>()
  for (const add of additions) byAuthorizer.set(add.authorizer_id as string, add)

  const unrecorded = authorizers.filter(a => !byAuthorizer.has(a))
  if (unrecorded.length > 0) {
    return missing(
      policy,
      'authorizer_addition_not_attested',
      `no authorizer_addition record for ${unrecorded.sort().join(',')}`,
    )
  }
  const withoutStanding = authorizers
    .filter(a => (byAuthorizer.get(a) as EventRecord).attestor_standing !== 'declared')
    .sort()
  if (withoutStanding.length > 0) {
    return missing(
      policy,
      'authorizer_addition_attestor_standing_not_established',
      `authorizer_addition for ${withoutStanding.join(',')}`,
    )
  }
  return {
    result: 'established_valid',
    reason: 'every_authorizer_has_an_attested_addition',
    basis: authorizers
      .map(a => (byAuthorizer.get(a) as EventRecord).event_id)
      .sort()
      .join(','),
  }
}

function checkCompromiseReach(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const disclosure = firstEvent(boundary, 'compromise_disclosure')
  if (!disclosure) {
    return {
      result: 'established_valid',
      reason: 'no_compromise_disclosure_at_this_boundary',
      basis: 'events',
    }
  }

  const selfInitiated = disclosure.self_initiated === true
  const accepted = selfInitiated || policy.ingest_third_party_triggers

  if (!accepted) {
    // The control that only reacts to triggers it raised itself writes no
    // reach block at all: it has nothing to say about a disclosure it ignored.
    return {
      result: 'established_valid',
      reason: 'no_self_initiated_revocation_recorded',
      basis: 'events',
    }
  }

  if (disclosure.attestor_standing !== 'declared') {
    // An unattributed compromise claim is not a trigger and is not a finding of
    // safety either. It is recorded, and the check it cannot settle says so.
    ctx.blocks.compromise_reach = {
      trigger_event_id: disclosure.event_id as string,
      trigger_accepted: false,
      reach_basis: policy.reach_basis,
      reached: [],
      credential_in_reach: false,
      reattested: false,
    }
    return {
      result: 'established_valid',
      reason: 'compromise_claim_attestor_standing_not_established_no_trigger',
      basis: disclosure.event_id as string,
    }
  }

  const subject = disclosure.subject as string
  const reached =
    policy.reach_basis === 'authority_graph'
      ? reachableFrom(boundary.trust_policy.authority_graph, subject)
      : boundary.trust_policy.enumerated_reach_list.slice().sort()
  const inReach = reached.includes(boundary.credential.subject)

  const reattestation = eventsOfType(boundary, 'reattestation').find(
    e => e.covers === 'credential' && e.attestor_standing === 'declared',
  )
  const reattested = Boolean(
    reattestation &&
      parseInstant(reattestation.at as string) >= parseInstant(disclosure.disclosed_at as string),
  )

  ctx.blocks.compromise_reach = {
    trigger_event_id: disclosure.event_id as string,
    trigger_accepted: true,
    reach_basis: policy.reach_basis,
    reached,
    credential_in_reach: inReach,
    reattested,
  }

  if (!inReach) {
    return {
      result: 'established_valid',
      reason: 'credential_not_reachable_from_compromised_subject',
      basis: disclosure.event_id as string,
    }
  }
  if (reattested) {
    return {
      result: 'established_valid',
      reason: 'reattested_after_disclosure',
      basis: (reattestation as EventRecord).event_id as string,
    }
  }
  return missing(
    policy,
    'in_reach_of_compromise_and_not_reattested',
    disclosure.event_id as string,
  )
}

function checkIssuanceLogIntegrity(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const finding = firstEvent(boundary, 'issuance_log_integrity_finding')
  if (!finding) {
    return {
      result: 'established_valid',
      reason: 'no_issuance_log_integrity_finding_at_this_boundary',
      basis: 'events',
    }
  }
  const window = finding.window as { start: string; end: string }
  const issued = parseInstant(boundary.credential.issued_at)
  const inside =
    issued >= parseInstant(window.start) && issued < parseInstant(window.end)
  if (!inside) {
    return {
      result: 'established_valid',
      reason: 'issued_outside_the_window_the_finding_covers',
      basis: finding.event_id,
    }
  }
  if (policy.log_integrity_settled_by_per_artifact_revocation) {
    const revoked = eventsOfType(boundary, 'revocation').some(
      r => r.credential_ref !== boundary.credential.subject,
    )
    return {
      result: 'established_valid',
      reason: revoked
        ? 'bad_artifacts_individually_revoked_so_this_one_assumed_good'
        : 'no_revocation_record_names_this_credential',
      basis: 'events',
    }
  }
  const reestablished = eventsOfType(boundary, 'reattestation').find(
    e => e.covers === 'issuance_window' && e.attestor_standing === 'declared',
  )
  if (reestablished) {
    return {
      result: 'established_valid',
      reason: 'reestablished_from_a_reverified_root',
      basis: reestablished.event_id,
    }
  }
  return missing(
    policy,
    'issuance_log_integrity_not_established_for_window',
    finding.event_id,
  )
}

function checkIssuerPopulationTrust(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const finding = firstEvent(boundary, 'issuer_misbehaviour_finding')
  if (!finding) {
    return {
      result: 'established_valid',
      reason: 'no_issuer_misbehaviour_finding_at_this_boundary',
      basis: 'events',
    }
  }
  if (policy.issuer_population_per_chain) {
    const revokedHere = eventsOfType(boundary, 'revocation').some(
      r => r.credential_ref === boundary.credential.subject,
    )
    return {
      result: revokedHere ? 'established_invalid' : 'established_valid',
      reason: revokedHere
        ? 'this_chain_was_among_the_ones_caught'
        : 'this_chain_was_not_among_the_ones_caught',
      basis: 'events',
    }
  }
  if (
    finding.attestor_standing !== 'declared' ||
    finding.discovered_by !== 'external_monitor'
  ) {
    return missing(
      policy,
      'issuer_misbehaviour_finding_basis_not_established',
      finding.event_id,
    )
  }
  const reattested = eventsOfType(boundary, 'reattestation').find(
    e => e.covers === 'issuer_population' && e.attestor_standing === 'declared',
  )
  if (reattested) {
    return {
      result: 'established_valid',
      reason: 'issuer_population_reattested',
      basis: reattested.event_id,
    }
  }
  return missing(policy, 'issuer_population_trust_not_established', finding.event_id)
}

function checkSuspectWindowPartition(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const planned = firstEvent(boundary, 'planned_rotation')
  const exposure = firstEvent(boundary, 'exposure_window_finding')
  const compromise = firstEvent(boundary, 'key_compromise_finding')

  if (planned && !exposure && !compromise) {
    if (policy.planned_rotation_opens_window) {
      ctx.blocks.suspect_window = {
        finding_event_id: planned.event_id,
        start: planned.cryptoperiod_end as string,
        start_basis: 'discovery',
        partition_timestamp_source: 'none',
        artifact_position: 'not_established',
      }
      return missing(
        policy,
        'rotation_opens_a_suspect_window',
        planned.event_id,
      )
    }
    ctx.blocks.suspect_window = {
      finding_event_id: planned.event_id,
      start: null,
      start_basis: 'none',
      partition_timestamp_source: 'none',
      artifact_position: 'before_window',
    }
    return {
      result: 'established_valid',
      reason: 'planned_rotation_at_declared_cryptoperiod_end_opens_no_suspect_window',
      basis: planned.event_id,
    }
  }

  if (exposure) {
    const start =
      policy.window_start === 'exposure'
        ? (exposure.exposure_start as string)
        : (exposure.discovered_at as string)
    const issued = parseInstant(boundary.credential.issued_at)
    const inside = issued >= parseInstant(start)
    ctx.blocks.suspect_window = {
      finding_event_id: exposure.event_id,
      start,
      start_basis: policy.window_start === 'exposure' ? 'exposure' : 'discovery',
      partition_timestamp_source: 'issuer_claim',
      artifact_position: inside ? 'inside_window' : 'before_window',
    }
    if (!inside) {
      return {
        result: 'established_valid',
        reason: 'artifact_dated_before_the_suspect_window',
        basis: exposure.event_id,
      }
    }
    return missing(policy, 'artifact_issued_inside_the_exposure_window', exposure.event_id)
  }

  if (compromise) {
    const point = compromise.compromise_point as string
    const independent = eventsOfType(boundary, 'independent_timestamp_attestation').find(
      e => e.attestor_standing === 'declared',
    )
    const source: SuspectWindowBlock['partition_timestamp_source'] =
      policy.partition_timestamp === 'independent'
        ? independent
          ? 'independent_attestation'
          : 'none'
        : 'issuer_claim'
    const dated =
      policy.partition_timestamp === 'independent'
        ? independent
          ? (independent.artifact_dated_at as string)
          : null
        : boundary.credential.issued_at

    if (dated === null) {
      ctx.blocks.suspect_window = {
        finding_event_id: compromise.event_id,
        start: point,
        start_basis: 'compromise_point',
        partition_timestamp_source: 'none',
        artifact_position: 'not_established',
      }
      return missing(
        policy,
        'partition_timestamp_evidence_not_independent_of_the_compromised_key',
        compromise.event_id,
      )
    }
    const before = parseInstant(dated) < parseInstant(point)
    ctx.blocks.suspect_window = {
      finding_event_id: compromise.event_id,
      start: point,
      start_basis: 'compromise_point',
      partition_timestamp_source: source,
      artifact_position: before ? 'before_window' : 'inside_window',
    }
    if (before) {
      return {
        result: 'established_valid',
        reason: 'independently_dated_before_the_compromise_point',
        basis: (independent as EventRecord | undefined)?.event_id ?? 'credential.issued_at',
      }
    }
    return missing(policy, 'dated_inside_the_compromise_window', compromise.event_id)
  }

  return {
    result: 'established_valid',
    reason: 'no_key_finding_at_this_boundary',
    basis: 'events',
  }
}

function checkRevocationEffectiveness(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const revocation = eventsOfType(boundary, 'revocation').find(
    r => r.credential_ref === boundary.credential.subject,
  )
  if (!revocation) {
    return {
      result: 'established_valid',
      reason: 'no_revocation_record_names_this_credential',
      basis: 'events',
    }
  }
  if (policy.revocation_universal) {
    return {
      result: 'established_invalid',
      reason: 'revoked',
      basis: revocation.event_id,
    }
  }
  if (boundary.credential.status_lookup) {
    ctx.blocks.revocation_effectiveness = {
      revocation_event_id: revocation.event_id,
      status: 'valid',
      effective_from: revocation.recorded_at as string,
      basis: 'boundary_performs_a_status_lookup_for_this_credential_class',
    }
    return { result: 'established_invalid', reason: 'revoked', basis: revocation.event_id }
  }
  ctx.blocks.revocation_effectiveness = {
    revocation_event_id: revocation.event_id,
    status: 'not yet effective',
    effective_from: boundary.credential.not_after,
    basis: 'credential_class_verified_by_signature_alone_with_no_status_lookup',
  }
  return {
    result: 'established_valid',
    reason: 'revocation_recorded_and_not_yet_effective_for_this_credential_class',
    basis: revocation.event_id,
  }
}

function checkClockAgreement(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const tolerance = boundary.trust_policy.clock_tolerance_s
  const attestation = eventsOfType(boundary, 'time_attestation').find(
    e => e.attestor_standing === 'declared',
  )
  const gatewayNow = parseInstant(boundary.gateway_now)

  if (!attestation) {
    ctx.blocks.clock = {
      gateway_now: boundary.gateway_now,
      reference_now: null,
      skew_s: null,
      tolerance_s: tolerance,
      within_tolerance: false,
    }
    return missing(policy, 'no_attested_reference_clock', 'no time_attestation record')
  }
  const reference = parseInstant(attestation.reference_now as string)
  const skew = Math.abs(Math.floor((gatewayNow - reference) / 1000))
  const within = skew <= tolerance
  ctx.blocks.clock = {
    gateway_now: boundary.gateway_now,
    reference_now: attestation.reference_now as string,
    skew_s: skew,
    tolerance_s: tolerance,
    within_tolerance: within,
  }
  if (!within) {
    if (policy.skew_category === 'expiry') {
      return {
        result: 'established_invalid',
        reason: 'expired',
        basis: attestation.event_id,
      }
    }
    return {
      result: 'not_established',
      reason: 'clock_disagreement_beyond_tolerance',
      basis: attestation.event_id,
    }
  }
  const inWindow =
    gatewayNow >= parseInstant(boundary.credential.not_before) &&
    gatewayNow < parseInstant(boundary.credential.not_after)
  if (!inWindow) {
    return {
      result: 'established_invalid',
      reason: 'expired',
      basis: 'credential.not_after',
    }
  }
  return {
    result: 'established_valid',
    reason: 'clocks_agree_within_tolerance_and_artifact_is_inside_its_window',
    basis: attestation.event_id,
  }
}

function checkInheritedRootReattestation(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  const inherited = boundary.trust_policy.roots.filter(r => r.inherited_at !== undefined)
  if (inherited.length === 0) {
    return {
      result: 'established_valid',
      reason: 'no_inherited_root_in_the_trust_policy',
      basis: 'trust_policy.roots',
    }
  }
  if (!policy.inherited_root_needs_reattestation) {
    return {
      result: 'established_valid',
      reason: 'root_was_valid_under_the_acquired_entity_before_the_change',
      basis: inherited.map(r => r.root_id).sort().join(','),
    }
  }
  const reattested = eventsOfType(boundary, 'reattestation').find(
    e => e.covers === 'inherited_root' && e.attestor_standing === 'declared',
  )
  if (reattested) {
    return {
      result: 'established_valid',
      reason: 'inherited_root_reestablished_under_the_inheriting_party_root',
      basis: reattested.event_id,
    }
  }
  const overdue = inherited.filter(
    r =>
      r.reattestation_deadline !== undefined &&
      parseInstant(boundary.gateway_now) >= parseInstant(r.reattestation_deadline),
  )
  if (overdue.length === 0) {
    return {
      result: 'established_valid',
      reason: 'inside_the_declared_reattestation_deadline',
      basis: inherited
        .map(r => `${r.root_id}@${r.reattestation_deadline ?? 'no_deadline'}`)
        .sort()
        .join(','),
    }
  }
  return missing(
    policy,
    'inherited_root_not_reattested_by_the_declared_deadline',
    overdue.map(r => r.root_id).sort().join(','),
  )
}

function checkExercisedAuthorityAccounting(ctx: CheckContext): CheckOutcome {
  const { boundary, policy } = ctx
  if (policy.accounting_from_authority_status) {
    const revoked = eventsOfType(boundary, 'revocation').some(
      r => r.credential_ref === boundary.credential.subject,
    )
    if (revoked) {
      return {
        result: 'established_valid',
        reason: 'authority_revoked_so_accounting_assumed_closed',
        basis: 'events',
      }
    }
  }
  const coverage = eventsOfType(boundary, 'accounting_coverage_basis').find(
    e => e.attestor_standing === 'declared',
  )
  if (!coverage) {
    return missing(
      policy,
      'no_coverage_basis_for_what_was_done_under_this_credential',
      'no accounting_coverage_basis record',
    )
  }
  if (coverage.complete !== true) {
    return missing(
      policy,
      'coverage_basis_does_not_claim_completeness_over_the_valid_interval',
      coverage.event_id,
    )
  }
  return {
    result: 'established_valid',
    reason: 'coverage_basis_complete_over_the_valid_interval',
    basis: coverage.event_id,
  }
}

const CHECKS: Record<CheckId, (ctx: CheckContext) => CheckOutcome> = {
  signature_and_key_version: checkSignatureAndKeyVersion,
  key_scope_containment: checkKeyScopeContainment,
  enforced_scope_containment: checkEnforcedScopeContainment,
  artifact_provenance: checkArtifactProvenance,
  authorizer_addition_provenance: checkAuthorizerAdditionProvenance,
  compromise_reach: checkCompromiseReach,
  issuance_log_integrity: checkIssuanceLogIntegrity,
  issuer_population_trust: checkIssuerPopulationTrust,
  suspect_window_partition: checkSuspectWindowPartition,
  revocation_effectiveness: checkRevocationEffectiveness,
  clock_agreement: checkClockAgreement,
  inherited_root_reattestation: checkInheritedRootReattestation,
  exercised_authority_accounting: checkExercisedAuthorityAccounting,
}

// ── the join ──────────────────────────────────────────────────────────────

/**
 * Evaluate one boundary under one policy.
 *
 * Every declared check runs. The verdict is the join: one established_invalid
 * makes the boundary invalid, otherwise one not_established makes it not
 * established, otherwise valid. The reason names the first deciding check in
 * the policy's declared precedence order, so the record says which check
 * carried the verdict.
 */
export function evaluateBoundary(
  boundary: Boundary,
  credentialRef: string,
  policy: PolicyProfile,
  vectorId: string,
  caseId: string | null,
): CredentialEventRecord {
  const ctx: CheckContext = {
    boundary,
    policy,
    blocks: {
      compromise_reach: null,
      suspect_window: null,
      clock: null,
      revocation_effectiveness: null,
    },
  }

  const required = boundary.trust_policy.required_checks
  const seen = new Set<CheckId>()
  const outcomes: Array<{ id: CheckId; outcome: CheckOutcome }> = []
  for (const id of required) {
    if (seen.has(id)) throw new Error(`required_checks repeats ${id}`)
    seen.add(id)
    const fn = CHECKS[id]
    if (!fn) throw new Error(`unknown check id ${id}`)
    outcomes.push({ id, outcome: fn(ctx) })
  }

  const firstInvalid = outcomes.find(o => o.outcome.result === 'established_invalid')
  const firstUnestablished = outcomes.find(o => o.outcome.result === 'not_established')

  let verdict: Verdict
  let verdictReason: string
  if (firstInvalid) {
    verdict = 'invalid'
    verdictReason = `${firstInvalid.id}:${firstInvalid.outcome.reason}`
  } else if (firstUnestablished) {
    verdict = 'not established'
    verdictReason = `${firstUnestablished.id}:${firstUnestablished.outcome.reason}`
  } else {
    verdict = 'valid'
    verdictReason = 'every_declared_check_established'
  }

  const checks: RecordedCheck[] = outcomes
    .map(o => ({
      check_id: o.id,
      result: o.outcome.result,
      reason: o.outcome.reason,
      basis: o.outcome.basis,
    }))
    .sort((a, b) => (a.check_id < b.check_id ? -1 : a.check_id > b.check_id ? 1 : 0))

  return {
    record_type: 'aac.credential-event-record.v0',
    vector_id: vectorId,
    case_id: caseId,
    credential_ref: credentialRef,
    evaluated_at: boundary.gateway_now,
    verdict,
    verdict_reason: verdictReason,
    required_checks: required,
    checks,
    compromise_reach: ctx.blocks.compromise_reach,
    suspect_window: ctx.blocks.suspect_window,
    clock: ctx.blocks.clock,
    revocation_effectiveness: ctx.blocks.revocation_effectiveness,
    prior_record_sha256: boundary.prior_record_sha256,
  }
}

export function canonicalRecordBytes(record: CredentialEventRecord): string {
  return canonicalizeJCS(record)
}

export function recordDigest(record: CredentialEventRecord): string {
  return createHash('sha256').update(canonicalizeJCS(record), 'utf8').digest('hex')
}

/** Replay every boundary of a vector in order, threading each record's digest
 *  into the next boundary's prior_record_sha256 where the vector declares the
 *  sentinel `PRIOR`. An earlier record is never revisited. */
export function evaluateVector(
  boundaries: Boundary[],
  credentialRef: string,
  policy: PolicyProfile,
  vectorId: string,
  caseId: string | null,
): CredentialEventRecord[] {
  const out: CredentialEventRecord[] = []
  for (const boundary of boundaries) {
    const prior =
      boundary.prior_record_sha256 === 'PRIOR'
        ? recordDigest(out[out.length - 1])
        : boundary.prior_record_sha256
    out.push(
      evaluateBoundary(
        { ...boundary, prior_record_sha256: prior },
        credentialRef,
        policy,
        vectorId,
        caseId,
      ),
    )
  }
  return out
}
