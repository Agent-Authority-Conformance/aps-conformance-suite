// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference authorization boundary for the lifecycle-legal-regulatory-events family.
//
// WHAT THIS IS. The proposed text this family tests is aeoess/agent-authority-lifecycle at
// commit 7796e22. Its "External restriction" entry reads, in full:
//
//     "External restriction.  A block from outside the grant chain, such as a sanction, a
//     court order, or a legal hold that blocks a deletion.  It can stop some effects while
//     the grant itself stays valid."
//
// and its "Lifecycle standing" entry:
//
//     "Lifecycle standing.  Who may suspend, revoke, replace or reaffirm an authority
//     artifact.  This is not always the issuer.  An organization, a quorum, a successor, a
//     court or a security function can have standing to change authority it never issued."
//
// Neither that text nor draft-pidlisnyi-aps-03 defines a record for an external authority
// event, an effect vocabulary, a suspension, a restricted state, or a way to separate when
// an effect began from when a verifier could observe it. draft-03 section 3.5 names exactly
// one party who may revoke a delegation, its issuer, and both reference SDKs enforce that:
// issueAuthorityRevocation refuses a non-issuer revoker with REVOKER_NOT_ISSUER, recorded
// at mint time in chain.json. An external authority with standing to end authority
// therefore cannot express that as an AuthorityRevocationV1 at all.
//
// THE EXTERNAL-EVENT BOUNDARY IS THIS FIXTURE'S CODE, NOT AN SDK CONFORMANCE RESULT. It
// calls the real SDK for every part the SDK does supply:
//
//   verifyAuthorityDelegationChain     chain structure, time and revocation state
//   createAuthorityRevocationResolver  the store-backed revocation answer, including the
//                                      'unknown' a store that does not track a delegation
//                                      must give instead of 'active'
//   scopeGrantCovers                   whether a gate's declared scope covers the action's
//   verify over canonicalizeJCS        every external event, dependency binding and
//                                      certification signature
//
// Node builtins only, plus the pinned SDK. No wall clock: every `now` compared here is
// supplied by the caller from the fixture's pinned timeline, never read from the system.

import {
  canonicalizeJCS,
  createAuthorityRevocationResolver,
  scopeGrantCovers,
  verify,
  verifyAuthorityDelegationChain,
  InMemoryAuthorityRevocationStore,
  type AuthorityDelegationV1,
} from 'agent-passport-system'
import { createHash } from 'node:crypto'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The settled verdict vocabulary. Nothing else is ever returned. */
export type Verdict = 'valid' | 'invalid' | 'suspended' | 'restricted' | 'not established' | 'not yet effective'

export type Effect =
  | 'terminate_principal_authority'
  | 'replace_principal'
  | 'restrict_execution'
  | 'release_restriction'
  | 'add_approval_gate'
  | 'suspend_principal'
  | 'release_suspension'
  | 'revoke_dependency'
  | 'transfer_resource_ownership'
  | 'ratify_action'
  | 'establish_trust_root'

export interface ExternalAuthorityEvent {
  profile: string
  event_id: string
  issuer: string
  verification_method: string
  effect: Effect
  target: { kind: string; id: string }
  parameters: Record<string, unknown>
  effective_at: string
  recorded_at: string
  standing_basis: string
  signature: string
}

export interface DependencyBinding {
  profile: string
  delegation_id: string
  issuer: string
  verification_method: string
  issued_at: string
  depends_on: string[]
  signature: string
}

export interface GateCertification {
  profile: string
  gate_event_id: string
  action_ref: string
  certifier: string
  verification_method: string
  issued_at: string
  signature: string
}

export interface VerifierTrustPolicy {
  lifecycle_standing: Record<string, string[]>
  trust_roots: Record<string, string[]>
}

export interface Outcome {
  verdict: Verdict
  reason: string
  /** The SDK's chain verdict. */
  chain_state: string | null
  chain_failure_code: string | null
  /** Sorted event ids the boundary treated as observed, standing-established and in force. */
  effective_event_ids: string[]
  /** Sorted event ids observed and standing-established whose effect begins later. */
  pending_event_ids: string[]
  /** Sorted event ids observed whose authenticity or standing is not established. */
  unestablished_event_ids: string[]
  /** Sorted suspension cause ids still unreleased for a principal on the presented chain. */
  suspension_causes: string[]
  /** JCS digest of the receipt an assess_act request carried, null for a presentation.
   *  An output, never an input: a ratification must not change these bytes. */
  receipt_digest: string | null
  /** Free-text diagnostic. Printed, never compared: it carries content-addressed ids. */
  detail?: string
}

export interface PresentRequest {
  kind: 'present'
  label: string
  /** The external authority records THIS verifier's status source holds for this vector.
   *  Per request, not global: the proposed text's "Status observation" entry makes the
   *  source part of what a verifier could establish, and two verifiers reading two status
   *  sources are two different observations of the same world. */
  events: ExternalAuthorityEvent[]
  /** The presented root-to-leaf chain. */
  chain: AuthorityDelegationV1[]
  /** The dependency binding for the chain's root, when the chain declares one. */
  dependency_binding: DependencyBinding | null
  action_ref: string
  action_scope: string
  /** The off-graph counterparty or resource the action names, or null. */
  action_target_id: string | null
  /** Canonical unsigned decimal integer in minor units, or null where no amount applies. */
  amount_minor: string | null
  /** A certification produced for this action by a gate's named certifier. */
  certification: GateCertification | null
  /** Which named trust-root basis in the policy the verifier is running under. */
  trust_root_basis: string
  /** Which revocation evidence set the verifier can reach. */
  evidence_set: 'complete' | 'pruned'
  now: string
}

export interface AssessActRequest {
  kind: 'assess_act'
  label: string
  /** The external authority records this verifier's status source holds. See PresentRequest. */
  events: ExternalAuthorityEvent[]
  /** The chain the past act cited. */
  chain: AuthorityDelegationV1[]
  /** The receipt recording the act. Never modified: its digest is an output. */
  receipt: Record<string, unknown>
  action_ref: string
  trust_root_basis: string
  evidence_set: 'complete' | 'pruned'
  now: string
}

export type BoundaryEvent = PresentRequest | AssessActRequest

export interface AuthorityBoundaryOptions {
  name: string
  /** reference: true. defective-boundary-chain-validity-only: false. */
  enforcesExternalEvents: boolean
  /** reference: true. defective-boundary-trusts-event-without-standing: false. */
  checksLifecycleStanding: boolean
  /** reference: true. defective-boundary-collapses-restricted-into-revoked: false. */
  reportsNonTerminalStatesSeparately: boolean
  /** reference: true. defective-boundary-single-suspension-flag: false. */
  tracksSuspensionCausesIndependently: boolean
  trustPolicy: VerifierTrustPolicy
  verificationKeys: Record<string, string>
  signatureDomains: { external_authority_event: string; dependency_binding: string; gate_certification: string }
  /** Every delegation_id the complete evidence set covers. */
  trackedDelegationIds: string[]
  /** The delegation_ids a pruned evidence set no longer covers. */
  prunedDelegationIds: string[]
}

interface Observation {
  effective: ExternalAuthorityEvent[]
  pending: ExternalAuthorityEvent[]
  unestablished: ExternalAuthorityEvent[]
}

interface ChainState {
  state: string
  code: string | null
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

export class AuthorityBoundary {
  constructor(private readonly options: AuthorityBoundaryOptions) {}

  get name(): string {
    return this.options.name
  }

  handle(event: BoundaryEvent): Outcome {
    return event.kind === 'present' ? this.present(event) : this.assessAct(event)
  }

  // -------------------------------------------------------------------------
  // Status observation: which events this verifier can see, and which are in force
  // -------------------------------------------------------------------------

  /**
   * Split the event log at one observation time.
   *
   * recorded_at gates observation and effective_at gates force, because the proposed text
   * keeps them apart: "Status observation.  What authority state a verifier could
   * establish, from which source, at what time and with what freshness.  Current authority
   * and observed authority can differ." An event whose effect began before `now` but whose
   * record was made after it is invisible here, and that invisibility is the point of one
   * of this family's cases: a later record never rewrites a verdict already reached.
   */
  private observe(events: ExternalAuthorityEvent[], now: string): Observation {
    const effective: ExternalAuthorityEvent[] = []
    const pending: ExternalAuthorityEvent[] = []
    const unestablished: ExternalAuthorityEvent[] = []

    for (const event of events) {
      if (event.recorded_at > now) continue

      if (!this.eventIsAuthentic(event)) {
        unestablished.push(event)
        continue
      }
      if (this.options.checksLifecycleStanding && !this.hasLifecycleStanding(event)) {
        // A valid signature establishes who signed. It does not establish that the signer
        // may change this authority. Not established is not the same as false: the boundary
        // does not conclude the event is a forgery, only that it cannot act on it.
        unestablished.push(event)
        continue
      }
      if (event.effective_at > now) {
        pending.push(event)
        continue
      }
      effective.push(event)
    }

    return { effective, pending, unestablished }
  }

  private eventIsAuthentic(event: ExternalAuthorityEvent): boolean {
    const { event_id, signature, ...body } = event
    const preimage = `${this.options.signatureDomains.external_authority_event} ${canonicalizeJCS(body)}`
    const recomputed = 'sha256:' + createHash('sha256').update(preimage, 'utf8').digest('hex')
    if (recomputed !== event_id) return false
    const publicKey = this.options.verificationKeys[event.verification_method]
    if (publicKey === undefined) return false
    return verify(preimage, signature, publicKey)
  }

  private hasLifecycleStanding(event: ExternalAuthorityEvent): boolean {
    const permitted = this.options.trustPolicy.lifecycle_standing[event.effect]
    return Array.isArray(permitted) && permitted.includes(event.issuer)
  }

  /** Whether an effective release event names `eventId` as the event it releases. */
  private releasedBy(effective: ExternalAuthorityEvent[], eventId: string): boolean {
    return effective.some((e) => e.effect === 'release_restriction' && e.target.kind === 'event' && e.target.id === eventId)
  }

  /** Suspension causes still unreleased for any principal on the presented chain. */
  private suspensionCauses(observation: Observation, principals: string[]): string[] {
    const causes = new Set<string>()
    for (const event of observation.effective) {
      if (event.effect === 'suspend_principal' && event.target.kind === 'principal' && principals.includes(event.target.id)) {
        causes.add(String(event.parameters.cause_id))
      }
    }
    if (causes.size === 0) return []
    for (const event of observation.effective) {
      if (event.effect !== 'release_suspension') continue
      if (event.target.kind !== 'principal' || !principals.includes(event.target.id)) continue
      if (this.options.tracksSuspensionCausesIndependently) {
        causes.delete(String(event.parameters.cause_id))
      } else {
        // One boolean for "suspended", cleared by any release for this principal whatever
        // cause it names. The declared defect of defective-boundary-single-suspension-flag.
        causes.clear()
      }
    }
    return [...causes].sort()
  }

  // -------------------------------------------------------------------------
  // Chain state, from the SDK
  // -------------------------------------------------------------------------

  private chainState(
    chain: AuthorityDelegationV1[],
    now: string,
    trustRootBasis: string,
    evidenceSet: 'complete' | 'pruned',
    effective: ExternalAuthorityEvent[],
  ): ChainState {
    const store = new InMemoryAuthorityRevocationStore()
    for (const id of this.options.trackedDelegationIds) {
      if (evidenceSet === 'pruned' && this.options.prunedDelegationIds.includes(id)) continue
      store.track(id)
    }
    const resolveVerificationKey = (_issuer: string, method: string) => this.options.verificationKeys[method] ?? null
    const resolveRevocation = createAuthorityRevocationResolver(store, { resolveVerificationKey })

    // A root the base policy does not name becomes acceptable only through an observed,
    // effective establish_trust_root event from a party with standing. That is the proposed
    // text's "Verifier trust policy" entry made executable, and it is why the receiver's
    // root is not simply listed as trusted.
    const base = this.options.trustPolicy.trust_roots[trustRootBasis] ?? []
    const established = effective.filter((e) => e.effect === 'establish_trust_root').map((e) => e.target.id)
    const trusted = trustRootBasis === 'accepts_established_roots' ? [...base, ...established] : base

    const result = verifyAuthorityDelegationChain(chain, {
      now,
      resolveVerificationKey,
      trustRoot: (root) => trusted.includes(root.issuer),
      resolveRevocation,
    })
    return { state: result.state, code: result.failures[0]?.code ?? null }
  }

  // -------------------------------------------------------------------------
  // A proposed action at the next authorization boundary
  // -------------------------------------------------------------------------

  private present(request: PresentRequest): Outcome {
    const observation = this.observe(request.events, request.now)
    const chain = this.chainState(request.chain, request.now, request.trust_root_basis, request.evidence_set, observation.effective)
    const principals = request.chain.map((record) => record.issuer)
    const causes = this.options.enforcesExternalEvents ? this.suspensionCauses(observation, principals) : []

    const base = {
      chain_state: chain.state,
      chain_failure_code: chain.code,
      effective_event_ids: observation.effective.map((e) => e.event_id).sort(),
      pending_event_ids: observation.pending.map((e) => e.event_id).sort(),
      unestablished_event_ids: observation.unestablished.map((e) => e.event_id).sort(),
      suspension_causes: causes,
      receipt_digest: null,
    }
    const out = (verdict: Verdict, reason: string, detail?: string): Outcome =>
      detail === undefined ? { verdict, reason, ...base } : { verdict, reason, ...base, detail }

    // Step 1, every boundary: the chain's own state. An indeterminate answer is reported as
    // not established, never as valid: the proposed text's L7 and draft-03 section 3.3 both
    // make an unavailable or stale revocation result indeterminate, and the coverage of the
    // evidence set is what produces one here.
    if (chain.state === 'indeterminate') return out('not established', 'chain_state_not_established')
    if (chain.state === 'invalid') {
      // A time facet that has not opened yet is a different lifecycle fact from a chain that
      // failed a check, and the settled vocabulary has a word for it. Distinguishing them
      // here is what keeps "not yet effective" from collapsing into "invalid".
      if (chain.code === 'NOT_YET_VALID') return out('not yet effective', 'grant_not_yet_effective')
      return out('invalid', 'chain_not_valid')
    }
    if (chain.state !== 'valid') return out('not established', 'chain_state_not_established')

    // Everything from here is the external-event boundary, which no SDK supplies.
    // defective-boundary-chain-validity-only stops at the line above: it does everything
    // draft-03 section 3.3 chain verification does and nothing else, which is exactly the
    // deployment this family exists to catch.
    // The same reason string the reference boundary uses when nothing restricts, so that a
    // divergence between the two is always about an external event this boundary never read
    // and never about wording.
    if (!this.options.enforcesExternalEvents) return out('valid', 'no_effective_restriction')

    // Step 2: an authority relationship one of the presented chain's issuers stands on has
    // been ended or handed to somebody else by an external record. Terminal, and reported as
    // invalid: no release event names either effect and nothing inside the graph lifts it.
    const terminated = observation.effective.find(
      (e) => e.effect === 'terminate_principal_authority' && e.target.kind === 'principal' && principals.includes(e.target.id),
    )
    if (terminated !== undefined) return out('invalid', 'principal_authority_terminated_externally', terminated.event_id)

    const replaced = observation.effective.find(
      (e) => e.effect === 'replace_principal' && e.target.kind === 'principal' && principals.includes(e.target.id),
    )
    if (replaced !== undefined) return out('invalid', 'principal_replaced_externally', `successor=${String(replaced.parameters.successor)}`)

    // Step 3: an off-graph dependency the chain declares has been revoked. One event, every
    // chain that declared the dependency, and no per-chain record anywhere.
    if (request.dependency_binding !== null) {
      if (!this.dependencyBindingIsAuthentic(request.dependency_binding)) {
        return out('not established', 'dependency_binding_not_authentic')
      }
      const dependsOn = request.dependency_binding.depends_on
      const revokedDependency = observation.effective.find(
        (e) => e.effect === 'revoke_dependency' && e.target.kind === 'dependency' && dependsOn.includes(e.target.id),
      )
      if (revokedDependency !== undefined) return out('invalid', 'declared_dependency_revoked', revokedDependency.target.id)
    }

    // Step 4: the resource the action names has changed owner. Distinct from a block on the
    // same resource, and not reachable by a release event: a release lifts a restriction,
    // and an ownership change is not one. No grant from the former owner reaches it again.
    if (request.action_target_id !== null) {
      const transferred = observation.effective.find(
        (e) => e.effect === 'transfer_resource_ownership' && e.target.kind === 'resource' && e.target.id === request.action_target_id,
      )
      if (transferred !== undefined) return out('invalid', 'target_owner_changed', `new_owner=${String(transferred.parameters.new_owner)}`)
    }

    // Step 5: suspension. Each cause is released on its own. The proposed text's L8 keeps
    // suspension apart from revocation, and OPEN-QUESTIONS.md's "Release from suspension"
    // says lifting one suspension should not clear another and that this is not specified.
    if (causes.length > 0) return this.nonTerminal('suspended', 'suspended_by_cause', base, causes.join(','))

    // Step 6: an execution block on the counterparty or resource the action names. The grant
    // stays valid throughout, which is the whole content of the external-restriction
    // concept: a block from outside the chain that stops some effects.
    if (request.action_target_id !== null) {
      const blocking = observation.effective.filter(
        (e) =>
          e.effect === 'restrict_execution' &&
          (e.target.kind === 'counterparty' || e.target.kind === 'resource') &&
          e.target.id === request.action_target_id &&
          !this.releasedBy(observation.effective, e.event_id),
      )
      if (blocking.length > 0) {
        return this.nonTerminal('restricted', 'external_restriction_in_force', base, blocking.map((e) => e.event_id).sort().join(','))
      }
    }

    // Step 7: an approval gate a third party added to an otherwise unmodified chain. The
    // gate's scope match is the SDK's own scope primitive, not a string compare.
    for (const gate of observation.effective) {
      if (gate.effect !== 'add_approval_gate') continue
      if (gate.target.kind !== 'principal' || !principals.includes(gate.target.id)) continue
      if (this.releasedBy(observation.effective, gate.event_id)) continue
      const sunset = gate.parameters.sunset === null ? null : String(gate.parameters.sunset)
      if (sunset !== null && sunset <= request.now) continue
      const gateScope = String(gate.parameters.gate_scope)
      if (!scopeGrantCovers(gateScope, request.action_scope)) continue
      const threshold = gate.parameters.threshold_minor === null ? null : String(gate.parameters.threshold_minor)
      if (threshold !== null) {
        if (request.amount_minor === null) return this.nonTerminal('restricted', 'gate_amount_not_established', base, gate.event_id)
        if (BigInt(request.amount_minor) < BigInt(threshold)) continue
      }
      const certified = this.certificationSatisfies(request.certification, gate, request.action_ref)
      if (!certified.ok) {
        return this.nonTerminal('restricted', 'external_approval_gate_unsatisfied', base, `${gate.event_id}/${certified.reason}`)
      }
    }

    // Nothing this verifier could establish restricts the action. Where a claim was observed
    // and could not be established, the reason says so: the action is admissible on the
    // evidence, and the unestablished claim stays visible rather than being silently dropped.
    // Denying here instead would let any party with a keypair disable any agent by asserting
    // an authority it does not have. See README "Where the proposed text was too vague to
    // test" for why the direction is this fixture's choice and not the text's requirement.
    if (observation.unestablished.length > 0) return out('valid', 'external_claim_not_established')
    return out('valid', 'no_effective_restriction')
  }

  /**
   * A restricted or suspended state, or the same fact collapsed into invalid.
   *
   * defective-boundary-collapses-restricted-into-revoked returns invalid here. It reaches
   * the SAME admit-or-deny bit as the reference boundary on every vector in this family, and
   * differs only in the lifecycle state it writes into its own record. A checker that
   * compares whether the action was allowed passes it everywhere. That is why `verdict` is a
   * compared field and not a log line.
   */
  private nonTerminal(
    verdict: 'suspended' | 'restricted',
    reason: string,
    base: Omit<Outcome, 'verdict' | 'reason' | 'detail'>,
    detail: string,
  ): Outcome {
    const reported = this.options.reportsNonTerminalStatesSeparately ? verdict : 'invalid'
    return { verdict: reported, reason, ...base, detail }
  }

  private dependencyBindingIsAuthentic(binding: DependencyBinding): boolean {
    const { signature, ...body } = binding
    const publicKey = this.options.verificationKeys[binding.verification_method]
    if (publicKey === undefined) return false
    return verify(`${this.options.signatureDomains.dependency_binding} ${canonicalizeJCS(body)}`, signature, publicKey)
  }

  private certificationSatisfies(
    certification: GateCertification | null,
    gate: ExternalAuthorityEvent,
    actionRef: string,
  ): { ok: boolean; reason: string } {
    if (certification === null) return { ok: false, reason: 'no_certification' }
    if (certification.gate_event_id !== gate.event_id) return { ok: false, reason: 'certification_names_another_gate' }
    if (certification.action_ref !== actionRef) return { ok: false, reason: 'certification_names_another_action' }
    if (certification.certifier !== String(gate.parameters.certifier)) return { ok: false, reason: 'certifier_not_named_by_gate' }
    const { signature, ...body } = certification
    const publicKey = this.options.verificationKeys[certification.verification_method]
    if (publicKey === undefined) return { ok: false, reason: 'no_key_for_certifier' }
    if (!verify(`${this.options.signatureDomains.gate_certification} ${canonicalizeJCS(body)}`, signature, publicKey)) {
      return { ok: false, reason: 'certification_signature_invalid' }
    }
    return { ok: true, reason: 'certified' }
  }

  // -------------------------------------------------------------------------
  // A verdict about one named past act
  // -------------------------------------------------------------------------

  /**
   * Assess a past act, not a proposed one.
   *
   * A ratification is a new record that names an earlier act. It never edits the earlier
   * record, and this method never touches `request.receipt`: the receipt's own JCS digest is
   * an output, so a runner can assert across two vectors that the same bytes produced both
   * the pre-ratification and the post-ratification verdict.
   */
  private assessAct(request: AssessActRequest): Outcome {
    const observation = this.observe(request.events, request.now)
    const chain = this.chainState(request.chain, request.now, request.trust_root_basis, request.evidence_set, observation.effective)
    const digest = 'sha256:' + createHash('sha256').update(canonicalizeJCS(request.receipt), 'utf8').digest('hex')

    const base = {
      chain_state: chain.state,
      chain_failure_code: chain.code,
      effective_event_ids: observation.effective.map((e) => e.event_id).sort(),
      pending_event_ids: observation.pending.map((e) => e.event_id).sort(),
      unestablished_event_ids: observation.unestablished.map((e) => e.event_id).sort(),
      suspension_causes: [] as string[],
      receipt_digest: digest,
    }
    const out = (verdict: Verdict, reason: string, detail?: string): Outcome =>
      detail === undefined ? { verdict, reason, ...base } : { verdict, reason, ...base, detail }

    if (this.options.enforcesExternalEvents) {
      const ratification = observation.effective.find(
        (e) => e.effect === 'ratify_action' && e.target.kind === 'action' && e.target.id === request.action_ref,
      )
      if (ratification !== undefined) return out('valid', 'ratified_by_record', ratification.event_id)

      // A ratification claim this boundary cannot act on leaves the act unsettled rather
      // than settled either way, and says which of the two it is in the reason.
      const claimed = observation.unestablished.find(
        (e) => e.effect === 'ratify_action' && e.target.kind === 'action' && e.target.id === request.action_ref,
      )
      if (claimed !== undefined && chain.state !== 'valid') {
        return out('not established', 'ratification_standing_not_established', claimed.event_id)
      }
    }

    if (chain.state === 'valid') return out('valid', 'chain_valid_at_act')
    if (chain.state === 'indeterminate') return out('not established', 'chain_state_not_established')
    return out('invalid', 'chain_not_valid')
  }
}

// ---------------------------------------------------------------------------
// The five configurations
// ---------------------------------------------------------------------------

type Shared = Omit<
  AuthorityBoundaryOptions,
  'name' | 'enforcesExternalEvents' | 'checksLifecycleStanding' | 'reportsNonTerminalStatesSeparately' | 'tracksSuspensionCausesIndependently'
>

const REFERENCE = {
  enforcesExternalEvents: true,
  checksLifecycleStanding: true,
  reportsNonTerminalStatesSeparately: true,
  tracksSuspensionCausesIndependently: true,
}

export function makeReferenceBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, name: 'reference-boundary' })
}

/**
 * Negative control 1. Everything draft-03 section 3.3 chain verification does, and nothing
 * else. It reads no external event at all. This is what a fully draft-03-conformant
 * implementation looks like, and it wrongly admits every action an external event should
 * have stopped.
 */
export function makeChainValidityOnlyBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, enforcesExternalEvents: false, name: 'defective-boundary-chain-validity-only' })
}

/**
 * Negative control 2, THE ONE A NAIVE CHECKER PASSES WRONGLY. It tracks every external event
 * correctly and reports a restricted or suspended authority as invalid. Its admit-or-deny
 * bit is identical to the reference boundary's on every vector in this family. What it has
 * actually done is record a terminal lifecycle state for an authority that is paused or
 * narrowed and can come back with no new grant, which is the exact distinction the proposed
 * text's L8 and L10 draw.
 */
export function makeCollapsingBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, reportsNonTerminalStatesSeparately: false, name: 'defective-boundary-collapses-restricted-into-revoked' })
}

/**
 * Negative control 3. One boolean for suspension, cleared by any release event for the
 * principal regardless of which cause it names.
 */
export function makeSingleSuspensionFlagBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, tracksSuspensionCausesIndependently: false, name: 'defective-boundary-single-suspension-flag' })
}

/**
 * Negative control 4. Verifies every event's signature and never asks whether the signer had
 * standing to make that statement, so it turns a claim it cannot establish into a settled
 * authority state.
 */
export function makeNoStandingCheckBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, checksLifecycleStanding: false, name: 'defective-boundary-trusts-event-without-standing' })
}
