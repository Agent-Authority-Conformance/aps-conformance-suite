// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference authorization boundaries for the lifecycle-purpose-exhaustion family.
//
// This file holds both of the family's boundary models. AuthorityBoundary is the bounds
// track (purpose, use count, budget). ExhaustionBoundary, at the bottom of the file, is
// the single-use track (LC-I-013 reuse cascade, LC-I-014 notch atomicity). They hold
// different ledgers over different record sets and are never mixed in one run. See
// README, "Two tracks in one family".
//
// WHAT THIS IS. The proposed text this family tests is aeoess/agent-authority-lifecycle
// at commit bbb4709, section "Authority lifecycle state", entry "Expiry or exhaustion":
//
//     "Expiry or exhaustion. Ends authority because a declared time, use count,
//     budget, purpose or other bound has been reached. Expiry is not revocation."
//
// and invariant L10, "Expiry is not revocation". Neither that text nor
// draft-pidlisnyi-aps-03 defines a wire shape for a purpose bound or a use-count bound,
// or names who may attest that a purpose was fulfilled. draft-03's authority vector
// (section 3.2) is a closed set of seven facets with no purpose facet and no use-count
// facet, so the bound cannot live in a signed delegation at all. This family therefore
// declares its own purpose-bound artifact (see mint-bounds.ts) and implements the boundary here.
//
// THE BOUNDARY IS THIS FIXTURE'S CODE, NOT AN SDK CONFORMANCE RESULT, for purpose and
// use-count exhaustion. It calls the real SDK for every part the SDK does supply:
//
//   verifyAuthorityDelegationChain   the grant's structural, temporal and revocation state
//   isPurposePermitted               purpose membership, which is not exhaustion
//   verifyReceiptV1                  a completion record's signature, stage validity and
//                                    enforcement-boundary identity axis
//   InMemoryAuthorityBudgetLedger    budget exhaustion, the one dimension a reference SDK
//                                    does implement (draft-03 sections 3.4 and 4)
//   verify                           the principal's signature over the purpose bound
//
// THREE BASES FOR ONE LIFECYCLE STATE. The three exhaustion modes reach the same state
// from different evidence, and the family keeps them apart on purpose:
//
//   purpose     turns on an authenticated fulfillment record from a party with standing.
//               Admitting a purchase does not by itself exhaust the purpose.
//   use_count   turns on the boundary's own admission ledger. Admitting does exhaust it.
//   budget      turns on the accounting ledger. draft-03 section 3.4: "Signatures
//               establish static limits; they do not establish the current cumulative
//               total."
//
// Node builtins only, plus the pinned SDK. No wall clock: every `now` compared here is
// supplied by the caller from the fixture's pinned timeline, never read from the system.

import {
  canonicalizeJCS,
  isPurposePermitted,
  verify,
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
  InMemoryAuthorityBudgetLedger,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BoundMode = 'purpose' | 'use_count' | 'budget'

export type Bound =
  | { mode: 'purpose'; purpose: string }
  | { mode: 'use_count'; limit: number }
  | { mode: 'budget'; unit: string; cumulative: string }

export interface PurposeBound {
  profile: string
  delegation_id: string
  issuer: string
  verification_method: string
  issued_at: string
  purpose: string
  bound: Bound
  fulfillment_attestors: string[]
  signature: string
}

export interface CompletionRecord {
  receipt_id: string
  receipt_type: string
  issuer: string
  action_ref: string
  delegation_ref: string
  result: { profile: string; status: string; effect_ref: string | null; error_code: string | null }
  [key: string]: unknown
}

/** The lifecycle state of one grant's declared bound, as this boundary can establish it. */
export type BoundState = 'not_reached' | 'exhausted' | 'not_established'

export type EventOutcomeKind = 'admitted' | 'not_admitted' | 'completion_accepted' | 'completion_rejected'

/**
 * How a bound reached the state this boundary reports for it. Added when the two
 * purpose-exhaustion builds were reconciled into one family: the bounds track and the
 * single-use track each produce a vector whose outcome, reason and bound_state are
 * identical (PXE-03 and LC-I-014-b, both `not_admitted` / `purpose_exhausted` /
 * `exhausted` on a chain that verifies valid), and the evidence route behind them is not.
 * One turns on an observed fulfillment record, the other on the admission itself. Without
 * this field that difference lives only in prose, which is the shape of claim this suite
 * does not accept. It is compared by both runners.
 */
export const BASIS_FULFILLMENT_RECORD = 'an authenticated fulfillment record from a party with standing'
export const BASIS_ADMISSION = 'the admission itself'
export const BASIS_BUDGET_LEDGER = 'the SDK budget ledger'

export interface Outcome {
  outcome: EventOutcomeKind
  reason: string
  bound_state: BoundState
  /** Null when the bound has not reached a state, or reached one nobody could establish. */
  exhaustion_basis: string | null
  /** The SDK's chain verdict for a presentation, null for an observation. */
  chain_state: string | null
  detail?: string
}

export interface GrantContext {
  key: string
  grant: AuthorityDelegationV1
  bound: PurposeBound
}

export interface PresentRequest {
  kind: 'present'
  label: string
  grant: GrantContext
  requestedPurpose: string
  actionRef: string
  /** Present only for a budget-bounded grant. Canonical unsigned decimal integer. */
  amount?: string
  now: string
  resolveRevocation: (delegation: AuthorityDelegationV1) => RevocationResolution
}

export interface ObserveRequest {
  kind: 'observe'
  label: string
  grant: GrantContext
  completion: CompletionRecord
  now: string
}

export type BoundaryEvent = PresentRequest | ObserveRequest

type KeyResolver = (signer: string, keyId: string, issuedAt: string) => string | undefined
type VerificationKeyResolver = (issuer: string, verificationMethod: string, issuedAt: string) => string | null

export interface AuthorityBoundaryOptions {
  name: string
  /** reference: true. defective-boundary-chain-validity-only: false. */
  enforcesBoundExhaustion: boolean
  /** reference: true. defective-boundary-trusts-unauthenticated-completion: false. */
  authenticatesCompletionRecords: boolean
  purposeBoundSignatureDomain: string
  principalPublicKeys: Record<string, string>
  resolveReceiptSignerKey: KeyResolver
  resolveDelegationVerificationKey: VerificationKeyResolver
  trustRoot: (root: AuthorityDelegationV1) => boolean
}

export interface AuditEntry {
  label: string
  outcome: EventOutcomeKind
  reason: string
  bound_state: BoundState
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

/**
 * One instance holds one set of exhaustion ledgers across the whole event timeline, the
 * way one deployed boundary holds one view of what its grants have already spent. Events
 * are presented to one instance in the pinned order of vectors.json. Order is part of the
 * fixture, not an accident of iteration.
 */
export class AuthorityBoundary {
  /** grant key -> whether an authenticated fulfillment record has been accepted. */
  private readonly fulfilled = new Set<string>()
  /** grant key -> a fulfillment claim arrived that could not be established. */
  private readonly unestablished = new Set<string>()
  /** grant key -> admissions counted against a use_count bound. */
  private readonly uses = new Map<string, number>()
  private readonly ledger = new InMemoryAuthorityBudgetLedger()
  readonly audit: AuditEntry[] = []

  constructor(private readonly options: AuthorityBoundaryOptions) {}

  get name(): string {
    return this.options.name
  }

  handle(event: BoundaryEvent): Outcome {
    const outcome = event.kind === 'present' ? this.present(event) : this.observe(event)
    this.audit.push({ label: event.label, outcome: outcome.outcome, reason: outcome.reason, bound_state: outcome.bound_state })
    return outcome
  }

  /** The state this boundary can establish for a grant's bound, before the current event. */
  boundState(ctx: GrantContext): BoundState {
    // Order matters and is the family's wording rule made executable: an established
    // exhaustion is never downgraded by a later claim nobody could authenticate. A later
    // finding is a new record about an old one, never a rewrite of it.
    if (this.fulfilled.has(ctx.key)) return 'exhausted'
    if (this.unestablished.has(ctx.key)) return 'not_established'
    const bound = ctx.bound.bound
    if (bound.mode === 'use_count') {
      return (this.uses.get(ctx.key) ?? 0) >= bound.limit ? 'exhausted' : 'not_reached'
    }
    if (bound.mode === 'budget') {
      const counter = this.ledger.counter(ctx.grant.delegation_id)
      const used = BigInt(counter.committed) + BigInt(counter.reserved)
      return used >= BigInt(bound.cumulative) ? 'exhausted' : 'not_reached'
    }
    return 'not_reached'
  }

  /**
   * What the state this boundary reports for a grant's bound turns on. Null when the
   * bound is not reached, and null when a fulfillment claim arrived that nobody could
   * establish: an indeterminate state has no basis, which is the whole of what makes it
   * indeterminate rather than exhausted.
   */
  boundBasis(ctx: GrantContext): string | null {
    if (this.fulfilled.has(ctx.key)) return BASIS_FULFILLMENT_RECORD
    if (this.unestablished.has(ctx.key)) return null
    const bound = ctx.bound.bound
    if (bound.mode === 'use_count') {
      return (this.uses.get(ctx.key) ?? 0) >= bound.limit ? BASIS_ADMISSION : null
    }
    if (bound.mode === 'budget') {
      const counter = this.ledger.counter(ctx.grant.delegation_id)
      const used = BigInt(counter.committed) + BigInt(counter.reserved)
      return used >= BigInt(bound.cumulative) ? BASIS_BUDGET_LEDGER : null
    }
    return null
  }

  // -------------------------------------------------------------------------
  // Presentation of a proposed action under a grant
  // -------------------------------------------------------------------------

  private present(request: PresentRequest): Outcome {
    const { grant: ctx, now } = request
    const stateBefore = this.boundState(ctx)
    const basisBefore = this.boundBasis(ctx)

    // Step 0, every boundary: the grant's own chain state at this instant. Real SDK. This
    // covers revocation and time, and it is the step that makes the family's point: on
    // Wednesday the grant that has already bought its one compressor still verifies
    // `valid` here. Exhaustion is not visible to chain verification at all.
    const chainResult = verifyAuthorityDelegationChain([ctx.grant], {
      now,
      resolveVerificationKey: this.options.resolveDelegationVerificationKey,
      trustRoot: this.options.trustRoot,
      resolveRevocation: request.resolveRevocation,
    })
    if (chainResult.state !== 'valid') {
      const failure = chainResult.failures[0]
      return {
        outcome: 'not_admitted',
        reason: 'grant_chain_not_valid',
        bound_state: stateBefore, exhaustion_basis: basisBefore,
        chain_state: chainResult.state,
        detail: failure ? `${chainResult.state}/${failure.code}` : chainResult.state,
      }
    }

    // Step 1, every boundary: purpose membership, with the SDK's own check. This asks
    // whether the requested purpose falls inside the grant's allowed purposes. It answers
    // true for the second purchase exactly as it does for the first, which is why
    // membership can never decide exhaustion.
    if (!isPurposePermitted(request.requestedPurpose, ctx.grant.authority.scope.grants)) {
      return { outcome: 'not_admitted', reason: 'purpose_not_in_grant', bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state }
    }

    // Step 2, every boundary: the purpose bound is a principal-signed artifact, so its
    // signature is checked before anything is read from it. No vector in this family
    // presents a tampered bound. The step is here because a bound nobody authenticated
    // could not carry a lifecycle claim at all.
    const boundCheck = this.verifyPurposeBound(ctx)
    if (!boundCheck.ok) {
      return { outcome: 'not_admitted', reason: 'purpose_bound_not_authentic', bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state, detail: boundCheck.detail }
    }

    // Step 3, reference boundary only: the exhaustion gate.
    // defective-boundary-chain-validity-only skips everything from here to the end of the
    // gate. It still tracks the same state (see boundState above) and still reports it,
    // its declared flaw is that it never gates on the state it can already see, which is
    // the shape of a deployment that logs fulfillment and enforces nothing.
    if (this.options.enforcesBoundExhaustion) {
      if (stateBefore === 'not_established') {
        // Distinguished from `exhausted` deliberately. The boundary holds a fulfillment
        // claim it could not authenticate or could not attribute to a party with
        // standing. That establishes neither that the purpose was fulfilled nor that it
        // was not. This family denies on indeterminate and says why. See README
        // "Where the proposed text was too vague to test" for why denying is a choice
        // this fixture makes rather than one either text requires.
        return { outcome: 'not_admitted', reason: 'bound_state_not_established', bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state }
      }
      // Step 4, reference boundary only, budget grants: the SDK ledger decides, and it
      // decides before this boundary's own bookkeeping gets a vote. draft-03 section 3.4's
      // reserve-then-settle, run for real rather than modelled. The denial detail is the
      // SDK's own code, which is what makes PXE-07 an SDK result rather than an assertion
      // about our own counter. draft-03 section 3.4: "Signatures establish static limits;
      // they do not establish the current cumulative total."
      if (ctx.bound.bound.mode === 'budget') {
        const amount = request.amount
        if (amount === undefined) {
          return { outcome: 'not_admitted', reason: 'budget_amount_missing', bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state }
        }
        const reservation = this.ledger.reserve([ctx.grant], request.actionRef, ctx.bound.bound.unit, amount)
        if (!reservation.ok) {
          return {
            outcome: 'not_admitted',
            reason: 'budget_exhausted',
            bound_state: 'exhausted', exhaustion_basis: BASIS_BUDGET_LEDGER,
            chain_state: chainResult.state,
            detail: reservation.code,
          }
        }
        this.ledger.markDispatched(request.actionRef)
        const commit = this.ledger.commit(request.actionRef)
        if (!commit.ok) {
          return { outcome: 'not_admitted', reason: 'budget_settlement_failed', bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state, detail: commit.code }
        }
      } else if (stateBefore === 'exhausted') {
        // Step 5, reference boundary only: the purpose and use-count bounds, which no SDK
        // implements and which this fixture therefore decides itself.
        const reason = ctx.bound.bound.mode === 'use_count' ? 'use_count_exhausted' : 'purpose_exhausted'
        return { outcome: 'not_admitted', reason, bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state }
      }
    }

    // Admitted. A use_count bound is consumed by the admission itself. A purpose bound is
    // not: nothing is exhausted until a fulfillment record arrives and is established.
    if (this.options.enforcesBoundExhaustion && ctx.bound.bound.mode === 'use_count') {
      this.uses.set(ctx.key, (this.uses.get(ctx.key) ?? 0) + 1)
    }

    return { outcome: 'admitted', reason: 'dispatch_admitted', bound_state: stateBefore, exhaustion_basis: basisBefore, chain_state: chainResult.state }
  }

  // -------------------------------------------------------------------------
  // Observation of a completion record claiming the purpose was fulfilled
  // -------------------------------------------------------------------------

  private observe(request: ObserveRequest): Outcome {
    const { grant: ctx, completion } = request

    // Step 1, reference boundary only: standing. Who may say this purpose was fulfilled
    // is named in the grant's own purpose bound. A valid signature establishes who
    // signed. It does not establish that the signer was allowed to make this statement.
    // defective-boundary-trusts-unauthenticated-completion skips this step and step 2.
    if (this.options.authenticatesCompletionRecords) {
      if (!ctx.bound.fulfillment_attestors.includes(completion.issuer)) {
        this.markUnestablished(ctx)
        // Recorded, not asserted: the SDK's own enforcement-boundary identity axis for
        // the same record, checked against the attestor the bound names. draft-03
        // section 5.3.3 requires an action-result record's issuer to be the enforcement
        // boundary, so this axis is the SDK's view of the same question.
        const sdkView = verifyReceiptV1(completion as never, this.options.resolveReceiptSignerKey, {
          boundaryIdentity: ctx.bound.fulfillment_attestors[0],
        })
        const axis = (sdkView as unknown as { stage?: { boundary_identity?: string } }).stage?.boundary_identity ?? 'unknown'
        return {
          outcome: 'completion_rejected',
          reason: 'completion_attestor_without_standing',
          bound_state: this.boundState(ctx), exhaustion_basis: this.boundBasis(ctx),
          chain_state: null,
          detail: `sdk_boundary_identity=${axis}`,
        }
      }

      // Step 2, reference boundary only: authenticity, with the SDK. The expected
      // enforcement-boundary identity is the record's own issuer, which step 1 has just
      // established has standing, so a failure here is a signature or stage failure and
      // nothing else.
      const verification = verifyReceiptV1(completion as never, this.options.resolveReceiptSignerKey, {
        boundaryIdentity: completion.issuer,
      })
      if (verification.status !== 'valid') {
        this.markUnestablished(ctx)
        return {
          outcome: 'completion_rejected',
          reason: 'completion_signature_invalid',
          bound_state: this.boundState(ctx), exhaustion_basis: this.boundBasis(ctx),
          chain_state: null,
          detail: `${verification.status}/${JSON.stringify(verification.errors)}`,
        }
      }
    }

    // Step 3, every boundary: the record has to be about this grant, and it has to say
    // the action succeeded. No vector presents a failed or unknown result. The branch is
    // here because "a completion record exists" and "it reports success" are different
    // facts and the family will not collapse them.
    if (completion.delegation_ref !== ctx.grant.delegation_id) {
      return { outcome: 'completion_rejected', reason: 'completion_not_bound_to_grant', bound_state: this.boundState(ctx), exhaustion_basis: this.boundBasis(ctx), chain_state: null }
    }
    if (completion.result.status !== 'succeeded') {
      return { outcome: 'completion_rejected', reason: 'completion_status_not_succeeded', bound_state: this.boundState(ctx), exhaustion_basis: this.boundBasis(ctx), chain_state: null }
    }

    this.fulfilled.add(ctx.key)
    return { outcome: 'completion_accepted', reason: 'fulfillment_recorded', bound_state: this.boundState(ctx), exhaustion_basis: this.boundBasis(ctx), chain_state: null }
  }

  /** A claim nobody could establish moves a not-yet-reached bound to not_established and
   *  leaves an already-established exhaustion alone. */
  private markUnestablished(ctx: GrantContext): void {
    if (!this.fulfilled.has(ctx.key)) this.unestablished.add(ctx.key)
  }

  private verifyPurposeBound(ctx: GrantContext): { ok: boolean; detail?: string } {
    const { signature, ...body } = ctx.bound
    const publicKey = this.options.principalPublicKeys[ctx.bound.verification_method]
    if (publicKey === undefined) return { ok: false, detail: 'no_key_for_verification_method' }
    const payload = `${this.options.purposeBoundSignatureDomain} ${canonicalizeJCS(body)}`
    return verify(payload, signature, publicKey) ? { ok: true } : { ok: false, detail: 'signature_did_not_verify' }
  }
}

// ---------------------------------------------------------------------------
// The three configurations
// ---------------------------------------------------------------------------

type Shared = Omit<AuthorityBoundaryOptions, 'name' | 'enforcesBoundExhaustion' | 'authenticatesCompletionRecords'>

export function makeReferenceBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, name: 'reference-boundary', enforcesBoundExhaustion: true, authenticatesCompletionRecords: true })
}

/**
 * Negative control 1. Everything draft-03 chain verification does, and nothing else: it
 * verifies the chain, checks purpose membership with the SDK, and never gates on any
 * exhaustion state. This is what an implementation that is fully conformant to draft-03
 * section 3.3 looks like, and it is exactly the implementation this family exists to
 * catch. Declared failing set in vectors.json.
 */
export function makeChainValidityOnlyBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, name: 'defective-boundary-chain-validity-only', enforcesBoundExhaustion: false, authenticatesCompletionRecords: true })
}

/**
 * Negative control 2. Full exhaustion tracking, but it reads result.status out of any
 * completion record without establishing who signed it or whether that party had
 * standing. On the two vectors that isolate this, it reaches the same admitted-or-not
 * answer as the reference boundary and reports a different lifecycle state: it calls a
 * grant `exhausted` on evidence that establishes nothing. A checker that compares only
 * the admit bit passes it. Declared failing set in vectors.json.
 */
export function makeTrustingBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, name: 'defective-boundary-trusts-unauthenticated-completion', enforcesBoundExhaustion: true, authenticatesCompletionRecords: false })
}

// ===========================================================================
// The single-use track: LC-I-013 reuse cascade and LC-I-014 notch atomicity
// ===========================================================================
//
// A second boundary model over a second record set (records-single-use.json), held
// in the same file because it is the same family and the same lifecycle concept.
// It reaches exhaustion by a different route: the admission is the exhaustion, with
// no completion record observed at all. Its state vocabulary differs from the bounds
// track's on purpose, and the README names the difference as an unresolved question
// in the proposed text rather than picking one of the two readings.
//
// The proposed text it is written against is aeoess/agent-authority-lifecycle at
// commit bbb4709, AUTHORITY-LIFECYCLE.md and CASES.md.

/** The settled verdict vocabulary. `not established` is never reached by a
 *  bound this family models, and is kept in the type so a future vector
 *  cannot introduce it without saying so. */
export type AuthorityVerdict =
  | 'valid'
  | 'invalid'
  | 'not established'
  | 'not yet effective'
  | 'suspended'
  | 'restricted'

export type SingleUseBoundState = 'not_reached' | 'exhausted' | 'invalid'

export type SingleUsePolicyName = 'reference' | 'reuse-rejecting-only' | 'validity-window-only'

export interface SingleUseFixture {
  _placeholder?: boolean
  mint_now: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chains: Record<string, any[]>
  grant_bounds: Record<string, { bound: string; issued_from: string | null }>
  void_standing: Record<string, { has_standing: string[]; subject: string }>
}

export interface SingleUseResult {
  outcome: 'admitted' | 'not_admitted' | 'void_refused'
  reason: string
  /** How this event's bound state was reached. The LC-I-014 vectors read it. */
  exhaustion_basis: string | null
  chain_verdict: AuthorityVerdict | null
  chain_failure_code: string | null
  bound_state: SingleUseBoundState
  /** Records this event wrote. LC-I-014-a checks there is exactly one. */
  records_written: number
}

interface GrantState {
  bound: string
  uses: number
  bound_state: SingleUseBoundState
  /** Set when a reuse was detected on this grant. */
  reuse_detected: boolean
}

export class ExhaustionBoundary {
  private readonly fixture: SingleUseFixture
  private readonly policy: SingleUsePolicyName
  private readonly grants = new Map<string, GrantState>()
  private readonly roleById = new Map<string, string>()

  constructor(fixture: SingleUseFixture, policy: SingleUsePolicyName) {
    this.fixture = fixture
    this.policy = policy
    for (const [role, id] of Object.entries(fixture.roles)) this.roleById.set(id, role)
    for (const [role, spec] of Object.entries(fixture.grant_bounds)) {
      this.grants.set(role, { bound: spec.bound, uses: 0, bound_state: 'not_reached', reuse_detected: false })
    }
  }

  private chainVerdict(chainName: string, now: string): { verdict: AuthorityVerdict; code: string | null } {
    const result: any = verifyAuthorityDelegationChain(this.fixture.chains[chainName], {
      now,
      resolveVerificationKey: (_issuer: string, method: string) =>
        this.fixture.verification_keys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: () => 'active',
    })
    const first = Array.isArray(result.failures) ? result.failures[0] : undefined
    const verdict: AuthorityVerdict =
      result.state === 'valid' ? 'valid' : result.state === 'indeterminate' ? 'not established' : 'invalid'
    return { verdict, code: first?.code ?? null }
  }

  /** The grant a presented chain's leaf depends on for its bound: the leaf
   *  itself when the leaf carries a bound, otherwise the grant the leaf was
   *  issued out of. */
  private boundGrantFor(leafRole: string): { role: string; state: GrantState } | null {
    const spec = this.fixture.grant_bounds[leafRole]
    if (spec === undefined) return null
    if (spec.bound !== 'none') return { role: leafRole, state: this.grants.get(leafRole)! }
    if (spec.issued_from === null) return null
    return { role: spec.issued_from, state: this.grants.get(spec.issued_from)! }
  }

  present(chainName: string, now: string): SingleUseResult {
    const chain = this.fixture.chains[chainName]
    const leafRole = this.roleById.get(chain[chain.length - 1].delegation_id)!
    const { verdict, code } = this.chainVerdict(chainName, now)

    if (verdict !== 'valid') {
      return {
        outcome: 'not_admitted', reason: 'grant_chain_not_valid', exhaustion_basis: null,
        chain_verdict: verdict, chain_failure_code: code,
        bound_state: this.boundGrantFor(leafRole)?.state.bound_state ?? 'not_reached',
        records_written: 1,
      }
    }

    const bound = this.boundGrantFor(leafRole)
    if (bound === null) {
      return {
        outcome: 'admitted', reason: 'admitted_no_bound_declared', exhaustion_basis: null,
        chain_verdict: verdict, chain_failure_code: null, bound_state: 'not_reached', records_written: 1,
      }
    }
    const { role, state } = bound
    const isLeafItself = role === leafRole

    // The validity-window-only boundary has no exhaustion ledger at all: a
    // grant is issued, valid until a date, then expired. One axis, and the
    // only one, separating it from the reference boundary.
    if (this.policy === 'validity-window-only') {
      return {
        outcome: 'admitted', reason: 'within_validity_window', exhaustion_basis: null,
        chain_verdict: verdict, chain_failure_code: null, bound_state: 'not_reached', records_written: 1,
      }
    }

    // An artifact issued out of a grant whose reuse was detected.
    if (!isLeafItself && state.reuse_detected) {
      // The reuse-rejecting-only boundary rejects a second presentation of the
      // grant and stops there: it never reaches what was issued out of it.
      if (this.policy === 'reuse-rejecting-only') {
        return {
          outcome: 'admitted', reason: 'derived_artifact_chain_valid', exhaustion_basis: null,
          chain_verdict: verdict, chain_failure_code: null, bound_state: state.bound_state, records_written: 1,
        }
      }
      return {
        outcome: 'not_admitted', reason: 'ancestor_invalidated_by_reuse', exhaustion_basis: null,
        chain_verdict: verdict, chain_failure_code: null, bound_state: state.bound_state, records_written: 1,
      }
    }
    if (!isLeafItself) {
      return {
        outcome: 'admitted', reason: 'derived_artifact_chain_valid', exhaustion_basis: null,
        chain_verdict: verdict, chain_failure_code: null, bound_state: state.bound_state, records_written: 1,
      }
    }

    if (state.bound_state === 'invalid') {
      return {
        outcome: 'not_admitted', reason: 'single_use_reuse_detected', exhaustion_basis: null,
        chain_verdict: verdict, chain_failure_code: null, bound_state: 'invalid', records_written: 1,
      }
    }

    if (state.bound_state === 'exhausted') {
      if (state.bound === 'single_use') {
        // The second presentation is not an ordinary retry. It is a signal
        // about the artifact, and it reaches what was issued out of it.
        state.reuse_detected = true
        state.bound_state = 'invalid'
        return {
          outcome: 'not_admitted', reason: 'single_use_reuse_detected', exhaustion_basis: null,
          chain_verdict: verdict, chain_failure_code: null, bound_state: 'invalid', records_written: 1,
        }
      }
      return {
        outcome: 'not_admitted', reason: 'purpose_exhausted', exhaustion_basis: 'the admission itself',
        chain_verdict: verdict, chain_failure_code: null, bound_state: 'exhausted', records_written: 1,
      }
    }

    // First use. For both bounds the admission is what consumes the grant, and
    // it is the same recorded event: no separate observation is read, and no
    // second record is written.
    state.uses += 1
    state.bound_state = 'exhausted'
    return {
      outcome: 'admitted', reason: 'admitted_and_exhausted', exhaustion_basis: 'the admission itself',
      chain_verdict: verdict, chain_failure_code: null, bound_state: 'exhausted', records_written: 1,
    }
  }

  /** A record asking to undo an exhaustion. It is never accepted. The two
   *  refusal reasons are kept apart so that "nobody may do this" is not
   *  reported as "you in particular may not". */
  voidExhaustion(grantRole: string, signedBy: string): SingleUseResult {
    const state = this.grants.get(grantRole)!
    const standing = this.fixture.void_standing[grantRole]
    const hasStanding = standing !== undefined && standing.has_standing.includes(signedBy)
    if (!hasStanding) {
      return {
        outcome: 'void_refused', reason: 'void_attestor_without_standing', exhaustion_basis: null,
        chain_verdict: null, chain_failure_code: null, bound_state: state.bound_state, records_written: 1,
      }
    }
    return {
      outcome: 'void_refused', reason: 'exhaustion_is_not_reversible', exhaustion_basis: null,
      chain_verdict: null, chain_failure_code: null, bound_state: state.bound_state, records_written: 1,
    }
  }
}
