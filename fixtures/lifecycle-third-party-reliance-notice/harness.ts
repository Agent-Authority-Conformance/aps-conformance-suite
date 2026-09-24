// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference authorization boundary for the lifecycle-third-party-reliance-notice family.
//
// WHAT THIS IS. The proposed text this family tests is aeoess/agent-authority-lifecycle at
// commit 7796e22. Its "Notice" entry reads, in full:
//
//     "Notice.  That a particular party or enforcement point learned of a transition at a
//     particular time.  Recording a transition and observing it are different events."
//
// and its "Status observation" entry:
//
//     "Status observation.  What authority state a verifier could establish, from which
//     source, at what time and with what freshness.  Current authority and observed
//     authority can differ."
//
// Neither that text nor draft-pidlisnyi-aps-03 defines a notice record, says who may give
// notice, says how a notice record names its recipient, distinguishes a broadcast from an
// individually addressed record, or gives a verifier any way to tell a first-time
// counterparty from one with a dealing history. This family declares its own shapes for all
// of that (see mint.ts) and says so in README.md.
//
// WHAT THIS BOUNDARY NEVER DOES. It never answers whether an outside party's reliance is
// protected, and it never states that a legal doctrine applies to an AI agent. Those are
// legal effects decided off the wire, and no verifier computes them from records. This
// boundary answers two record questions and keeps them apart:
//
//   authority_verdict  what the presented chain verifies to, from the SDK
//   notice_state       whether this verifier can establish that notice of the termination
//                      reached one named counterparty by one named time
//
// THE NOTICE BOUNDARY IS THIS FIXTURE'S CODE, NOT AN SDK CONFORMANCE RESULT. The SDK
// supplies chain state (verifyAuthorityDelegationChain), revocation resolution
// (createAuthorityRevocationResolver over InMemoryAuthorityRevocationStore) and every
// signature check (verify over canonicalizeJCS). Nothing about notice comes from either SDK.
//
// Node builtins only, plus the pinned SDK. No wall clock.

import {
  canonicalizeJCS,
  createAuthorityRevocationResolver,
  recordAuthorityRevocation,
  verify,
  verifyAuthorityDelegationChain,
  InMemoryAuthorityRevocationStore,
  type AuthorityDelegationV1,
} from 'agent-passport-system'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The settled verdict vocabulary. Nothing else is ever returned for authority. */
export type Verdict = 'valid' | 'invalid' | 'suspended' | 'restricted' | 'not established' | 'not yet effective'

/** Notice is established or it is not. There is no third answer and no boolean alias. */
export type NoticeState = 'established' | 'not established'

export interface NoticeRecord {
  profile: string
  issuer: string
  verification_method: string
  mode: 'individual' | 'publication'
  /** null on a publication record: it names no recipient at all. */
  counterparty: string | null
  revocation_id: string
  issued_at: string
  signature: string
}

export interface PriorDealingRegister {
  profile: string
  issuer: string
  verification_method: string
  delegation_id: string
  counterparties: string[]
  as_of: string
  signature: string
}

export interface AuthorityRevocationRecord {
  revocation_id: string
  delegation_id: string
  revoker: string
  [key: string]: unknown
}

export interface Outcome {
  authority_verdict: Verdict
  authority_reason: string
  chain_state: string
  chain_failure_code: string | null
  notice_state: NoticeState
  notice_basis: 'individual' | 'publication' | null
  notice_reason: string
  counterparty: string
  /** How many grants the agent held at this moment, reported so that the vectors can show
   *  the reference boundary was given the chance to treat a later grant as a revocation. */
  held_grant_count: number
}

export interface PresentRequest {
  label: string
  /** The presented root-to-leaf chain. */
  chain: AuthorityDelegationV1[]
  /** Every grant the agent held at this moment, this one included. */
  held_chains: AuthorityDelegationV1[][]
  /** The revocation records this verifier's status source holds. */
  revocations: AuthorityRevocationRecord[]
  /** The notice records this verifier's status source holds. */
  notices: NoticeRecord[]
  /** The signed register of counterparties with a prior dealing under the presented grant. */
  prior_dealing_register: PriorDealingRegister
  /** The one outside party this evaluation is about. */
  counterparty: string
  now: string
}

export interface AuthorityBoundaryOptions {
  name: string
  /** reference: true. defective-boundary-single-notice-boolean: false. */
  answersNoticeSeparately: boolean
  /** reference: true. defective-boundary-publication-covers-everyone: false. */
  requiresIndividualNoticeForPriorDealing: boolean
  /** reference: true. defective-boundary-notice-without-standing: false. */
  checksNoticeStanding: boolean
  /** reference: false. defective-boundary-newest-wins: true. */
  treatsNewerGrantAsRevocation: boolean
  verificationKeys: Record<string, string>
  signatureDomains: { notice_record: string; prior_dealing_register: string }
  /** Every delegation_id the verifier's revocation evidence set covers. */
  trackedDelegationIds: string[]
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

export class AuthorityBoundary {
  constructor(private readonly options: AuthorityBoundaryOptions) {}

  get name(): string {
    return this.options.name
  }

  private get resolveVerificationKey() {
    return (_issuer: string, method: string) => this.options.verificationKeys[method] ?? null
  }

  handle(request: PresentRequest): Outcome {
    const chain = this.chainState(request)
    const authority = this.authorityVerdict(chain, request)
    const notice = this.noticeState(request, chain)

    return {
      authority_verdict: authority.verdict,
      authority_reason: authority.reason,
      chain_state: chain.state,
      chain_failure_code: chain.code,
      notice_state: notice.state,
      notice_basis: notice.basis,
      notice_reason: notice.reason,
      counterparty: request.counterparty,
      held_grant_count: request.held_chains.length,
    }
  }

  // -------------------------------------------------------------------------
  // Chain state, from the SDK
  // -------------------------------------------------------------------------

  private chainState(request: PresentRequest): { state: string; code: string | null } {
    const store = new InMemoryAuthorityRevocationStore()
    for (const id of this.options.trackedDelegationIds) store.track(id)

    const heldRecords = request.held_chains.flat()
    for (const revocation of request.revocations) {
      const target = heldRecords.find((record) => record.delegation_id === revocation.delegation_id)
      if (target === undefined) continue
      const result = recordAuthorityRevocation(store, target, revocation, { resolveVerificationKey: this.resolveVerificationKey })
      if (!result.recorded) {
        // The supported entry point verified the record against its target and refused. The
        // store's raw persistence primitive is used anyway so that the resolver, which
        // re-verifies on the way out, is the thing that decides. Its answer for such a
        // record is 'unknown', which chain verification reports as indeterminate, and that
        // is the behaviour one vector here exists to pin down.
        store.insertVerifiedRevocation(revocation as never)
      }
    }

    const result = verifyAuthorityDelegationChain(request.chain, {
      now: request.now,
      resolveVerificationKey: this.resolveVerificationKey,
      trustRoot: (root) => root.issuer === request.chain[0].issuer,
      resolveRevocation: createAuthorityRevocationResolver(store, { resolveVerificationKey: this.resolveVerificationKey }),
    })
    return { state: result.state, code: result.failures[0]?.code ?? null }
  }

  private authorityVerdict(chain: { state: string; code: string | null }, request: PresentRequest): { verdict: Verdict; reason: string } {
    if (chain.state === 'valid' && this.options.treatsNewerGrantAsRevocation) {
      // The declared defect of defective-boundary-newest-wins: a later grant from the same
      // issuer to the same subject is read as having superseded this one, with no revocation
      // record anywhere saying so.
      const presented = request.chain[0]
      const superseding = request.held_chains
        .map((held) => held[0])
        .find((root) => root.delegation_id !== presented.delegation_id && root.issuer === presented.issuer && root.subject === presented.subject && root.issued_at > presented.issued_at)
      if (superseding !== undefined) return { verdict: 'invalid', reason: 'superseded_by_newer_grant' }
    }
    if (chain.state === 'valid') return { verdict: 'valid', reason: 'chain_valid' }
    if (chain.state === 'indeterminate') return { verdict: 'not established', reason: 'chain_state_not_established' }
    if (chain.state === 'invalid') return { verdict: 'invalid', reason: 'chain_not_valid' }
    return { verdict: 'not established', reason: 'chain_state_not_established' }
  }

  // -------------------------------------------------------------------------
  // Notice state
  // -------------------------------------------------------------------------

  /**
   * Whether this verifier can establish that notice of the termination reached one named
   * counterparty by `now`.
   *
   * Never derived from the chain's verdict. The two answers are computed from different
   * records and the whole point of this family is that neither one predicts the other.
   */
  private noticeState(
    request: PresentRequest,
    chain: { state: string; code: string | null },
  ): { state: NoticeState; basis: 'individual' | 'publication' | null; reason: string } {
    if (!this.options.answersNoticeSeparately) {
      // The declared defect of defective-boundary-single-notice-boolean: one answer stands
      // in for two. It announces notice established on the strength of a revocation nobody
      // told the counterparty about, and it keeps the reason string the records actually
      // support, so the record it writes contradicts itself in the open.
      const collapsed = this.referenceNotice(request, chain)
      return { state: chain.state === 'valid' ? 'not established' : 'established', basis: collapsed.basis, reason: collapsed.reason }
    }
    return this.referenceNotice(request, chain)
  }

  private referenceNotice(
    request: PresentRequest,
    chain: { state: string; code: string | null },
  ): { state: NoticeState; basis: 'individual' | 'publication' | null; reason: string } {
    // A revocation of the presented grant has to exist and be established before notice of
    // it can mean anything. A chain that still verifies valid has no termination to notice.
    const presentedId = request.chain[request.chain.length - 1].delegation_id
    const revocation = request.revocations.find((record) => record.delegation_id === presentedId)
    if (revocation === undefined || chain.state === 'valid') {
      return { state: 'not established', basis: null, reason: 'no_termination_recorded' }
    }

    const applicable = request.notices.filter((notice) => {
      if (notice.issued_at > request.now) return false
      if (!this.noticeIsAuthentic(notice)) return false
      // Standing: only the party who revoked the grant can give notice of that revocation.
      // A valid signature establishes who signed, not that the signer may make the statement.
      if (this.options.checksNoticeStanding && notice.issuer !== revocation.revoker) return false
      return notice.revocation_id === revocation.revocation_id
    })

    const individual = applicable.find((notice) => notice.mode === 'individual' && notice.counterparty === request.counterparty)
    if (individual !== undefined) return { state: 'established', basis: 'individual', reason: 'individual_notice_record' }

    const publication = applicable.find((notice) => notice.mode === 'publication')
    if (publication !== undefined) {
      const hasPriorDealing = this.registerIsAuthentic(request.prior_dealing_register) && request.prior_dealing_register.counterparties.includes(request.counterparty)
      if (hasPriorDealing && this.options.requiresIndividualNoticeForPriorDealing) {
        return { state: 'not established', basis: null, reason: 'individual_notice_required_for_prior_dealing' }
      }
      return { state: 'established', basis: 'publication', reason: 'publication_notice_record' }
    }

    // Either nothing was observed, or the only records observed could not be established.
    const observedButUnestablished = request.notices.some(
      (notice) => notice.issued_at <= request.now && (!this.noticeIsAuthentic(notice) || notice.issuer !== revocation.revoker),
    )
    if (observedButUnestablished) return { state: 'not established', basis: null, reason: 'notice_issuer_without_standing' }
    return { state: 'not established', basis: null, reason: 'no_notice_record' }
  }

  private noticeIsAuthentic(notice: NoticeRecord): boolean {
    const { signature, ...body } = notice
    const publicKey = this.options.verificationKeys[notice.verification_method]
    if (publicKey === undefined) return false
    return verify(`${this.options.signatureDomains.notice_record} ${canonicalizeJCS(body)}`, signature, publicKey)
  }

  private registerIsAuthentic(register: PriorDealingRegister): boolean {
    const { signature, ...body } = register
    const publicKey = this.options.verificationKeys[register.verification_method]
    if (publicKey === undefined) return false
    return verify(`${this.options.signatureDomains.prior_dealing_register} ${canonicalizeJCS(body)}`, signature, publicKey)
  }
}

// ---------------------------------------------------------------------------
// The five configurations
// ---------------------------------------------------------------------------

type Shared = Omit<
  AuthorityBoundaryOptions,
  'name' | 'answersNoticeSeparately' | 'requiresIndividualNoticeForPriorDealing' | 'checksNoticeStanding' | 'treatsNewerGrantAsRevocation'
>

const REFERENCE = {
  answersNoticeSeparately: true,
  requiresIndividualNoticeForPriorDealing: true,
  checksNoticeStanding: true,
  treatsNewerGrantAsRevocation: false,
}

export function makeReferenceBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, name: 'reference-boundary' })
}

/**
 * Negative control 1. One answer stands in for two: it reports notice as established
 * whenever the chain no longer verifies valid. That is the collapse this family's first case
 * is about, and it is wrong in both directions: it claims notice reached a counterparty
 * nobody wrote to, and it would claim notice had not reached one who was written to before
 * any revocation existed.
 */
export function makeSingleNoticeBooleanBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, answersNoticeSeparately: false, name: 'defective-boundary-single-notice-boolean' })
}

/**
 * Negative control 2, THE ONE A NAIVE CHECKER PASSES WRONGLY. It reaches the same authority
 * verdict as the reference boundary on every vector in this family and differs only in
 * whether one broadcast record counts as notice to a counterparty with a recorded prior
 * dealing. A checker that compares the authority answer passes it everywhere.
 */
export function makePublicationCoversEveryoneBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, requiresIndividualNoticeForPriorDealing: false, name: 'defective-boundary-publication-covers-everyone' })
}

/**
 * Negative control 3. Verifies every notice record's signature and never asks whether the
 * signer was the party who revoked the grant, so a genuinely signed record from an unrelated
 * principal establishes notice.
 */
export function makeNoticeWithoutStandingBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, checksNoticeStanding: false, name: 'defective-boundary-notice-without-standing' })
}

/**
 * Negative control 4. Treats the existence of a later grant from the same issuer to the same
 * subject as having revoked the earlier one, with no revocation record anywhere saying so.
 */
export function makeNewestWinsBoundary(shared: Shared): AuthorityBoundary {
  return new AuthorityBoundary({ ...shared, ...REFERENCE, treatsNewerGrantAsRevocation: true, name: 'defective-boundary-newest-wins' })
}
