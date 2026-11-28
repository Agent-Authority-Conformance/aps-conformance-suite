// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference consumption boundary for the approval-authority-expiry family.
//
// WHAT THIS IS. draft-pidlisnyi-aps-03 section 4.3 lines 914-918 (quoted in README.md):
// "At consumption the boundary MUST re-validate what can have changed since issuance,
// including revocation status and temporal validity, as required by Section 3.5. An
// approval that has expired, has already been consumed, or fails re-validation MUST NOT
// admit execution." Neither reference SDK implements a consumption boundary (see
// fixtures/approval-single-use/README.md, "What exists"), so this family supplies one,
// following that family's DispatchBoundary. The SDK is called for what it does
// establish: a policy-decision receipt's signature and section 5.3 stage validity
// (verifyReceiptV1), and the backing AuthorityDelegationV1 chain's structural, temporal
// and revocation state (verifyAuthorityDelegationChain). The single-use ledger, the
// approval expiry gate and the action_ref binding check are this file's own.
//
// The difference between the two configurations is the instant the authority chain is
// re-verified at. REFERENCE_BOUNDARY re-verifies it at the consumption instant, so both
// the chain's temporal validity and its revocation state are current. DEFECTIVE_BOUNDARY
// re-verifies it at the decision's own issued_at, with the consumption-time revocation
// answer: it rechecks revocation, and it checks the approval's own expiry, but the
// authority's temporal validity it sees is the one that held at issuance. See README
// "Negative control".
//
// No wall clock: every `now` this file compares against is supplied by the caller from
// the fixture's pinned timeline.

import {
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

export interface PolicyDecisionReceipt {
  receipt_id: string
  action_ref: string
  issued_at: string
  result: { verdict: 'permit' | 'narrow' | 'deny'; valid_until: string | null }
  [key: string]: unknown
}

export interface ConsumeRequest {
  decision: PolicyDecisionReceipt
  requestedActionRef: string
  now: string
  chain: readonly AuthorityDelegationV1[]
  resolveRevocation: (delegation: AuthorityDelegationV1) => RevocationResolution
}

export interface Outcome {
  admitted: boolean
  reason: string
  detail?: string
}

type KeyResolver = (signer: string, keyId: string, issuedAt: string) => string | undefined
type VerificationKeyResolver = (issuer: string, verificationMethod: string, issuedAt: string) => string | null

export interface ConsumptionBoundaryOptions {
  name: string
  /** REFERENCE_BOUNDARY: 'consumption'. DEFECTIVE_BOUNDARY: 'decision_issued_at', its declared flaw. */
  authorityRecheckClock: 'consumption' | 'decision_issued_at'
  boundaryIdentity: string
  resolveReceiptSignerKey: KeyResolver
  resolveDelegationVerificationKey: VerificationKeyResolver
  trustRoot: (root: AuthorityDelegationV1) => boolean
}

/** One instance holds one single-use ledger, shared across the family's ordered presentations. */
export class ConsumptionBoundary {
  private readonly consumed = new Set<string>()

  constructor(private readonly options: ConsumptionBoundaryOptions) {}

  get name(): string {
    return this.options.name
  }

  consume(request: ConsumeRequest): Outcome {
    const { decision, requestedActionRef, now, chain, resolveRevocation } = request

    // Step 0: the record's own signature and section 5.3 stage validity, by the SDK.
    const receiptVerification = verifyReceiptV1(
      decision as never,
      this.options.resolveReceiptSignerKey,
      { boundaryIdentity: this.options.boundaryIdentity },
    )
    if (receiptVerification.status !== 'valid') {
      return { admitted: false, reason: 'signature_or_shape_invalid', detail: JSON.stringify(receiptVerification.errors) }
    }

    // Step 1: a deny is never an approval (section 5.3.2 line 1098).
    if (decision.result.verdict === 'deny') {
      return { admitted: false, reason: 'deny_terminal_not_approval' }
    }

    // Step 2: the approval is bound to its action_ref (section 4.3 line 912).
    if (decision.action_ref !== requestedActionRef) {
      return { admitted: false, reason: 'action_binding_mismatch' }
    }

    // Step 3: the approval's own bounded lifetime (section 4.3 line 917, "has expired").
    const validUntil = decision.result.valid_until as string
    if (!(now < validUntil)) {
      return { admitted: false, reason: 'expired' }
    }

    // Step 4: single use (section 4.3 line 917, "has already been consumed").
    if (this.consumed.has(decision.receipt_id)) {
      return { admitted: false, reason: 'already_consumed' }
    }
    this.consumed.add(decision.receipt_id)

    // Step 5: re-validate what can have changed since issuance, "including revocation
    // status and temporal validity" (section 4.3 lines 914-916). One fresh
    // verifyAuthorityDelegationChain call. The revocation answer is always the one the
    // caller supplies for the consumption instant. The clock is the consumption instant
    // for REFERENCE_BOUNDARY and the decision's issued_at for DEFECTIVE_BOUNDARY.
    const recheckAt = this.options.authorityRecheckClock === 'consumption' ? now : decision.issued_at
    const chainResult = verifyAuthorityDelegationChain(chain, {
      now: recheckAt,
      resolveVerificationKey: this.options.resolveDelegationVerificationKey,
      trustRoot: this.options.trustRoot,
      resolveRevocation,
    })
    if (chainResult.state !== 'valid') {
      const failure = chainResult.failures[0]
      return {
        admitted: false,
        reason: 'authority_chain_not_valid_at_consumption',
        detail: failure ? `${chainResult.state}/${failure.code}` : chainResult.state,
      }
    }

    return { admitted: true, reason: 'dispatch_admitted' }
  }
}

type SharedOptions = Omit<ConsumptionBoundaryOptions, 'name' | 'authorityRecheckClock'>

export function makeReferenceBoundary(shared: SharedOptions): ConsumptionBoundary {
  return new ConsumptionBoundary({ ...shared, name: 'reference-boundary', authorityRecheckClock: 'consumption' })
}

/**
 * The declared negative control: rechecks revocation at consumption and enforces the
 * approval's own expiry, but evaluates the authority chain's temporal validity at the
 * decision's issued_at instead of the consumption instant.
 */
export function makeDefectiveBoundary(shared: SharedOptions): ConsumptionBoundary {
  return new ConsumptionBoundary({ ...shared, name: 'defective-boundary-authority-time-frozen-at-issuance', authorityRecheckClock: 'decision_issued_at' })
}
