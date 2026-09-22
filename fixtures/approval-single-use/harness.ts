// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference dispatch boundary for the approval-single-use family.
//
// WHAT THIS IS. draft-pidlisnyi-aps-03 section 5.3.2 lines 1093-1099 (quoted in full in
// README.md) states what an enforcement boundary MUST do with a permit or narrow
// policy-decision record before dispatch: verify it has not expired, atomically consume
// its receipt_id, recheck time and revocation state, and refuse an already consumed,
// expired or stale approval. A deny record is terminal and MUST NOT be consumed as an
// approval. Neither reference SDK implements this boundary (see README "What exists"):
// both SDKs' own doc comments say the single-record and composite verifiers stop at
// artifact integrity, signer authority, action and decision binding, and stage
// continuity, and name lines 1093-1099 by number as enforcement-boundary state outside
// that scope (node_modules/agent-passport-system/dist/src/v2/receipt-core/stage.d.ts
// lines 62-64, quoted in README.md).
//
// This file is that missing boundary: the family's own code, not an SDK conformance
// result. It calls the real SDK for the two things the SDK does establish -- a
// policy-decision receipt's signature and section 5.3 stage validity
// (verifyReceiptV1), and the backing AuthorityDelegationV1 chain's structural,
// temporal and revocation state (verifyAuthorityDelegationChain) -- and supplies
// everything lines 1093-1099 ask for beyond that itself: the single-use ledger, the
// expiry gate, the action_ref binding check, and the deny-is-terminal rule.
//
// REFERENCE_BOUNDARY implements all of it. DEFECTIVE_BOUNDARY is the negative control the
// prompt asks for: it still calls verifyReceiptV1 (so it still enforces signature, verdict
// and action binding, and expiry, all of which live before the consumption step below) but
// it never consumes a receipt_id and never rechecks the authority chain at consumption
// time. See README "Negative control" for the failing set this predicts and the family's
// vectors.json for where each of the two differs from the reference boundary's behaviour.
//
// Node builtins only, no imports beyond the pinned SDK's verification entrypoints. No wall
// clock: every `now` this file compares against is supplied by the caller from the
// fixture's pinned timeline, never read from the system.

import {
  verifyAuthorityDelegationChain,
  verifyReceiptV1,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

export interface PolicyDecisionResult {
  profile: 'aps-core-decision-output-v1'
  verdict: 'permit' | 'narrow' | 'deny'
  effective_authority_ref: string | null
  constraints: string[]
  valid_until: string | null
}

export interface PolicyDecisionReceipt {
  receipt_id: string
  action_ref: string
  delegation_ref: string
  issuer: string
  result: PolicyDecisionResult
  [key: string]: unknown
}

export interface ConsumeRequest {
  /** A label for audit output only; not consulted by any check. */
  label: string
  decision: PolicyDecisionReceipt
  requestedActionRef: string
  now: string
  /** The one-hop chain backing this decision, resolved by the caller from chain.json. */
  chain: readonly AuthorityDelegationV1[]
  resolveRevocation: (delegation: AuthorityDelegationV1) => RevocationResolution
}

export interface Outcome {
  admitted: boolean
  reason: string
  detail?: string
}

export interface AuditEntry {
  label: string
  receiptId: string
  admitted: boolean
  reason: string
}

type KeyResolver = (signer: string, keyId: string, issuedAt: string) => string | undefined
type VerificationKeyResolver = (issuer: string, verificationMethod: string, issuedAt: string) => string | null

export interface DispatchBoundaryOptions {
  name: string
  /** REFERENCE_BOUNDARY: true. DEFECTIVE_BOUNDARY: false, the family's declared flaw. */
  consumesReceiptIds: boolean
  /** REFERENCE_BOUNDARY: true. DEFECTIVE_BOUNDARY: false, the family's other declared flaw. */
  rechecksAuthorityChainAtConsumption: boolean
  boundaryIdentity: string
  resolveReceiptSignerKey: KeyResolver
  resolveDelegationVerificationKey: VerificationKeyResolver
  trustRoot: (root: AuthorityDelegationV1) => boolean
}

/**
 * One boundary instance holds one single-use ledger. The eight vectors are presented to
 * one instance, in the fixture's pinned timeline order, exactly as section 5.3.2 describes
 * one boundary consuming one stream of approvals -- this is why the family calls itself
 * "timeline style, one clock" rather than one independent case per boundary instance.
 */
export class DispatchBoundary {
  private readonly consumed = new Set<string>()
  readonly audit: AuditEntry[] = []

  constructor(private readonly options: DispatchBoundaryOptions) {}

  get name(): string {
    return this.options.name
  }

  consume(request: ConsumeRequest): Outcome {
    const outcome = this.evaluate(request)
    this.audit.push({ label: request.label, receiptId: request.decision.receipt_id, admitted: outcome.admitted, reason: outcome.reason })
    return outcome
  }

  private evaluate(request: ConsumeRequest): Outcome {
    const { decision, requestedActionRef, now, chain, resolveRevocation } = request

    // Step 0, both boundaries: the record's own signature and section 5.3 stage validity.
    // This is the SDK's own job (verifyReceiptV1), never reimplemented here.
    const receiptVerification = verifyReceiptV1(
      decision as never,
      this.options.resolveReceiptSignerKey,
      { boundaryIdentity: this.options.boundaryIdentity },
    )
    if (receiptVerification.status !== 'valid') {
      return { admitted: false, reason: 'signature_or_shape_invalid', detail: JSON.stringify(receiptVerification.errors) }
    }

    // Step 1, both boundaries: line 1098, "A deny record is terminal and MUST NOT be
    // consumed as an approval." Checked before anything else, since a deny carries no
    // valid_until to check expiry against.
    if (decision.result.verdict === 'deny') {
      return { admitted: false, reason: 'deny_terminal_not_approval' }
    }

    // Step 2, both boundaries: the approval is bound to its action_ref (line 1093,
    // "a bounded, single-use approval for its action_ref").
    if (decision.action_ref !== requestedActionRef) {
      return { admitted: false, reason: 'action_binding_mismatch' }
    }

    // Step 3, both boundaries: "verify that it has not expired" (line 1095). valid_until
    // is non-null here because verdict is permit or narrow (section 5.3.2 lines 1090-1091).
    const validUntil = decision.result.valid_until as string
    if (!(now < validUntil)) {
      return { admitted: false, reason: 'expired' }
    }

    // Step 4, REFERENCE_BOUNDARY only: "atomically consume its receipt_id" (line 1095-1096).
    // DEFECTIVE_BOUNDARY skips this, its first declared flaw: a second presentation of an
    // already-admitted permit is indistinguishable from a first one.
    if (this.options.consumesReceiptIds) {
      if (this.consumed.has(decision.receipt_id)) {
        return { admitted: false, reason: 'already_consumed' }
      }
      this.consumed.add(decision.receipt_id)
    }

    // Step 5, REFERENCE_BOUNDARY only: "recheck time and revocation state" (line 1096).
    // Folded here into one fresh verifyAuthorityDelegationChain call at the consumption
    // instant `now`, which re-derives both the chain's own temporal validity and its
    // revocation state in one real SDK call, rather than a second implementation of
    // either. DEFECTIVE_BOUNDARY skips this, its second declared flaw: a chain revoked
    // after the decision was issued and before dispatch is never re-examined.
    if (this.options.rechecksAuthorityChainAtConsumption) {
      const chainResult = verifyAuthorityDelegationChain(chain, {
        now,
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
    }

    // Step 6: "complete any spend reservation" (line 1097). Not modeled. draft-03 section
    // 3.4's cumulative-spend reservation machinery is out of scope for this family; see
    // README "Does not claim". This boundary has nothing here by design, not by omission.

    return { admitted: true, reason: 'dispatch_admitted' }
  }
}

export function makeReferenceBoundary(shared: Omit<DispatchBoundaryOptions, 'name' | 'consumesReceiptIds' | 'rechecksAuthorityChainAtConsumption'>): DispatchBoundary {
  return new DispatchBoundary({ ...shared, name: 'reference-boundary', consumesReceiptIds: true, rechecksAuthorityChainAtConsumption: true })
}

/**
 * The prompt's negative control: checks signature, verdict, action binding and expiry
 * (steps 0-3 above, unchanged) but never consumes a receipt_id and never rechecks the
 * authority chain at consumption. Declared failing set: the vectors that turn on exactly
 * those two removed steps. See README "Negative control".
 */
export function makeDefectiveBoundary(shared: Omit<DispatchBoundaryOptions, 'name' | 'consumesReceiptIds' | 'rechecksAuthorityChainAtConsumption'>): DispatchBoundary {
  return new DispatchBoundary({ ...shared, name: 'defective-boundary-never-consumes-never-rechecks', consumesReceiptIds: false, rechecksAuthorityChainAtConsumption: false })
}
