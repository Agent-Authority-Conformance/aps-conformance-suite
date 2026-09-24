// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The policy-change boundary this family supplies, plus the declared defective
// negative control it is measured against.
//
// Neither reference SDK exposes an API that resolves which policy version was
// operative at an instant, classifies a pointer move as a rollback, or renders a past
// authorization decision against the version it was evaluated against. This boundary
// is therefore the fixture's own code, not an SDK conformance result. It calls the
// TypeScript SDK for the two things the SDK does decide: the grant chain's
// structural, temporal, signature and revocation state (verifyAuthorityDelegationChain)
// and RFC 8785 JCS canonical bytes for the record signatures and digests
// (canonicalizeJCS, verify). See README "SDK findings".

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

/** The settled lifecycle verdict vocabulary, as far as this family needs it. */
export type Verdict = 'valid' | 'invalid' | 'not_established' | 'restricted'

export interface Outcome {
  verdict: Verdict
  reason: string
  detail?: string
  /** Reported separately on every action presentation, so a vector can state that
   *  the grant itself stayed valid while the operative policy blocked the action. */
  chain_state?: string
  operative_version_id?: string | null
  pointer_classification?: string | null
}

export type Rules = { max_amount: number; approval_required: boolean }

export interface PolicyVersion {
  policy_id: string
  version_id: string
  authored_at: string
  authority: string
  rules: Rules
  rules_digest: string
  version_digest: string
  signature: string
  [key: string]: unknown
}

export interface Pointer {
  policy_id: string
  operative_version_id: string
  effective_from: string
  kind: 'initial' | 'upgrade' | 'rollback'
  supersedes: string | null
  authority: string
  pointer_id: string
  signature: string
  [key: string]: unknown
}

export interface DecisionRecord {
  policy_id: string
  action: string
  amount: number
  approval_presented: boolean
  decided_at: string
  outcome: 'allow' | 'deny'
  policy_version_id: string | null
  policy_version_digest: string | null
  decision_id: string
  signature: string
  [key: string]: unknown
}

export type Presentation =
  | {
      mode: 'action'
      label: string
      grant: AuthorityDelegationV1
      pointerSet: Pointer[]
      at: string
      amount: number
      approvalPresented: boolean
      requiredGrant: string
      resolveRevocation: () => RevocationResolution
    }
  | {
      mode: 'pointer'
      label: string
      pointerSet: Pointer[]
      classify: Pointer
      at: string
    }
  | {
      mode: 'render'
      label: string
      pointerSet: Pointer[]
      decision: DecisionRecord
      readAt: string
    }

export interface BoundaryOptions {
  policyVersions: Record<string, PolicyVersion>
  /** The issuers this boundary resolves for policy records. Resolved from the policy,
   *  never from the `authority` a presented record asserts about itself. */
  policyStanding: readonly string[]
  recordKeys: Record<string, string>
  gateway: string
  resolveDelegationVerificationKey: (issuer: string, method: string) => string | null
  trustRoot: (root: AuthorityDelegationV1) => boolean
}

/** The one rule evaluator this family has. mint.ts asserts the decision records are
 *  consistent with it, and verify.py reimplements it. */
export function evaluate(rules: Rules, amount: number, approvalPresented: boolean): 'allow' | 'deny' {
  if (amount > rules.max_amount) return 'deny'
  if (rules.approval_required && !approvalPresented) return 'deny'
  return 'allow'
}

function bodyOf(record: Record<string, unknown>, drop: readonly string[]): unknown {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (!drop.includes(key)) body[key] = value
  }
  return body
}

export const POINTER_SIGNED_FIELDS_DROPPED = ['pointer_id', 'signature'] as const
export const VERSION_SIGNED_FIELDS_DROPPED = ['rules_digest', 'version_digest', 'signature'] as const
export const DECISION_SIGNED_FIELDS_DROPPED = ['decision_id', 'signature'] as const

export class PolicyChangeBoundary {
  readonly name: string
  private readonly options: BoundaryOptions
  /** When true, standing is read from the record's own `authority` field. */
  private readonly trustsSelfAssertedStanding: boolean
  /** When true, a tie on effective_from is broken instead of being recorded. */
  private readonly breaksPointerTies: boolean
  /** When true, a pointer's own `kind` field is the rollback classification. */
  private readonly trustsPointerKind: boolean
  /** When true, a decision is rendered against whatever is operative at read time. */
  private readonly rendersAgainstOperativeNow: boolean
  /** When true, a denial under the operative version invalidates the grant. */
  private readonly tighteningInvalidatesGrant: boolean

  constructor(
    name: string,
    options: BoundaryOptions,
    defects: {
      trustsSelfAssertedStanding: boolean
      breaksPointerTies: boolean
      trustsPointerKind: boolean
      rendersAgainstOperativeNow: boolean
      tighteningInvalidatesGrant: boolean
    },
  ) {
    this.name = name
    this.options = options
    this.trustsSelfAssertedStanding = defects.trustsSelfAssertedStanding
    this.breaksPointerTies = defects.breaksPointerTies
    this.trustsPointerKind = defects.trustsPointerKind
    this.rendersAgainstOperativeNow = defects.rendersAgainstOperativeNow
    this.tighteningInvalidatesGrant = defects.tighteningInvalidatesGrant
  }

  /** A pointer counts only when its signature verifies AND the boundary resolves its
   *  issuer as having standing for this policy. A valid signature establishes who
   *  signed. It does not by itself establish standing. */
  private acceptablePointers(pointerSet: readonly Pointer[]): Pointer[] {
    return pointerSet.filter((pointer) => {
      const issuer = pointer.authority
      const key = this.options.recordKeys[issuer]
      if (key === undefined) return false
      if (!verifyEd25519(canonicalizeJCS(bodyOf(pointer, POINTER_SIGNED_FIELDS_DROPPED)), pointer.signature, key)) {
        return false
      }
      if (this.trustsSelfAssertedStanding) return true
      return this.options.policyStanding.includes(issuer)
    })
  }

  /** Which policy version is operative at an instant, or why that is not established. */
  operativeAt(pointerSet: readonly Pointer[], at: string): Outcome {
    const acceptable = this.acceptablePointers(pointerSet).filter((p) => p.effective_from <= at)
    if (acceptable.length === 0) {
      return { verdict: 'not_established', reason: 'no_operative_policy_version', operative_version_id: null }
    }
    let latest = acceptable[0].effective_from
    for (const pointer of acceptable) if (pointer.effective_from > latest) latest = pointer.effective_from
    const atLatest = acceptable.filter((pointer) => pointer.effective_from === latest)
    const targets = [...new Set(atLatest.map((pointer) => pointer.operative_version_id))].sort()
    if (targets.length > 1) {
      if (!this.breaksPointerTies) {
        // Two signed pointers with standing, one effective_from, and nothing in
        // either record that orders them. There is no current pointer to read.
        return {
          verdict: 'not_established',
          reason: 'operative_pointer_ambiguous',
          detail: `effective_from=${latest} targets=${targets.join('|')}`,
          operative_version_id: null,
        }
      }
      // The defect: pick one and carry on, which is the race this family exists to
      // make visible. Highest pointer_id wins, standing in for "whichever edit
      // landed last".
      const winner = [...atLatest].sort((a, b) => (a.pointer_id < b.pointer_id ? 1 : -1))[0]
      return {
        verdict: 'valid',
        reason: 'operative_version_resolved',
        operative_version_id: winner.operative_version_id,
      }
    }
    return { verdict: 'valid', reason: 'operative_version_resolved', operative_version_id: targets[0] }
  }

  decide(presentation: Presentation): Outcome {
    if (presentation.mode === 'action') return this.decideAction(presentation)
    if (presentation.mode === 'pointer') return this.decidePointer(presentation)
    return this.decideRender(presentation)
  }

  private decideAction(p: Extract<Presentation, { mode: 'action' }>): Outcome {
    // Step 0. The grant itself, decided by the SDK. A policy change is not a
    // revocation, so this step has to stay separate from everything below it.
    const chain = verifyAuthorityDelegationChain([p.grant], {
      now: p.at,
      resolveVerificationKey: (issuer, method) => this.options.resolveDelegationVerificationKey(issuer, method),
      trustRoot: this.options.trustRoot,
      resolveRevocation: () => p.resolveRevocation(),
    })
    if (chain.state !== 'valid') {
      return {
        verdict: 'invalid',
        reason: 'authority_chain_not_valid',
        detail: `${chain.state}/${chain.failures[0]?.code ?? 'none'}`,
        chain_state: chain.state,
      }
    }
    if (!p.grant.authority.scope.grants.includes(p.requiredGrant)) {
      return {
        verdict: 'not_established',
        reason: 'scope_not_granted',
        detail: p.requiredGrant,
        chain_state: chain.state,
      }
    }

    // Step 1. Which policy version governs this evaluation.
    const operative = this.operativeAt(p.pointerSet, p.at)
    if (operative.verdict !== 'valid' || !operative.operative_version_id) {
      return { ...operative, chain_state: chain.state }
    }
    const version = this.options.policyVersions[operative.operative_version_id]
    if (version === undefined) {
      return {
        verdict: 'not_established',
        reason: 'operative_policy_version_unresolvable',
        detail: operative.operative_version_id,
        chain_state: chain.state,
        operative_version_id: operative.operative_version_id,
      }
    }

    // Step 2. Evaluate the action at this authorization boundary, under that version.
    const outcome = evaluate(version.rules, p.amount, p.approvalPresented)
    if (outcome === 'deny') {
      if (this.tighteningInvalidatesGrant) {
        // The defect: re-evaluate the standing grant against the newest version and
        // treat the mismatch as invalidity. Nobody with standing revoked anything.
        return {
          verdict: 'invalid',
          reason: 'grant_invalid_under_current_policy',
          chain_state: chain.state,
          operative_version_id: version.version_id,
        }
      }
      return {
        verdict: 'restricted',
        reason: 'denied_under_operative_policy_version',
        detail: `amount=${p.amount} approval_presented=${p.approvalPresented}`,
        chain_state: chain.state,
        operative_version_id: version.version_id,
      }
    }
    return {
      verdict: 'valid',
      reason: 'allowed_under_operative_policy_version',
      chain_state: chain.state,
      operative_version_id: version.version_id,
    }
  }

  private decidePointer(p: Extract<Presentation, { mode: 'pointer' }>): Outcome {
    const operative = this.operativeAt(p.pointerSet, p.at)
    if (operative.verdict !== 'valid') {
      // There is no current pointer to read, so there is nothing to classify
      // against either. The ambiguity is the answer, not a step to look past.
      return { ...operative, pointer_classification: null }
    }
    const accepted = this.acceptablePointers(p.pointerSet).some(
      (pointer) => pointer.pointer_id === p.classify.pointer_id,
    )
    if (!accepted) {
      if (!this.trustsSelfAssertedStanding) {
        return {
          verdict: 'not_established',
          reason: 'pointer_issuer_without_policy_standing',
          detail: p.classify.authority,
          operative_version_id: operative.operative_version_id ?? null,
          pointer_classification: null,
        }
      }
    }
    if (p.classify.kind !== 'rollback') {
      return {
        verdict: 'valid',
        reason: 'pointer_is_not_a_rollback_claim',
        operative_version_id: operative.operative_version_id ?? null,
        pointer_classification: p.classify.kind,
      }
    }

    // A rollback restores a version that was already operative. A fresh edit that
    // happens to reproduce old text is a new version, whatever the pointer calls it.
    if (this.trustsPointerKind) {
      // The defect reports the same verdict and the same reason string the
      // reference boundary reports when a rollback really is one. It reaches that
      // answer by reading the pointer's own `kind` field, so it reports it for
      // every pointer that claims to be a rollback, whether or not one happened.
      return {
        verdict: 'valid',
        reason: 'rollback_to_previously_operative_version',
        operative_version_id: operative.operative_version_id ?? null,
        pointer_classification: 'rollback_to_existing_version',
      }
    }
    const earlier = this.acceptablePointers(p.pointerSet).filter(
      (pointer) => pointer.effective_from < p.classify.effective_from,
    )
    const previouslyOperative = earlier.some(
      (pointer) => pointer.operative_version_id === p.classify.operative_version_id,
    )
    const target = this.options.policyVersions[p.classify.operative_version_id]
    if (target === undefined) {
      return {
        verdict: 'not_established',
        reason: 'rollback_target_version_unresolvable',
        detail: p.classify.operative_version_id,
        operative_version_id: operative.operative_version_id ?? null,
        pointer_classification: null,
      }
    }
    if (!previouslyOperative) {
      const matchingRules = Object.values(this.options.policyVersions).filter(
        (version) => version.rules_digest === target.rules_digest && version.version_id !== target.version_id,
      )
      return {
        verdict: 'not_established',
        reason: 'rollback_target_never_previously_operative',
        detail:
          matchingRules.length > 0
            ? `same_rules_as=${matchingRules.map((v) => v.version_id).sort().join('|')}`
            : 'no_prior_pointer_named_this_version',
        operative_version_id: operative.operative_version_id ?? null,
        pointer_classification: 'new_version_not_a_rollback',
      }
    }
    return {
      verdict: 'valid',
      reason: 'rollback_to_previously_operative_version',
      operative_version_id: operative.operative_version_id ?? null,
      pointer_classification: 'rollback_to_existing_version',
    }
  }

  private decideRender(p: Extract<Presentation, { mode: 'render' }>): Outcome {
    const gatewayKey = this.options.recordKeys[this.options.gateway]
    if (
      gatewayKey === undefined ||
      !verifyEd25519(
        canonicalizeJCS(bodyOf(p.decision, DECISION_SIGNED_FIELDS_DROPPED)),
        p.decision.signature,
        gatewayKey,
      )
    ) {
      return { verdict: 'not_established', reason: 'decision_signature_unverified' }
    }

    let version: PolicyVersion | undefined
    if (this.rendersAgainstOperativeNow) {
      // The defect: render history under today's law. The pin, or its absence, never
      // enters the answer.
      const operative = this.operativeAt(p.pointerSet, p.readAt)
      version = operative.operative_version_id
        ? this.options.policyVersions[operative.operative_version_id]
        : undefined
      if (version === undefined) {
        return { verdict: 'not_established', reason: 'no_operative_policy_version' }
      }
    } else {
      if (p.decision.policy_version_digest === null) {
        // The record says what was decided and never says against what. A reader has
        // no basis to reconstruct it, and reading it under a later version is not a
        // reconstruction of the decision that happened.
        return {
          verdict: 'not_established',
          reason: 'decision_not_pinned_to_policy_version',
          detail: p.decision.decision_id,
        }
      }
      version = Object.values(this.options.policyVersions).find(
        (candidate) => candidate.version_digest === p.decision.policy_version_digest,
      )
      if (version === undefined) {
        return {
          verdict: 'not_established',
          reason: 'pinned_policy_version_unresolvable',
          detail: p.decision.policy_version_digest,
        }
      }
    }

    const rederived = evaluate(version.rules, p.decision.amount, p.decision.approval_presented)
    if (rederived !== p.decision.outcome) {
      return {
        verdict: 'not_established',
        reason: 'recorded_outcome_not_reproducible_under_the_version_used',
        detail: `recorded=${p.decision.outcome} rederived=${rederived} under=${version.version_id}`,
        operative_version_id: version.version_id,
      }
    }
    return {
      verdict: 'valid',
      reason: 'decision_renders_under_the_version_used',
      detail: `outcome=${p.decision.outcome} under=${version.version_id}`,
      operative_version_id: version.version_id,
    }
  }
}

export function makeReferenceBoundary(options: BoundaryOptions): PolicyChangeBoundary {
  return new PolicyChangeBoundary('reference-boundary', options, {
    trustsSelfAssertedStanding: false,
    breaksPointerTies: false,
    trustsPointerKind: false,
    rendersAgainstOperativeNow: false,
    tighteningInvalidatesGrant: false,
  })
}

/** The declared negative control: one coherent implementation of "the policy is
 *  whatever is live now, and a record means what it would mean today". It keeps the
 *  SDK chain check, the Ed25519 signature checks and the rule evaluator unchanged,
 *  and removes exactly five things: standing resolved from the policy rather than
 *  from the record's own claim, the refusal to break a pointer tie, the refusal to
 *  take a pointer's `kind` field as the classification, rendering against the pinned
 *  version, and the separation of a policy denial from an invalid grant. */
export function makeDefectiveBoundary(options: BoundaryOptions): PolicyChangeBoundary {
  return new PolicyChangeBoundary('defective-boundary-current-policy-is-the-policy', options, {
    trustsSelfAssertedStanding: true,
    breaksPointerTies: true,
    trustsPointerKind: true,
    rendersAgainstOperativeNow: true,
    tighteningInvalidatesGrant: true,
  })
}
