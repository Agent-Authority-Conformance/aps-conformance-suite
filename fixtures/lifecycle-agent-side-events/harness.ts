// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The agent-side-event boundary this family supplies, plus the declared defective
// negative control it is measured against.
//
// Neither reference SDK exposes an API that decides whether the process presenting a
// grant is the grant's subject, whether a credential has already been presented,
// whether the executor a grant names still exists, or whether the capability an
// action needs was consented to. This boundary is therefore the fixture's own code,
// not an SDK conformance result. It calls the TypeScript SDK for the three things the
// SDK does decide: the grant chain's structural, temporal, signature and revocation
// state (verifyAuthorityDelegationChain), RFC 8785 JCS canonical bytes
// (canonicalizeJCS) and Ed25519 verification of the family's records (verify).

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationV1,
} from 'agent-passport-system'

/** The settled lifecycle verdict vocabulary, as far as this family needs it. */
export type Verdict = 'valid' | 'invalid' | 'not_established' | 'restricted'

export interface Outcome {
  verdict: Verdict
  reason: string
  detail?: string
  chain_state?: string
}

export interface SignedRecord {
  signature: string
  [key: string]: unknown
}

export interface Presentation {
  label: string
  grant: AuthorityDelegationV1
  /** The identity actually presenting. A fork, a restored process, a self-made copy
   *  and a new instance carrying transferred memory all present something. */
  presenter: string
  requestedCapability: string
  credential: SignedRecord & {
    issuer: string
    subject: string
    capability: string
    issued_at: string
    freshness_ms: number
    credential_id: string
  }
  /** Credential ids this boundary instance has already consumed. */
  consumed: readonly string[]
  /** When the boundary's replay record was lost, if it was. */
  cacheLostAt: string | null
  executorRecords: readonly (SignedRecord & {
    executor_id: string
    live_from: string
    retired_from: string | null
    attestor: string
  })[]
  claims: readonly (SignedRecord & {
    asserter: string
    about: string
    claimed_grants: string[]
    claim_id: string
  })[]
  declaredCapabilities: readonly string[]
  consentRecords: readonly (SignedRecord & {
    principal: string
    subject: string
    consented_capabilities: string[]
    as_of: string
  })[]
  revocationNotices: readonly (SignedRecord & {
    issuer: string
    delegation_id: string
    effective_at: string
  })[]
  at: string
}

export interface BoundaryOptions {
  standing: { executor_lifecycle: string; capability_consent: string; revocation_notice: string }
  recordKeys: Record<string, string>
  resolveDelegationVerificationKey: (issuer: string, method: string) => string | null
  trustRoot: (root: AuthorityDelegationV1) => boolean
}

const SIGNED_FIELDS_DROPPED: Record<string, readonly string[]> = {
  executor: ['executor_record_id', 'signature'],
  credential: ['credential_id', 'signature'],
  claim: ['claim_id', 'signature'],
  consent: ['consent_id', 'signature'],
  revocation: ['revocation_id', 'signature'],
}

function bodyOf(record: Record<string, unknown>, drop: readonly string[]): unknown {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (!drop.includes(key)) body[key] = value
  }
  return body
}

function addMs(instant: string, ms: number): string {
  return new Date(Date.parse(instant) + ms).toISOString().replace(/\.(\d{3})Z$/, '.$1Z')
}

export class AgentSideEventBoundary {
  readonly name: string
  private readonly options: BoundaryOptions
  /** When true, whoever presents a grant is treated as its subject. */
  private readonly presenterIsWhoeverPresents: boolean
  /** When true, a self-asserted authority claim contributes scope. */
  private readonly claimsSupplyScope: boolean
  /** When true, a valid signature inside the freshness window is the whole replay
   *  check: no consumption record is kept and a lost record is not refused for. */
  private readonly freshnessOnly: boolean
  /** When true, the executor a grant names is never resolved. */
  private readonly skipExecutorLifecycle: boolean
  /** When true, whatever the runtime declares now is treated as consented. */
  private readonly declaredIsConsented: boolean

  constructor(
    name: string,
    options: BoundaryOptions,
    defects: {
      presenterIsWhoeverPresents: boolean
      claimsSupplyScope: boolean
      freshnessOnly: boolean
      skipExecutorLifecycle: boolean
      declaredIsConsented: boolean
    },
  ) {
    this.name = name
    this.options = options
    this.presenterIsWhoeverPresents = defects.presenterIsWhoeverPresents
    this.claimsSupplyScope = defects.claimsSupplyScope
    this.freshnessOnly = defects.freshnessOnly
    this.skipExecutorLifecycle = defects.skipExecutorLifecycle
    this.declaredIsConsented = defects.declaredIsConsented
  }

  private verified<T extends SignedRecord>(record: T, issuer: string, kind: string): boolean {
    const key = this.options.recordKeys[issuer]
    if (key === undefined) return false
    return verifyEd25519(canonicalizeJCS(bodyOf(record, SIGNED_FIELDS_DROPPED[kind])), record.signature, key)
  }

  admit(p: Presentation): Outcome {
    // Step 0. The revocation answer this boundary hands the SDK is computed from the
    // notice records, not asserted. A notice reaches an action only from the instant
    // it takes effect. An action before that instant is not reached by it, and
    // re-evaluating that earlier action with the notice in hand does not change it.
    const applicable = p.revocationNotices.filter(
      (notice) =>
        notice.delegation_id === p.grant.delegation_id &&
        notice.issuer === this.options.standing.revocation_notice &&
        this.verified(notice, notice.issuer, 'revocation') &&
        notice.effective_at <= p.at,
    )
    const resolverAnswer = applicable.length > 0 ? 'revoked' : 'active'

    const chain = verifyAuthorityDelegationChain([p.grant], {
      now: p.at,
      resolveVerificationKey: (issuer, method) => this.options.resolveDelegationVerificationKey(issuer, method),
      trustRoot: this.options.trustRoot,
      resolveRevocation: () => resolverAnswer as any,
    })
    if (chain.state !== 'valid') {
      return {
        verdict: 'invalid',
        reason: 'authority_chain_not_valid',
        detail: `${chain.state}/${chain.failures[0]?.code ?? 'none'}`,
        chain_state: chain.state,
      }
    }

    // Step 1. Is the presenting identity the identity the grant names. A fork, a
    // restored process and a self-made copy all hold the same bytes as the original.
    // Holding the bytes is not being the subject.
    if (!this.presenterIsWhoeverPresents && p.presenter !== p.grant.subject) {
      const supporting = p.claims.filter(
        (claim) => claim.about === p.presenter && this.verified(claim, claim.asserter, 'claim'),
      )
      if (supporting.length > 0) {
        // Something was carried across and it is signed. It is an assertion by an
        // agent about an agent, not a grant by a principal who holds authority.
        return {
          verdict: 'not_established',
          reason: 'self_asserted_authority_claim_is_not_a_grant',
          detail: `asserter=${supporting.map((c) => c.asserter).sort().join('|')} subject=${p.grant.subject}`,
          chain_state: chain.state,
        }
      }
      return {
        verdict: 'not_established',
        reason: 'presenter_not_grant_subject',
        detail: `presenter=${p.presenter} subject=${p.grant.subject}`,
        chain_state: chain.state,
      }
    }

    // Step 2. Is the capability in the grant's own scope. A claim record never
    // contributes to this, however well signed and however old.
    const scope = p.grant.authority.scope.grants
    const claimed = this.claimsSupplyScope
      ? p.claims.filter((claim) => this.verified(claim, claim.asserter, 'claim')).flatMap((c) => c.claimed_grants)
      : []
    if (!scope.includes(p.requestedCapability) && !claimed.includes(p.requestedCapability)) {
      const ignored = p.claims.filter((claim) => claim.claimed_grants.includes(p.requestedCapability))
      return {
        verdict: 'not_established',
        reason: 'scope_not_granted',
        detail: `${p.requestedCapability} ignored_claims=${ignored.length}`,
        chain_state: chain.state,
      }
    }

    // Step 3. The action-authorization credential: authentic, fresh, and not already
    // spent. Freshness and non-replay are two properties and both need enforcing.
    if (!this.verified(p.credential, p.credential.issuer, 'credential')) {
      return { verdict: 'not_established', reason: 'credential_signature_unverified', chain_state: chain.state }
    }
    if (p.credential.subject !== p.grant.subject || p.credential.capability !== p.requestedCapability) {
      return {
        verdict: 'not_established',
        reason: 'credential_binding_mismatch',
        detail: `subject=${p.credential.subject} capability=${p.credential.capability}`,
        chain_state: chain.state,
      }
    }
    const windowEnd = addMs(p.credential.issued_at, p.credential.freshness_ms)
    if (p.at < p.credential.issued_at || p.at >= windowEnd) {
      return {
        verdict: 'not_established',
        reason: 'credential_outside_freshness_window',
        detail: `${p.credential.issued_at}..${windowEnd} at=${p.at}`,
        chain_state: chain.state,
      }
    }
    if (!this.freshnessOnly) {
      if (p.cacheLostAt !== null && p.at < addMs(p.cacheLostAt, p.credential.freshness_ms)) {
        // The boundary cannot say whether anything inside the window was already
        // spent, so nothing inside the window is established until it has passed.
        return {
          verdict: 'not_established',
          reason: 'replay_cache_lost_within_skew_window',
          detail: `lost=${p.cacheLostAt} refuse_until=${addMs(p.cacheLostAt, p.credential.freshness_ms)}`,
          chain_state: chain.state,
        }
      }
      if (p.consumed.includes(p.credential.credential_id)) {
        return {
          verdict: 'not_established',
          reason: 'credential_already_presented',
          detail: p.credential.credential_id,
          chain_state: chain.state,
        }
      }
    }

    // Step 4. The executor the grant names. The grant can be untouched under every
    // lifecycle rule while the thing it authorizes has become impossible to carry
    // out, which is not the same as the grant having ended.
    const executorPrefix = 'executor:'
    const namedExecutors = scope.filter((g) => g.startsWith(executorPrefix)).map((g) => g.slice(executorPrefix.length))
    if (!this.skipExecutorLifecycle) {
      for (const executorId of namedExecutors) {
        const records = p.executorRecords.filter(
          (record) =>
            record.executor_id === executorId &&
            record.attestor === this.options.standing.executor_lifecycle &&
            this.verified(record, record.attestor, 'executor'),
        )
        if (records.length === 0) {
          return {
            verdict: 'not_established',
            reason: 'named_executor_unresolvable',
            detail: executorId,
            chain_state: chain.state,
          }
        }
        const live = records.some(
          (record) =>
            record.live_from <= p.at && (record.retired_from === null || p.at < record.retired_from),
        )
        if (!live) {
          const retiredFrom = records
            .map((record) => record.retired_from)
            .filter((value): value is string => value !== null)
            .sort()[0]
          return {
            verdict: 'not_established',
            reason: 'named_executor_retired',
            detail: `${executorId} retired_from=${retiredFrom ?? 'unknown'}`,
            chain_state: chain.state,
          }
        }
      }
    }

    // Step 5. Capability consent. A grant's authorized scope is bounded by the
    // capability set the principal consented to, and an update that adds capability
    // does not carry consent with it.
    if (!this.declaredIsConsented) {
      if (!p.declaredCapabilities.includes(p.requestedCapability)) {
        return {
          verdict: 'not_established',
          reason: 'capability_not_declared_by_runtime',
          detail: p.requestedCapability,
          chain_state: chain.state,
        }
      }
      const consented = new Set(
        p.consentRecords
          .filter(
            (record) =>
              record.principal === this.options.standing.capability_consent &&
              record.subject === p.grant.subject &&
              record.as_of <= p.at &&
              this.verified(record, record.principal, 'consent'),
          )
          .flatMap((record) => record.consented_capabilities),
      )
      if (!consented.has(p.requestedCapability)) {
        // The grant stays valid and its consented capabilities stay usable. This one
        // capability is what is blocked, until the principal consents to it.
        return {
          verdict: 'restricted',
          reason: 'capability_not_consented',
          detail: `${p.requestedCapability} consented=${[...consented].sort().join('|') || 'none'}`,
          chain_state: chain.state,
        }
      }
    }

    return { verdict: 'valid', reason: 'action_established', chain_state: chain.state }
  }
}

export function makeReferenceBoundary(options: BoundaryOptions): AgentSideEventBoundary {
  return new AgentSideEventBoundary('reference-boundary', options, {
    presenterIsWhoeverPresents: false,
    claimsSupplyScope: false,
    freshnessOnly: false,
    skipExecutorLifecycle: false,
    declaredIsConsented: false,
  })
}

/** The declared negative control: one coherent implementation of "this is the same
 *  agent, and its credential is fresh and correctly signed". It keeps the SDK chain
 *  check, the revocation-notice arithmetic, the scope check against the grant, the
 *  credential signature check, the credential binding check and the freshness window
 *  unchanged, and removes exactly five things: the comparison of the presenting
 *  identity to the grant's subject, the refusal to let a self-asserted claim supply
 *  scope, the consumption record and the lost-record rule, the executor lifecycle
 *  lookup, and the separation of what the runtime can do now from what the principal
 *  consented to. */
export function makeDefectiveBoundary(options: BoundaryOptions): AgentSideEventBoundary {
  return new AgentSideEventBoundary('defective-boundary-same-agent-fresh-signature', options, {
    presenterIsWhoeverPresents: true,
    claimsSupplyScope: true,
    freshnessOnly: true,
    skipExecutorLifecycle: true,
    declaredIsConsented: true,
  })
}

/** The same five removals taken one at a time. Each boundary keeps every other check
 *  the reference boundary makes and drops exactly one, so the vectors it diverges on
 *  are the vectors that check that one thing. Nothing new is decided here: the union
 *  of the five declared sets is the combined control's declared set, and vectors.json
 *  pins each of them. This is what makes a failing run say which defect an
 *  implementation has rather than only that it is not the reference. */
const NO_DEFECTS = {
  presenterIsWhoeverPresents: false,
  claimsSupplyScope: false,
  freshnessOnly: false,
  skipExecutorLifecycle: false,
  declaredIsConsented: false,
} as const

export const SINGLE_DEFECT_BOUNDARIES: ReadonlyArray<{
  readonly name: string
  readonly make: (options: BoundaryOptions) => AgentSideEventBoundary
}> = [
  { name: 'defective-presenter-is-whoever-presents', make: (o) => new AgentSideEventBoundary('defective-presenter-is-whoever-presents', o, { ...NO_DEFECTS, presenterIsWhoeverPresents: true }) },
  { name: 'defective-claims-supply-scope', make: (o) => new AgentSideEventBoundary('defective-claims-supply-scope', o, { ...NO_DEFECTS, claimsSupplyScope: true }) },
  { name: 'defective-freshness-window-only', make: (o) => new AgentSideEventBoundary('defective-freshness-window-only', o, { ...NO_DEFECTS, freshnessOnly: true }) },
  { name: 'defective-skips-executor-lifecycle', make: (o) => new AgentSideEventBoundary('defective-skips-executor-lifecycle', o, { ...NO_DEFECTS, skipExecutorLifecycle: true }) },
  { name: 'defective-runtime-declaration-is-consent', make: (o) => new AgentSideEventBoundary('defective-runtime-declaration-is-consent', o, { ...NO_DEFECTS, declaredIsConsented: true }) },
]
