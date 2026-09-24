// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the lifecycle-organization-events candidate family
// (CASES.md section "Organization events").
//
// WHAT THIS IS. Two models, and the named policies each is run under.
//
//   AuthorityBoundary   one authorization boundary: chain verification, then
//                       principal binding, then any external restriction, then
//                       any third-party consent gate. Used by LC-B-004,
//                       LC-B-012, LC-B-013, LC-B-016 and LC-B-030.
//   InFlightBoundary    an ordered timeline for one payment order: submitted,
//                       accepted by the receiving institution, stopped,
//                       settled. Used by LC-B-028 and LC-B-029.
//
// Neither reads a clock or makes a network call. Every instant comes from the
// vector, and every chain verdict comes from the SDK's chain verifier.
//
// WHAT THEY MODEL, in the vocabulary of the proposed text they are written
// against (aeoess/agent-authority-lifecycle, commit 2bf5c7e):
//
//   Principal binding      which principal a chain establishes an agent acts
//                          for. It is a separate question from whether the
//                          chain verifies.
//   Issuer standing        why a party was allowed to sign a record. Checked
//                          against the verifier's trust policy, never against
//                          what a record claims about itself.
//   External restriction   a block or a narrowing from outside the grant
//                          chain. It can stop some effects while the grant
//                          stays valid, which is why `restricted` is its own
//                          verdict here and not a flavour of invalid.
//   In-flight state        an action between authorization and a known
//                          outcome. Authority can change inside that interval.
//   Evidence               one record per event. A later event writes a new
//                          record and never rewrites an earlier one.
//
// EVERY DEFECTIVE POLICY DIFFERS FROM THE REFERENCE ALONG EXACTLY ONE
// DECLARED AXIS. A policy that simply answered differently would prove
// nothing about which implementation shape is wrong.

import { createHash } from 'node:crypto'

import {
  verify as verifyDetachedSignature,
  verifyAuthorityDelegationChain,
  verifyAuthorityDelegationSignature,
} from 'agent-passport-system'

import { canonicalizeJCS } from '../../runners/ts/canonicalize.js'

export type AuthorityVerdict =
  | 'valid'
  | 'invalid'
  | 'not established'
  | 'not yet effective'
  | 'suspended'
  | 'restricted'

export interface Fixture {
  _placeholder?: boolean
  mint_now: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chains: Record<string, any[]>
  principal_of_root: Record<string, string>
  attestor_standing: Record<string, string[] | string>
  external_records: Record<string, any>
  refusals: Record<string, { raised: boolean; code: string | null; message: string | null }>
}

/** The four axes a policy can differ along. `reference` is all four set the
 *  strict way; each defective policy flips exactly one. */
export interface PolicyProfile {
  compares_parent_linkage: boolean
  treats_corporate_record_as_delegation_event: boolean
  enforces_external_restriction: boolean
  enforces_third_party_consent: boolean
}

export const POLICY_PROFILES: Record<string, PolicyProfile> = {
  reference: {
    compares_parent_linkage: true,
    treats_corporate_record_as_delegation_event: false,
    enforces_external_restriction: true,
    enforces_third_party_consent: true,
  },
  'successor-exists-in-role': {
    compares_parent_linkage: false,
    treats_corporate_record_as_delegation_event: false,
    enforces_external_restriction: true,
    enforces_third_party_consent: true,
  },
  'corporate-record-as-delegation-event': {
    compares_parent_linkage: true,
    treats_corporate_record_as_delegation_event: true,
    enforces_external_restriction: true,
    enforces_third_party_consent: true,
  },
  'restriction-blind': {
    compares_parent_linkage: true,
    treats_corporate_record_as_delegation_event: false,
    enforces_external_restriction: false,
    enforces_third_party_consent: true,
  },
  'internal-chain-only': {
    compares_parent_linkage: true,
    treats_corporate_record_as_delegation_event: false,
    enforces_external_restriction: true,
    enforces_third_party_consent: false,
  },
}

export interface BoundaryRequest {
  chain: string
  now: string
  revocation?: Record<string, string>
  /** The principal the action requires the agent to be acting for. Null when
   *  the vector is asking only about the chain. */
  required_principal?: string | null
  operation?: string | null
  target?: string | null
  /** Keys into fixture.external_records. */
  present_records?: string[]
}

export interface BoundaryResult {
  outcome: 'admitted' | 'not_admitted'
  authority_verdict: AuthorityVerdict
  reason: string
  failure_code: string | null
  failure_index: number | null
  principal_established: string | null
}

const LINKAGE_CODES = new Set(['PARENT_MISMATCH', 'CHAIN_CONTINUITY'])

export class AuthorityBoundary {
  private readonly fixture: Fixture
  private readonly profile: PolicyProfile
  private readonly roleById = new Map<string, string>()

  constructor(fixture: Fixture, policy: string) {
    this.fixture = fixture
    const profile = POLICY_PROFILES[policy]
    if (profile === undefined) throw new Error(`unknown policy ${policy}`)
    this.profile = profile
    for (const [role, id] of Object.entries(fixture.roles)) this.roleById.set(id, role)
  }

  private answerFor(revocation: Record<string, string>) {
    return (delegation: any) => {
      const role = this.roleById.get(delegation?.delegation_id)
      if (role === undefined) {
        throw new Error('organization-events resolver received a delegation with no registered role')
      }
      return revocation[role] ?? 'active'
    }
  }

  private chainVerdict(chainName: string, now: string, revocation: Record<string, string>) {
    const result: any = verifyAuthorityDelegationChain(this.fixture.chains[chainName], {
      now,
      resolveVerificationKey: (_issuer: string, method: string) =>
        this.fixture.verification_keys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: this.answerFor(revocation) as any,
    })
    const first = Array.isArray(result.failures) ? result.failures[0] : undefined
    const verdict: AuthorityVerdict =
      result.state === 'valid' ? 'valid' : result.state === 'indeterminate' ? 'not established' : 'invalid'
    return { verdict, code: (first?.code ?? null) as string | null, index: (typeof first?.index === 'number' ? first.index : null) }
  }

  /** The linkage-blind path: the root is verified as its own chain and the
   *  leaf is checked on its own, with no comparison between them. This is the
   *  shape of an implementation that asks "is there a currently valid holder
   *  of this role" and then evaluates the leaf against that answer. */
  private linkageBlindVerdict(chainName: string, now: string, revocation: Record<string, string>) {
    const chain = this.fixture.chains[chainName]
    const rootOnly: any = verifyAuthorityDelegationChain([chain[0]], {
      now,
      resolveVerificationKey: (_issuer: string, method: string) =>
        this.fixture.verification_keys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: this.answerFor(revocation) as any,
    })
    if (rootOnly.state !== 'valid') {
      const first = Array.isArray(rootOnly.failures) ? rootOnly.failures[0] : undefined
      return { verdict: 'invalid' as AuthorityVerdict, code: (first?.code ?? null) as string | null, index: 0 }
    }
    const answer = this.answerFor(revocation)
    for (let i = 1; i < chain.length; i += 1) {
      const record = chain[i]
      const key = this.fixture.verification_keys[record.verification_method]
      if (typeof key !== 'string' || !verifyAuthorityDelegationSignature(record, key)) {
        return { verdict: 'invalid' as AuthorityVerdict, code: 'SIGNATURE_INVALID', index: i }
      }
      const time = record.authority.time
      if (now < time.not_before) return { verdict: 'invalid' as AuthorityVerdict, code: 'NOT_YET_VALID', index: i }
      if (now > time.not_after) return { verdict: 'invalid' as AuthorityVerdict, code: 'EXPIRED', index: i }
      if (answer(record) === 'revoked') return { verdict: 'invalid' as AuthorityVerdict, code: 'REVOKED', index: i }
    }
    return { verdict: 'valid' as AuthorityVerdict, code: null as string | null, index: null as number | null }
  }

  /** True when the record's signature verifies over its own canonical bytes. */
  private externalRecordAuthentic(record: any): boolean {
    const { signature, ...body } = record
    const key = this.fixture.verification_keys[`${record.attestor}#key-1`]
    if (typeof key !== 'string' || typeof signature !== 'string') return false
    return verifyDetachedSignature(canonicalizeJCS({ ...body }), signature, key) === true
  }

  /** Standing comes from the verifier's trust policy, never from what the
   *  record claims about itself. */
  private attestorHasStanding(record: any): boolean {
    const rule = this.fixture.attestor_standing[record.record_type]
    if (rule === undefined) return false
    if (rule === 'gate_holder') return record.attestor === record.gate_holder
    return Array.isArray(rule) && rule.includes(record.attestor)
  }

  evaluate(request: BoundaryRequest): BoundaryResult {
    const revocation = request.revocation ?? {}
    const chain = this.fixture.chains[request.chain]
    const rootId = chain[0].delegation_id
    const principalOfRoot = this.fixture.principal_of_root[rootId] ?? null

    const verdict = this.profile.compares_parent_linkage
      ? this.chainVerdict(request.chain, request.now, revocation)
      : (() => {
          const strict = this.chainVerdict(request.chain, request.now, revocation)
          // The axis bites only where the strict verdict failed on linkage.
          return strict.code !== null && LINKAGE_CODES.has(strict.code)
            ? this.linkageBlindVerdict(request.chain, request.now, revocation)
            : strict
        })()

    if (verdict.verdict !== 'valid') {
      return {
        outcome: 'not_admitted',
        authority_verdict: verdict.verdict,
        reason: 'chain_not_valid',
        failure_code: verdict.code,
        failure_index: verdict.index,
        principal_established: null,
      }
    }

    const presented = (request.present_records ?? []).map(name => this.fixture.external_records[name])

    // Principal binding. A corporate succession record can be authentic, can
    // come from a party with standing, and is still not a delegation-layer
    // event. Whether this boundary treats it as one is the declared axis.
    let principalEstablished = principalOfRoot
    if (request.required_principal != null && principalEstablished !== request.required_principal) {
      const succession = presented.find((r: any) => r?.record_type === 'aac:corporate-succession:v0')
      if (succession === undefined) {
        return {
          outcome: 'not_admitted', authority_verdict: 'not established',
          reason: 'principal_binding_not_established', failure_code: null, failure_index: null,
          principal_established: principalEstablished,
        }
      }
      if (!this.externalRecordAuthentic(succession)) {
        return {
          outcome: 'not_admitted', authority_verdict: 'not established',
          reason: 'attestation_signature_invalid', failure_code: null, failure_index: null,
          principal_established: principalEstablished,
        }
      }
      if (!this.attestorHasStanding(succession)) {
        return {
          outcome: 'not_admitted', authority_verdict: 'not established',
          reason: 'attestation_attestor_without_standing', failure_code: null, failure_index: null,
          principal_established: principalEstablished,
        }
      }
      if (!this.profile.treats_corporate_record_as_delegation_event) {
        return {
          outcome: 'not_admitted', authority_verdict: 'not established',
          reason: 'corporate_record_is_not_a_delegation_event', failure_code: null, failure_index: null,
          principal_established: principalEstablished,
        }
      }
      principalEstablished = succession.surviving
    }

    // External restriction. The grant stays valid. What it covers narrows.
    let verdictSoFar: AuthorityVerdict = 'valid'
    if (this.profile.enforces_external_restriction) {
      for (const record of presented) {
        if (record?.record_type !== 'aac:external-restriction:v0') continue
        if (record.about_principal !== principalOfRoot) continue
        if (!this.externalRecordAuthentic(record) || !this.attestorHasStanding(record)) continue
        if (record.effective_at > request.now) continue
        verdictSoFar = 'restricted'
        if (request.operation != null && !record.remaining_operations.includes(request.operation)) {
          return {
            outcome: 'not_admitted', authority_verdict: 'restricted',
            reason: 'external_restriction_excludes_operation', failure_code: null, failure_index: null,
            principal_established: principalEstablished,
          }
        }
      }
    }

    // Third-party consent gate, keyed to the exact target the action names.
    if (this.profile.enforces_third_party_consent && request.target != null) {
      const consents = presented.filter((r: any) => r?.record_type === 'aac:third-party-consent:v0')
      const authentic = consents.filter((r: any) => this.externalRecordAuthentic(r))
      const forTarget = authentic.filter((r: any) => r.target === request.target && r.operation === request.operation)
      if (forTarget.length === 0) {
        const reason = authentic.length === 0
          ? 'third_party_consent_absent'
          : 'consent_target_mismatch'
        return {
          outcome: 'not_admitted', authority_verdict: 'not established',
          reason, failure_code: null, failure_index: null,
          principal_established: principalEstablished,
        }
      }
      if (!forTarget.some((r: any) => this.attestorHasStanding(r))) {
        return {
          outcome: 'not_admitted', authority_verdict: 'not established',
          reason: 'consent_attestor_without_standing', failure_code: null, failure_index: null,
          principal_established: principalEstablished,
        }
      }
    }

    return {
      outcome: 'admitted', authority_verdict: verdictSoFar,
      reason: verdictSoFar === 'restricted' ? 'admitted_within_remaining_scope' : 'admitted',
      failure_code: null, failure_index: null,
      principal_established: principalEstablished,
    }
  }
}

// ---------------------------------------------------------------------------
// In-flight timelines, for LC-B-028 and LC-B-029.
// ---------------------------------------------------------------------------

export type InFlightPolicy =
  | 'reference'
  | 'approval-time-check-only'
  | 'revocation-halts-everything'

export interface FlowResult {
  outcome: string
  order_state: string
  reason: string
  authority_verdict: AuthorityVerdict | null
  failure_code: string | null
}

interface OrderState {
  state: 'submitted' | 'accepted' | 'stopped' | 'not_accepted' | 'settled' | 'not_settled'
}

export class InFlightBoundary {
  private readonly fixture: Fixture
  private readonly policy: InFlightPolicy
  private readonly orders = new Map<string, OrderState>()
  private readonly revoked = new Set<string>()
  private readonly roleById = new Map<string, string>()

  constructor(fixture: Fixture, policy: InFlightPolicy) {
    this.fixture = fixture
    this.policy = policy
    for (const [role, id] of Object.entries(fixture.roles)) this.roleById.set(id, role)
  }

  private chainVerdict(chainName: string, now: string) {
    const revoked = this.revoked
    const byId = this.roleById
    const result: any = verifyAuthorityDelegationChain(this.fixture.chains[chainName], {
      now,
      resolveVerificationKey: (_issuer: string, method: string) =>
        this.fixture.verification_keys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: ((delegation: any) =>
        revoked.has(byId.get(delegation?.delegation_id)!) ? 'revoked' : 'active') as any,
    })
    const first = Array.isArray(result.failures) ? result.failures[0] : undefined
    const verdict: AuthorityVerdict = result.state === 'valid' ? 'valid' : 'invalid'
    return { verdict, code: (first?.code ?? null) as string | null }
  }

  step(event: any): FlowResult {
    if (event.kind === 'submit') {
      const { verdict, code } = this.chainVerdict(event.chain, event.now)
      if (verdict !== 'valid') {
        return { outcome: 'not_admitted', order_state: 'none', reason: 'chain_not_valid', authority_verdict: verdict, failure_code: code }
      }
      this.orders.set(event.order, { state: 'submitted' })
      return { outcome: 'admitted', order_state: 'submitted', reason: 'order_submitted', authority_verdict: 'valid', failure_code: null }
    }

    if (event.kind === 'revoke') {
      this.revoked.add(event.role)
      return { outcome: 'recorded', order_state: 'n/a', reason: 'revocation_recorded', authority_verdict: null, failure_code: null }
    }

    if (event.kind === 'stop') {
      const order = this.orders.get(event.order)!
      // The declared axis for this policy: it checked for a stop only when the
      // order was authorized, so a stop that arrives afterwards never works,
      // whichever side of acceptance it lands on.
      if (this.policy === 'approval-time-check-only') {
        return { outcome: 'stop_not_effective', order_state: order.state, reason: 'authorization_settled_at_submission', authority_verdict: null, failure_code: null }
      }
      if (order.state === 'submitted') {
        order.state = 'stopped'
        return { outcome: 'stop_effective', order_state: 'stopped', reason: 'stop_received_before_acceptance', authority_verdict: null, failure_code: null }
      }
      return { outcome: 'stop_not_effective', order_state: order.state, reason: 'stop_received_after_acceptance', authority_verdict: null, failure_code: null }
    }

    if (event.kind === 'accept') {
      const order = this.orders.get(event.order)!
      if (order.state === 'stopped') {
        return { outcome: 'not_accepted', order_state: 'stopped', reason: 'stopped_before_acceptance', authority_verdict: null, failure_code: null }
      }
      const { verdict, code } = this.chainVerdict(event.chain, event.now)
      if (verdict !== 'valid') {
        order.state = 'not_accepted'
        return { outcome: 'not_accepted', order_state: 'not_accepted', reason: 'authority_ended_before_acceptance', authority_verdict: verdict, failure_code: code }
      }
      order.state = 'accepted'
      return { outcome: 'accepted', order_state: 'accepted', reason: 'accepted_by_receiving_institution', authority_verdict: 'valid', failure_code: null }
    }

    if (event.kind === 'settle') {
      const order = this.orders.get(event.order)!
      if (order.state === 'accepted') {
        // The declared axis for this policy: it treats a revocation as halting
        // anything already submitted, acceptance or not.
        if (this.policy === 'revocation-halts-everything' && this.revoked.size > 0) {
          order.state = 'not_settled'
          return { outcome: 'not_settled', order_state: 'not_settled', reason: 'revocation_halts_submitted_orders', authority_verdict: null, failure_code: null }
        }
        order.state = 'settled'
        return { outcome: 'settled', order_state: 'settled', reason: 'accepted_order_proceeds', authority_verdict: null, failure_code: null }
      }
      const reason = order.state === 'stopped' ? 'stopped_before_acceptance' : 'never_accepted'
      order.state = 'not_settled'
      return { outcome: 'not_settled', order_state: 'not_settled', reason, authority_verdict: null, failure_code: null }
    }

    if (event.kind === 'present_new') {
      const { verdict, code } = this.chainVerdict(event.chain, event.now)
      if (verdict !== 'valid') {
        return { outcome: 'not_admitted', order_state: 'none', reason: 'chain_not_valid', authority_verdict: verdict, failure_code: code }
      }
      return { outcome: 'admitted', order_state: 'submitted', reason: 'order_submitted', authority_verdict: 'valid', failure_code: null }
    }

    throw new Error(`unknown in-flight event kind ${event.kind}`)
  }
}

export function digestOf(value: unknown): string {
  return createHash('sha256').update(canonicalizeJCS(value), 'utf8').digest('hex')
}
