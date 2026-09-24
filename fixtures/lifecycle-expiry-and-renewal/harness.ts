// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference authorization boundary for the lifecycle-expiry-and-renewal family.
//
// WHAT THIS IS. The proposed text this family tests is aeoess/agent-authority-lifecycle,
// AUTHORITY-LIFECYCLE.md at commit 7796e22 or later:
//
//   L10  "Both stop authority from being used. Expiry says the grant reached its planned
//        end. Revocation says someone with authority ended it early."
//   L3   "Continuity after revocation means a new grant from a principal who currently
//        holds authority."
//
// together with the three cases in the "Expiry and renewal" section of CASES.md at commit
// 2bf5c7e. draft-pidlisnyi-aps-03 decides whether a chain is currently usable. It does not
// carry a field saying which of the two endings happened, who ended it or on what ground,
// and it has no renewal operation at all. This family declares its own signed records for
// those and implements the boundary here.
//
// THE ENDING FIELD IS THE POINT. Every outcome carries `ending`, which is null, "expiry"
// or "revocation". On the three vectors where a grant has ended, the reference boundary
// and the declared boolean-validity boundary return the same verdict. Only `ending`
// differs, which is exactly the gap LC-I-007 names.
//
// VERDICT VOCABULARY. valid, invalid, not_established, not_yet_effective, suspended,
// restricted. A later record never rewrites an earlier one: where a grant was ended early
// for cause and then also reached its declared end, the ending stays "revocation" and the
// SDK's own EXPIRED answer is reported next to it, not instead of it.
//
// Node builtins only, plus the pinned SDK. No wall clock.

import {
  canonicalizeJCS,
  isPurposePermitted,
  verify,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export type Ending = null | 'expiry' | 'revocation'

export interface SignedRecord {
  profile: string
  kind: string
  record_id: string
  issuer: string
  verification_method: string
  issued_at: string
  body: Record<string, unknown>
  signature: string
}

export interface ActionEntry {
  action_ref: string
  requested_scope: string
}

export interface Outcome {
  verdict: Verdict
  reason: string
  /** Which of L10's two endings the records establish, where one has happened. */
  ending: Ending
  sdk_chain_state: string | null
  sdk_failure_code: string | null
  detail?: string
}

export interface Event {
  id: string
  check: string
  chain: AuthorityDelegationV1[]
  action: ActionEntry
  now: string
  revocation: RevocationResolution
  records: SignedRecord[]
}

export interface BoundaryOptions {
  name: string
  /** reference: true. defective-boundary-boolean-validity: false. */
  recordsEndingKind: boolean
  /** reference: false. defective-boundary-renewal-extends-identity: true. */
  treatsRenewalAsExtension: boolean
}

export interface Fixture {
  identities: Record<string, string>
  verification_keys: Record<string, string>
  record_signature_domain: string
}

const ms = (t: string): number => Date.parse(t)

function out(
  verdict: Verdict,
  reason: string,
  ending: Ending,
  chain: { state: string; code: string | null } | null,
  detail?: string,
): Outcome {
  return {
    verdict,
    reason,
    ending,
    sdk_chain_state: chain === null ? null : chain.state,
    sdk_failure_code: chain === null ? null : chain.code,
    ...(detail === undefined ? {} : { detail }),
  }
}

const REQUIRED_ROLE: Record<string, string> = {
  renewal: 'renewal_author',
  interim_instrument: 'interim_instrument_author',
  cached_decision: 'decision_attestor',
}

export class AuthorityBoundary {
  constructor(
    private readonly options: BoundaryOptions,
    private readonly fixture: Fixture,
  ) {}

  get name(): string {
    return this.options.name
  }

  opt<K extends keyof BoundaryOptions>(key: K): BoundaryOptions[K] {
    return this.options[key]
  }

  handle(event: Event): Outcome {
    const byKind = new Map<string, SignedRecord[]>()
    for (const rec of event.records) {
      if (!this.authentic(rec)) return out('not_established', 'record_not_authentic', null, null, rec.record_id)
      const list = byKind.get(rec.kind) ?? []
      list.push(rec)
      byKind.set(rec.kind, list)
    }
    const registry = byKind.get('standing_registry')?.[0]
    if (registry === undefined) return out('not_established', 'standing_registry_not_presented', null, null)
    for (const rec of event.records) {
      const role = REQUIRED_ROLE[rec.kind]
      if (role === undefined) continue
      const allowed = (registry.body[role] as string[] | undefined) ?? []
      if (!allowed.includes(rec.issuer)) {
        return out('not_established', 'record_without_standing', null, null, `${rec.record_id}/${rec.kind}`)
      }
    }
    // `revocation_notice` and `interim_extension` are deliberately absent from
    // REQUIRED_ROLE. Their standing question is the case's own question, so each rule
    // asks it itself and says so in its reason rather than in a generic one.
    const rule = RULES[event.check]
    if (rule === undefined) return out('not_established', 'unknown_check', null, null, event.check)
    return rule(this, event, byKind, registry)
  }

  authentic(rec: SignedRecord): boolean {
    const { signature, ...unsigned } = rec
    const publicKey = this.fixture.verification_keys[rec.verification_method]
    if (publicKey === undefined) return false
    return verify(`${this.fixture.record_signature_domain} ${canonicalizeJCS(unsigned)}`, signature, publicKey)
  }

  chain(event: Event, now: string): { state: string; code: string | null } {
    const result = verifyAuthorityDelegationChain(event.chain, {
      now,
      resolveVerificationKey: (_issuer: string, method: string) => this.fixture.verification_keys[method] ?? null,
      trustRoot: (root: { issuer?: string }) => root.issuer === this.fixture.identities.OFFICE,
      resolveRevocation: () => event.revocation,
    })
    return { state: result.state, code: result.failures[0]?.code ?? null }
  }

  leaf(event: Event): AuthorityDelegationV1 {
    return event.chain[event.chain.length - 1]
  }
}

type Rule = (
  b: AuthorityBoundary,
  e: Event,
  r: Map<string, SignedRecord[]>,
  registry: SignedRecord,
) => Outcome

const one = (r: Map<string, SignedRecord[]>, kind: string): SignedRecord | undefined => r.get(kind)?.[0]

const RULES: Record<string, Rule> = {
  // LC-I-007. Reaching the stated end and being cut off early for cause are two events.
  // A record set that says only "not valid" has lost the thing an investigator wants.
  // The ending field carries it, with the cause and the actor for the second path.
  ending_kind(b, e, r, registry) {
    const chain = b.chain(e, e.now)
    const notice = (r.get('revocation_notice') ?? []).find(
      (n) => n.body.grant === b.leaf(e).delegation_id,
    )
    if (notice !== undefined) {
      // Standing to end an artifact early is not the same as being able to sign. This is
      // the case's own question, so the reason names it.
      const allowed = (registry.body.lifecycle_standing as string[] | undefined) ?? []
      if (!allowed.includes(notice.issuer)) {
        return out('not_established', 'revocation_without_lifecycle_standing', null, chain, `claimed_by=${notice.issuer}`)
      }
      if (ms(e.now) >= ms(notice.body.recorded_at as string)) {
        // The ending stays "revocation" even where the SDK reports EXPIRED, because the
        // grant later also reached its declared end. The later event is a new fact about
        // an old record, not a rewrite of it.
        return out(
          'invalid',
          'ended_early_for_cause',
          b.opt('recordsEndingKind') ? 'revocation' : null,
          chain,
          b.opt('recordsEndingKind')
            ? `cause=${notice.body.cause as string} actor=${notice.body.actor as string}`
            : undefined,
        )
      }
    }
    if (chain.state === 'valid') {
      if (!isPurposePermitted(e.action.requested_scope, b.leaf(e).authority.scope.grants)) {
        return out('invalid', 'scope_not_in_grant', null, chain)
      }
      return out('valid', 'inside_declared_window', null, chain)
    }
    if (chain.code === 'EXPIRED') {
      return out('invalid', 'reached_declared_end', b.opt('recordsEndingKind') ? 'expiry' : null, chain)
    }
    if (chain.code === 'REVOKED') {
      // The resolver says revoked and no notice with standing explains it. The artifact is
      // not usable and the ground for ending it is not on the record.
      return out('invalid', 'revoked_without_a_recorded_ground', null, chain)
    }
    if (chain.code === 'NOT_YET_VALID') {
      return out('not_yet_effective', 'declared_start_not_reached', null, chain)
    }
    return out('not_established', 'chain_state_not_decidable', null, chain)
  },

  // LC-I-008. "Renewed" is ambiguous until the mechanism is known. Where the mechanism is
  // reissuance, the new artifact is evaluated on its own terms, the old one runs to its
  // own unchanged end, and evidence keyed to the old identifier does not transfer.
  renewal(b, e, r) {
    const claim = one(r, 'renewal')
    const chain = b.chain(e, e.now)
    const leafId = b.leaf(e).delegation_id
    if (claim !== undefined && claim.body.mode === 'reissue') {
      const supersedes = claim.body.supersedes as string
      const issues = claim.body.issues as string
      if (b.opt('treatsRenewalAsExtension')) {
        // The declared defect: the renewal is read as the same authority with a later end
        // date, so the superseded identifier inherits the new artifact's window and
        // evidence keyed to it carries forward.
        return out('valid', 'renewal_treated_as_extension_of_the_same_identity', null, chain, `identity=${supersedes}`)
      }
      const cached = (r.get('cached_decision') ?? []).find((c) => c.body.delegation_ref === supersedes)
      if (cached !== undefined && leafId === issues) {
        return out('not_established', 'evidence_keyed_to_superseded_artifact', null, chain, `keyed_to=${supersedes}`)
      }
      if (leafId === supersedes) {
        if (chain.code === 'EXPIRED') {
          return out('invalid', 'superseded_artifact_reached_its_own_declared_end', 'expiry', chain)
        }
      }
    }
    if (chain.code === 'ID_MISMATCH') {
      // Extending in place is not expressible: draft-03 derives the identifier from the
      // content, so changing the window changes the identifier.
      return out('invalid', 'delegation_id_does_not_bind_its_content', null, chain)
    }
    if (chain.code === 'SCOPE_WIDENING') {
      return out('invalid', 'renewal_widens_beyond_its_parent', null, chain)
    }
    if (chain.state === 'valid') {
      if (!isPurposePermitted(e.action.requested_scope, b.leaf(e).authority.scope.grants)) {
        return out('invalid', 'scope_not_in_grant', null, chain)
      }
      return out('valid', 'renewal_evaluated_on_its_own_terms', null, chain, `delegation_id=${leafId}`)
    }
    if (chain.code === 'EXPIRED') return out('invalid', 'reached_declared_end', 'expiry', chain)
    if (chain.code === 'NOT_YET_VALID') return out('not_yet_effective', 'declared_start_not_reached', null, chain)
    return out('not_established', 'chain_state_not_decidable', null, chain)
  },

  // LC-I-009. An interim mandate bounded to caretaking. Holding the authority to act for
  // an office and deciding the scope and duration of holding it are different questions.
  // This rule reads one recorded instrument. It makes no claim that the mechanism
  // generalizes, and office vacancy stays open in OPEN-QUESTIONS.md.
  interim_mandate(b, e, r) {
    const instrument = one(r, 'interim_instrument')
    if (instrument === undefined) return out('not_established', 'interim_instrument_not_recorded', null, null)
    const extension = one(r, 'interim_extension')
    if (extension !== undefined) {
      const mayExtend = (instrument.body.may_extend as string[]) ?? []
      if (!mayExtend.includes(extension.issuer)) {
        return out(
          'not_established',
          'extension_issuer_not_named_by_the_recorded_instrument',
          null,
          null,
          `claimed_by=${extension.issuer}`,
        )
      }
    }
    const chain = b.chain(e, e.now)
    if (chain.code === 'TIME_WIDENING') {
      return out('invalid', 'mandate_extension_widens_beyond_the_interim_grant', null, chain)
    }
    if (chain.code === 'EXPIRED') {
      // Even from the party the instrument names, a record saying "extended" is not a
      // fresh grant. L3: continuity means new authority from someone who currently holds it.
      return out(
        'invalid',
        extension === undefined ? 'reached_declared_end' : 'extension_record_is_not_a_fresh_grant',
        'expiry',
        chain,
      )
    }
    if (chain.state !== 'valid') return out('not_established', 'chain_state_not_decidable', null, chain)
    const caretaking = instrument.body.caretaking_scope as string[]
    if (!isPurposePermitted(e.action.requested_scope, caretaking)) {
      return out('invalid', 'outside_the_recorded_caretaking_scope', null, chain, `caretaking=${caretaking.join(',')}`)
    }
    if (!isPurposePermitted(e.action.requested_scope, b.leaf(e).authority.scope.grants)) {
      return out('invalid', 'scope_not_in_grant', null, chain)
    }
    return out('valid', 'inside_the_recorded_caretaking_scope', null, chain, `caretaking=${caretaking.join(',')}`)
  },
}

const REFERENCE: Omit<BoundaryOptions, 'name'> = {
  recordsEndingKind: true,
  treatsRenewalAsExtension: false,
}

export function makeReferenceBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary({ ...REFERENCE, name: 'reference-boundary' }, f)
}

/**
 * Negative control 1, LC-I-007. Records a boolean and nothing else: same verdict, same
 * reason, no ending, no cause, no actor. On all three vectors where a grant has ended it
 * returns the same verdict the reference boundary returns, so a checker comparing only
 * the verdict passes it. That is the whole of the defect LC-I-007 names.
 */
export function makeBooleanValidityBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary({ ...REFERENCE, name: 'defective-boundary-boolean-validity', recordsEndingKind: false }, f)
}

/**
 * Negative control 2, LC-I-008. Reads "renewed" as "the same authority, later end date",
 * so the superseded identifier keeps working and a cached decision keyed to it carries
 * forward onto what is structurally a fresh grant.
 */
export function makeRenewalExtendsIdentityBoundary(f: Fixture): AuthorityBoundary {
  return new AuthorityBoundary(
    { ...REFERENCE, name: 'defective-boundary-renewal-extends-identity', treatsRenewalAsExtension: true },
    f,
  )
}
