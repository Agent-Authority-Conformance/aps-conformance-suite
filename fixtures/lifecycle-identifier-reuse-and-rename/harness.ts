// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The external-identifier dependency boundary this family supplies, plus the
// declared defective negative control it is measured against.
//
// Neither reference SDK exposes an API that decides whether an authority path whose
// recovery or verification depends on an external identifier still depends on the
// same party. This boundary is therefore the fixture's own code, not an SDK
// conformance result. It calls the TypeScript SDK for the two things the SDK does
// decide: the grant chain's structural, temporal, signature and revocation state
// (verifyAuthorityDelegationChain) and RFC 8785 JCS canonical bytes plus Ed25519
// verification for the custodian records (canonicalizeJCS, verify). See README.

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationV1,
  type RevocationResolution,
} from 'agent-passport-system'

/** The settled lifecycle verdict vocabulary, as far as this family needs it. */
export type Verdict = 'valid' | 'invalid' | 'not_established'

export interface Outcome {
  verdict: Verdict
  reason: string
  detail?: string
  chain_state?: string
  /** Who the custodian records say holds the identifier at the action instant, when
   *  the boundary could establish that at all. */
  controller_at_instant?: string | null
}

export interface Binding {
  identifier_kind: string
  identifier: string
  controller: string
  bound_from: string
  bound_until: string | null
  custodian: string
  binding_id: string
  signature: string
  [key: string]: unknown
}

export interface Retention {
  identifier_kind: string
  identifier: string
  retained_from: string
  retained_until: string
  custodian: string
  retention_id: string
  signature: string
  [key: string]: unknown
}

export interface Presentation {
  label: string
  grant: AuthorityDelegationV1
  /** The identifier the action in fact relies on, whether or not the grant says so. */
  reliesOnKind: string
  reliesOnIdentifier: string
  bindings: readonly Binding[]
  retentions: readonly Retention[]
  at: string
  resolveRevocation: () => RevocationResolution
}

export interface BoundaryOptions {
  /** The one custodian this boundary resolves per identifier kind. */
  custodianStanding: Record<string, string>
  custodianKeys: Record<string, string>
  resolveDelegationVerificationKey: (issuer: string, method: string) => string | null
  trustRoot: (root: AuthorityDelegationV1) => boolean
}

export const BINDING_SIGNED_FIELDS_DROPPED = ['binding_id', 'signature'] as const
export const RETENTION_SIGNED_FIELDS_DROPPED = ['retention_id', 'signature'] as const

function bodyOf(record: Record<string, unknown>, drop: readonly string[]): unknown {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (!drop.includes(key)) body[key] = value
  }
  return body
}

/** Half-open [from, until). A null `until` is open-ended. */
function covers(from: string, until: string | null, instant: string): boolean {
  if (instant < from) return false
  if (until === null) return true
  return instant < until
}

type Interval = { from: string; until: string | null }

/** Subtract a covered interval from a list of gaps, half-open throughout. */
function subtract(gaps: Interval[], from: string, until: string): Interval[] {
  const out: Interval[] = []
  for (const gap of gaps) {
    const gapUntil = gap.until
    if (gapUntil !== null && from >= gapUntil) {
      out.push(gap)
      continue
    }
    if (until <= gap.from) {
      out.push(gap)
      continue
    }
    if (from > gap.from) out.push({ from: gap.from, until: from })
    if (gapUntil === null || until < gapUntil) out.push({ from: until, until: gapUntil })
  }
  return out
}

export function dependencyGrant(kind: string, identifier: string): string {
  return `extid:${kind}:${identifier}`
}

export class IdentifierDependencyBoundary {
  readonly name: string
  private readonly options: BoundaryOptions
  /** When true, an undeclared dependency is treated as no dependency. */
  private readonly undeclaredAdmits: boolean
  /** When true, an absent controller pin is treated as satisfied. */
  private readonly unpinnedAdmits: boolean
  /** When true, the identifier string matching is the whole check. */
  private readonly stringMatchIsEnough: boolean
  /** When true, standing is read from the record's own `custodian` field. */
  private readonly trustsSelfAssertedCustodian: boolean

  constructor(
    name: string,
    options: BoundaryOptions,
    defects: {
      undeclaredAdmits: boolean
      unpinnedAdmits: boolean
      stringMatchIsEnough: boolean
      trustsSelfAssertedCustodian: boolean
    },
  ) {
    this.name = name
    this.options = options
    this.undeclaredAdmits = defects.undeclaredAdmits
    this.unpinnedAdmits = defects.unpinnedAdmits
    this.stringMatchIsEnough = defects.stringMatchIsEnough
    this.trustsSelfAssertedCustodian = defects.trustsSelfAssertedCustodian
  }

  /** A custodian record counts only when its signature verifies AND this boundary
   *  resolves its issuer as the custodian for that identifier kind. A valid
   *  signature establishes who signed. It does not by itself establish standing. */
  private acceptable<T extends { identifier_kind: string; custodian: string; signature: string }>(
    records: readonly T[],
    drop: readonly string[],
  ): T[] {
    return records.filter((record) => {
      const key = this.options.custodianKeys[record.custodian]
      if (key === undefined) return false
      if (!verifyEd25519(canonicalizeJCS(bodyOf(record, drop)), record.signature, key)) return false
      if (this.trustsSelfAssertedCustodian) return true
      return this.options.custodianStanding[record.identifier_kind] === record.custodian
    })
  }

  admit(p: Presentation): Outcome {
    // Step 0. The grant itself, decided by the SDK. An identifier changing hands is
    // not a revocation, so this step has to stay separate from everything below it.
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

    const grants = p.grant.authority.scope.grants
    const dependency = dependencyGrant(p.reliesOnKind, p.reliesOnIdentifier)

    // Step 1. Is the dependency in the grant at all. A verifier that never modelled
    // the identifier has no record to invalidate when control of it moves.
    if (!grants.includes(dependency)) {
      if (!this.undeclaredAdmits) {
        return {
          verdict: 'not_established',
          reason: 'identifier_dependency_not_declared',
          detail: dependency,
          chain_state: chain.state,
          controller_at_instant: null,
        }
      }
    }

    // Step 2. Does the grant pin who controls it.
    const pinPrefix = `${dependency}:controller:`
    const pins = grants.filter((g) => g.startsWith(pinPrefix)).map((g) => g.slice(pinPrefix.length))
    if (pins.length === 0) {
      if (!this.unpinnedAdmits) {
        // The grant names a string and says nothing about who holds it, so continuity
        // of the thing named is not something the grant establishes either way.
        return {
          verdict: 'not_established',
          reason: 'identifier_controller_not_pinned',
          detail: dependency,
          chain_state: chain.state,
          controller_at_instant: null,
        }
      }
    }

    if (this.stringMatchIsEnough) {
      // The defect: the string in the grant equals the string being relied on, so the
      // dependency is treated as satisfied. No custodian record is ever read.
      return {
        verdict: 'valid',
        reason: 'identifier_continuity_established',
        detail: `matched=${dependency}`,
        chain_state: chain.state,
        controller_at_instant: pins[0] ?? null,
      }
    }

    const relevant = this.acceptable(p.bindings, BINDING_SIGNED_FIELDS_DROPPED).filter(
      (b) => b.identifier_kind === p.reliesOnKind && b.identifier === p.reliesOnIdentifier,
    )

    // Step 3. Who holds the identifier at the action instant, according to records
    // from a custodian this boundary resolves for that kind.
    const atInstant = relevant.filter((b) => covers(b.bound_from, b.bound_until, p.at))
    const holders = [...new Set(atInstant.map((b) => b.controller))].sort()
    if (holders.length === 0) {
      return {
        verdict: 'not_established',
        reason: 'identifier_binding_lapsed',
        detail: `no_binding_covers=${p.at}`,
        chain_state: chain.state,
        controller_at_instant: null,
      }
    }
    if (holders.length > 1) {
      return {
        verdict: 'not_established',
        reason: 'identifier_binding_conflict',
        detail: `holders=${holders.join('|')}`,
        chain_state: chain.state,
        controller_at_instant: null,
      }
    }
    const holder = holders[0]
    if (!pins.includes(holder)) {
      // The string is the same. The party behind it is not.
      return {
        verdict: 'not_established',
        reason: 'identifier_controller_changed',
        detail: `pinned=${pins.join('|')} holder=${holder}`,
        chain_state: chain.state,
        controller_at_instant: holder,
      }
    }

    // Step 4. Continuity since the grant was issued. The holder now being the pinned
    // holder says nothing about whether the identifier was continuously theirs, and
    // an interval where it was held by nobody is an interval where anyone could have
    // taken it. A retention record from the custodian is what closes that interval.
    let gaps: Interval[] = [{ from: p.grant.issued_at, until: p.at }]
    for (const b of relevant) {
      if (b.controller !== holder) continue
      gaps = subtract(gaps, b.bound_from, b.bound_until ?? p.at)
    }
    if (gaps.length > 0) {
      const acceptableRetentions = this.acceptable(p.retentions, RETENTION_SIGNED_FIELDS_DROPPED).filter(
        (r) => r.identifier_kind === p.reliesOnKind && r.identifier === p.reliesOnIdentifier,
      )
      let uncovered = gaps
      for (const r of acceptableRetentions) uncovered = subtract(uncovered, r.retained_from, r.retained_until)
      if (uncovered.length > 0) {
        // A retention record that exists but does not count is worth naming apart from
        // there being no retention record at all.
        const presentButUnacceptable = p.retentions.filter(
          (r) =>
            r.identifier_kind === p.reliesOnKind &&
            r.identifier === p.reliesOnIdentifier &&
            !acceptableRetentions.some((ok) => ok.retention_id === r.retention_id),
        )
        let covered = uncovered
        for (const r of presentButUnacceptable) covered = subtract(covered, r.retained_from, r.retained_until)
        if (covered.length === 0) {
          return {
            verdict: 'not_established',
            reason: 'retention_custodian_without_standing',
            detail: presentButUnacceptable.map((r) => r.custodian).sort().join('|'),
            chain_state: chain.state,
            controller_at_instant: holder,
          }
        }
        return {
          verdict: 'not_established',
          reason: 'identifier_continuity_gap_uncovered',
          detail: uncovered.map((g) => `${g.from}..${g.until ?? 'open'}`).join(','),
          chain_state: chain.state,
          controller_at_instant: holder,
        }
      }
      return {
        verdict: 'valid',
        reason: 'identifier_continuity_established',
        detail: `retained_gap=${gaps.map((g) => `${g.from}..${g.until ?? 'open'}`).join(',')}`,
        chain_state: chain.state,
        controller_at_instant: holder,
      }
    }

    return {
      verdict: 'valid',
      reason: 'identifier_continuity_established',
      detail: 'continuously_bound',
      chain_state: chain.state,
      controller_at_instant: holder,
    }
  }
}

export function makeReferenceBoundary(options: BoundaryOptions): IdentifierDependencyBoundary {
  return new IdentifierDependencyBoundary('reference-boundary', options, {
    undeclaredAdmits: false,
    unpinnedAdmits: false,
    stringMatchIsEnough: false,
    trustsSelfAssertedCustodian: false,
  })
}

/** The declared negative control: one coherent implementation of "the address on
 *  file has not changed". It keeps the SDK chain check unchanged and removes exactly
 *  four things: the requirement that a dependency be declared, the requirement that
 *  a controller be pinned, every reading of a custodian record, and the resolution of
 *  custodian standing from the identifier kind. It is what a system looks like when
 *  the identifier was never a modelled authority artifact, only a string other
 *  artifacts silently depend on. */
export function makeDefectiveBoundary(options: BoundaryOptions): IdentifierDependencyBoundary {
  return new IdentifierDependencyBoundary('defective-boundary-the-string-is-the-identifier', options, {
    undeclaredAdmits: true,
    unpinnedAdmits: true,
    stringMatchIsEnough: true,
    trustsSelfAssertedCustodian: true,
  })
}
