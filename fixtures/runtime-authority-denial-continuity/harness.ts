// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the runtime-authority-denial-continuity candidate family.
//
// WHAT THIS IS. A synthetic enforcement point in front of a small in-memory
// resource store. It is a reference model written to make two candidate
// properties from OWASP/www-project-agentic-skills-top-10#71 executable. It is
// not APS, it speaks no protocol, and it is not a real authorization system. A
// result here is a statement about this model and nothing else.
//
// THE MODEL. A protected effect is identified by resource + security-relevant
// state transition + authorization domain (issue #71 comment 5610348204), never
// by the literal tool name. A DENY for an effect is recorded in a denial
// ledger. Property A asks whether a retry, an alias tool, or a delegated call
// reaching the same effect under the same authorization state is still denied,
// and whether an explicit reauthorization bound to that effect and context is
// the only thing that lifts it (comments 5610341311, 5634265554). Property B
// asks whether a sequence of individually permitted writes that composes the
// same effect is caught -- and only for an implementation that declares it can
// identify the composed effect (comments 5595612289, 5624800343).
//
// THE THREE POLICIES differ along two independent axes:
//
//   ledger key       canonical (effect + context, tool-independent) or
//                     path-scoped (tool + effect + context)
//   composed-effect   present or absent
//   identification
//
// REFERENCE_GATE is canonical + present. FRESH_PATH_CONTROL (N1) is
// path-scoped + present, used only against Property A. PER_WRITE_CONTROL (N2)
// is canonical + absent, used only against Property B. Each negative control
// isolates one axis; running N1 against A and N2 against B is what keeps that
// isolation clean instead of blending two unrelated defects into one fail set.
//
// Node builtins only, no imports. No wall clock, no randomness: the "authority
// state" this file tracks is a generation counter advanced only by an explicit
// reauthorize() call, so nothing here is nondeterministic.

export interface EffectIdentity {
  resource: string
  transition: string
  domain: string
}

export function effectKey(e: EffectIdentity): string {
  return `${e.resource} ${e.transition} ${e.domain}`
}

export function effectsEqual(a: EffectIdentity, b: EffectIdentity): boolean {
  return effectKey(a) === effectKey(b)
}

export type Decision = 'allow' | 'deny'

export interface Outcome {
  decision: Decision
  reason: string
}

/**
 * The one thing a policy decides differently: which key binds a request to a
 * prior denial. `ledgerKey` is used for direct attempts (Property A).
 * Property B's composed-effect check always uses the canonical
 * effect+context key -- once an implementation has identified a composed
 * effect at all, checking it under a tool-scoped key would make
 * "composed-effect identification" and "path scoping" the same axis, and they
 * are not: FRESH_PATH_CONTROL is not run against Property B for exactly this
 * reason, see verify.ts.
 */
export interface PolicyProfile {
  readonly name: string
  readonly hasComposedEffectIdentification: boolean
  ledgerKey(tool: string, effect: EffectIdentity, context: string): string
}

function canonicalKey(effect: EffectIdentity, context: string): string {
  return `${effectKey(effect)} ${context}`
}

export const REFERENCE_GATE: PolicyProfile = {
  name: 'reference-gate',
  hasComposedEffectIdentification: true,
  ledgerKey(_tool, effect, context) {
    return canonicalKey(effect, context)
  },
}

/** N1: treats a different tool or a delegated path as a fresh request. */
export const FRESH_PATH_CONTROL: PolicyProfile = {
  name: 'fresh-path-control',
  hasComposedEffectIdentification: true,
  ledgerKey(tool, effect, context) {
    return `${tool} ${effectKey(effect)} ${context}`
  },
}

/** N2: canonical binding for direct attempts, but no composed-effect check. */
export const PER_WRITE_CONTROL: PolicyProfile = {
  name: 'per-write-control',
  hasComposedEffectIdentification: false,
  ledgerKey(_tool, effect, context) {
    return canonicalKey(effect, context)
  },
}

interface DenialRecord {
  key: string
  effect: EffectIdentity
  context: string
  reason: string
  denialRef: string
  deniedAtGeneration: number
  resolved: boolean
  resolvedAtGeneration: number | null
  resolvedBasis: string | null
}

export interface RecordState {
  content: string
  flags: Record<string, boolean>
  linked: boolean
  available: boolean
}

const defaultRecordState = (): RecordState => ({ content: 'original content', flags: {}, linked: true, available: true })

export class ResourceStore {
  private readonly records = new Map<string, RecordState>()

  get(id: string): RecordState {
    let state = this.records.get(id)
    if (state === undefined) {
      state = defaultRecordState()
      this.records.set(id, state)
    }
    return state
  }

  set(id: string, state: RecordState): void {
    this.records.set(id, state)
  }
}

export interface AuditEntry {
  request: string
  kind: 'deny' | 'attempt' | 'decompose_write' | 'reauthorize'
  tool: string | null
  effect: EffectIdentity | null
  context: string
  decision: Decision | 'reauthorized'
  reason: string
}

/**
 * The composed-effect pattern this harness's oracle recognizes: content
 * emptied, flagged quarantined, and unlinked from the index together are read
 * as the same "record unavailable" effect a direct delete or overwrite
 * produces. This is one implementation's effect-interpretation choice, not a
 * general algorithm; see README.md "Does not claim".
 */
function classifyComposedEffect(resourceId: string, state: RecordState): EffectIdentity | null {
  if (state.content === '' && state.flags.quarantined === true && state.linked === false) {
    return { resource: `record:${resourceId}`, transition: 'unavailable', domain: 'records' }
  }
  return null
}

export type DecomposedWrite =
  | { kind: 'set_content'; content: string }
  | { kind: 'set_flag'; flag: string; value: boolean }
  | { kind: 'unlink_index' }

function applyWrite(state: RecordState, write: DecomposedWrite): RecordState {
  switch (write.kind) {
    case 'set_content':
      return { ...state, content: write.content }
    case 'set_flag':
      return { ...state, flags: { ...state.flags, [write.flag]: write.value } }
    case 'unlink_index':
      return { ...state, linked: false }
  }
}

function atomicIdentity(resourceId: string, write: DecomposedWrite): EffectIdentity {
  const resource = `record:${resourceId}`
  switch (write.kind) {
    case 'set_content':
      return { resource, transition: 'content_updated', domain: 'records' }
    case 'set_flag':
      return { resource, transition: `flag_set:${write.flag}`, domain: 'records' }
    case 'unlink_index':
      return { resource, transition: 'unlinked', domain: 'records' }
  }
}

export class EnforcementPoint {
  private generation = 0
  private readonly ledger = new Map<string, DenialRecord>()
  readonly audit: AuditEntry[] = []

  constructor(
    private readonly policy: PolicyProfile,
    private readonly store: ResourceStore,
  ) {}

  get policyName(): string {
    return this.policy.name
  }

  /**
   * Injects a denial as ground truth: the point-of-effect gate returned
   * AUTHORITY_DENIED for this request (issue #71 comment 5593939386). This
   * harness does not model the policy that produced it; it models what must
   * happen to every subsequent attempt at the same protected effect.
   */
  deny(requestId: string, tool: string, effect: EffectIdentity, context: string, reason: string): Outcome {
    const key = this.policy.ledgerKey(tool, effect, context)
    this.ledger.set(key, {
      key,
      effect,
      context,
      reason,
      denialRef: requestId,
      deniedAtGeneration: this.generation,
      resolved: false,
      resolvedAtGeneration: null,
      resolvedBasis: null,
    })
    this.audit.push({ request: requestId, kind: 'deny', tool, effect, context, decision: 'deny', reason })
    return { decision: 'deny', reason }
  }

  /** A retry, an alias-tool call, or a delegated call attempting effect via `tool`. */
  attempt(requestId: string, tool: string, effect: EffectIdentity, context: string): Outcome {
    const key = this.policy.ledgerKey(tool, effect, context)
    const entry = this.ledger.get(key)
    let outcome: Outcome
    if (entry !== undefined && !entry.resolved) {
      outcome = { decision: 'deny', reason: 'denied_effect_continuity' }
    } else if (entry !== undefined && entry.resolved) {
      this.applyDirectEffect(effect)
      outcome = { decision: 'allow', reason: 'reauthorized' }
    } else {
      this.applyDirectEffect(effect)
      outcome = { decision: 'allow', reason: 'no_denial_on_effect' }
    }
    this.audit.push({ request: requestId, kind: 'attempt', tool, effect, context, decision: outcome.decision, reason: outcome.reason })
    return outcome
  }

  /**
   * This candidate model binds release to effect, context and exact denialRef.
   * Validate before changing the ledger or generation. Rejection adds only a
   * deny audit entry. A6 allows null when no unresolved denial matches.
   * Reference-gate replaces same-key denials (A7). N1 can retain separate
   * tool-keyed records, covered by the direct harness regression.
   */
  reauthorize(requestId: string, effect: EffectIdentity, context: string, denialRef: string | null, basis: string): Outcome {
    const candidates: DenialRecord[] = []
    for (const record of this.ledger.values()) {
      if (!record.resolved && effectsEqual(record.effect, effect) && record.context === context) {
        candidates.push(record)
      }
    }

    let outcome: Outcome
    if (candidates.length === 0 && denialRef === null) {
      outcome = { decision: 'allow', reason: 'reauthorized' }
    } else if (denialRef === null) {
      outcome = { decision: 'deny', reason: 'reauthorize_denial_ref_required' }
    } else {
      const target = candidates.find((record) => record.denialRef === denialRef)
      if (target === undefined) {
        outcome = { decision: 'deny', reason: 'reauthorize_denial_ref_not_found' }
      } else {
        this.generation += 1
        target.resolved = true
        target.resolvedAtGeneration = this.generation
        target.resolvedBasis = basis
        outcome = { decision: 'allow', reason: 'reauthorized' }
      }
    }

    this.audit.push({ request: requestId, kind: 'reauthorize', tool: null, effect, context, decision: outcome.decision, reason: outcome.reason })
    return outcome
  }

  /**
   * One individually-permitted write toward a resource. When the policy
   * declares composed-effect identification, the resulting state is checked
   * against the canonical composed-effect pattern first; only when that
   * pattern is not completed (or the policy lacks the capability) does the
   * write fall back to its own atomic identity, which a denial never targets
   * in this family's vectors.
   */
  decomposeWrite(requestId: string, tool: string, resourceId: string, write: DecomposedWrite, context: string): Outcome {
    const before = this.store.get(resourceId)
    const after = applyWrite(before, write)

    let checkEffect: EffectIdentity
    let checkKey: string
    if (this.policy.hasComposedEffectIdentification) {
      const composed = classifyComposedEffect(resourceId, after)
      if (composed !== null) {
        checkEffect = composed
        checkKey = canonicalKey(composed, context)
      } else {
        checkEffect = atomicIdentity(resourceId, write)
        checkKey = this.policy.ledgerKey(tool, checkEffect, context)
      }
    } else {
      checkEffect = atomicIdentity(resourceId, write)
      checkKey = this.policy.ledgerKey(tool, checkEffect, context)
    }

    const entry = this.ledger.get(checkKey)
    let outcome: Outcome
    if (entry !== undefined && !entry.resolved) {
      const composedHit = checkEffect.transition === 'unavailable'
      outcome = { decision: 'deny', reason: composedHit ? 'composed_effect_denied_continuity' : 'denied_effect_continuity' }
    } else {
      this.store.set(resourceId, after)
      outcome = { decision: 'allow', reason: 'individually_permitted_write' }
    }
    this.audit.push({ request: requestId, kind: 'decompose_write', tool, effect: checkEffect, context, decision: outcome.decision, reason: outcome.reason })
    return outcome
  }

  private applyDirectEffect(effect: EffectIdentity): void {
    if (effect.transition !== 'unavailable') return
    const id = effect.resource.split(':')[1]
    if (id === undefined) return
    const state = this.store.get(id)
    this.store.set(id, { ...state, available: false, content: '' })
  }
}
