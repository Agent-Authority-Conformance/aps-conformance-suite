// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference components for the arap-reevaluation-context candidate family:
// candidate cases against openid/authzen PR #745, which proposes what Context a
// PEP sends at re-evaluation (#663). Line numbers cite the profile file as
// PR #745 head 9bd238a applied locally to main 4deba63 (see README.md).
//
// The PDP approval verifier, the ledger and the structural comparison come
// unchanged from fixtures/arap-binding/harness.ts. This file adds:
//   1. a PEP that builds re-evaluation Context by its ordinary rules (822-826);
//   2. an approval-only PEP, the shape #663 reported, as a negative control;
//   3. a PDP that compares only the bound members present in the request,
//      the defect 982 rules out, as a negative control;
//   4. the member-set comparison PR #745's description names as the test for
//      822-824: the same operation evaluated with and without an approval;
//   5. four PEPs that drop or alter the approval, as negative controls for
//      822's requirement that the approval is included unchanged;
//   6. a PEP whose first request differs from its later ones, as a negative
//      control on the runner checking the request actually sent.
// None of these is an AuthZEN implementation. Nothing reads wall time.

import {
  CORRECT_APPROVAL_VERIFIER,
  structurallyEqual,
  type ApprovalVerifier,
  type AuthzenContext,
} from '../arap-binding/harness.js'

export { CORRECT_APPROVAL_VERIFIER }

/** One ordinary Context rule of the PEP: which member, from which input, under which condition. */
export interface ContextRule {
  member: string
  /** Name of the input the value comes from. */
  input: string
  /** Name of a boolean input; the member is included only while it is true. */
  when?: string
}

/** What the PEP can reach at the moment it builds a request. A missing key is an unreachable input. */
export type Inputs = Record<string, unknown>

export type BuildResult =
  | { kind: 'request'; context: AuthzenContext }
  | { kind: 'stop'; unreachable: string }

/** Ordinary Access Evaluation Context, no approval. */
export function buildOrdinaryContext(rules: readonly ContextRule[], inputs: Inputs): BuildResult {
  const context: AuthzenContext = {}
  for (const r of rules) {
    if (r.when !== undefined) {
      if (!(r.when in inputs)) return { kind: 'stop', unreachable: r.when }
      if (inputs[r.when] !== true) continue
    }
    if (!(r.input in inputs)) return { kind: 'stop', unreachable: r.input }
    context[r.member] = inputs[r.input]
  }
  return { kind: 'request', context }
}

export interface Pep {
  readonly name: string
  buildReevaluation(rules: readonly ContextRule[], inputs: Inputs, approval: Record<string, unknown>): BuildResult
}

/** 822-826: the ordinary rules, plus the approval unchanged at context.approval. */
export const ORDINARY_RULES_PEP: Pep = {
  name: 'ordinary-rules',
  buildReevaluation(rules, inputs, approval) {
    const built = buildOrdinaryContext(rules, inputs)
    if (built.kind === 'stop') return built
    return { kind: 'request', context: { ...built.context, approval } }
  },
}

/**
 * Negative control: the shape #663 reported, where presenting an approval
 * replaces ordinary construction with only `approval` and `time`. 824 forbids it.
 */
export const APPROVAL_ONLY_PEP: Pep = {
  name: 'approval-only',
  buildReevaluation(_rules, inputs, approval) {
    const context: AuthzenContext = { approval }
    if ('now' in inputs) context.time = inputs.now
    return { kind: 'request', context }
  },
}

/**
 * The test PR #745's description proposes for 822-824: evaluate the same
 * operation without an approval and compare member sets. `ordinary` is the
 * ordinary construction, built before the PEP runs, and `reeval` is the one
 * request the PEP actually emitted. Equal, after removing `approval`, for a
 * PEP that follows 822-824.
 */
export function memberSetsMatch(ordinary: BuildResult, reeval: BuildResult): boolean {
  if (ordinary.kind !== 'request' || reeval.kind !== 'request') return ordinary.kind === reeval.kind
  const { approval: _a, ...rest } = reeval.context
  const a = Object.keys(ordinary.context).sort()
  const b = Object.keys(rest).sort()
  return a.length === b.length && a.every((k, i) => k === b[i])
}

/**
 * Negative control for 982: the reference verifier with one change, a bound
 * member absent from the request is skipped rather than compared. Done by
 * filling each absent bound member from the bound Context before calling the
 * reference verifier, so every other check is the reference one.
 */
export function presentOnlyVerifier(boundContext: AuthzenContext, boundMembers: readonly string[]): ApprovalVerifier {
  return {
    name: 'present-only-pdp',
    verify(presented, evaluation, nowMs, verifyingPdpId, ledger, jwks, policy) {
      const filled: AuthzenContext = { ...evaluation.context }
      for (const m of boundMembers) if (!(m in filled) && m in boundContext) filled[m] = boundContext[m]
      return CORRECT_APPROVAL_VERIFIER.verify(presented, { ...evaluation, context: filled }, nowMs, verifyingPdpId, ledger, jwks, policy)
    },
  }
}

/** Negative control for 822: the ordinary rules, with the approval left out of the request. */
export const DROP_APPROVAL_PEP: Pep = {
  name: 'drop-approval',
  buildReevaluation(rules, inputs, _approval) {
    return buildOrdinaryContext(rules, inputs)
  },
}

/** Negative control for 822: the ordinary rules, with a different approval id. */
export const CHANGED_ID_PEP: Pep = {
  name: 'changed-approval-id',
  buildReevaluation(rules, inputs, approval) {
    return ORDINARY_RULES_PEP.buildReevaluation(rules, inputs, { ...approval, id: `${String(approval.id)}-x` })
  },
}

/**
 * Negative control for 822: rewrites `approved_at` in place on the approval
 * object it was handed, then includes that same object. Caught only if the
 * runner keeps its own pristine copy of the approval.
 */
export const IN_PLACE_APPROVAL_PEP: Pep = {
  name: 'in-place-approval-rewrite',
  buildReevaluation(rules, inputs, approval) {
    approval.approved_at = '2099-01-01T00:00:00Z'
    return ORDINARY_RULES_PEP.buildReevaluation(rules, inputs, approval)
  },
}

/**
 * Negative control for the runner itself: a PEP whose first request carries a
 * member no ordinary rule produces, and whose later requests are clean. Caught
 * only if the member-set test runs on the request the PEP actually emitted.
 * A fresh instance is made for each case.
 */
export function makeAlternatingPep(): Pep {
  let calls = 0
  return {
    name: 'alternating-extra-member',
    buildReevaluation(rules, inputs, approval) {
      calls += 1
      const built = ORDINARY_RULES_PEP.buildReevaluation(rules, inputs, approval)
      if (built.kind === 'request' && calls % 2 === 1) return { kind: 'request', context: { ...built.context, unexpected: 'not-an-ordinary-member' } }
      return built
    },
  }
}

/**
 * Negative control for 822: the ordinary rules, with one approval timestamp
 * rewritten. A PDP that resolves the approval by id from trusted state still
 * applies it, so only the unchanged-approval check catches this one.
 */
export const CHANGED_TIMESTAMP_PEP: Pep = {
  name: 'changed-approval-timestamp',
  buildReevaluation(rules, inputs, approval) {
    return ORDINARY_RULES_PEP.buildReevaluation(rules, inputs, { ...approval, approved_until: '2099-01-01T00:00:00Z' })
  },
}
