// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the lifecycle-shared-identity-with-no-accountable-principal
// candidate family.
//
// WHAT THIS IS. One pure evaluator over one record shape. It is a reference
// model written to make proposed text executable. It is not APS, it speaks no
// protocol, and it is not a real authorization system. A result here is a
// statement about this model and nothing else.
//
// TWO VERDICTS AND A FLAG. `authority_verdict` is the state of the authority the
// acting identity holds. `accountability_verdict` is whether the record set
// establishes which individual is accountable for this action. They are computed
// from disjoint inputs on purpose: the whole section exists because a perfectly
// good chain says nothing about who was driving. `anomaly` is a third field and
// not a verdict: it records whether an unscoped all-powerful identity was used
// on or off its own enumerated required-list.
//
// WHAT not_established MEANS HERE. That the record set does not establish who is
// accountable. It is not a claim that nobody is, and it is not a claim that the
// action was unauthorized. Naming a person the records do not place at the
// keyboard would be a worse answer than this one, which is why the overlapping
// case resolves this way rather than to a tie-break.
//
// DETERMINISM. Node builtins only, no imports. No randomness, no wall clock.

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export type Anomaly = 'not_applicable' | 'on_enumerated_list' | 'off_enumerated_list'

export interface Outcome {
  authority_verdict: Verdict
  accountability_verdict: Verdict
  reason: string
  anomaly: Anomaly
}

export interface Checkout {
  individual: string
  from: string
  to: string
  signer_key_id: string
  signer_has_standing: boolean
}

export interface AttributionRecord {
  kind: string
  individual: string
  recorded_at: string
  signer_key_id: string
  signer_has_standing: boolean
  references_record_sha256: string
}

export interface Input {
  evaluated_at: string
  chain_state: Verdict
  identity: { identity_id: string; kind: 'individual' | 'shared' | 'privileged_unscoped' }
  action: { at: string; task: string }
  privileged_task_list: string[]
  checkouts: Checkout[]
  attribution_records: AttributionRecord[]
  record_sha256: string
}

function instant(iso: string): number {
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) throw new Error(`not an RFC 3339 instant: ${iso}`)
  return ms
}

/** Whether an unscoped all-powerful identity was reached for on or off its own
 *  enumerated list. Computed for that identity kind only: for anything else the
 *  question does not arise. */
export function anomalyFor(input: Input): Anomaly {
  if (input.identity.kind !== 'privileged_unscoped') return 'not_applicable'
  return input.privileged_task_list.includes(input.action.task) ? 'on_enumerated_list' : 'off_enumerated_list'
}

/** The accountability axis, on its own. Callers pass flags for the two things a
 *  weaker implementation skips, so the negative controls are this same function
 *  under different flags rather than a second copy of the rules. */
function accountability(
  input: Input,
  opts: { checkCheckoutInterval: boolean; checkCheckoutMultiplicity: boolean },
): { verdict: Verdict; reason: string } {
  if (input.identity.kind === 'individual') {
    return { verdict: 'valid', reason: 'individual_identity_bound' }
  }

  const withStanding = input.checkouts.filter(c => c.signer_has_standing)
  const actionAt = instant(input.action.at)
  const covering = opts.checkCheckoutInterval
    ? withStanding.filter(c => actionAt >= instant(c.from) && actionAt <= instant(c.to))
    : withStanding

  if (covering.length === 1) {
    return { verdict: 'valid', reason: 'individual_bound_by_checkout' }
  }
  if (covering.length > 1) {
    // A broker that was supposed to make the identity exclusive did not.
    // Resolving to one of them would name someone the records do not establish
    // acted, so this resolves to neither.
    return opts.checkCheckoutMultiplicity
      ? { verdict: 'not_established', reason: 'overlapping_checkouts' }
      : { verdict: 'valid', reason: 'individual_bound_by_checkout' }
  }
  if (withStanding.length > 0) {
    // A checkout exists for this identity, and none of them covers this action.
    return { verdict: 'not_established', reason: 'no_checkout_covers_the_action' }
  }

  // No checkout at all. A later record from a party with standing, referencing
  // this boundary's record, can still close the gap.
  const attributions = input.attribution_records
  if (attributions.length === 0) {
    return { verdict: 'not_established', reason: 'shared_identity_attribution_pending_or_external' }
  }
  const referencing = attributions.filter(a => a.references_record_sha256 === input.record_sha256)
  if (referencing.length === 0) {
    return { verdict: 'not_established', reason: 'attribution_does_not_reference_the_record' }
  }
  if (!referencing.some(a => a.signer_has_standing)) {
    return { verdict: 'not_established', reason: 'attribution_without_standing' }
  }
  return { verdict: 'valid', reason: 'attribution_established_by_later_record' }
}

export function evaluateReference(input: Input): Outcome {
  const acc = accountability(input, { checkCheckoutInterval: true, checkCheckoutMultiplicity: true })
  return {
    authority_verdict: input.chain_state,
    accountability_verdict: acc.verdict,
    reason: acc.reason,
    anomaly: anomalyFor(input),
  }
}

/** N1. A valid, currently authorized authenticated identity is taken as the
 *  answer to who is accountable. The implementation the section is about. */
export function evaluateN1(input: Input): Outcome {
  return {
    authority_verdict: input.chain_state,
    accountability_verdict: input.chain_state === 'valid' ? 'valid' : 'not_established',
    reason: input.chain_state === 'valid' ? 'individual_identity_bound' : 'shared_identity_attribution_pending_or_external',
    anomaly: anomalyFor(input),
  }
}

/** N2. Notices the shared flag and looks for a checkout, but reads the presence
 *  of any checkout as an answer: no interval check, no multiplicity check. */
export function evaluateN2(input: Input): Outcome {
  const acc = accountability(input, { checkCheckoutInterval: false, checkCheckoutMultiplicity: false })
  return {
    authority_verdict: input.chain_state,
    accountability_verdict: acc.verdict,
    reason: acc.reason,
    anomaly: anomalyFor(input),
  }
}

export const CONTROLS: Record<string, (input: Input) => Outcome> = {
  'N1-authenticated-is-accountable': evaluateN1,
  'N2-shared-flag-only': evaluateN2,
}
