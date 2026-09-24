// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the lifecycle-evidence-and-record candidate family.
//
// WHAT THIS IS. Two small pure evaluators, one per question the "Evidence and
// record" section of CASES.md raises. It is a reference model written to make
// proposed text executable. It is not APS, it speaks no protocol, and it is not
// a real authorization system. A result here is a statement about this model and
// nothing else.
//
// TWO VERDICTS, NOT ONE. Every evaluation returns a `chain_verdict` and a
// `verdict`. The first is the state of the authority the requester holds. The
// second is the state of the effect being requested under it. Keeping them apart
// is the whole point of the retention group: a valid chain whose particular
// effect is blocked from outside the grant chain is `restricted`, which is a
// different fact from the chain being bad.
//
// DETERMINISM. Node builtins only, no imports. No randomness, no wall clock:
// every instant comes from the vector's own input.

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export interface Outcome {
  chain_verdict: Verdict
  verdict: Verdict
  reason: string
}

export function instant(iso: string): number {
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) throw new Error(`not an RFC 3339 instant: ${iso}`)
  return ms
}

/** The instant a retention duty of `years` running from `trigger` runs out.
 *  Computed by advancing the calendar year on the trigger's own UTC date, not
 *  by adding a fixed number of milliseconds, so a duty stated in years does not
 *  drift by a day per leap year. No date this family uses is 29 February, so
 *  there is no end-of-February case to resolve and the model does not pretend
 *  to have a rule for one. */
export function retentionExpiry(trigger: string, years: number): number {
  const d = new Date(instant(trigger))
  return Date.UTC(
    d.getUTCFullYear() + years,
    d.getUTCMonth(),
    d.getUTCDate(),
    d.getUTCHours(),
    d.getUTCMinutes(),
    d.getUTCSeconds(),
    d.getUTCMilliseconds(),
  )
}

// ---------------------------------------------------------------------------
// Group: retention_restriction  (LC-G-005)
// ---------------------------------------------------------------------------
//
// A record's retention duty is set by the record's own type and runs from the
// record's own trigger. It is not scoped to the life of the authority
// relationship the record documents. Restrictions from different sources
// compose, and each is released separately.

export interface RetentionInput {
  evaluated_at: string
  requester_chain_state: Verdict
  requested_effect: string
  record: {
    record_type: string
    retention_trigger: string
    trigger_occurred_at: string | null
    retention_years: number
  }
  external_holds: { hold_id: string; source: string; released: boolean }[]
}

export function evaluateRetention(input: RetentionInput): Outcome {
  const chain = input.requester_chain_state

  // Retention restricts destruction. Ending authority does not by itself erase
  // or invalidate evidence of earlier events, so a read is not restricted here.
  if (input.requested_effect !== 'records:delete') {
    return { chain_verdict: chain, verdict: 'valid', reason: 'evidence_survives_authority_end' }
  }

  if (input.record.trigger_occurred_at === null) {
    return { chain_verdict: chain, verdict: 'restricted', reason: 'retention_trigger_not_reached' }
  }

  const expiry = retentionExpiry(input.record.trigger_occurred_at, input.record.retention_years)
  if (instant(input.evaluated_at) < expiry) {
    return { chain_verdict: chain, verdict: 'restricted', reason: 'retention_duty_unexpired' }
  }

  // A second, independent restriction is released on its own terms. The
  // retention duty running out does not release it.
  if (input.external_holds.some(h => !h.released)) {
    return { chain_verdict: chain, verdict: 'restricted', reason: 'external_hold_active' }
  }

  return { chain_verdict: chain, verdict: 'valid', reason: 'retention_duty_elapsed' }
}

/** N1. The retention duty is scoped to the life of the relationship: open means
 *  blocked, closed means free. No record-type clock, no composition. */
export function evaluateRetentionN1(input: RetentionInput): Outcome {
  const chain = input.requester_chain_state
  if (input.requested_effect !== 'records:delete') {
    return { chain_verdict: chain, verdict: 'valid', reason: 'evidence_survives_authority_end' }
  }
  if (input.record.trigger_occurred_at === null) {
    return { chain_verdict: chain, verdict: 'restricted', reason: 'retention_trigger_not_reached' }
  }
  return { chain_verdict: chain, verdict: 'valid', reason: 'retention_duty_elapsed' }
}

// ---------------------------------------------------------------------------
// Group: receipt_immutability  (LC-G-006)
// ---------------------------------------------------------------------------
//
// Two different questions over one unchanged record. What did the boundary
// decide, on the inputs it actually had? And what does the record set say now?
// Later evidence answers the second and never the first. A receipt whose bytes
// no longer match its own recorded digest answers neither.

export interface ReceiptInput {
  query: 'verdict_at_decision_time' | 'verdict_now'
  prior_receipt: {
    receipt_id: string
    decided_at: string
    recorded_verdict: Verdict
    inputs_available: string[]
    recorded_bytes_sha256: string
    actual_bytes_sha256: string
  }
  later_evidence: { kind: 'none' | 'new_information' | 'void_from_inception'; known_at: string | null }
}

export function evaluateReceipt(input: ReceiptInput): Outcome {
  const r = input.prior_receipt

  if (r.actual_bytes_sha256 !== r.recorded_bytes_sha256) {
    return {
      chain_verdict: 'not_established',
      verdict: 'not_established',
      reason: 'prior_receipt_bytes_do_not_match_digest',
    }
  }

  if (input.query === 'verdict_at_decision_time') {
    return {
      chain_verdict: r.recorded_verdict,
      verdict: r.recorded_verdict,
      reason: 'decided_on_the_record_then_available',
    }
  }

  switch (input.later_evidence.kind) {
    case 'new_information':
      return { chain_verdict: 'invalid', verdict: 'invalid', reason: 'new_record_references_prior' }
    case 'void_from_inception':
      return { chain_verdict: 'invalid', verdict: 'invalid', reason: 'ancestor_never_validly_issued' }
    case 'none':
      return { chain_verdict: r.recorded_verdict, verdict: r.recorded_verdict, reason: 'no_later_record' }
  }
}

/** N2. Everything is answered against what is known now, and the receipt's
 *  bytes are never checked against its recorded digest. */
export function evaluateReceiptN2(input: ReceiptInput): Outcome {
  const r = input.prior_receipt
  switch (input.later_evidence.kind) {
    case 'new_information':
      return { chain_verdict: 'invalid', verdict: 'invalid', reason: 'new_record_references_prior' }
    case 'void_from_inception':
      return { chain_verdict: 'invalid', verdict: 'invalid', reason: 'ancestor_never_validly_issued' }
    case 'none':
      return {
        chain_verdict: r.recorded_verdict,
        verdict: r.recorded_verdict,
        reason: 'decided_on_the_record_then_available',
      }
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export const GROUPS = ['retention_restriction', 'receipt_immutability'] as const
export type Group = (typeof GROUPS)[number]

export const CONTROL_FOR_GROUP: Record<Group, string> = {
  retention_restriction: 'N1-relationship-scoped-retention',
  receipt_immutability: 'N2-retroactive-correction',
}

export function evaluateReference(group: Group, input: unknown): Outcome {
  return group === 'retention_restriction'
    ? evaluateRetention(input as RetentionInput)
    : evaluateReceipt(input as ReceiptInput)
}

export function evaluateControl(group: Group, input: unknown): Outcome {
  return group === 'retention_restriction'
    ? evaluateRetentionN1(input as RetentionInput)
    : evaluateReceiptN2(input as ReceiptInput)
}
