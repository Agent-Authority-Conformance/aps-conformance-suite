// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the lifecycle-infrastructure-failure candidate family.
//
// WHAT THIS IS. Six small, independent boundary evaluators, one per question the
// "Infrastructure failure" section of CASES.md raises. Each is a pure function
// from one vector's `input` object to one `{verdict, reason}` pair. It is a
// reference model written to make proposed text executable. It is not APS, it
// speaks no protocol, and it is not a real authorization system. A result here
// is a statement about this model and nothing else.
//
// WHY SIX EVALUATORS AND NOT ONE. The six groups ask genuinely different
// questions over genuinely different record sets: a status artifact's own
// declared window, a publisher correcting its own bad publication, the evidence
// behind an issuer's timestamp, the merge of two divergent write histories, a
// read that must follow a specific prior write, and the coverage of an evidence
// interval. Folding them into one evaluator would mean inventing a union record
// shape that none of the cases describes, which would make the model the thing
// under test instead of the text.
//
// DETERMINISM. Node builtins only, no imports. No randomness, no wall clock:
// every instant an evaluator reads comes from the vector's own input. `now` is
// never consulted anywhere in this file.
//
// VERDICT VOCABULARY. The settled lifecycle vocabulary: valid, invalid,
// not_established, not_yet_effective, suspended, restricted. `not_established`
// says the record set does not establish the fact. It never says the fact is
// false.

export type Verdict =
  | 'valid'
  | 'invalid'
  | 'not_established'
  | 'not_yet_effective'
  | 'suspended'
  | 'restricted'

export interface Outcome {
  verdict: Verdict
  reason: string
}

/** Milliseconds since the epoch for an RFC 3339 instant. Throws on anything
 *  this family did not put in its own vectors, so a typo in a literal fails
 *  loudly rather than silently dating a record to 1970. */
export function instant(iso: string): number {
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) throw new Error(`not an RFC 3339 instant: ${iso}`)
  return ms
}

// ---------------------------------------------------------------------------
// Group: status_artifact  (LC-F-006, variant LC-F-015)
// ---------------------------------------------------------------------------
//
// Two windows govern a status answer and they are independent. The publisher
// declares, on the artifact, the time by which it commits to publish a
// successor. The verifier declares, in its own trust policy, how old an answer
// it will act on. Either one lapsing is enough to stop the answer establishing
// anything. A recorded revocation is not undone by either window lapsing.

export interface StatusArtifactInput {
  evaluated_at: string
  artifact: { list_id: string; answer: 'active' | 'revoked'; this_update: string; next_update: string }
  verifier_freshness_bound_s: number
}

export function evaluateStatusArtifact(input: StatusArtifactInput): Outcome {
  const now = instant(input.evaluated_at)
  const produced = instant(input.artifact.this_update)
  const dueBy = instant(input.artifact.next_update)

  // 1. An answer dated ahead of the instant being evaluated has no readable
  //    age. Flooring a negative age at zero would read it as maximally fresh,
  //    which is the LC-F-015 trap.
  if (produced > now) return { verdict: 'not_established', reason: 'status_artifact_future_dated' }

  // 2. A recorded revocation stands. An overdue list may be missing later
  //    changes; it does not un-say what it already records (L3).
  if (input.artifact.answer === 'revoked') return { verdict: 'invalid', reason: 'status_revoked' }

  // 3. The publisher's own declared commitment.
  if (now > dueBy) return { verdict: 'not_established', reason: 'status_artifact_past_next_update' }

  // 4. The verifier's own bound, inclusive at the boundary.
  const ageS = (now - produced) / 1000
  if (ageS > input.verifier_freshness_bound_s) {
    return { verdict: 'not_established', reason: 'status_past_verifier_bound' }
  }

  return { verdict: 'valid', reason: 'status_active_within_both_windows' }
}

/** N1. Consults only the verifier's own bound. No artifact window, no
 *  future-dating check, and a negative age floored at zero. */
export function evaluateStatusArtifactN1(input: StatusArtifactInput): Outcome {
  const now = instant(input.evaluated_at)
  const produced = instant(input.artifact.this_update)
  if (input.artifact.answer === 'revoked') return { verdict: 'invalid', reason: 'status_revoked' }
  const ageS = Math.max(0, (now - produced) / 1000)
  if (ageS > input.verifier_freshness_bound_s) {
    return { verdict: 'not_established', reason: 'status_past_verifier_bound' }
  }
  return { verdict: 'valid', reason: 'status_active_within_both_windows' }
}

// ---------------------------------------------------------------------------
// Group: status_correction  (LC-F-009)
// ---------------------------------------------------------------------------
//
// A publisher retracting its own erroneous publication is a different operation
// from withdrawing a revocation somebody with standing actually made. The first
// is available to the publisher of that list, over the versions it names, and
// only where no signed revocation underlies the entry. The second is not
// available here at all.

export interface StatusCorrectionInput {
  evaluated_at: string
  held_version: number
  entry: { list_id: string; version: number; answer: 'active' | 'revoked' }
  underlying_revocation_record: null | { record_id: string; signer_key_id: string; signer_has_lifecycle_standing: boolean }
  correction: null | { kind: string; list_id: string; erroneous_versions: [number, number]; signer_key_id: string }
  list_publisher_key_id: string
}

export function evaluateStatusCorrection(input: StatusCorrectionInput): Outcome {
  if (input.entry.answer !== 'revoked') return { verdict: 'valid', reason: 'status_entry_active' }
  const c = input.correction
  if (c === null) return { verdict: 'invalid', reason: 'status_entry_revoked' }

  // Standing to retract a publication belongs to whoever publishes it.
  if (c.signer_key_id !== input.list_publisher_key_id || c.list_id !== input.entry.list_id) {
    return { verdict: 'invalid', reason: 'correction_without_publisher_standing' }
  }
  // A publisher can un-say its own publication. It cannot un-say a revocation
  // somebody else had standing to make (L3).
  const underlying = input.underlying_revocation_record
  if (underlying !== null && underlying.signer_has_lifecycle_standing) {
    return { verdict: 'invalid', reason: 'correction_refused_underlying_revocation' }
  }
  // A correction reaches the versions it names and no others.
  const [lo, hi] = c.erroneous_versions
  if (input.held_version < lo || input.held_version > hi) {
    return { verdict: 'invalid', reason: 'correction_does_not_cover_held_version' }
  }
  return { verdict: 'valid', reason: 'publication_error_corrected' }
}

/** N2. Any signed correction naming the list is taken at face value. */
export function evaluateStatusCorrectionN2(input: StatusCorrectionInput): Outcome {
  if (input.entry.answer !== 'revoked') return { verdict: 'valid', reason: 'status_entry_active' }
  if (input.correction === null) return { verdict: 'invalid', reason: 'status_entry_revoked' }
  return { verdict: 'valid', reason: 'publication_error_corrected' }
}

// ---------------------------------------------------------------------------
// Group: issuer_time_evidence  (LC-F-014)
// ---------------------------------------------------------------------------
//
// An issuer's issued_at is an issuer claim. Where a verdict turns on whether an
// artifact was signed before some other event, the claim needs evidence from
// outside the issuer, and an interval the issuer itself flagged as disputed is
// not a base for any ordering claim.

export interface IssuerTimeInput {
  ordering_is_load_bearing: boolean
  issuer_claimed_issued_at: string
  revocation_at: string | null
  independent_time_evidence: null | { attestor: string; covers_from: string; covers_to: string }
  declared_time_source_disagreement_windows: { from: string; to: string; detected_by: string }[]
}

function covers(ev: { covers_from: string; covers_to: string }, at: number): boolean {
  return at >= instant(ev.covers_from) && at <= instant(ev.covers_to)
}

export function evaluateIssuerTime(input: IssuerTimeInput): Outcome {
  const issuedAt = instant(input.issuer_claimed_issued_at)

  for (const w of input.declared_time_source_disagreement_windows) {
    if (issuedAt >= instant(w.from) && issuedAt <= instant(w.to)) {
      return { verdict: 'not_established', reason: 'issuer_time_source_disputed' }
    }
  }

  if (!input.ordering_is_load_bearing || input.revocation_at === null) {
    return { verdict: 'valid', reason: 'no_ordering_claim_rests_on_the_timestamp' }
  }

  const ev = input.independent_time_evidence
  if (ev === null || !covers(ev, issuedAt)) {
    return { verdict: 'not_established', reason: 'issuer_timestamp_unattested' }
  }

  if (issuedAt >= instant(input.revocation_at)) {
    return { verdict: 'invalid', reason: 'issued_after_revocation' }
  }
  return { verdict: 'valid', reason: 'ordering_established_by_independent_time_evidence' }
}

/** N3. The issuer's own clock is taken as ground truth. */
export function evaluateIssuerTimeN3(input: IssuerTimeInput): Outcome {
  const issuedAt = instant(input.issuer_claimed_issued_at)
  if (!input.ordering_is_load_bearing || input.revocation_at === null) {
    return { verdict: 'valid', reason: 'no_ordering_claim_rests_on_the_timestamp' }
  }
  if (issuedAt >= instant(input.revocation_at)) {
    return { verdict: 'invalid', reason: 'issued_after_revocation' }
  }
  return { verdict: 'valid', reason: 'ordering_established_by_independent_time_evidence' }
}

// ---------------------------------------------------------------------------
// Group: history_reconciliation  (LC-F-016, LC-F-022, LC-F-026)
// ---------------------------------------------------------------------------
//
// Two sides of a partition each accepted writes. Three rules: a merge with no
// record of what it kept establishes nothing; a revocation anywhere in the kept
// set decides, whatever a non-revocation write's timestamp says; and a grant
// that exists only on a discarded history is not established rather than
// invalid, because nobody with standing ended it.

export interface Write {
  seq: number
  at: string
  kind: 'grant' | 'revocation' | 'metadata'
  delegation_id: string
}

export interface ReconciliationInput {
  delegation_id: string
  side_a: Write[]
  side_b: Write[]
  reconciliation_record: { present: boolean; kept: string[]; discarded: string[] }
}

function tagged(input: ReconciliationInput): { tag: string; w: Write }[] {
  return [
    ...input.side_a.map(w => ({ tag: `a:${w.seq}`, w })),
    ...input.side_b.map(w => ({ tag: `b:${w.seq}`, w })),
  ]
}

export function evaluateReconciliation(input: ReconciliationInput): Outcome {
  const rec = input.reconciliation_record
  const all = tagged(input).filter(x => x.w.delegation_id === input.delegation_id)

  if (!rec.present) {
    // Something merged and nothing says what it covered. L12: authenticity of
    // individual records is weaker than a claim about the set.
    return { verdict: 'not_established', reason: 'reconciliation_record_absent' }
  }

  const kept = all.filter(x => rec.kept.includes(x.tag))
  const discarded = all.filter(x => rec.discarded.includes(x.tag))

  if (kept.some(x => x.w.kind === 'revocation')) {
    return { verdict: 'invalid', reason: 'revoked_on_reconciled_history' }
  }
  if (kept.some(x => x.w.kind === 'grant')) {
    return { verdict: 'valid', reason: 'grant_on_reconciled_history' }
  }
  if (discarded.some(x => x.w.kind === 'grant')) {
    // Authentic, correctly signed, and never in the accepted set.
    return { verdict: 'not_established', reason: 'grant_on_discarded_history' }
  }
  return { verdict: 'not_established', reason: 'no_authority_write_on_reconciled_history' }
}

/** N4. Per delegation, the single highest-timestamp write across both sides
 *  decides. No revocation priority, no discarded-history handling, no
 *  requirement that a reconciliation record exist. */
export function evaluateReconciliationN4(input: ReconciliationInput): Outcome {
  const all = tagged(input).filter(x => x.w.delegation_id === input.delegation_id)
  if (all.length === 0) return { verdict: 'not_established', reason: 'no_authority_write_on_reconciled_history' }
  let latest = all[0]
  for (const x of all) if (instant(x.w.at) > instant(latest.w.at)) latest = x
  if (latest.w.kind === 'revocation') return { verdict: 'invalid', reason: 'revoked_on_reconciled_history' }
  return { verdict: 'valid', reason: 'grant_on_reconciled_history' }
}

// ---------------------------------------------------------------------------
// Group: causal_read  (LC-F-017)
// ---------------------------------------------------------------------------
//
// A request can carry a required-observation token naming a write this read has
// to follow. A replica that has not applied that write has not answered the
// question, however recent it is. Lag and required observation are separate
// checks, and the vectors pair each one against the other's control.

export interface CausalReadInput {
  evaluated_at: string
  required_observation: null | { write_id: string }
  replica: { replica_id: string; applied_writes: string[]; as_of: string; answer: 'active' | 'revoked' }
  replica_lag_bound_s: number
}

export function evaluateCausalRead(input: CausalReadInput): Outcome {
  const req = input.required_observation
  if (req !== null && !input.replica.applied_writes.includes(req.write_id)) {
    return { verdict: 'not_established', reason: 'required_write_not_observed' }
  }
  if (input.replica.answer === 'revoked') return { verdict: 'invalid', reason: 'status_revoked' }
  const lagS = (instant(input.evaluated_at) - instant(input.replica.as_of)) / 1000
  if (lagS > input.replica_lag_bound_s) {
    return { verdict: 'not_established', reason: 'replica_past_bound' }
  }
  return { verdict: 'valid', reason: 'within_declared_replica_bound' }
}

/** N5. Lag is checked, the required observation is not. */
export function evaluateCausalReadN5(input: CausalReadInput): Outcome {
  if (input.replica.answer === 'revoked') return { verdict: 'invalid', reason: 'status_revoked' }
  const lagS = (instant(input.evaluated_at) - instant(input.replica.as_of)) / 1000
  if (lagS > input.replica_lag_bound_s) {
    return { verdict: 'not_established', reason: 'replica_past_bound' }
  }
  return { verdict: 'valid', reason: 'within_declared_replica_bound' }
}

// ---------------------------------------------------------------------------
// Group: evidence_coverage  (LC-F-027, variant LC-F-029)
// ---------------------------------------------------------------------------
//
// Coverage over an interval, not authenticity of any record in it. An interval
// whose tail is still inside the declared delivery lag has an unsettled tail, so
// an empty result over it is not evidence of absence. A declared consumer whose
// delivery record stops short of the interval's end is a gap that only a later
// delivery record closes.

export interface CoverageInput {
  evaluated_at: string
  query_interval: { from: string; to: string }
  delivery_lag_bound_s: number
  records_found_in_interval: number
  consumers: { consumer_id: string; delivered_through: string }[]
}

export function evaluateCoverage(input: CoverageInput): Outcome {
  const settledHorizon = instant(input.evaluated_at) - input.delivery_lag_bound_s * 1000
  if (instant(input.query_interval.to) > settledHorizon) {
    return { verdict: 'not_established', reason: 'interval_inside_delivery_lag' }
  }
  const to = instant(input.query_interval.to)
  for (const c of input.consumers) {
    if (instant(c.delivered_through) < to) {
      return { verdict: 'not_established', reason: 'consumer_delivery_gap' }
    }
  }
  return { verdict: 'valid', reason: 'interval_settled_and_consumers_delivered' }
}

/** N6. An empty result means nothing happened. No delivery lag, no consumer
 *  delivery records. */
export function evaluateCoverageN6(_input: CoverageInput): Outcome {
  return { verdict: 'valid', reason: 'interval_settled_and_consumers_delivered' }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export const GROUPS = [
  'status_artifact',
  'status_correction',
  'issuer_time_evidence',
  'history_reconciliation',
  'causal_read',
  'evidence_coverage',
] as const

export type Group = (typeof GROUPS)[number]

export const CONTROL_FOR_GROUP: Record<Group, string> = {
  status_artifact: 'N1-verifier-bound-only',
  status_correction: 'N2-correction-accepts-any-signer',
  issuer_time_evidence: 'N3-trusts-issuer-clock',
  history_reconciliation: 'N4-last-writer-wins',
  causal_read: 'N5-ignores-required-observation',
  evidence_coverage: 'N6-empty-means-absent',
}

export function evaluateReference(group: Group, input: unknown): Outcome {
  switch (group) {
    case 'status_artifact':
      return evaluateStatusArtifact(input as StatusArtifactInput)
    case 'status_correction':
      return evaluateStatusCorrection(input as StatusCorrectionInput)
    case 'issuer_time_evidence':
      return evaluateIssuerTime(input as IssuerTimeInput)
    case 'history_reconciliation':
      return evaluateReconciliation(input as ReconciliationInput)
    case 'causal_read':
      return evaluateCausalRead(input as CausalReadInput)
    case 'evidence_coverage':
      return evaluateCoverage(input as CoverageInput)
  }
}

export function evaluateControl(group: Group, input: unknown): Outcome {
  switch (group) {
    case 'status_artifact':
      return evaluateStatusArtifactN1(input as StatusArtifactInput)
    case 'status_correction':
      return evaluateStatusCorrectionN2(input as StatusCorrectionInput)
    case 'issuer_time_evidence':
      return evaluateIssuerTimeN3(input as IssuerTimeInput)
    case 'history_reconciliation':
      return evaluateReconciliationN4(input as ReconciliationInput)
    case 'causal_read':
      return evaluateCausalReadN5(input as CausalReadInput)
    case 'evidence_coverage':
      return evaluateCoverageN6(input as CoverageInput)
  }
}
