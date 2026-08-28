// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// receipt-decision-relation verifier.
//
// WHAT THIS FAMILY IS FOR
// A receipt carries a decision_ref: a digest of the decision it was issued
// under. Holding a receipt and holding a decision is not the same as holding a
// receipt and ITS decision. Two cross-document failures follow, and a conformant
// verifier must reject both:
//
//   DECISION_REF_MISMATCH   the supplied decision is not the one the receipt
//                           references. Left unchecked, a receipt for decision A
//                           can be presented alongside an unrelated decision B
//                           picked for its convenient validity window.
//   VALID_UNTIL_NOT_LATER   the decision's validity window does not extend past
//                           the moment the receipt was issued. The receipt would
//                           then rest on authority that had already lapsed.
//
// SCOPE OF THIS VERIFIER
// This verifier assumes the pinned artifacts have already passed their
// standalone structural and signature checks, which were asserted with the SDK
// at generation time and are recorded in SOURCE.md. It independently evaluates
// ONLY the Gate 2 cross-document relation. Its verdicts are RELATION verdicts,
// not full receipt-verification verdicts: a PASS here says the receipt and the
// decision belong together and are correctly ordered in time, and says nothing
// about whether the receipt would verify on its own.
//
// It also does not exercise dispatch-time enforcement. Consumption of
// receipt_id, single-use, revocation or time recheck at dispatch, and spend
// reservation are enforcement-boundary obligations and are not tested here.
//
// INDEPENDENCE
// Nothing here imports the APS SDK. The decision reference is recomputed from
// the domain-separated construction transcribed below, using this family's own
// JCS and SHA-256 in lib.ts. Agreement with the SDK's digests is therefore
// evidence about the construction, not an artifact of shared code.
//
// FAILURE NAMES are family-level conformance semantics. They describe an
// observable classification, not an SDK enum; no SDK identifier is imported or
// copied as authority here.
//
// USAGE
//   npx tsx fixtures/receipt-decision-relation/verify.ts
//   npx tsx fixtures/receipt-decision-relation/verify.ts --flip-check

import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeJCS, compareCodePoints, HEX64, isExactUtcMilliseconds, sha256Hex, tagged } from './lib.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const VECTOR_DIR = join(__dirname, 'receipt-decision-relation-v1')

// ── The construction, transcribed from the specification ─────────────────────
// Domain tags and assembly as implemented by the APS SDK at commit 79d936c in
// src/v2/receipt-core/decision-ref.ts. Transcribed as literals so this file
// stands alone; see SOURCE.md for the same values with their line references.
//
//   component digest := SHA-256( TAG || 0x00 || JCS(component value) )
//   decision_ref     := SHA-256( "APS-DECISION-REF-V1" || 0x00 || JCS(input) )
//
// where `input` is exactly these six members and no others:
//   profile              "aps-decision-ref-v1"
//   action_ref           taken from the RECEIPT, never from the decision
//   authority_state_ref  component digest of authority_state
//   policy_ref           component digest of policy_input
//   context_ref          component digest of decision_context
//   decision_output_ref  component digest of the NORMALIZED decision_output
const DECISION_REF_TAG = 'APS-DECISION-REF-V1'
const DECISION_REF_PROFILE = 'aps-decision-ref-v1'
const DECISION_COMPONENT_TAGS = {
  authority: 'APS-DECISION-AUTHORITY-V1',
  policy: 'APS-DECISION-POLICY-V1',
  context: 'APS-DECISION-CONTEXT-V1',
  output: 'APS-DECISION-OUTPUT-V1',
} as const

const DECISION_OUTPUT_PROFILE = 'aps-core-decision-output-v1'
const DECISION_OUTPUT_MEMBERS = ['profile', 'verdict', 'effective_authority_ref', 'constraints', 'valid_until'] as const

type Failure = 'PASS' | 'DECISION_REF_MISMATCH' | 'VALID_UNTIL_NOT_LATER'

interface DecisionOutput {
  profile: string
  verdict: string
  effective_authority_ref: string | null
  constraints: string[]
  valid_until: string | null
}
interface DecisionEvidence {
  authority_state: unknown
  policy_input: unknown
  decision_context: unknown
  decision_output: DecisionOutput
}
interface Receipt { action_ref: string; decision_ref?: string; issued_at: string }
interface Vector {
  profile: string
  name: string
  description: string
  expected: { verdict: 'accept' | 'reject'; failure: Failure }
  receipt: Receipt
  provided_decision_evidence: DecisionEvidence
  provenance: {
    provided_decision_ref: string
    correct_decision_evidence?: DecisionEvidence
    correct_decision_ref?: string
  }
}

/** A defect in the corpus itself rather than a relation verdict. The scope note
 *  above says structural soundness is a precondition, so a violation means the
 *  pinned artifacts are broken and the run must abort rather than classify. */
class CorpusError extends Error {}

/** Reproduce the SDK's normalize-before-hash step for the decision output.
 *  The digest is taken over the normalized form, so a verifier that skips this
 *  computes a different reference. The pinned vectors store `constraints` out of
 *  order precisely so that omitting the sort is caught by the PASS vector. */
function normalizeDecisionOutput(output: DecisionOutput): DecisionOutput {
  const keys = Object.keys(output)
  for (const key of keys) {
    if (!(DECISION_OUTPUT_MEMBERS as readonly string[]).includes(key)) throw new CorpusError(`decision_output: unknown member ${key}`)
  }
  for (const key of DECISION_OUTPUT_MEMBERS) {
    if (!(key in output)) throw new CorpusError(`decision_output: missing member ${key}`)
  }
  if (output.profile !== DECISION_OUTPUT_PROFILE) throw new CorpusError(`decision_output: profile ${output.profile}`)
  if (!['permit', 'deny', 'narrow'].includes(output.verdict)) throw new CorpusError(`decision_output: verdict ${output.verdict}`)
  if (output.effective_authority_ref !== null && !HEX64.test(output.effective_authority_ref)) {
    throw new CorpusError('decision_output: effective_authority_ref')
  }
  if (!Array.isArray(output.constraints) || !output.constraints.every(v => typeof v === 'string')) {
    throw new CorpusError('decision_output: constraints')
  }
  // NFC first, then de-duplicate, then order by code point. The sequence matters:
  // two constraints that differ only by Unicode composition are the same
  // constraint, and de-duplicating before normalizing would keep both.
  const constraints = [...new Set(output.constraints.map(v => v.normalize('NFC')))].sort(compareCodePoints)
  return { ...output, constraints }
}

function componentRef(tag: keyof typeof DECISION_COMPONENT_TAGS, value: unknown): string {
  return sha256Hex(tagged(DECISION_COMPONENT_TAGS[tag], canonicalizeJCS(value)))
}

/** Recompute the decision reference from the FULL supplied evidence and the
 *  receipt's own action_ref. action_ref is read from the receipt on purpose: a
 *  decision built for some other action then cannot bind, and a caller cannot
 *  quietly supply an action_ref that disagrees with the receipt being checked. */
function computeDecisionRef(receiptActionRef: string, evidence: DecisionEvidence): string {
  if (!HEX64.test(receiptActionRef)) throw new CorpusError('receipt: action_ref must be lowercase sha256 hex')
  const input = {
    profile: DECISION_REF_PROFILE,
    action_ref: receiptActionRef,
    authority_state_ref: componentRef('authority', evidence.authority_state),
    policy_ref: componentRef('policy', evidence.policy_input),
    context_ref: componentRef('context', evidence.decision_context),
    decision_output_ref: componentRef('output', normalizeDecisionOutput(evidence.decision_output)),
  }
  return sha256Hex(tagged(DECISION_REF_TAG, canonicalizeJCS(input)))
}

/** The Gate 2 relation, in the order that makes each result mean something.
 *  Binding is settled BEFORE the temporal comparison: a validity window read off
 *  a decision that does not belong to this receipt is not evidence about this
 *  receipt at all, so a temporal verdict computed over an unbound pair would be
 *  a statement about nothing. */
function classifyRelation(receipt: Receipt, evidence: DecisionEvidence): Failure {
  if (typeof receipt.decision_ref !== 'string' || !HEX64.test(receipt.decision_ref)) {
    throw new CorpusError('receipt: decision_ref absent or malformed')
  }
  const recomputed = computeDecisionRef(receipt.action_ref, evidence)
  if (recomputed !== receipt.decision_ref) return 'DECISION_REF_MISMATCH'

  const validUntil = evidence.decision_output.valid_until
  if (!isExactUtcMilliseconds(receipt.issued_at)) throw new CorpusError('receipt: issued_at is not exact UTC milliseconds')
  if (!isExactUtcMilliseconds(validUntil)) throw new CorpusError('decision_output: valid_until is not exact UTC milliseconds')
  // Compared as instants, never as strings: two different textual forms can name
  // the same moment, and string order is not time order in general.
  if (!(Date.parse(validUntil) > Date.parse(receipt.issued_at))) return 'VALID_UNTIL_NOT_LATER'

  return 'PASS'
}

/** Provenance is an AUDIT OUTPUT, never an input.
 *
 *  Nothing in classifyRelation reads this block. What happens here is the
 *  reverse: the digests the generator recorded are recomputed from the evidence
 *  in the file and must agree, which is what lets a reviewer establish
 *  hash(correct) == receipt.decision_ref and hash(provided) != receipt.decision_ref
 *  from the file alone. A disagreement means the pinned file is inconsistent
 *  with itself and the run fails. */
function auditProvenance(v: Vector): string[] {
  const problems: string[] = []
  const providedRef = computeDecisionRef(v.receipt.action_ref, v.provided_decision_evidence)
  if (v.provenance.provided_decision_ref !== providedRef) {
    problems.push(`provenance.provided_decision_ref ${v.provenance.provided_decision_ref.slice(0, 16)}… != recomputed ${providedRef.slice(0, 16)}…`)
  }
  if (v.provenance.correct_decision_evidence) {
    const correctRef = computeDecisionRef(v.receipt.action_ref, v.provenance.correct_decision_evidence)
    if (v.provenance.correct_decision_ref !== correctRef) {
      problems.push(`provenance.correct_decision_ref ${String(v.provenance.correct_decision_ref).slice(0, 16)}… != recomputed ${correctRef.slice(0, 16)}…`)
    }
    if (correctRef !== v.receipt.decision_ref) problems.push('provenance.correct_decision_evidence does not hash to receipt.decision_ref')
    if (providedRef === v.receipt.decision_ref) problems.push('provenance: the provided evidence binds, so this is not a substitution')
  }
  return problems
}

// ── Corpus discovery ─────────────────────────────────────────────────────────
// The directory is enumerated rather than hardcoded, so a vector added later is
// run rather than silently skipped, and the required names are then asserted, so
// a vector deleted later fails the run rather than shrinking it.

const REQUIRED_PRIMARY = ['pass', 'temporal-equal', 'temporal-earlier', 'substitution']
const REQUIRED_FLIPPED = ['temporal-equal.flipped', 'temporal-earlier.flipped', 'substitution.flipped']

const flipCheck = process.argv.includes('--flip-check')
const mode = flipCheck ? 'flip-check' : 'vectors'

const names = readdirSync(VECTOR_DIR).filter(f => f.endsWith('.json')).map(f => f.slice(0, -'.json'.length)).sort()
const flipped = names.filter(n => n.endsWith('.flipped'))
const primary = names.filter(n => !n.endsWith('.flipped'))

let failures = 0
const missing = [...REQUIRED_PRIMARY.filter(n => !primary.includes(n)), ...REQUIRED_FLIPPED.filter(n => !flipped.includes(n))]
if (missing.length > 0) {
  console.error(`  FAIL required vectors missing from the corpus: ${missing.join(', ')}`)
  failures++
}

const selected = flipCheck ? flipped : primary
console.log(`receipt-decision-relation verifier [${mode}]: ${selected.length} vectors from ${VECTOR_DIR}`)
console.log('  Gate 2 cross-document relation only; standalone structure and signatures asserted at generation.\n')

for (const name of selected) {
  const v = JSON.parse(readFileSync(join(VECTOR_DIR, `${name}.json`), 'utf8')) as Vector
  if (v.profile !== 'aps-receipt-decision-relation-vector-v1') {
    console.error(`  FAIL ${name.padEnd(24)} unexpected vector profile ${v.profile}`)
    failures++
    continue
  }
  // A flipped counterpart exists to show the corrected artifact is genuinely
  // valid rather than differently invalid, so PASS is required of it here
  // regardless of what the file states about itself.
  const expectedFailure: Failure = flipCheck ? 'PASS' : v.expected.failure
  const expectedVerdict = expectedFailure === 'PASS' ? 'accept' : 'reject'
  if (!flipCheck && (v.expected.verdict !== expectedVerdict)) {
    console.error(`  FAIL ${name.padEnd(24)} vector states verdict=${v.expected.verdict} with failure=${v.expected.failure}, which disagree`)
    failures++
    continue
  }

  let actual: Failure
  try {
    actual = classifyRelation(v.receipt, v.provided_decision_evidence)
  } catch (err) {
    console.error(`  FAIL ${name.padEnd(24)} corpus error: ${err instanceof Error ? err.message : String(err)}`)
    failures++
    continue
  }
  const verdict = actual === 'PASS' ? 'accept' : 'reject'
  const agree = actual === expectedFailure

  const problems = auditProvenance(v)
  if (agree && problems.length === 0) {
    console.log(`  PASS ${name.padEnd(24)} ${verdict.padEnd(6)} ${actual}`)
  } else {
    failures++
    if (!agree) console.error(`  FAIL ${name.padEnd(24)} got ${verdict}/${actual}, expected ${expectedVerdict}/${expectedFailure}`)
    for (const p of problems) console.error(`  FAIL ${name.padEnd(24)} ${p}`)
  }
}

console.log()
if (failures > 0) {
  console.error(`${failures} failure(s)`)
  process.exit(1)
}
console.log(flipCheck ? 'ALL FLIPPED COUNTERPARTS PASS' : 'ALL VECTORS PASS')
