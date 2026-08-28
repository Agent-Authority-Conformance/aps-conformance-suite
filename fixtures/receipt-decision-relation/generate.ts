// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Generator for the receipt-decision-relation conformance family.
//
// Every artifact in receipt-decision-relation-v1/ is produced here through the
// real APS SDK: real Ed25519 signatures, real digests, real receipt ids. No
// JSON in that directory is hand written or hand edited. A vector that rejects
// does so because the material genuinely has the defect the vector names, not
// because a field was typed to look wrong.
//
// SDK: ../../../agent-passport-system, main at 79d936c
//   79d936c80555679c1d19abaed70da9dfa07fe5ee
//   "feat(receipt-core): public strict serialized-input path for receipt verification"
//
// Run from the repository root:
//   npx tsx fixtures/receipt-decision-relation/generate.ts
//
// The SDK is reached by a relative path, so this assumes agent-passport-system
// and aps-conformance-suite are checked out as siblings. The generator is a
// provenance record and a regeneration tool; it is NOT part of `npm test`, and
// nothing in the test path imports the SDK.
//
// DETERMINISM. Keys, identifiers, timestamps and payloads are all pinned
// constants derived from documented literals, so a re-run on the same SDK
// commit reproduces byte-identical files. There is no clock read and no
// randomness anywhere in this file.

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { createReceiptV1 } from '../../../agent-passport-system/src/v2/receipt-core/receipt.js'
import { buildDecisionRefV1 } from '../../../agent-passport-system/src/v2/receipt-core/decision-ref.js'
import { verifyReceiptWithDecisionV1 } from '../../../agent-passport-system/src/v2/receipt-core/composite.js'
import type { DecisionEvidenceV1 } from '../../../agent-passport-system/src/v2/receipt-core/composite.js'
import type { CoreDecisionOutputV1, ReceiptV1 } from '../../../agent-passport-system/src/v2/receipt-core/types.js'
import { publicKeyFromPrivate } from '../../../agent-passport-system/src/crypto/keys.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT_DIR = join(__dirname, 'receipt-decision-relation-v1')

const SDK_COMMIT = '79d936c80555679c1d19abaed70da9dfa07fe5ee'
const GENERATOR_COMMAND = 'npx tsx fixtures/receipt-decision-relation/generate.ts'

const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')

// BURNED TEST KEY. Derived from a fixed literal so the value is reproducible
// from this file alone and is obviously not an operational secret. Any 32 bytes
// are a valid Ed25519 seed, so a digest is a legitimate way to pin one.
const ISSUER_PRIVATE_KEY = sha256Hex('aps-conformance/receipt-decision-relation-v1/issuer-ed25519-seed')
const ISSUER_PUBLIC_KEY = publicKeyFromPrivate(ISSUER_PRIVATE_KEY)

const SIGNER = 'did:aps:conformance:issuer-receipt-decision-relation-v1'
const KEY_ID = 'receipt-decision-relation-v1-k1'
const SUBJECT = 'did:aps:conformance:agent-receipt-decision-relation-v1'
const DELEGATION_REF = 'did:aps:conformance:delegation-receipt-decision-relation-v1'
const ACTION_REF = sha256Hex('aps-conformance/receipt-decision-relation-v1/action')

const ISSUED_AT = '2026-08-28T12:00:00.000Z'
const LATER = '2026-08-28T12:30:00.000Z'      // strictly after ISSUED_AT
const EQUAL = ISSUED_AT                        // equal to ISSUED_AT, must reject
const EARLIER = '2026-08-28T11:59:59.999Z'     // before ISSUED_AT, must reject

const SIGNERS = [{ signer: SIGNER, key_id: KEY_ID, private_key: ISSUER_PRIVATE_KEY }]
const resolveKey = (signer: string, keyId: string): string | undefined =>
  signer === SIGNER && keyId === KEY_ID ? ISSUER_PUBLIC_KEY : undefined

/** Build one decision. `label` makes each decision's context distinct, so no two
 *  vectors accidentally share a digest and pass for the wrong reason.
 *
 *  `constraints` is deliberately pinned OUT of sorted order. The digest is taken
 *  over the NORMALIZED output (NFC, de-duplicated, code-point sorted), so a
 *  verifier that skips normalization computes a different digest and fails the
 *  pass vector. The unsorted pinning is what makes that step observable. */
function decision(label: string, validUntil: string | null): DecisionEvidenceV1 {
  const decision_output: CoreDecisionOutputV1 = {
    profile: 'aps-core-decision-output-v1',
    verdict: 'permit',
    effective_authority_ref: sha256Hex(`aps-conformance/receipt-decision-relation-v1/authority/${label}`),
    constraints: ['region:us-west-2', 'max_spend_usd:25', 'egress:deny'],
    valid_until: validUntil,
  }
  return {
    authority_state: {
      profile: 'aps-conformance-authority-state-v1',
      delegation_ref: DELEGATION_REF,
      subject_agent: SUBJECT,
      scope: ['read:catalog', 'write:order'],
    },
    policy_input: {
      profile: 'aps-conformance-policy-input-v1',
      policy_id: 'conformance.receipt-decision-relation',
      policy_version: '1',
    },
    decision_context: {
      profile: 'aps-conformance-decision-context-v1',
      vector: label,
      request_id: sha256Hex(`aps-conformance/receipt-decision-relation-v1/request/${label}`),
    },
    decision_output,
  }
}

function receiptFor(evidence: DecisionEvidenceV1): ReceiptV1 {
  const { decision_ref } = buildDecisionRefV1({
    action_ref: ACTION_REF,
    authority_state: evidence.authority_state,
    policy_input: evidence.policy_input,
    decision_context: evidence.decision_context,
    decision_output: evidence.decision_output,
  })
  return createReceiptV1({
    profile: 'aps-receipt-v1',
    receipt_type: 'aps.conformance.receipt-decision-relation',
    issuer: SIGNER,
    subject_agent: SUBJECT,
    action_ref: ACTION_REF,
    delegation_ref: DELEGATION_REF,
    decision_ref,
    issued_at: ISSUED_AT,
    evidence_refs: [],
    result: { status: 'executed' },
  }, SIGNERS)
}

const refOf = (e: DecisionEvidenceV1): string => buildDecisionRefV1({
  action_ref: ACTION_REF,
  authority_state: e.authority_state,
  policy_input: e.policy_input,
  decision_context: e.decision_context,
  decision_output: e.decision_output,
}).decision_ref

// ── Generation-time assertions ───────────────────────────────────────────────
// The corpus claim is that each rejecting vector has exactly ONE defect and that
// the defect is the cross-document relation, not a broken artifact. These
// assertions are how that claim is established, and they run before anything is
// written: a failure aborts with no file on disk.

let asserted = 0
function assertSdk(label: string, receipt: ReceiptV1, evidence: DecisionEvidenceV1, want: { valid: boolean; errors?: string[] }): void {
  const r = verifyReceiptWithDecisionV1(receipt, evidence, resolveKey)
  if (r.valid !== want.valid) {
    throw new Error(`${label}: SDK composite valid=${r.valid}, expected ${want.valid} (errors: ${JSON.stringify(r.errors)})`)
  }
  if (want.errors && JSON.stringify(r.errors) !== JSON.stringify(want.errors)) {
    throw new Error(`${label}: SDK errors ${JSON.stringify(r.errors)}, expected ${JSON.stringify(want.errors)}`)
  }
  // Every vector's receipt must be structurally and cryptographically sound on
  // its own, whatever the relation verdict is. Without this a "reject" could be
  // hiding a malformed receipt rather than the relation defect it claims.
  if (!r.receipt.valid) throw new Error(`${label}: receipt not independently valid: ${JSON.stringify(r.receipt.errors)}`)
  asserted++
}

// ── The vectors ──────────────────────────────────────────────────────────────

const dPass = decision('pass', LATER)
const rPass = receiptFor(dPass)
assertSdk('pass', rPass, dPass, { valid: true, errors: [] })

const dEqual = decision('temporal-equal', EQUAL)
const rEqual = receiptFor(dEqual)
assertSdk('temporal-equal', rEqual, dEqual, { valid: false, errors: ['valid_until_not_after_issued_at'] })

const dEarlier = decision('temporal-earlier', EARLIER)
const rEarlier = receiptFor(dEarlier)
assertSdk('temporal-earlier', rEarlier, dEarlier, { valid: false, errors: ['valid_until_not_after_issued_at'] })

// Substitution: the receipt references decision A; the verifier is handed B.
// B is a complete, well formed permit whose own temporal relation passes, so the
// only thing wrong with the pair is that they are not the same decision.
const dSubA = decision('substitution-correct', LATER)
const dSubB = decision('substitution-provided', LATER)
const rSub = receiptFor(dSubA)
assertSdk('substitution/receipt-with-A', rSub, dSubA, { valid: true, errors: [] })
assertSdk('substitution/receipt-with-B', rSub, dSubB, { valid: false, errors: ['decision_ref_mismatch'] })
// B's independent soundness, established against a receipt that DOES reference
// it. This is the evidence that B's rejection above is a binding failure and
// nothing else; that auxiliary receipt is not pinned, only its verdict matters.
assertSdk('substitution/B-is-independently-valid', receiptFor(dSubB), dSubB, { valid: true, errors: [] })
if (refOf(dSubA) === refOf(dSubB)) throw new Error('substitution: A and B share a digest')
if (refOf(dSubA) !== rSub.decision_ref) throw new Error('substitution: receipt does not reference A')

// Flipped counterparts. Correcting valid_until changes the decision digest, so
// the receipt cannot be reused for the temporal vectors: it is rebuilt and
// re-signed against the corrected decision with the same burned key. The
// substitution flip needs no new receipt at all, because the defect was never in
// the receipt; the SAME receipt bytes are re-pinned with A supplied.
const dEqualFixed = decision('temporal-equal', LATER)
const rEqualFixed = receiptFor(dEqualFixed)
assertSdk('temporal-equal.flipped', rEqualFixed, dEqualFixed, { valid: true, errors: [] })

const dEarlierFixed = decision('temporal-earlier', LATER)
const rEarlierFixed = receiptFor(dEarlierFixed)
assertSdk('temporal-earlier.flipped', rEarlierFixed, dEarlierFixed, { valid: true, errors: [] })

assertSdk('substitution.flipped', rSub, dSubA, { valid: true, errors: [] })

// ── Emit ─────────────────────────────────────────────────────────────────────

interface Provenance {
  note: string
  sdk_repo: string
  sdk_commit: string
  generator_command: string
  issuer_public_keys: { signer: string; key_id: string; alg: string; public_key: string }[]
  provided_decision_ref: string
  correct_decision_evidence?: DecisionEvidenceV1
  correct_decision_ref?: string
}

const PROVENANCE_NOTE =
  'AUDIT OUTPUTS ONLY. Every digest in this block is a value a reviewer can ' +
  'recompute from the evidence in this file. A conformant verifier MUST NOT read ' +
  'any of them as an input to its own computation: the decision reference is ' +
  'recomputed from the supplied decision evidence and the receipt action_ref, and ' +
  'is compared against receipt.decision_ref, never against anything here.'

function emit(
  name: string,
  description: string,
  expected: { verdict: 'accept' | 'reject'; failure: string },
  receipt: ReceiptV1,
  provided: DecisionEvidenceV1,
  extra?: { correct_decision_evidence: DecisionEvidenceV1 },
): void {
  const provenance: Provenance = {
    note: PROVENANCE_NOTE,
    sdk_repo: 'https://github.com/aeoess/agent-passport-system',
    sdk_commit: SDK_COMMIT,
    generator_command: GENERATOR_COMMAND,
    issuer_public_keys: [{ signer: SIGNER, key_id: KEY_ID, alg: 'Ed25519', public_key: ISSUER_PUBLIC_KEY }],
    provided_decision_ref: refOf(provided),
  }
  if (extra) {
    provenance.correct_decision_evidence = extra.correct_decision_evidence
    provenance.correct_decision_ref = refOf(extra.correct_decision_evidence)
  }
  const vector = {
    profile: 'aps-receipt-decision-relation-vector-v1',
    name,
    description,
    expected,
    receipt,
    provided_decision_evidence: provided,
    provenance,
  }
  const path = join(OUT_DIR, `${name}.json`)
  writeFileSync(path, JSON.stringify(vector, null, 2) + '\n')
  console.log(`  wrote ${name}.json  sha256=${createHash('sha256').update(JSON.stringify(vector, null, 2) + '\n').digest('hex')}`)
}

console.log(`receipt-decision-relation generator: SDK ${SDK_COMMIT.slice(0, 7)}`)
console.log(`  ${asserted} SDK composite assertions passed before any write\n`)

emit('pass', 'Receipt bound to the decision it references, decision valid_until strictly later than receipt issued_at.',
  { verdict: 'accept', failure: 'PASS' }, rPass, dPass)

emit('temporal-equal', 'Correct binding; decision valid_until EQUAL to receipt issued_at. The window must be strictly later, so equality is a rejection.',
  { verdict: 'reject', failure: 'VALID_UNTIL_NOT_LATER' }, rEqual, dEqual)

emit('temporal-earlier', 'Correct binding; decision valid_until EARLIER than receipt issued_at.',
  { verdict: 'reject', failure: 'VALID_UNTIL_NOT_LATER' }, rEarlier, dEarlier)

emit('substitution', 'The receipt references decision A. The verifier is supplied decision B, which is itself a complete permit with a passing temporal relation. The only defect is that B is not the decision the receipt references.',
  { verdict: 'reject', failure: 'DECISION_REF_MISMATCH' }, rSub, dSubB, { correct_decision_evidence: dSubA })

emit('temporal-equal.flipped', 'Corrected counterpart of temporal-equal: decision valid_until moved strictly later, receipt rebuilt and re-signed against the corrected decision with the same burned key.',
  { verdict: 'accept', failure: 'PASS' }, rEqualFixed, dEqualFixed)

emit('temporal-earlier.flipped', 'Corrected counterpart of temporal-earlier: decision valid_until moved strictly later, receipt rebuilt and re-signed against the corrected decision with the same burned key.',
  { verdict: 'accept', failure: 'PASS' }, rEarlierFixed, dEarlierFixed)

emit('substitution.flipped', 'Corrected counterpart of substitution: the SAME receipt, byte for byte unmodified, supplied with decision A, the decision it actually references.',
  { verdict: 'accept', failure: 'PASS' }, rSub, dSubA)

console.log('\nall vectors generated')
