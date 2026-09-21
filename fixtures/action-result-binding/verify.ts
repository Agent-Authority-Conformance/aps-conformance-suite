// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// TypeScript runner for the action-result-binding family.
//
// It runs the pinned agent-passport-system 7.0.0 over each case on TWO separate
// surfaces and holds each one to what vectors.json records for it:
//
//   validateReceiptStageV1        the section 5.3 stage rules for one record
//   verifyReceiptWithDecisionV1   the section 5.6 composite check against the
//                                 committed DecisionEvidenceV1 material
//
// The two are never merged. A case may be stage-valid and composite-invalid, and that
// distinction is printed on its own line and compared field by field.
//
// It also holds three things the two surfaces above do not reach on their own:
//
//   the three chain receipts (intent, permit decision, deny decision), each with its
//   receipt_id recomputed, its signatures verified and its stage validated
//
//   case 2's own receipt_id and boundary signature, which both SDK entrypoints skip
//   because they fail that record on its schema first
//
//   which decision's evidence each composite check actually ran against, recomputed
//   through buildDecisionRefV1 and compared with the digest vectors.json pins
//
// The draft03 and replay_policy blocks are printed for the reader and are NOT asserted
// against the SDK: one comes from the published text, the other is this suite's own
// derivation from a third party's stated rules, and a runner that asserted one against
// the other would be deciding which of them is authoritative. That is the whole point
// of keeping the blocks apart.
//
// The prev comparison of section 5.3.3 lines 1104 to 1105 is NOT an SDK result. Neither
// SDK resolves prev. Case 3 prints one harness line, labelled as such, and nothing in
// that line is recorded or reported as SDK behaviour.
//
// Run from the suite root:
//
//     npm run verify:action-result-binding

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildDecisionRefV1,
  computeReceiptIdV1,
  receiptSignaturePayloadV1,
  validateReceiptStageV1,
  verify,
  verifyReceiptWithDecisionV1,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// SDK version guard.
//
// The sdk_ts block in vectors.json is a record of one pinned release. Reporting it as
// agreement under a different release would make the record say something it never
// established, so the version is read off the resolved package before anything is run.
// This mirrors validate.py's guard on the Python side and exists for the same reason:
// package.json pins the dependency, but a local override or a changed resolution would
// otherwise silently redefine what sdk_ts means while this runner still printed a match.
// ---------------------------------------------------------------------------

const PINNED_TS_SDK = '7.0.0'

function resolvedSdkPackageJson(): { path: string; version: string } {
  let dir = path.dirname(fileURLToPath(import.meta.resolve('agent-passport-system')))
  for (;;) {
    const candidate = path.join(dir, 'package.json')
    if (fs.existsSync(candidate)) {
      const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'))
      if (parsed.name === 'agent-passport-system') {
        return { path: candidate, version: parsed.version }
      }
    }
    const parent = path.dirname(dir)
    if (parent === dir) {
      console.error('verify.ts: cannot locate the resolved agent-passport-system package.json')
      process.exit(2)
    }
    dir = parent
  }
}

const sdk = resolvedSdkPackageJson()
if (sdk.version !== PINNED_TS_SDK) {
  console.error(
    `agent-passport-system ${sdk.version} resolves at ${sdk.path}; vectors.json records ` +
      `${PINNED_TS_SDK}. Run this against the pinned release.`,
  )
  process.exit(2)
}

function readJson(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8'))
}

const chain = readJson('chain.json')
const vectors = readJson('vectors.json')

const boundary: string = chain.identities.enforcement_boundary
const keys: Record<string, string> = chain.verification_keys
const resolveKey = (_signer: string, keyId: string): string | undefined => keys[keyId]

/** Canonical bytes with keys sorted at every depth, so member order alone can never make
 *  two equal objects compare different. validate.py compares with sort_keys=True; this is
 *  the same sensitivity on this side. */
function canonical(value: unknown): string {
  const sorted = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sorted)
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {}
      for (const key of Object.keys(v as Record<string, unknown>).sort()) {
        out[key] = sorted((v as Record<string, unknown>)[key])
      }
      return out
    }
    return v
  }
  return JSON.stringify(sorted(value))
}

const json = (value: unknown): string => JSON.stringify(value)

/** Compare the members vectors.json records, by canonical bytes. Members vectors.json
 *  does not record are not compared: the observed objects below are built with a fixed
 *  key set, so an SDK member outside that set never reaches this function. */
function diff(expected: Record<string, unknown>, actual: Record<string, unknown>): string[] {
  const out: string[] = []
  for (const key of Object.keys(expected)) {
    if (key === 'entrypoint') continue
    if (canonical(expected[key]) !== canonical(actual[key])) {
      out.push(`${key}: recorded ${json(expected[key])}, observed ${json(actual[key])}`)
    }
  }
  return out
}

console.log(
  'MATCH means observed SDK behavior equals the recorded expectation. It is not a conformance verdict.',
)

let passed = 0
const failures: string[] = []

// ---------------------------------------------------------------------------
// The three chain receipts. The cases below are all action-result records; the intent
// and the two decisions they hang off are exercised here, on the same three surfaces,
// so a regression in them fails this runner rather than passing unnoticed.
// ---------------------------------------------------------------------------

const receiptChecks = vectors.chain_receipts.expected.length
let receiptsMatched = 0

for (const expected of vectors.chain_receipts.expected) {
  const record = chain.receipts[expected.receipt]
  const problems: string[] = []

  if (record === undefined) {
    problems.push(`chain.json has no receipt named ${expected.receipt}`)
  } else {
    if (record.receipt_type !== expected.receipt_type) {
      problems.push(
        `receipt_type: recorded ${json(expected.receipt_type)}, observed ${json(record.receipt_type)}`,
      )
    }

    const idRecomputed = computeReceiptIdV1(record) === record.receipt_id
    if (idRecomputed !== expected.receipt_id_recomputed) {
      problems.push(
        `receipt_id_recomputed: recorded ${expected.receipt_id_recomputed}, observed ${idRecomputed}`,
      )
    }

    const observedSignatures = record.signatures.map((signature: any) => {
      const descriptor = { signer: signature.signer, key_id: signature.key_id, alg: signature.alg }
      const key = keys[signature.key_id]
      return {
        signer: signature.signer,
        key_id: signature.key_id,
        verified:
          key === undefined
            ? false
            : verify(receiptSignaturePayloadV1(record, descriptor), signature.value, key),
      }
    })
    if (canonical(observedSignatures) !== canonical(expected.signatures)) {
      problems.push(
        `signatures: recorded ${json(expected.signatures)}, observed ${json(observedSignatures)}`,
      )
    }

    const stage = validateReceiptStageV1(record, { boundaryIdentity: boundary })
    const stageObserved = {
      status: stage.status,
      boundary_identity: stage.boundary_identity,
      stage: stage.stage,
      failures: stage.failures,
    }
    problems.push(...diff(expected.stage, stageObserved).map(line => `stage ${line}`))
  }

  if (problems.length === 0) {
    receiptsMatched += 1
    console.log(`MATCH chain receipt ${expected.receipt}`)
  } else {
    console.error(`FAIL chain receipt ${expected.receipt}`)
    for (const problem of problems) console.error(`  ${problem}`)
    failures.push(`chain receipt ${expected.receipt}`)
  }
}

console.log(`action-result-binding TypeScript chain receipts: ${receiptsMatched}/${receiptChecks} matched`)

// ---------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------

for (const vector of vectors.cases) {
  const record = chain.cases[vector.case]
  if (record === undefined) {
    failures.push(`${vector.id}: chain.json has no case named ${vector.case}`)
    continue
  }

  const evidence = chain.decision_evidence[vector.decision_evidence]
  if (evidence === undefined) {
    failures.push(`${vector.id}: chain.json has no decision evidence named ${vector.decision_evidence}`)
    continue
  }

  // Surface 1: section 5.3 stage rules for this record alone.
  const stage = validateReceiptStageV1(record, { boundaryIdentity: boundary })
  const stageObserved = {
    status: stage.status,
    boundary_identity: stage.boundary_identity,
    stage: stage.stage,
    failures: stage.failures,
  }

  // Surface 2: the section 5.6 composite check, receipt together with its decision.
  const composite = verifyReceiptWithDecisionV1(record, evidence, resolveKey, {
    boundaryIdentity: boundary,
  })
  const compositeObserved = {
    status: composite.status,
    valid: composite.valid,
    receipt_status: composite.receipt.status,
    decision_ref_present: composite.decision_ref_present,
    decision_ref_bound: composite.decision_ref_bound,
    decision_output_bound: composite.decision_output_bound,
    temporal_relation_valid: composite.temporal_relation_valid,
    errors: composite.errors,
  }

  const stageDiff = diff(vector.sdk_ts.validateReceiptStageV1, stageObserved)
  const compositeDiff = diff(vector.sdk_ts.verifyReceiptWithDecisionV1, compositeObserved)

  // Which decision the composite check ran against.
  //
  // The composite result alone does not always say. For case 5 both decisions' evidence
  // mismatch and the returned fields are byte-identical either way, so the sdk_ts block
  // above would still match with the evidence swapped. The digest recomputed here is not
  // evidence-insensitive: it is buildDecisionRefV1 over the supplied evidence and this
  // record's own action_ref, the same value the composite compares with decision_ref, and
  // substituting the other decision's evidence changes it for every case.
  const bindingDiff: string[] = []
  const binding = vector.decision_ref_binding
  if (binding !== undefined) {
    if (binding.evidence !== vector.decision_evidence) {
      bindingDiff.push(
        `decision_ref_binding.evidence: records ${json(binding.evidence)} but the case reads ` +
          `${json(vector.decision_evidence)}`,
      )
    }
    const recomputed = buildDecisionRefV1({
      action_ref: record.action_ref,
      authority_state: evidence.authority_state,
      policy_input: evidence.policy_input,
      decision_context: evidence.decision_context,
      decision_output: evidence.decision_output,
    }).decision_ref
    const bindingObserved = {
      recomputed_from_permit_evidence: recomputed,
      equals_record_decision_ref: recomputed === record.decision_ref,
      equals_permit_decision_ref: recomputed === chain.decision_refs.permit,
      record_decision_ref_is_deny: record.decision_ref === chain.decision_refs.deny,
    }
    bindingDiff.push(
      ...diff(
        {
          recomputed_from_permit_evidence: binding.recomputed_from_permit_evidence,
          equals_record_decision_ref: binding.equals_record_decision_ref,
          equals_permit_decision_ref: binding.equals_permit_decision_ref,
          record_decision_ref_is_deny: binding.record_decision_ref_is_deny,
        },
        bindingObserved,
      ).map(line => `decision_ref_binding ${line}`),
    )
  }

  // Case 2's own sealing. Both SDK entrypoints fail that record on its schema before any
  // signature is verified, so without this the one thing the section 5.2 sealing path
  // exists to produce would never be exercised by either runner.
  const sealedDiff: string[] = []
  const sealed = vector.sealed_signature_check
  if (sealed !== undefined) {
    const idRecomputed = computeReceiptIdV1(record) === record.receipt_id
    if (idRecomputed !== sealed.receipt_id_recomputed) {
      sealedDiff.push(
        `sealed_signature_check receipt_id_recomputed: recorded ${sealed.receipt_id_recomputed}, ` +
          `observed ${idRecomputed}`,
      )
    }
    const observedSignatures = record.signatures.map((signature: any) => {
      const descriptor = { signer: signature.signer, key_id: signature.key_id, alg: signature.alg }
      const key = keys[signature.key_id]
      return {
        signer: signature.signer,
        key_id: signature.key_id,
        verified:
          key === undefined
            ? false
            : verify(receiptSignaturePayloadV1(record, descriptor), signature.value, key),
      }
    })
    if (canonical(observedSignatures) !== canonical(sealed.signatures)) {
      sealedDiff.push(
        `sealed_signature_check signatures: recorded ${json(sealed.signatures)}, ` +
          `observed ${json(observedSignatures)}`,
      )
    }
  }

  // The harness prev check, for the cases that declare one. This is this family's own
  // reading of section 5.3.3 lines 1104 to 1105. It is not an SDK result and is never
  // recorded in an sdk_ts or sdk_py block.
  let harnessLine: string | null = null
  const harnessDiff: string[] = []
  if (vector.harness_prev_check) {
    const observed =
      record.prev === chain.consumed_decision_receipt_id
        ? 'prev_is_the_consumed_decision'
        : 'prev_is_not_the_consumed_decision'
    harnessLine = observed
    if (observed !== vector.harness_prev_check.expected) {
      harnessDiff.push(
        `harness prev check: recorded ${vector.harness_prev_check.expected}, observed ${observed}`,
      )
    }
  }

  const problems = [...stageDiff, ...compositeDiff, ...bindingDiff, ...sealedDiff, ...harnessDiff]

  if (problems.length === 0) {
    passed += 1
    console.log(`MATCH ${vector.id}`)
  } else {
    console.error(`FAIL ${vector.id}`)
    for (const problem of problems) console.error(`  ${problem}`)
    failures.push(vector.id)
  }

  const replay = vector.replay_policy
  const replayValue = replay.status === 'derived' ? replay.outcome : replay.status

  console.log(`  draft03                              ${vector.draft03.outcome}  [${vector.draft03.sections.join('; ')}]`)
  console.log(`  sdk_ts validateReceiptStageV1        status=${stageObserved.status} boundary_identity=${stageObserved.boundary_identity} stage=${json(stageObserved.stage)} failures=${json(stageObserved.failures.map((f: any) => f.code))}`)
  console.log(`  sdk_ts verifyReceiptWithDecisionV1   status=${compositeObserved.status} decision_ref_bound=${compositeObserved.decision_ref_bound} errors=${json(compositeObserved.errors)}`)
  console.log(`  sdk_py                               run fixtures/action-result-binding/validate.py separately; composite verifier ${vector.sdk_py.composite_decision_verifier.result}`)
  console.log(`  replay_policy (derived from stated rules, not run) ${replayValue}`)
  console.log(`  classification                       ${vector.classification}`)
  if (harnessLine !== null) {
    console.log(`  draft03 text check (harness, not SDK) ${harnessLine}`)
  }
}

const total = vectors.cases.length + receiptChecks
const matched = passed + receiptsMatched
console.log(`action-result-binding TypeScript: ${matched}/${total} matched`)
process.exit(matched === total && failures.length === 0 ? 0 : 1)
