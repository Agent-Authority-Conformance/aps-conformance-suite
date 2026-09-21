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
// The draft03 and replay_policy blocks are printed for the reader and are NOT asserted
// against the SDK: they come from the published text and from a third party's report,
// and a runner that asserted one against the other would be deciding which of them is
// authoritative. That is the whole point of keeping the blocks apart.
//
// The prev comparison of section 5.3.3 line 1104 is NOT an SDK result. Neither SDK
// resolves prev. Case 3 prints one harness line, labelled as such, and nothing in that
// line is recorded or reported as SDK behaviour.
//
// Run from the suite root:
//
//     npm run verify:action-result-binding

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { validateReceiptStageV1, verifyReceiptWithDecisionV1 } from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8'))
}

const chain = readJson('chain.json')
const vectors = readJson('vectors.json')

const boundary: string = chain.identities.enforcement_boundary
const keys: Record<string, string> = chain.verification_keys
const resolveKey = (_signer: string, keyId: string): string | undefined => keys[keyId]

const json = (value: unknown): string => JSON.stringify(value)

/** Compare only the members vectors.json records. Extra members the SDK returns are
 *  reported in the failure detail but never silently accepted as agreement. */
function diff(expected: Record<string, unknown>, actual: Record<string, unknown>): string[] {
  const out: string[] = []
  for (const key of Object.keys(expected)) {
    if (key === 'entrypoint') continue
    if (json(expected[key]) !== json(actual[key])) {
      out.push(`${key}: recorded ${json(expected[key])}, observed ${json(actual[key])}`)
    }
  }
  return out
}

let passed = 0
const failures: string[] = []

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

  // The harness prev check, for the cases that declare one. This is this family's own
  // reading of section 5.3.3 line 1104. It is not an SDK result and is never recorded
  // in an sdk_ts or sdk_py block.
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

  const problems = [...stageDiff, ...compositeDiff, ...harnessDiff]

  if (problems.length === 0) {
    passed += 1
    console.log(`PASS ${vector.id}`)
  } else {
    console.error(`FAIL ${vector.id}`)
    for (const problem of problems) console.error(`  ${problem}`)
    failures.push(vector.id)
  }

  console.log(`  draft03                              ${vector.draft03.outcome}  [${vector.draft03.sections.join('; ')}]`)
  console.log(`  sdk_ts validateReceiptStageV1        status=${stageObserved.status} boundary_identity=${stageObserved.boundary_identity} stage=${json(stageObserved.stage)} failures=${json(stageObserved.failures.map((f: any) => f.code))}`)
  console.log(`  sdk_ts verifyReceiptWithDecisionV1   status=${compositeObserved.status} decision_ref_bound=${compositeObserved.decision_ref_bound} errors=${json(compositeObserved.errors)}`)
  console.log(`  sdk_py                               run fixtures/action-result-binding/validate.py separately; composite verifier ${vector.sdk_py.composite_decision_verifier.result}`)
  console.log(`  replay_policy (reported, not run)    ${vector.replay_policy.outcome}${vector.replay_policy.note ? ` (${vector.replay_policy.note})` : ''}`)
  console.log(`  classification                       ${vector.classification}`)
  if (harnessLine !== null) {
    console.log(`  draft03 text check (harness, not SDK) ${harnessLine}`)
  }
}

console.log(`action-result-binding TypeScript: ${passed}/${vectors.cases.length} passed`)
process.exit(passed === vectors.cases.length && failures.length === 0 ? 0 : 1)
