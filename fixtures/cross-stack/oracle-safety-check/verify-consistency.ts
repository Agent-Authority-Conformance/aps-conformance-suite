// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic consistency comparison that PRODUCES the "56/56" figure.
//
// For every one of the 13 vectors it rebuilds the four ABI-keccak commitments
// from the vector's own oracle_input (via the vendored pipeline) and compares
// them with the values baked into the envelope (13 × 4 = 52 checks). For the
// two positive vectors (pass, caution) it also re-derives the EIP-712 digest
// and verifies the secp256k1 signature against the declared attester
// (2 × 2 = 4 checks). Total: 56 checks.
//
// This is SAME-IMPLEMENTATION CONSISTENCY, not independent verification: it
// re-uses the same vendored Insight builder the upstream generator uses. See
// SOURCE.md for what independent recomputation exists.
//
// Run: npm run verify:oracle-safety-check-consistency

import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { hashTypedData, verifyTypedData } from 'viem'

import { loadCorpus } from './corpus.js'
import { buildOracleSafetyCheck } from './vendor/insight/oracleSafetyCheck.js'
import { OSC_DOMAIN, OSC_PRIMARY_TYPE, OSC_TYPES } from './vendor/insight/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, 'oracle-safety-check-v1')

const COMMITMENTS = ['requestHash', 'reasonCodesHash', 'evaluatedAssetIdsHash', 'providerObservationsHash'] as const

// Membership is derived from index.json so an extra, missing, duplicated or
// unreadable vector cannot slip past the 56-check figure.
const { entries, problems } = loadCorpus(FIXTURE_DIR)
if (problems.length > 0) {
  for (const p of problems) console.log(`[FAIL] corpus[${p.kind}] ${p.detail}`)
  console.log(`\n${problems.length} failures — corpus membership is invalid`)
  process.exit(1)
}

let checked = 0
let failures = 0

for (const { id, doc } of entries) {
  const env = doc.envelope

  // 1. four commitments rebuilt from oracle_input
  const rebuilt = buildOracleSafetyCheck(doc.oracle_input)
  for (const name of COMMITMENTS) {
    checked++
    if (rebuilt[name] !== env.oracle.data[name]) {
      failures++
      console.log(`[FAIL] ${id}.${name}\n  rebuilt: ${rebuilt[name]}\n  baked:   ${env.oracle.data[name]}`)
    }
  }

  // 2. positive vectors only (unmutated): digest + secp256k1. Which vectors
  //    count as positive is read from the data, not from their names.
  if (doc.expected === 'allowed') {
    const message: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(env.oracle.data)) {
      message[k] = typeof v === 'number' ? BigInt(v) : v
    }
    const typedData = { domain: OSC_DOMAIN, types: OSC_TYPES, primaryType: OSC_PRIMARY_TYPE, message }
    checked++
    if (hashTypedData(typedData as any) !== env.oracle.uid) {
      failures++
      console.log(`[FAIL] ${id}.uid`)
    }
    checked++
    const valid = await verifyTypedData({
      ...(typedData as any),
      address: env.oracle.attester as `0x${string}`,
      signature: env.oracle.signature as `0x${string}`,
    })
    if (!valid) {
      failures++
      console.log(`[FAIL] ${id}.secp256k1`)
    }
  }
}

console.log(`\n${checked} checks, ${failures} failures (${checked - failures}/${checked} identical values)`)
process.exit(failures === 0 ? 0 : 1)
