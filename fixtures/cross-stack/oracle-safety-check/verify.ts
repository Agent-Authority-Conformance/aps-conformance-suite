// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Verify oracle-safety-check-v1/*.json against the PUBLISHED APS SDK package
// (agent-passport-system — no deep imports into src/) plus the vendored
// Insight verifier. This is the "runner must truly verify the inner layer and
// check what each vector declares" contract from conformance issue #26 and
// review aeoess/agent-passport-system#119.
//
// For every vector (coverage is enumerated in README.md, not in a
// verification_mode field):
//   0. Corpus membership is DERIVED from index.json (see corpus.ts): missing,
//      extra, duplicate, unreadable and id/file-mismatched entries all FAIL.
//   1. Recompute JCS canonical bytes + SHA-256 → canonical_bytes_hex / canonical_sha256.
//   2. Verify the Ed25519 witness over canonical bytes (agent key, derived
//      deterministically from seed_input).
//   3. Verify the outer receipts (computeReceiptIdV1 + verifyReceiptV1) and,
//      for the delegation chain via the SDK package: each delegation's Ed25519
//      signature, its parent_delegation_id linkage, and issuer/subject
//      continuity across the chain. This is NOT the SDK's full chain
//      verification — authority attenuation (facet and spend-limit narrowing)
//      is out of scope here; see README.md.
//   4. Truly verify the inner layer: recompute the 26-field EIP-712 digest and
//      recover the secp256k1 signer, which must equal
//      roles.evm_attester.address.
//   5. REBUILD the oracle data from oracle_input (the four ABI-keccak
//      commitments + verdict + windows) and compare with the envelope.
//   6. DERIVE the composite-gate reason set from the observable signals
//      (oracle_input.verdict, policy deny, evidence digest, inner
//      verification, revocation metadata, delegation time window) and assert
//      it EXACTLY equals the vector's expectReasons; assert
//      (reasons empty) ⇔ (expected === "allowed").
//   7. Compare the observed sub-results with the vector's own
//      expected_sub_results — negative expectations live in the DATA, so this
//      runner never branches on a fixture's id or name.
//
// Flipping oracle_input.verdict, emptying revocation, replacing
// expectReasons, or flipping expected on any vector FAILS the run.
//
// Run: npm run verify:oracle-safety-check            (semantic 13/13)
//      npm run verify:oracle-safety-check-flips     (--flip-check: 5 declared
//           mutations, each of which must FAIL)
//
// APS_FIXTURES_DIR overrides the fixture directory (same convention as
// runners/ts/verify.ts) so a harness can point the runner at a
// copied-and-mutated fixture tree.

import crypto from 'node:crypto'
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { hashTypedData, recoverTypedDataAddress } from 'viem'

import {
  canonicalizeJCS,
  computeReceiptIdV1,
  verifyReceiptV1,
  verifyAuthorityDelegationSignature,
} from 'agent-passport-system'

import { loadCorpus } from './corpus.js'
import { buildOracleSafetyCheck, verifyOracleSafetyCheck } from './vendor/insight/oracleSafetyCheck.js'
import { OSC_ARTIFACT_TYPE, OSC_DOMAIN, OSC_PRIMARY_TYPE, OSC_TYPES } from './vendor/insight/types.js'
import { AGENT_DID, BASELINE_MS, GATEWAY_DID, PRINCIPAL_DID, deriveEd25519, evmAttesterAddress } from './keys.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
// Dynamic (not captured at load) so --flip-check can repoint it at a mutated
// copy; same APS_FIXTURES_DIR convention as runners/ts/verify.ts.
function fixtureDir(): string {
  return process.env.APS_FIXTURES_DIR
    ? resolve(process.env.APS_FIXTURES_DIR)
    : join(__dirname, 'oracle-safety-check-v1')
}

const PKCS8_ED25519_PUB_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

// Sub-results a vector may declare in `expected_sub_results`. Every one of them
// is evaluated for every vector; the vector declares which ones must hold.
// Nothing here keys off a fixture's id or name.
const SUB_RESULTS = [
  'decision_signature_invalid',
  'evidence_digest_mismatch',
  'evidence_ref_absent',
  'attester_address_mismatch',
  'oracle_input_rebuild_differs',
  'rebuild_digest_equals_declared',
] as const
type SubResult = (typeof SUB_RESULTS)[number]

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex')
}

function verifyEd25519(message: Uint8Array, signatureHex: string, publicKeyHex: string): boolean {
  const pub = Buffer.from(publicKeyHex, 'hex')
  const derKey = Buffer.concat([PKCS8_ED25519_PUB_PREFIX, pub])
  const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
  return crypto.verify(null, Buffer.from(message), keyObj, Buffer.from(signatureHex, 'hex'))
}

function resolveKey(signer: string): string | undefined {
  const dids = new Map<string, string>([
    [PRINCIPAL_DID, deriveEd25519('principal').publicKeyHex],
    [AGENT_DID, deriveEd25519('agent').publicKeyHex],
    [GATEWAY_DID, deriveEd25519('gateway').publicKeyHex],
  ])
  return dids.get(signer)
}

interface Failure { fixture: string; check: string; expected: string; actual: string }

// ---------------------------------------------------------------------------
// Semantic gate: derive the composite-gate reason set from observable signals
// ---------------------------------------------------------------------------

async function deriveGateReasons(doc: Record<string, any>): Promise<string[]> {
  const env = doc.envelope
  const reasons: string[] = []
  const leaf = env.delegations[env.delegations.length - 1]

  // 1. oracle verdict (from oracle_input; input-faithfulness check ties it to
  //    the envelope data)
  const verdict = doc.oracle_input?.verdict
  if (verdict === 'DANGER') reasons.push('HALT_VERDICT_DANGER')
  if (verdict === 'BLOCK') reasons.push('HALT_VERDICT_BLOCK')

  // 2. policy outcome
  if (env.decision?.result?.verdict === 'deny') {
    reasons.push('HALT_AUTHORITY', 'POLICY_DENIED')
  }

  // 3. decision receipt signature
  const dVer = verifyReceiptV1(env.decision, (_s, _k, _i) => resolveKey(env.decision.issuer))
  if (!dVer.valid) {
    reasons.push('HALT_AUTHORITY', 'SIGNATURE_INVALID')
  }

  // 4. delegation time window at verification_time
  if (doc.verification_time && leaf?.authority?.time?.not_after) {
    const vNow = Date.parse(doc.verification_time)
    const notAfter = Date.parse(leaf.authority.time.not_after)
    if (vNow >= notAfter) {
      reasons.push('HALT_AUTHORITY', 'AUTH_DELEGATION_EXPIRED')
    }
  }

  // 5. declared ledger-side revocation
  if (
    Array.isArray(doc.revocation) &&
    doc.revocation.some(
      (r: any) => r.status === 'revoked' && env.delegations.some((d: any) => d.delegation_id === r.delegation_id)
    )
  ) {
    reasons.push('HALT_AUTHORITY', 'AUTH_DELEGATION_REVOKED')
  }

  // 6. evidence presence + digest
  const ref = env.decision.evidence_refs?.find((e: any) => e.artifact_type === OSC_ARTIFACT_TYPE)
  if (!ref) {
    reasons.push('HALT_ORACLE_EVIDENCE', 'EVIDENCE_MISSING')
  } else {
    const digest = sha256Hex(canonicalizeJCS(env.oracle))
    if (digest !== ref.sha256) {
      reasons.push('HALT_ORACLE_EVIDENCE', 'EVIDENCE_DIGEST_MISMATCH')
    }
  }

  // 7. inner verification (first root cause the gate would report)
  const inner = await verifyOracleSafetyCheck(env.oracle, BASELINE_MS)
  if (!inner.valid && inner.reasons.length > 0) {
    reasons.push('HALT_ORACLE_EVIDENCE', inner.reasons[0])
  }

  return reasons
}

// ---------------------------------------------------------------------------
// oracle_input faithfulness — rebuild the full 26-field data and compare
// ---------------------------------------------------------------------------

function dataEquals(a: Record<string, any>, b: Record<string, any>): boolean {
  const keysA = Object.keys(a).sort()
  const keysB = Object.keys(b).sort()
  if (JSON.stringify(keysA) !== JSON.stringify(keysB)) return false
  for (const k of keysA) {
    if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) return false
  }
  return true
}

function typedDataFrom(data: Record<string, any>) {
  const message: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(data)) {
    message[k] = typeof v === 'number' ? BigInt(v) : v
  }
  return { domain: OSC_DOMAIN, types: OSC_TYPES, primaryType: OSC_PRIMARY_TYPE, message }
}

function checkInputFaithfulness(doc: Record<string, any>): { failures: Failure[]; observed: SubResult[] } {
  const failures: Failure[] = []
  const observed: SubResult[] = []
  const id = doc.fixture
  const rebuilt = buildOracleSafetyCheck(doc.oracle_input)
  const envelopeData = doc.envelope.oracle.data
  const faithful = dataEquals(rebuilt, envelopeData)

  // Whether a mismatch is EXPECTED is declared by the vector in
  // `expected_sub_results` — not inferred from the fixture's id.
  if (!faithful) {
    observed.push('oracle_input_rebuild_differs')
    // The rebuild is the PRE-tamper data: its digest must equal the declared
    // (original) digest. Only meaningful when the two actually differ.
    const uid = hashTypedData(typedDataFrom(rebuilt as any) as any)
    if (uid === doc.eip712_digest_hex) {
      observed.push('rebuild_digest_equals_declared')
    }
  } else {
    const diffKeys = Object.keys(envelopeData).filter((k) => JSON.stringify(rebuilt[k]) !== JSON.stringify(envelopeData[k]))
    if (diffKeys.length > 0) {
      failures.push({
        fixture: id,
        check: 'oracle_input_rebuild',
        expected: 'rebuild from oracle_input == envelope.oracle.data',
        actual: `differs on: ${diffKeys.join(', ')}`,
      })
    }
  }
  return { failures, observed }
}

// ---------------------------------------------------------------------------
// Per-vector structural checks (unchanged contract: canonical, witness,
// outer receipts, chain, inner verification)
// ---------------------------------------------------------------------------

async function checkFixture(doc: Record<string, any>): Promise<{ failures: Failure[]; observed: SubResult[] }> {
  const failures: Failure[] = []
  const observed: SubResult[] = []
  const id = doc.fixture
  const env = doc.envelope

  // 0. contract: the declared outcome must be one of the two valid values.
  //    The gate used to compare "reasons empty" against "expected === 'allowed'",
  //    so `expected: "banana"` on a halt vector passed.
  if (doc.expected !== 'allowed' && doc.expected !== 'halt') {
    failures.push({ fixture: id, check: 'expected', expected: 'allowed | halt', actual: String(doc.expected) })
  }

  // 1. canonical witness
  const canonical = canonicalizeJCS(env)
  const canonicalBytes = Buffer.from(canonical, 'utf8')
  if (canonicalBytes.toString('hex') !== doc.canonical_bytes_hex) {
    failures.push({ fixture: id, check: 'canonical_bytes_hex', expected: doc.canonical_bytes_hex, actual: canonicalBytes.toString('hex') })
  }
  if (sha256Hex(canonical) !== doc.canonical_sha256) {
    failures.push({ fixture: id, check: 'canonical_sha256', expected: doc.canonical_sha256, actual: sha256Hex(canonical) })
  }
  // The witness key must be the agent key DERIVED from seed_input, not whatever
  // key the vector happens to carry. Verifying against the vector's own
  // ed25519_pubkey_hex would let anyone re-sign the same bytes with an
  // arbitrary key, put that key in the vector, and pass.
  const agentPub = deriveEd25519('agent').publicKeyHex
  if (doc.ed25519_pubkey_hex !== agentPub) {
    failures.push({ fixture: id, check: 'ed25519_pubkey_hex(derived)', expected: agentPub, actual: String(doc.ed25519_pubkey_hex) })
  }
  if (!verifyEd25519(canonicalBytes, doc.ed25519_signature_over_canonical_hex, agentPub)) {
    failures.push({ fixture: id, check: 'ed25519_witness', expected: 'valid under the derived agent key', actual: 'invalid' })
  }
  // seed_input must be the documented seed (everything else derives from it)
  if (doc.seed_input !== 'aps-oracle-safety-check-fixture-v1') {
    failures.push({ fixture: id, check: 'seed_input', expected: 'aps-oracle-safety-check-fixture-v1', actual: String(doc.seed_input) })
  }
  // ...and the seed hash and every role key must match that derivation, so a
  // vector cannot declare its own keys and still pass.
  if (doc.seed_sha256_hex !== sha256Hex(doc.seed_input)) {
    failures.push({ fixture: id, check: 'seed_sha256_hex(derived)', expected: sha256Hex(doc.seed_input), actual: String(doc.seed_sha256_hex) })
  }
  for (const role of ['principal', 'agent', 'gateway'] as const) {
    const derived = deriveEd25519(role).publicKeyHex
    if (doc.roles?.[role]?.publicKeyHex !== derived) {
      failures.push({ fixture: id, check: `roles.${role}.publicKeyHex(derived)`, expected: derived, actual: String(doc.roles?.[role]?.publicKeyHex) })
    }
  }
  if (doc.roles?.evm_attester?.address !== evmAttesterAddress()) {
    failures.push({
      fixture: id,
      check: 'roles.evm_attester.address(derived)',
      expected: evmAttesterAddress(),
      actual: String(doc.roles?.evm_attester?.address),
    })
  }

  // 2. outer receipts — id recompute + signature + chain links
  for (const [name, receipt] of [['intent', env.intent], ['decision', env.decision]] as const) {
    if (computeReceiptIdV1(receipt) !== receipt.receipt_id) {
      failures.push({ fixture: id, check: `${name}.receipt_id`, expected: receipt.receipt_id, actual: computeReceiptIdV1(receipt) })
    }
    const vr = verifyReceiptV1(receipt, (_s, _k, _i) => resolveKey(receipt.issuer))
    if (!vr.valid) {
      if (name === 'decision') {
        // Whether an invalid decision signature is EXPECTED is declared by the
        // vector, not by its id.
        observed.push('decision_signature_invalid')
      } else {
        // The intent receipt is expected to verify on every vector.
        failures.push({ fixture: id, check: `${name}.signature`, expected: 'valid', actual: vr.errors.join(';') })
      }
    }
  }
  if (env.decision.prev !== env.intent.receipt_id) {
    failures.push({ fixture: id, check: 'decision.prev', expected: env.intent.receipt_id, actual: env.decision.prev })
  }
  const leaf = env.delegations[env.delegations.length - 1]
  if (env.decision.delegation_ref !== leaf.delegation_id) {
    failures.push({ fixture: id, check: 'decision.delegation_ref', expected: leaf.delegation_id, actual: env.decision.delegation_ref })
  }

  // 3. delegation chain — via the published SDK this covers each delegation's
  //    Ed25519 signature, its parent_delegation_id linkage, and issuer/subject
  //    continuity. Authority attenuation (facet and spend-limit narrowing) is
  //    NOT checked here: `verifyAuthorityDelegationChain` is not exported by
  //    the published agent-passport-system package, and deep imports into
  //    dist/src/** are blocked by the package `exports` map — see README.md.
  for (let i = 0; i < env.delegations.length; i++) {
    const d = env.delegations[i]
    if (i > 0 && d.parent_delegation_id !== env.delegations[i - 1].delegation_id) {
      failures.push({ fixture: id, check: `delegation[${i}].parent`, expected: env.delegations[i - 1].delegation_id, actual: d.parent_delegation_id })
    }
    if (i > 0 && d.issuer !== env.delegations[i - 1].subject) {
      failures.push({ fixture: id, check: `delegation[${i}].continuity`, expected: env.delegations[i - 1].subject, actual: d.issuer })
    }
    const key = resolveKey(d.issuer)
    if (!key || !verifyAuthorityDelegationSignature(d, key)) {
      failures.push({ fixture: id, check: `delegation[${i}].signature`, expected: 'valid', actual: 'invalid' })
    }
  }

  // 4. inner layer — truly verified (digest + secp256k1), plus witness fields
  const ref = env.decision.evidence_refs?.find((e: any) => e.artifact_type === OSC_ARTIFACT_TYPE)
  if (!ref) {
    observed.push('evidence_ref_absent')
  } else {
    const digest = sha256Hex(canonicalizeJCS(env.oracle))
    if (digest !== ref.sha256) observed.push('evidence_digest_mismatch')
  }

  const oracleOk = await verifyOracleSafetyCheck(env.oracle, BASELINE_MS)
  if (doc.expected === 'allowed' && !oracleOk.valid) {
    failures.push({ fixture: id, check: 'inner_verification', expected: 'valid', actual: oracleOk.reasons.join(';') })
  }

  if (doc.eip712_digest_hex !== env.oracle.uid) {
    failures.push({ fixture: id, check: 'eip712_digest_hex', expected: env.oracle.uid, actual: doc.eip712_digest_hex })
  }
  if (doc.secp256k1_signature_hex !== env.oracle.signature) {
    failures.push({ fixture: id, check: 'secp256k1_signature_hex', expected: env.oracle.signature, actual: doc.secp256k1_signature_hex })
  }
  if (env.oracle.attester !== evmAttesterAddress()) {
    // Whether the mismatch is EXPECTED is declared by the vector (wrong-signer
    // declares it); the envelope field itself is never silently accepted.
    observed.push('attester_address_mismatch')
  }

  // 5. the inner signature must RECOVER the declared attester role address.
  //    README promises this field is consumed; without it a vector that
  //    declares an arbitrary address still passes.
  //
  //    Signer recovery is only meaningful over the bytes that were actually
  //    signed: on a vector whose data was modified after signing (tampered-
  //    oracle) recovery returns an unrelated address, which says nothing about
  //    the attester. So this runs only when the recomputed digest still equals
  //    the declared one; tampering is caught by the inner verification above.
  const declaredAttester = doc.roles?.evm_attester?.address
  if (typeof declaredAttester !== 'string' || declaredAttester.length === 0) {
    failures.push({ fixture: id, check: 'roles.evm_attester.address', expected: 'a declared address', actual: String(declaredAttester) })
  } else {
    const typedData = typedDataFrom(env.oracle.data)
    const recomputedDigest = hashTypedData(typedData as any)
    if (recomputedDigest === doc.eip712_digest_hex) {
      const recovered = await recoverTypedDataAddress({
        ...typedData,
        signature: env.oracle.signature,
      } as any)
      if (recovered.toLowerCase() !== declaredAttester.toLowerCase()) {
        failures.push({ fixture: id, check: 'roles.evm_attester.address(recovered)', expected: declaredAttester, actual: recovered })
      }
    }
  }

  return { failures, observed }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function verifyVector(entry: CorpusEntry): Promise<Failure[]> {
  const { id, doc } = entry
  const failures: Failure[] = []

  // structural + inner-layer checks
  const structural = await checkFixture(doc)
  failures.push(...structural.failures)

  // oracle_input faithfulness (four commitments rebuilt from oracle_input)
  const faithfulness = checkInputFaithfulness(doc)
  failures.push(...faithfulness.failures)

  // Sub-results: what a negative case MEANS is declared by the vector, not by
  // this runner. Observed and declared sets must match in both directions.
  const observed = [...new Set([...structural.observed, ...faithfulness.observed])].sort()
  const declaredSubResults = doc.expected_sub_results
  if (!Array.isArray(declaredSubResults)) {
    failures.push({
      fixture: id,
      check: 'expected_sub_results',
      expected: 'an array of declared sub-results',
      actual: String(declaredSubResults),
    })
  } else {
    const unknown = declaredSubResults.filter((s: unknown) => !SUB_RESULTS.includes(s as SubResult))
    if (unknown.length > 0) {
      failures.push({
        fixture: id,
        check: 'expected_sub_results(known names)',
        expected: SUB_RESULTS.join(', '),
        actual: unknown.join(', '),
      })
    }
    const declared = [...declaredSubResults].sort()
    if (JSON.stringify(observed) !== JSON.stringify(declared)) {
      failures.push({
        fixture: id,
        check: 'expected_sub_results',
        expected: JSON.stringify(declared),
        actual: JSON.stringify(observed),
      })
    }
  }

  // semantic gate — the fields the vector NAMES must affect the verdict
  const derived = await deriveGateReasons(doc)
  const declared = [...(doc.expectReasons ?? [])].sort()
  const derivedSorted = [...derived].sort()
  if (JSON.stringify(derivedSorted) !== JSON.stringify(declared)) {
    failures.push({
      fixture: id,
      check: 'expectReasons(semantic gate)',
      expected: JSON.stringify(declared),
      actual: JSON.stringify(derivedSorted),
    })
  }
  const allowed = (derived.length === 0) === (doc.expected === 'allowed')
  if (!allowed) {
    failures.push({
      fixture: id,
      check: 'expected(semantic gate)',
      expected: doc.expected === 'allowed' ? 'allowed (empty reasons)' : `halt (${JSON.stringify(declared)})`,
      actual: `derived reasons: ${JSON.stringify(derivedSorted)}`,
    })
  }
  return failures
}

async function main() {
  const dir = fixtureDir()
  const { entries, problems } = loadCorpus(dir)

  if (problems.length > 0) {
    for (const p of problems) console.log(`  FAIL corpus[${p.kind}] ${p.detail}`)
    console.log('')
    console.log(`0/${entries.length} fixtures passed — corpus membership is invalid`)
    process.exit(1)
  }

  const allFailures: Failure[] = []
  let passed = 0
  for (const entry of entries) {
    const failures = await verifyVector(entry)
    if (failures.length === 0) {
      passed++
      console.log(`  ok  ${entry.id}`)
    } else {
      console.log(`  FAIL ${entry.id}`)
      for (const f of failures) {
        console.log(`       ${f.check}`)
        console.log(`         expected: ${f.expected}`)
        console.log(`         actual:   ${f.actual}`)
      }
      allFailures.push(...failures)
    }
  }
  console.log('')
  console.log(`${passed}/${entries.length} fixtures passed`)
  if (allFailures.length > 0) {
    console.log(`${allFailures.length} check(s) failed`)
    process.exit(1)
  }
}

// --flip-check: reproduce the review's field-flip experiments on a COPY of the
// fixture tree. Each flip MUST produce at least one failure — proving the
// declared fields (expectReasons / verdict / revocation / expected /
// oracle_input) actually affect verification.
async function mainFlipCheck() {
  const tmp = mkdtempSync(join(tmpdir(), 'osc-flip-'))
  // These five mutations are the whole set. The claim below is scoped to them
  // — it is not a general "every field affects the verdict" proof.
  const cases: Array<[string, string, (d: Record<string, any>) => void]> = [
    ['empty revocation block on delegation-revoked', 'delegation-revoked', (d) => { d.revocation = [] }],
    ['replace expectReasons with a bogus code on authority-denied', 'authority-denied', (d) => { d.expectReasons = ['BOGUS_CODE'] }],
    ['flip expected halt→allowed on danger', 'danger', (d) => { d.expected = 'allowed' }],
    ['change oracle_input.verdict on pass', 'pass', (d) => { d.oracle_input.verdict = 'DANGER' }],
    ['empty expectReasons on tampered-oracle', 'tampered-oracle', (d) => { d.expectReasons = [] }],
  ]
  let allDetected = true
  try {
    // Copy the whole corpus so membership stays complete: a flip run that
    // silently lost 12 vectors would "detect" everything for the wrong reason.
    cpSync(fixtureDir(), tmp, { recursive: true })
    const baseline = loadCorpus(tmp)
    if (baseline.problems.length > 0) {
      throw new Error(`copied corpus is invalid: ${baseline.problems.map((p) => p.detail).join('; ')}`)
    }

    for (const [label, fixture, mutate] of cases) {
      const src = readFileSync(join(tmp, `${fixture}.json`), 'utf8')
      const doc = JSON.parse(src)
      mutate(doc)
      writeFileSync(join(tmp, `${fixture}.json`), JSON.stringify(doc, null, 2))
      const prevDir = process.env.APS_FIXTURES_DIR
      process.env.APS_FIXTURES_DIR = tmp
      const { entries, problems } = loadCorpus(tmp)
      const entry = entries.find((e) => e.id === fixture)
      const failures = entry ? await verifyVector(entry) : []
      if (prevDir) process.env.APS_FIXTURES_DIR = prevDir
      else delete process.env.APS_FIXTURES_DIR
      const detected = problems.length > 0 || failures.length > 0
      console.log(`${detected ? 'DETECTED' : 'MISSED  '}  ${label}`)
      if (!detected) allDetected = false
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true })
    delete process.env.APS_FIXTURES_DIR
  }
  console.log('')
  console.log(
    allDetected
      ? `ALL ${cases.length} DECLARED MUTATIONS DETECTED`
      : 'SOME MUTATIONS WERE MISSED',
  )
  process.exit(allDetected ? 0 : 1)
}

if (process.argv.includes('--flip-check')) {
  mainFlipCheck().catch((e) => {
    console.error(e)
    process.exit(1)
  })
} else {
  main().catch((e) => {
    console.error(e)
    process.exit(1)
  })
}
