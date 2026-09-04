// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The validation layers of the accountability-record family, and the single
// place that runs all of them.
//
// This family's twelve vectors are not decided by one layer. Three negatives
// are decided by cryptography (a signature that does not verify, an inline
// payload that does not bind to its digest) and two by schema (a `decision`
// outside the boundary enum, a non-canonical `sig_alg` label). Both kinds of
// record are cryptographically coherent; the schema negatives carry a valid
// signature over their own bytes and no crypto check can or should reject them.
//
// The layers stay orthogonal. The crypto layer is not taught to read the
// schema, and the schema layer knows nothing about Ed25519. Neither emits an
// overall verdict. Both report their own result for every vector, and the
// overall per-vector verdict is computed by runners/ts/layered-gate.ts from the
// layers fixtures/manifest.json declares required. A required layer that could
// not run fails the family; it does not skip it.
//
// Both entry points -- fixtures/accountability-record/verify.ts (cold clone)
// and runners/ts/verify.ts (manifest runner) -- call evaluateFamily here, so
// there is one implementation of the gate rather than two that can drift.

import { join } from 'node:path'
import {
  computeVerdicts,
  loadSchemaLayer,
  type LayerError,
  type LayerReport,
  type LayerVectorResult,
  type LayeredDecl,
  type Verdict,
} from '../../runners/ts/layered-gate.js'
import { canonicalizeJCS, sha256Hex, signingInput, utf8Hex, verifyRecord, type AccountabilityRecord } from './lib.js'

export interface AccountabilityVector {
  name: string
  record: AccountabilityRecord
  signing_input_canonical: string
  signing_input_bytes_hex: string
  canonical: string
  canonical_bytes_hex: string
  canonical_sha256: string
  ed25519_pubkey_hex: string
  ed25519_signature_over_signing_input_hex: string
  expected_verification: boolean
  rejection_kind?: string
  expected_error_code?: string
}

export interface AccountabilityFixture {
  vectors: AccountabilityVector[]
}

/**
 * Fixture integrity, asserted for every vector regardless of expected outcome.
 *
 * This is not a validation layer: it does not judge whether a record is valid,
 * it checks that the fixture's stored bytes are what re-derivation produces. A
 * mismatch means the published bytes and the record disagree, which invalidates
 * every claim recorded against them, so it fails the vector outright.
 */
export function byteParityProblems(v: AccountabilityVector): string[] {
  const problems: string[] = []
  const si = signingInput(v.record as unknown as Record<string, unknown>)
  if (si !== v.signing_input_canonical) problems.push('signing_input_canonical mismatch')
  if (utf8Hex(si) !== v.signing_input_bytes_hex) problems.push('signing_input_bytes_hex mismatch')
  const canonical = canonicalizeJCS(v.record)
  if (canonical !== v.canonical) problems.push('canonical mismatch')
  if (utf8Hex(canonical) !== v.canonical_bytes_hex) problems.push('canonical_bytes_hex mismatch')
  if (sha256Hex(canonical) !== v.canonical_sha256) problems.push('canonical_sha256 mismatch')
  if (v.record.sig !== v.ed25519_signature_over_signing_input_hex) problems.push('record.sig != published signature')
  return problems
}

/**
 * The cryptographic layer: Ed25519 over the signing input, action_digest
 * binding, and action_ref recomputation when the payload is inline.
 *
 * It answers exactly one question -- does this record hold together
 * cryptographically -- and reports that answer for every vector, including the
 * schema negatives, whose records it accepts because they genuinely are
 * cryptographically coherent. Reporting an accept for a schema negative is
 * correct; what would be wrong is calling that accept an overall PASS.
 *
 * The instancePath/keyword pairs below are the vocabulary the manifest's
 * error_bindings refer to, so a vector's expected_error_code is checked against
 * a concrete observed error rather than against the mere fact of rejection.
 */
export function cryptoLayer(layerName: string, vectors: AccountabilityVector[]): LayerReport {
  const results: LayerVectorResult[] = []
  for (const v of vectors) {
    const res = verifyRecord(v.record, v.ed25519_pubkey_hex)
    const errors: LayerError[] = []
    if (res.checks.signature !== true) {
      errors.push({ instancePath: '/sig', keyword: 'ed25519', message: 'Ed25519 signature does not verify against the resolved key' })
    }
    if (res.checks.action_digest_binds === false) {
      errors.push({
        instancePath: '/action_digest/sha256',
        keyword: 'digest-binding',
        message: 'sha256(JCS(action)) does not equal action_digest.sha256',
      })
    }
    if (res.checks.action_ref_recomputes === false) {
      errors.push({
        instancePath: '/action_ref',
        keyword: 'action-ref-recompute',
        message: 'action_ref does not recompute from the inline action',
      })
    }
    const detached = res.checks.action_digest_binds === 'detached (no inline action)'
    results.push({
      vector: v.name,
      accepted: res.ok,
      errors,
      note: detached ? 'payload-unverified (detached)' : undefined,
    })
  }
  return { layer: layerName, available: true, results }
}

export interface FamilyEvaluation {
  verdicts: Verdict[]
  reports: LayerReport[]
  /** Per-vector byte-parity problems, keyed by vector name. */
  parity: Map<string, string[]>
}

/**
 * Run every layer the manifest declares required for this family and compute
 * the per-vector verdict. `fixturesDir` is the root the manifest's paths are
 * relative to, so a mutation harness can point this at a copied tree.
 */
export async function evaluateFamily(
  fixturesDir: string,
  fixture: AccountabilityFixture,
  decl: LayeredDecl,
): Promise<FamilyEvaluation> {
  const vectors = fixture.vectors
  const reports: LayerReport[] = []

  for (const layerName of decl.required_layers) {
    const layerDecl = decl.layers[layerName]
    if (!layerDecl) {
      reports.push({ layer: layerName, available: false, reason: 'no declaration in manifest layers' })
      continue
    }
    if (layerDecl.kind === 'crypto') {
      reports.push(cryptoLayer(layerName, vectors))
    } else if (layerDecl.kind === 'json-schema') {
      if (!layerDecl.schema_path) {
        reports.push({ layer: layerName, available: false, reason: 'json-schema layer declares no schema_path' })
        continue
      }
      reports.push(
        await loadSchemaLayer(
          layerName,
          layerDecl,
          join(fixturesDir, layerDecl.schema_path),
          vectors,
          (v) => (v as AccountabilityVector).name,
        ),
      )
    } else {
      reports.push({ layer: layerName, available: false, reason: `unknown layer kind "${layerDecl.kind}"` })
    }
  }

  const verdicts = computeVerdicts(vectors, decl, reports)

  // Byte parity is folded in after the layer verdicts so a fixture whose stored
  // bytes disagree with its record can never present as a clean pass.
  const parity = new Map<string, string[]>()
  for (const v of vectors) {
    const problems = byteParityProblems(v)
    parity.set(v.name, problems)
    if (problems.length > 0) {
      const verdict = verdicts.find((x) => x.vector === v.name)
      if (verdict) {
        verdict.problems.push(...problems.map((p) => `byte-parity: ${p}`))
        verdict.pass = false
      }
    }
  }

  return { verdicts, reports, parity }
}
