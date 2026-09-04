// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Layered verdicts for fixture families that are decided by more than one
// validation layer.
//
// The problem this solves. A family whose negatives are split across layers --
// some rejected by cryptography, some by schema -- used to let each layer print
// PASS for the vectors it did not decide, on the stated grounds that another
// layer decided them. When that other layer was not in the default command,
// nothing decided them at all: the schema could be deleted and `npm test` still
// printed ALL VECTORS PASS.
//
// The rule here. Layers stay orthogonal. Each layer answers one question about
// a record and reports its own result. No layer is taught another layer's job,
// and no layer emits an overall verdict. The overall verdict is computed HERE,
// from the results of every layer the manifest declares required, and a layer
// that produced no result -- absent, crashed, skipped, unavailable -- makes the
// verdict FAIL, never SKIP.
//
// Vocabulary:
//   layer            a named validation layer, e.g. 'crypto' or 'schema'
//   required_layers  the manifest's declaration of which layers decide a family
//   owns_rejection_kinds
//                    which vector rejection_kind values a layer is accountable
//                    for. A negative vector's rejection_kind MUST be owned by
//                    exactly one required layer, otherwise nothing is
//                    accountable for it and the verdict is FAIL.
//   error_bindings   maps a vector's expected_error_code to the concrete error
//                    its owning layer must produce (instance path + keyword).
//                    A negative passes only when the owning layer rejected AND
//                    produced that specific error. This is what makes a
//                    weakened constraint fail: drop the `decision` enum and the
//                    schema stops producing /decision + enum, so the expected
//                    rejection is not observed and the verdict is FAIL.
//
// No dependency beyond ajv (pinned) and Node builtins.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

export const DRAFT_2020_12 = 'https://json-schema.org/draft/2020-12/schema'

/** One concrete reason a layer rejected a record. */
export interface LayerError {
  /** RFC 6901 pointer into the record, e.g. '/decision'. '' means the record root. */
  instancePath: string
  /** The rule that failed: a JSON Schema keyword, or a layer-defined check name. */
  keyword: string
  message: string
}

/** What one layer concluded about one vector. */
export interface LayerVectorResult {
  vector: string
  /** Did this layer accept the record? */
  accepted: boolean
  errors: LayerError[]
  /** Free text shown next to the layer result; never affects the verdict. */
  note?: string
}

/**
 * What one layer concluded about a whole fixture file. `available: false` is a
 * layer that could not run at all (schema file missing, unparseable, not a
 * valid Draft 2020-12 schema, validator module not installed). It fails every
 * vector in the family; it never downgrades them to skip.
 */
export type LayerReport =
  | { layer: string; available: true; results: LayerVectorResult[] }
  | { layer: string; available: false; reason: string }

export interface ErrorBinding {
  instance_path: string
  keyword: string
}

/** A layer's declaration in fixtures/manifest.json. */
export interface LayerDecl {
  kind: string
  description?: string
  owns_rejection_kinds: string[]
  error_bindings?: Record<string, ErrorBinding>
  // json-schema layers only
  dialect?: string
  validator?: string
  schema_path?: string
  schema_sha256?: string
  instance_pointer?: string
  parity_implementation?: string
}

export interface LayeredDecl {
  required_layers: string[]
  layers: Record<string, LayerDecl>
}

/** The vector fields the verdict algebra reads. */
export interface VerdictVector {
  name: string
  expected_verification?: boolean
  rejection_kind?: string
  expected_error_code?: string
}

export interface Verdict {
  vector: string
  pass: boolean
  /** Per-layer summary, always reported, whether or not it was decisive. */
  layerSummary: string
  problems: string[]
}

/** RFC 6901 JSON pointer resolution. '' is the whole document. */
export function resolvePointer(doc: unknown, pointer: string): unknown {
  if (pointer === '') return doc
  if (!pointer.startsWith('/')) throw new Error(`not a JSON pointer: ${JSON.stringify(pointer)}`)
  let cur: unknown = doc
  for (const rawToken of pointer.slice(1).split('/')) {
    const token = rawToken.replace(/~1/g, '/').replace(/~0/g, '~')
    if (cur === null || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[token]
  }
  return cur
}

function sha256OfFile(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

// ---------------------------------------------------------------------------
// JSON Schema layer (Draft 2020-12, ajv)
// ---------------------------------------------------------------------------

/**
 * Build a Draft 2020-12 schema layer from a manifest declaration.
 *
 * Every one of these is a hard failure, reported as an unavailable layer rather
 * than swallowed: the validator module is not installed, the schema file is
 * missing or unreadable, the schema is not parseable JSON, the schema's bytes
 * do not match the digest pinned in the manifest, the schema does not declare
 * the Draft 2020-12 dialect, the schema is not itself a valid Draft 2020-12
 * schema (meta-validation), or the schema does not compile.
 *
 * `schemaAbsPath` is resolved by the caller so a mutation harness can point the
 * loader at a copied tree.
 */
export async function loadSchemaLayer(
  layerName: string,
  decl: LayerDecl,
  schemaAbsPath: string,
  vectors: unknown[],
  vectorName: (v: unknown) => string,
): Promise<LayerReport> {
  const unavailable = (reason: string): LayerReport => ({ layer: layerName, available: false, reason })

  const dialect = decl.dialect ?? DRAFT_2020_12
  if (dialect !== DRAFT_2020_12) {
    return unavailable(`unsupported dialect ${dialect}; this gate implements ${DRAFT_2020_12}`)
  }

  // The validator itself is a required layer component. An absent module is a
  // failure, not a reason to skip. Imported dynamically so its absence is
  // reportable instead of an unhandled module-resolution crash.
  let Ajv2020: new (opts: Record<string, unknown>) => AjvLike
  try {
    const mod = (await import('ajv/dist/2020.js')) as unknown as { default: unknown }
    const candidate = (mod.default as { default?: unknown })?.default ?? mod.default
    Ajv2020 = candidate as new (opts: Record<string, unknown>) => AjvLike
    if (typeof Ajv2020 !== 'function') {
      return unavailable(`ajv/dist/2020.js did not export a constructor (got ${typeof Ajv2020})`)
    }
  } catch (err) {
    return unavailable(`schema validator unavailable: ${(err as Error).message}`)
  }

  let raw: string
  try {
    raw = readFileSync(schemaAbsPath, 'utf8')
  } catch (err) {
    return unavailable(`schema file missing or unreadable at ${schemaAbsPath}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`)
  }

  if (decl.schema_sha256) {
    const actual = sha256OfFile(schemaAbsPath)
    if (actual !== decl.schema_sha256) {
      return unavailable(
        `schema digest mismatch: manifest pins ${decl.schema_sha256.slice(0, 16)}…, file is ${actual.slice(0, 16)}…`,
      )
    }
  }

  let schema: Record<string, unknown>
  try {
    schema = JSON.parse(raw) as Record<string, unknown>
  } catch (err) {
    return unavailable(`schema is not parseable JSON: ${(err as Error).message}`)
  }

  if (schema.$schema !== dialect) {
    return unavailable(`schema does not declare the ${dialect} dialect (found ${JSON.stringify(schema.$schema)})`)
  }

  // strict: true rejects unknown keywords, so a typo'd constraint is a loud
  // failure rather than an ignored annotation. validateFormats: false keeps
  // `format` annotation-only, matching Python jsonschema's default
  // Draft202012Validator, so the two implementations stay at parity.
  const ajv = new Ajv2020({ strict: true, allErrors: true, validateFormats: false })

  try {
    if (!ajv.validateSchema(schema)) {
      const errs = (ajv.errors ?? []).map((e) => `${e.instancePath || '<root>'} ${e.keyword}: ${e.message}`).join('; ')
      return unavailable(`schema is not a valid Draft 2020-12 schema: ${errs || 'meta-validation failed'}`)
    }
  } catch (err) {
    return unavailable(`schema meta-validation threw: ${(err as Error).message}`)
  }

  let validate: AjvValidate
  try {
    validate = ajv.compile(schema)
  } catch (err) {
    return unavailable(`schema does not compile: ${(err as Error).message}`)
  }

  const pointer = decl.instance_pointer ?? ''
  const results: LayerVectorResult[] = []
  for (const v of vectors) {
    const name = vectorName(v)
    const instance = resolvePointer(v, pointer)
    if (instance === undefined) {
      results.push({
        vector: name,
        accepted: false,
        errors: [{ instancePath: '', keyword: 'instance_pointer', message: `no value at instance_pointer ${pointer || '<root>'}` }],
      })
      continue
    }
    const ok = validate(instance)
    results.push({
      vector: name,
      accepted: ok,
      errors: ok
        ? []
        : (validate.errors ?? []).map((e) => ({
            instancePath: e.instancePath,
            keyword: e.keyword,
            message: e.message ?? '',
          })),
    })
  }

  return { layer: layerName, available: true, results }
}

interface AjvErrorObject {
  instancePath: string
  keyword: string
  message?: string
}
interface AjvValidate {
  (data: unknown): boolean
  errors?: AjvErrorObject[] | null
}
interface AjvLike {
  errors?: AjvErrorObject[] | null
  validateSchema(schema: unknown): boolean
  compile(schema: unknown): AjvValidate
}

// ---------------------------------------------------------------------------
// Verdict algebra
// ---------------------------------------------------------------------------

function describeErrors(errs: LayerError[]): string {
  if (errs.length === 0) return 'accept'
  return errs.map((e) => `${e.instancePath || '<root>'} ${e.keyword}`).join(', ')
}

/**
 * Compute one verdict per vector from the reports of every required layer.
 *
 * Rules, in order:
 *   1. A required layer that is unavailable fails every vector.
 *   2. A vector with no result from a required layer FAILS (never skips).
 *   3. expected_verification === true: every required layer must accept.
 *   4. expected_verification === false: rejection_kind must be owned by exactly
 *      one required layer; that layer must reject; and if the vector declares
 *      an expected_error_code, the layer's declaration must bind that code and
 *      the layer must have produced a matching error. Non-owning layers report
 *      their result and never affect the verdict.
 *   5. A negative with no rejection_kind FAILS: nothing is accountable for it.
 */
export function computeVerdicts(
  vectors: VerdictVector[],
  decl: LayeredDecl,
  reports: LayerReport[],
): Verdict[] {
  const byName = new Map(reports.map((r) => [r.layer, r]))
  const verdicts: Verdict[] = []

  // Structural problems with the declaration itself apply to every vector.
  const declProblems: string[] = []
  for (const layerName of decl.required_layers) {
    if (!decl.layers[layerName]) declProblems.push(`required layer "${layerName}" has no declaration in manifest layers`)
    if (!byName.has(layerName)) declProblems.push(`required layer "${layerName}" produced no report`)
  }

  for (const v of vectors) {
    const problems: string[] = [...declProblems]
    const summary: string[] = []

    const perLayer = new Map<string, LayerVectorResult>()
    for (const layerName of decl.required_layers) {
      const report = byName.get(layerName)
      if (!report) {
        summary.push(`${layerName}=<no report>`)
        continue
      }
      if (!report.available) {
        problems.push(`required layer "${layerName}" is unavailable: ${report.reason}`)
        summary.push(`${layerName}=<unavailable>`)
        continue
      }
      const r = report.results.find((x) => x.vector === v.name)
      if (!r) {
        problems.push(`required layer "${layerName}" produced no result for this vector (absent, crashed, or skipped)`)
        summary.push(`${layerName}=<no result>`)
        continue
      }
      perLayer.set(layerName, r)
      summary.push(`${layerName}=${r.accepted ? 'accept' : `reject(${describeErrors(r.errors)})`}`)
    }

    if (v.expected_verification === true) {
      for (const [layerName, r] of perLayer) {
        if (!r.accepted) {
          problems.push(`positive vector rejected by layer "${layerName}": ${describeErrors(r.errors)}`)
        }
      }
    } else if (v.expected_verification === false) {
      const kind = v.rejection_kind
      if (kind === undefined) {
        problems.push('negative vector declares no rejection_kind, so no layer is accountable for rejecting it')
      } else {
        const owners = decl.required_layers.filter((n) => (decl.layers[n]?.owns_rejection_kinds ?? []).includes(kind))
        if (owners.length === 0) {
          problems.push(`rejection_kind "${kind}" is owned by no required layer; nothing asserts this rejection`)
        } else if (owners.length > 1) {
          problems.push(`rejection_kind "${kind}" is owned by more than one required layer (${owners.join(', ')}); ownership must be unambiguous`)
        } else {
          const owner = owners[0]
          const r = perLayer.get(owner)
          if (r) {
            if (r.accepted) {
              problems.push(`expected rejection by layer "${owner}" (${kind}) was NOT observed: the layer accepted this record`)
            } else if (v.expected_error_code !== undefined) {
              const binding = decl.layers[owner]?.error_bindings?.[v.expected_error_code]
              if (!binding) {
                problems.push(`expected_error_code "${v.expected_error_code}" has no error_binding on layer "${owner}"; the expected error cannot be checked`)
              } else {
                const matched = r.errors.some(
                  (e) => e.instancePath === binding.instance_path && e.keyword === binding.keyword,
                )
                if (!matched) {
                  problems.push(
                    `layer "${owner}" rejected, but not with the expected error ${v.expected_error_code} ` +
                      `(${binding.instance_path} ${binding.keyword}); observed: ${describeErrors(r.errors)}`,
                  )
                }
              }
            }
          }
        }
      }
    } else {
      problems.push('vector declares no expected_verification; the expected outcome is unstated')
    }

    verdicts.push({ vector: v.name, pass: problems.length === 0, layerSummary: summary.join(' '), problems })
  }

  return verdicts
}

/**
 * Read a manifest entry's layer declaration. Returns null when the entry
 * declares none (a single-layer family). A partial declaration -- one of the
 * two keys without the other -- is an error, not a silent single-layer family.
 */
export function readLayeredDecl(entry: Record<string, unknown>): LayeredDecl | null {
  const required = entry.required_layers
  const layers = entry.layers
  if (required === undefined && layers === undefined) return null
  if (!Array.isArray(required) || required.length === 0) {
    throw new Error('manifest entry declares `layers` without a non-empty `required_layers`')
  }
  if (layers === null || typeof layers !== 'object') {
    throw new Error('manifest entry declares `required_layers` without a `layers` map')
  }
  return { required_layers: required as string[], layers: layers as Record<string, LayerDecl> }
}
