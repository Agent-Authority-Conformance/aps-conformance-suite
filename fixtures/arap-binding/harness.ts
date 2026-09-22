// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the arap-binding candidate family.
//
// WHAT THIS IS. Three small reference components written against the proposed
// AuthZEN Access Request Approval Profile (ARAP), openid/authzen PR #658, head
// 2e9412c943d77c3a1ec82de59f8903b45c5bec14:
//
//   1. an Access Request Service (ARS) denial-binding verifier, checking the
//      five steps of {{verifying-denial-binding}} for both the inline and
//      hashed binding forms;
//   2. a PDP approval verifier at re-evaluation, checking
//      {{approval-verification}}, {{approval-current-status}} and
//      {{approval-scope}} against a trusted-state ledger and a JWS
//      approval.state;
//   3. a PEP next-action resolver, a pure function over the fallback table in
//      {{pep-reevaluation-handling}} (839-843).
//
// None of this is an AuthZEN implementation, a PDP, an Access Request Service,
// or a PEP. Each component is a minimal model of the one rule set it exercises,
// so the proposed checks have something executable to run against. A result
// here is a statement about this model and about the text it was built to
// read, not about any real system.
//
// Node builtins only, no imports beyond node:crypto. The repository has no JWS
// library as a dependency (checked: no "jose" in package.json, no jose in
// node_modules, no existing compact-JWS code anywhere in the tree), and the
// suite's own posture is few dependencies, so this file hand-rolls a minimal
// Ed25519 JWS (sign/verify, compact serialization, alg EdDSA) and a minimal
// RFC 8785 JSON Canonicalization Scheme (JCS) serializer. Both are small
// because the inputs are small: no non-finite numbers, no need for the fuller
// ECMA-262 number-to-string algorithm RFC 8785 delegates to, and no assumption
// that arbitrary attacker input ever reaches this canonicalizer.
//
// Every key is an Ed25519 seed derived from a published label via SHA-256, so
// the file carries no secret material and the keys anyone regenerates from the
// same labels are identical. Nothing here reads wall time or draws randomness;
// "now" is always a value the caller passes in.

import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto'

// ---------------------------------------------------------------------------
// base64url (RFC 4648 §5, no padding)
// ---------------------------------------------------------------------------

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64urlToBytes(value: string): Uint8Array {
  const padded = value.length % 4 === 0 ? value : value + '='.repeat(4 - (value.length % 4))
  return new Uint8Array(Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'))
}

function utf8(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'utf8'))
}

// ---------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme, minimal: object keys sorted by UTF-16
// code unit (which is exactly what JavaScript's default Array.sort on strings
// does), members and elements serialized recursively, strings and numbers
// serialized with JSON.stringify. JSON.stringify's string escaping already
// matches what JCS asks for (control characters escaped, non-ASCII left as
// literal UTF-8), and every number this family canonicalizes is a small
// integer or absent altogether, so ECMA-262's fuller Number::toString rules
// are not needed here.
// ---------------------------------------------------------------------------

export function canonicalizeJCS(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite numbers are not representable')
    return JSON.stringify(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalizeJCS).join(',')}]`
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalizeJCS(obj[k])}`).join(',')}}`
  }
  throw new Error(`JCS: unsupported value type ${typeof value}`)
}

export function sha256Base64url(input: string): string {
  return base64url(new Uint8Array(createHash('sha256').update(utf8(input)).digest()))
}

// ---------------------------------------------------------------------------
// Deterministic Ed25519 keys from published seed labels.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:arap-binding:'

export function seedHex(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

// node:crypto has no direct "raw 32-byte seed in, keypair out" entry point for
// Ed25519. What it does accept is a PKCS8 DER private key, and for Ed25519 that
// DER blob is always the same fixed 16-byte ASN.1 wrapper
//   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING (OCTET STRING seed) }
// followed by the raw 32-byte seed, because Ed25519 has no algorithm
// parameters. agent-passport-system's own crypto/keys.ts carries this same
// prefix for the same reason; it is independently re-derived here rather than
// imported, because that module signs and verifies APS's own receipt envelope
// format, not a generic JWS. The SPKI prefix below is the equivalent fixed
// wrapper for a raw 32-byte Ed25519 public key.
const ED25519_PKCS8_PREFIX_HEX = '302e020100300506032b657004220420'
const ED25519_SPKI_PREFIX_HEX = '302a300506032b6570032100'

export interface Ed25519KeyPair {
  privateKey: KeyObject
  publicKey: KeyObject
  publicKeyRaw: Uint8Array
}

export function keyPairFromSeed(seedHexValue: string): Ed25519KeyPair {
  const seedBytes = Buffer.from(seedHexValue, 'hex').subarray(0, 32)
  if (seedBytes.length !== 32) throw new Error('ed25519 seed must be exactly 32 bytes')
  const der = Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX_HEX, 'hex'), seedBytes])
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  const publicKey = createPublicKey(privateKey)
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer
  const publicKeyRaw = new Uint8Array(spki.subarray(spki.length - 32))
  return { privateKey, publicKey, publicKeyRaw }
}

export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  const der = Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX_HEX, 'hex'), Buffer.from(raw)])
  return createPublicKey({ key: der, format: 'der', type: 'spki' })
}

// ---------------------------------------------------------------------------
// Compact-serialization JWS, alg EdDSA. Header and payload are plain JSON (not
// JCS): a JWS signs the literal bytes it transmits, so there is nothing to
// canonicalize, only something to transmit unchanged between minting and
// verification, which the compact-serialization format already guarantees.
// ---------------------------------------------------------------------------

export function signJWS(header: Record<string, unknown>, payload: Record<string, unknown>, privateKey: KeyObject): string {
  const signingInput = `${base64url(utf8(JSON.stringify(header)))}.${base64url(utf8(JSON.stringify(payload)))}`
  const signature = cryptoSign(null, utf8(signingInput), privateKey)
  return `${signingInput}.${base64url(new Uint8Array(signature))}`
}

export interface DecodedJWS {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signingInput: string
  signature: Uint8Array
}

export function decodeJWS(compact: string): DecodedJWS {
  const parts = compact.split('.')
  if (parts.length !== 3) throw new Error('malformed JWS: expected three dot-separated segments')
  const [headerPart, payloadPart, signaturePart] = parts
  return {
    header: JSON.parse(Buffer.from(base64urlToBytes(headerPart)).toString('utf8')) as Record<string, unknown>,
    payload: JSON.parse(Buffer.from(base64urlToBytes(payloadPart)).toString('utf8')) as Record<string, unknown>,
    signingInput: `${headerPart}.${payloadPart}`,
    signature: base64urlToBytes(signaturePart),
  }
}

export function checkSignature(signingInput: string, signature: Uint8Array, publicKey: KeyObject): boolean {
  return cryptoVerify(null, utf8(signingInput), publicKey, Buffer.from(signature))
}

export function verifyJWS(compact: string, publicKey: KeyObject): DecodedJWS & { verified: boolean } {
  const decoded = decodeJWS(compact)
  return { ...decoded, verified: checkSignature(decoded.signingInput, decoded.signature, publicKey) }
}

export class JwksRegistry {
  private readonly keys = new Map<string, KeyObject>()
  publish(iss: string, kid: string, publicKey: KeyObject): void {
    this.keys.set(`${iss}:${kid}`, publicKey)
  }
  resolve(iss: string, kid: string): KeyObject | undefined {
    return this.keys.get(`${iss}:${kid}`)
  }
}

// ---------------------------------------------------------------------------
// AuthZEN shapes and structural comparison, {{structural-comparison}} (712-733).
// ---------------------------------------------------------------------------

export interface AuthzenSubject { type: string; id: string; properties?: Record<string, unknown> }
export interface AuthzenResource { type: string; id: string; properties?: Record<string, unknown> }
export interface AuthzenAction { name: string; properties?: Record<string, unknown> }
export type AuthzenContext = Record<string, unknown>

/**
 * Structural comparison: same JSON type, numbers and strings compared by
 * value, arrays element-by-element in order, objects by matching member-name
 * sets with recursively equal values, and an absent member distinct from a
 * member whose value is null (714-720). The null-vs-absent distinction falls
 * out of the `typeof` check below: `typeof null === 'object'` while
 * `typeof undefined === 'undefined'`, so a value present-as-null and a value
 * that is simply missing never compare equal.
 */
export function structurallyEqual(a: unknown, b: unknown): boolean {
  if (a === null || b === null) return a === b
  if (typeof a !== typeof b) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false
    return a.every((v, i) => structurallyEqual(v, b[i]))
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const ao = a as Record<string, unknown>
    const bo = b as Record<string, unknown>
    const ak = Object.keys(ao).sort()
    const bk = Object.keys(bo).sort()
    if (ak.length !== bk.length || ak.some((k, i) => k !== bk[i])) return false
    return ak.every(k => structurallyEqual(ao[k], bo[k]))
  }
  return a === b
}

/** Removes subject.properties.act, the exclusion at line 724. */
export function stripAct(subject: AuthzenSubject): AuthzenSubject {
  if (subject.properties === undefined || !('act' in subject.properties)) return subject
  const { act: _act, ...rest } = subject.properties
  return { ...subject, properties: rest }
}

/** Subject comparison with the subject.properties.act exclusion (724). */
export function subjectsEqualExcludingAct(a: AuthzenSubject, b: AuthzenSubject): boolean {
  return structurallyEqual(stripAct(a), stripAct(b))
}

/** Compares only the members named by `members`, the authorization-relevant Context set (726-731). */
export function contextEqualOverMembers(a: AuthzenContext, b: AuthzenContext, members: readonly string[]): boolean {
  return members.every(m => structurallyEqual(a[m], b[m]))
}

// ---------------------------------------------------------------------------
// Component 1: ARS denial-binding verifier, {{verifying-denial-binding}} (1205-1220)
// and {{denial-binding-hash}} (1186-1203).
// ---------------------------------------------------------------------------

export type DenialBindingOutcome = 'accepted' | 'invalid_denial_binding' | 'expired_denial' | 'invalid_audience'

export interface Submission {
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  denialExpiresAt: string
}

export interface BindingTokenClaims {
  iss: string
  aud?: string | string[]
  iat: number
  exp: number
  jti: string
  denial_expires_at?: string
  bindingContextMembers?: string[]
  form: 'inline' | 'hashed'
  subject?: AuthzenSubject
  resource?: AuthzenResource
  action?: AuthzenAction
  context?: AuthzenContext
  binding_hash?: string
}

/**
 * `binding_hash`: base64url SHA-256 of the JCS serialization of
 * `{ subject, resource, action, context }`, subject with `properties.act`
 * removed, context restricted to `bindingContextMembers` (1188-1201).
 *
 * `omitContextKeyWhenAbsent` selects between the two readings this family
 * leaves open when `bindingContextMembers` itself is absent -- see README,
 * vector D12. 1179 says the binding covers "only Subject, Resource, and
 * Action" when the member set is absent, which reads naturally as no context
 * key in the hashed object at all; the object literal at 1190-1197 always
 * shows a "context" key. Both readings are implemented so the two digests can
 * sit side by side; neither is picked as correct.
 */
export function computeBindingHash(
  subject: AuthzenSubject,
  resource: AuthzenResource,
  action: AuthzenAction,
  context: AuthzenContext,
  bindingContextMembers: readonly string[] | undefined,
  omitContextKeyWhenAbsent: boolean,
): string {
  const strippedSubject = stripAct(subject)
  if (bindingContextMembers === undefined) {
    const obj: Record<string, unknown> = omitContextKeyWhenAbsent
      ? { subject: strippedSubject, resource, action }
      : { subject: strippedSubject, resource, action, context: {} }
    return sha256Base64url(canonicalizeJCS(obj))
  }
  const relevantContext: Record<string, unknown> = {}
  for (const member of bindingContextMembers) if (member in context) relevantContext[member] = context[member]
  const obj = { subject: strippedSubject, resource, action, context: relevantContext }
  return sha256Base64url(canonicalizeJCS(obj))
}

export class SeenJtiLedger {
  private readonly seen = new Set<string>()
  replay(jti: string): boolean {
    return this.seen.has(jti)
  }
  record(jti: string): void {
    this.seen.add(jti)
  }
}

function audOk(aud: string | string[] | undefined, arsIdentifier: string): boolean {
  if (aud === undefined) return false
  return Array.isArray(aud) ? aud.includes(arsIdentifier) : aud === arsIdentifier
}

/** The freshness deadline rules at 1215-1220. */
function freshnessDeadlineMs(
  claims: BindingTokenClaims,
  submission: Submission,
): { deadlineMs: number } | { insufficient: true } | { mismatch: true } {
  if (claims.denial_expires_at !== undefined) {
    if (claims.denial_expires_at !== submission.denialExpiresAt) return { mismatch: true }
    return { deadlineMs: Math.min(claims.exp * 1000, Date.parse(submission.denialExpiresAt)) }
  }
  const expMs = claims.exp * 1000
  const denialExpiresMs = Date.parse(submission.denialExpiresAt)
  if (expMs <= denialExpiresMs) return { deadlineMs: expMs }
  return { insufficient: true }
}

function structuralCompareBindingClaims(claims: BindingTokenClaims, submission: Submission): boolean {
  if (claims.form === 'inline') {
    if (claims.subject === undefined || claims.resource === undefined || claims.action === undefined) return false
    if (!subjectsEqualExcludingAct(claims.subject, submission.subject)) return false
    if (!structurallyEqual(claims.resource, submission.resource)) return false
    if (!structurallyEqual(claims.action, submission.action)) return false
    if (claims.bindingContextMembers !== undefined) {
      const boundContext = claims.context ?? {}
      if (!contextEqualOverMembers(boundContext, submission.context, claims.bindingContextMembers)) return false
    }
    return true
  }
  if (claims.binding_hash === undefined) return false
  const recomputed = computeBindingHash(submission.subject, submission.resource, submission.action, submission.context, claims.bindingContextMembers, true)
  return recomputed === claims.binding_hash
}

/**
 * The negative control's defect: raw byte/string comparison instead of
 * {{structural-comparison}}. It does not know about the `subject.properties.act`
 * exclusion, so it hashes or compares the submission's subject unmodified.
 */
function byteCompareBindingClaims(claims: BindingTokenClaims, submission: Submission): boolean {
  if (claims.form === 'inline') {
    if (claims.subject === undefined || claims.resource === undefined || claims.action === undefined) return false
    if (JSON.stringify(claims.subject) !== JSON.stringify(submission.subject)) return false
    if (JSON.stringify(claims.resource) !== JSON.stringify(submission.resource)) return false
    if (JSON.stringify(claims.action) !== JSON.stringify(submission.action)) return false
    if (claims.bindingContextMembers !== undefined) {
      const boundContext = claims.context ?? {}
      for (const member of claims.bindingContextMembers) {
        if (JSON.stringify(boundContext[member]) !== JSON.stringify(submission.context[member])) return false
      }
    }
    return true
  }
  if (claims.binding_hash === undefined) return false
  const obj =
    claims.bindingContextMembers === undefined
      ? { subject: submission.subject, resource: submission.resource, action: submission.action, context: {} }
      : {
          subject: submission.subject,
          resource: submission.resource,
          action: submission.action,
          context: Object.fromEntries(claims.bindingContextMembers.filter(m => m in submission.context).map(m => [m, submission.context[m]])),
        }
  const recomputed = sha256Base64url(canonicalizeJCS(obj))
  return recomputed === claims.binding_hash
}

export interface DenialBindingVerifier {
  readonly name: string
  verify(compactJWS: string, submission: Submission, arsIdentifier: string, pdpPublicKey: KeyObject, nowMs: number, jtiLedger: SeenJtiLedger): DenialBindingOutcome
}

function makeDenialVerifier(name: string, compare: (claims: BindingTokenClaims, submission: Submission) => boolean): DenialBindingVerifier {
  return {
    name,
    verify(compactJWS, submission, arsIdentifier, pdpPublicKey, nowMs, jtiLedger) {
      // Step 1-2: resolve the key (the caller already selected it by iss/kid for
      // this single-PDP harness), verify the signature and the aud claim.
      const { payload, verified } = verifyJWS(compactJWS, pdpPublicKey)
      if (!verified) throw new Error('signature invalid: fixture vectors are always minted with the matching key')
      const claims = payload as unknown as BindingTokenClaims
      if (!audOk(claims.aud, arsIdentifier)) return 'invalid_audience'
      // Step 3: replay.
      if (jtiLedger.replay(claims.jti)) return 'invalid_denial_binding'
      jtiLedger.record(claims.jti)
      // Step 4: binding claims against the submission.
      if (!compare(claims, submission)) return 'invalid_denial_binding'
      // Step 5: freshness.
      const fresh = freshnessDeadlineMs(claims, submission)
      if ('mismatch' in fresh) return 'invalid_denial_binding'
      if ('insufficient' in fresh) return 'invalid_denial_binding'
      if (nowMs > fresh.deadlineMs) return 'expired_denial'
      return 'accepted'
    },
  }
}

export const CORRECT_DENIAL_VERIFIER = makeDenialVerifier('correct', structuralCompareBindingClaims)
export const BYTE_COMPARE_ARS_VERIFIER = makeDenialVerifier('byte-compare-ars', byteCompareBindingClaims)

// ---------------------------------------------------------------------------
// Component 2: PDP approval verifier at re-evaluation, {{approval-verification}}
// (936-954), {{approval-current-status}} (960-962), {{approval-scope}} (964-972).
// ---------------------------------------------------------------------------

export type NextAction = 'request' | 'retry' | 'none'

/** The reason-code default next actions, {{reevaluation-denials}} (614-619). */
export const REASON_DEFAULT_NEXT_ACTION: Record<string, NextAction> = {
  approval_expired: 'request',
  out_of_scope: 'request',
  grant_pending: 'retry',
  policy_denied: 'none',
  approval_unverifiable: 'none',
}

export type ApprovalOutcome = 'approval_applies' | 'approval_expired' | 'out_of_scope' | 'approval_unverifiable' | 'policy_denied'

export interface ApprovalVerificationResult {
  outcome: ApprovalOutcome
  nextAction?: NextAction
}

function outcomeResult(outcome: ApprovalOutcome): ApprovalVerificationResult {
  if (outcome === 'approval_applies') return { outcome }
  return { outcome, nextAction: REASON_DEFAULT_NEXT_ACTION[outcome] }
}

export interface ApprovalRecord {
  id: string
  taskId: string
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  boundContextMembers: readonly string[]
  approvedAt: string
  approvedUntil: string
  status: 'active' | 'revoked' | 'cancelled' | 'superseded'
}

/** Trusted server-side state, the lookup alternative in {{approval-reference-lookup}}. */
export class ApprovalLedger {
  private readonly records = new Map<string, ApprovalRecord>()
  register(record: ApprovalRecord): void {
    this.records.set(record.id, record)
  }
  get(id: string): ApprovalRecord | undefined {
    return this.records.get(id)
  }
}

/** The mandatory policy gate 618 describes: valid and in scope, denied anyway. */
export class PolicyStub {
  private readonly disabledSubjects = new Set<string>()
  disableSubject(subjectId: string): void {
    this.disabledSubjects.add(subjectId)
  }
  isSubjectDisabled(subjectId: string): boolean {
    return this.disabledSubjects.has(subjectId)
  }
}

export interface ApprovalStateClaims {
  iss: string
  aud: string
  approval_id: string
  taskId: string
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  boundContextMembers: string[]
  approvedAt: string
  approvedUntil: string
}

export interface PresentedApproval {
  id?: string
  state?: string
}

export interface CurrentEvaluation {
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
}

interface ScopeRecord {
  subject: AuthzenSubject
  resource: AuthzenResource
  action: AuthzenAction
  context: AuthzenContext
  boundContextMembers: readonly string[]
}

/** Exact-match approval scope, {{approval-scope}} (964-972). */
function isWithinScope(record: ScopeRecord, evaluation: CurrentEvaluation): boolean {
  if (!subjectsEqualExcludingAct(record.subject, evaluation.subject)) return false
  if (!structurallyEqual(record.resource, evaluation.resource)) return false
  if (!structurallyEqual(record.action, evaluation.action)) return false
  return contextEqualOverMembers(record.context, evaluation.context, record.boundContextMembers)
}

export interface ApprovalVerifier {
  readonly name: string
  verify(
    presented: PresentedApproval,
    evaluation: CurrentEvaluation,
    nowMs: number,
    verifyingPdpId: string,
    ledger: ApprovalLedger,
    jwks: JwksRegistry,
    policy: PolicyStub,
  ): ApprovalVerificationResult
}

export const CORRECT_APPROVAL_VERIFIER: ApprovalVerifier = {
  name: 'correct',
  verify(presented, evaluation, nowMs, verifyingPdpId, ledger, jwks, policy) {
    let stateClaims: ApprovalStateClaims | undefined

    // approval.state carried by value as a JWS, {{approval-state}} (1234-1240).
    if (presented.state !== undefined) {
      const decoded = decodeJWS(presented.state)
      const iss = String(decoded.payload.iss)
      const kid = String(decoded.header.kid)
      const key = jwks.resolve(iss, kid)
      if (key === undefined) return outcomeResult('approval_unverifiable')
      if (!checkSignature(decoded.signingInput, decoded.signature, key)) return outcomeResult('approval_unverifiable')
      // aud MUST identify the verifying PDP (1239): a value that names a
      // different PDP sharing the same signer's key MUST be rejected here.
      if (decoded.payload.aud !== verifyingPdpId) return outcomeResult('approval_unverifiable')
      stateClaims = decoded.payload as unknown as ApprovalStateClaims
    }

    // When both approval.id and a state-embedded identifier are present, they
    // MUST match (942).
    if (presented.id !== undefined && stateClaims !== undefined && stateClaims.approval_id !== presented.id) {
      return outcomeResult('approval_unverifiable')
    }

    // Resolve the authoritative record. Ledger lookup by id is preferred when
    // available, because it reflects live status (a later revocation, say);
    // the state's own claims are the fallback for the bound-reference topology
    // where no id-backed shared state exists.
    let record: ScopeRecord & { approvedUntil: string; status: string } | undefined
    if (presented.id !== undefined) {
      const ledgerRecord = ledger.get(presented.id)
      if (ledgerRecord !== undefined) record = ledgerRecord
    }
    if (record === undefined && stateClaims !== undefined) {
      record = {
        subject: stateClaims.subject,
        resource: stateClaims.resource,
        action: stateClaims.action,
        context: stateClaims.context,
        boundContextMembers: stateClaims.boundContextMembers,
        approvedUntil: stateClaims.approvedUntil,
        status: 'active',
      }
    }
    if (record === undefined) return outcomeResult('approval_unverifiable')

    // Current approval status, including revocation, before approved_until (960-962).
    if (record.status !== 'active') return outcomeResult('approval_expired')
    if (nowMs > Date.parse(record.approvedUntil)) return outcomeResult('approval_expired')

    // Exact-match approval scope (964-972).
    if (!isWithinScope(record, evaluation)) return outcomeResult('out_of_scope')

    // Mandatory policy, subject status, or risk state (618).
    if (policy.isSubjectDisabled(evaluation.subject.id)) return outcomeResult('policy_denied')

    return outcomeResult('approval_applies')
  },
}

/**
 * The negative control's defect: any `approval.id` this PDP recognizes in its
 * ledger is trusted outright, with no scope check, no current-status check
 * (revocation or expiry), and no `aud` check on `approval.state`. That is
 * exactly what 739 calls insufficient: possession of a valid-looking approval
 * identifier. Policy denial is still applied, because it is a separate
 * mandatory gate this defect does not claim to bypass.
 */
export const TRUSTING_PDP_APPROVAL_VERIFIER: ApprovalVerifier = {
  name: 'trusting-pdp',
  verify(presented, evaluation, _nowMs, _verifyingPdpId, ledger, _jwks, policy) {
    if (presented.id === undefined) return outcomeResult('approval_unverifiable')
    const record = ledger.get(presented.id)
    if (record === undefined) return outcomeResult('approval_unverifiable')
    if (policy.isSubjectDisabled(evaluation.subject.id)) return outcomeResult('policy_denied')
    return outcomeResult('approval_applies')
  },
}

// ---------------------------------------------------------------------------
// Component 3: PEP next-action resolver, {{pep-reevaluation-handling}} (824-843).
// A pure function: no state, no clock, no I/O.
// ---------------------------------------------------------------------------

const KNOWN_NEXT_ACTIONS: ReadonlySet<string> = new Set(['request', 'retry', 'none'])

export interface PepFallbackInput {
  nextAction?: string
  reason?: string
  accessRequestPresent: boolean
}

/**
 * The fallback order at 828-831, restated as the table at 839-843: a
 * recognized `next_action` wins outright, even over a reason code that would
 * suggest something else (828, 841). Absent or unrecognized `next_action`
 * falls back to a recognized reason's registered default (830, 842); with
 * neither recognized, it falls back to the requestable-denial signal (830,
 * 843). Either way, a resolved action of `request` still requires
 * `context.access_request` to be present, or the PEP treats the denial as
 * `none` instead (829, 831) -- this is why `next_action: "request"` without
 * `context.access_request` resolves to `none` even though a recognized
 * `next_action` would otherwise win outright.
 */
export function resolvePepNextAction(input: PepFallbackInput): NextAction {
  const { nextAction, reason, accessRequestPresent } = input

  if (nextAction !== undefined && KNOWN_NEXT_ACTIONS.has(nextAction)) {
    if (nextAction === 'request' && !accessRequestPresent) return 'none'
    return nextAction as NextAction
  }

  if (reason !== undefined && reason in REASON_DEFAULT_NEXT_ACTION) {
    const fallback = REASON_DEFAULT_NEXT_ACTION[reason]
    if (fallback === 'request' && !accessRequestPresent) return 'none'
    return fallback
  }

  return accessRequestPresent ? 'request' : 'none'
}
