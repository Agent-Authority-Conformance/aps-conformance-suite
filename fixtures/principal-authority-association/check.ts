// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference checker for the principal-authority-association candidate family.
//
// CANDIDATE MATERIAL. Not a conformance verifier. The association statement, the
// association profile, the values `established` and `inconsistent`, and every
// X_FIXTURE_ reason code are fixture local. draft-pidlisnyi-aps-04 defines no
// artifact for the association (Section 19.2.10, lines 11300 to 11307).
//
// One vector in, four axes out:
//
//   binding      PrincipalBindingV1, verified by the SDK's verifyPrincipalBindingV1
//   root_basis   the root AuthorityDelegationV1, verified by the SDK's
//                verifyAuthorityDelegationChain under the vector's trust anchors
//   association  the profile applied to the association evidence
//   boundary     what an enforcement point does for the principal the chain names
//
// Each association statement is checked in a fixed order and the first failing
// check is that statement's reason, the same pattern -04 uses for activation
// attestations (lines 4459 to 4507). A statement that fails a check is not
// evidence in either direction.

import {
  canonicalizeJCS,
  verify,
  verifyAuthorityDelegationChain,
  verifyPrincipalBindingV1,
  type AuthorityDelegationV1,
  type PrincipalBindingV1,
} from './sdk.js'

export const STATEMENT_TYPE = 'x-fixture/principal-authority-association/v0'
export const PROFILE_TYPE = 'x-fixture/principal-authority-association-profile/v0'
export const SIGNATURE_DOMAIN = 'X-FIXTURE-PRINCIPAL-AUTHORITY-ASSOCIATION-SIG-V0'

export const RELATIONS = ['same_authority_context', 'different_authority_context'] as const
export type Relation = (typeof RELATIONS)[number]

// Every code here is fixture local. -04 defines reason codes per subject and none
// has the association as its subject. The README lists the nearest -04 codes and
// why they are not reused.
export const CODES = {
  notPresented: 'X_FIXTURE_ASSOCIATION_NOT_PRESENTED',
  malformed: 'X_FIXTURE_ASSOCIATION_MALFORMED',
  sourceUnrecognized: 'X_FIXTURE_ASSOCIATION_SOURCE_UNRECOGNIZED',
  signatureUnverified: 'X_FIXTURE_ASSOCIATION_SIGNATURE_UNVERIFIED',
  refsNotCovered: 'X_FIXTURE_ASSOCIATION_REFS_NOT_COVERED',
  sourceNotCompetent: 'X_FIXTURE_ASSOCIATION_SOURCE_NOT_COMPETENT',
  datedAfterEvaluation: 'X_FIXTURE_ASSOCIATION_DATED_AFTER_EVALUATION',
  expired: 'X_FIXTURE_ASSOCIATION_EXPIRED',
  sourcesConflict: 'X_FIXTURE_ASSOCIATION_SOURCES_CONFLICT',
  differentContext: 'X_FIXTURE_ASSOCIATION_DIFFERENT_AUTHORITY_CONTEXT',
  established: 'X_FIXTURE_ASSOCIATION_ESTABLISHED',
  boundaryNotEstablished: 'X_FIXTURE_BOUNDARY_PRINCIPAL_AUTHORITY_NOT_ESTABLISHED',
  boundaryInconsistent: 'X_FIXTURE_PRINCIPAL_AUTHORITY_INCONSISTENT',
  boundaryAuthorized: 'X_FIXTURE_BOUNDARY_AUTHORIZED_ASSOCIATION_ESTABLISHED',
  boundaryPrecondition: 'X_FIXTURE_BOUNDARY_BINDING_OR_ROOT_NOT_ACCEPTED',
} as const

export interface AssociationStatement {
  type: typeof STATEMENT_TYPE
  principal_ref: string
  root_ref: string
  relation: Relation
  source_id: string
  issued_at: string
  expires_at: string
  signature: string
}

export interface CompetentSource {
  source_id: string
  verification_key_hex: string
  competent_for: { principals: string[]; scopes: string[]; domains: string[] }
}

export interface AssociationProfile {
  type: typeof PROFILE_TYPE
  profile_id: string
  competent_sources: CompetentSource[]
}

export interface VectorInputs {
  evaluation_instant: string
  context: { audience: string; scope: string; domain: string }
  principal_binding: PrincipalBindingV1
  root_delegation: AuthorityDelegationV1
  association_evidence: AssociationStatement[]
  trust_anchors: { root_issuers: string[]; verification_keys: Record<string, string> }
  revocation_state: { source: string; every_delegation: 'active' }
  association_profile: AssociationProfile
}

export type Limb = 'source' | 'freshness' | 'coverage'

export type AssociationResult =
  | { result: 'not_established'; limb: Limb; reason_code: string; aps_04_defined_shape: true }
  | { result: 'inconsistent'; reason_code: string; aps_04_defined_shape: false }
  | { result: 'established'; reason_code: string; aps_04_defined_shape: false }
  | { result: 'not_evaluated'; reason_code: string; aps_04_defined_shape: false }

export interface CheckResult {
  binding: { result: 'accepted' | 'not_accepted'; sdk_state: string; sdk_code: string }
  root_basis: { result: 'accepted' | 'not_accepted'; sdk_state: string; sdk_failures: string[] }
  association: AssociationResult
  boundary: {
    outcome: 'authorized' | 'denied' | 'not_established'
    reason_code: string
    authorized_for_named_principal: boolean
  }
}

export function statementSigningInput(statement: Omit<AssociationStatement, 'signature'>): string {
  return `${SIGNATURE_DOMAIN}\u0000${canonicalizeJCS(statement)}`
}

const STATEMENT_KEYS = ['expires_at', 'issued_at', 'principal_ref', 'relation', 'root_ref', 'signature', 'source_id', 'type']
const UTC_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

function wellFormed(value: unknown): value is AssociationStatement {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  if (keys.length !== STATEMENT_KEYS.length || keys.some((k, i) => k !== STATEMENT_KEYS[i])) return false
  if (record.type !== STATEMENT_TYPE) return false
  if (!RELATIONS.includes(record.relation as Relation)) return false
  for (const k of ['principal_ref', 'root_ref', 'source_id', 'signature']) {
    if (typeof record[k] !== 'string' || record[k] === '') return false
  }
  for (const k of ['issued_at', 'expires_at']) {
    if (typeof record[k] !== 'string' || !UTC_MS.test(record[k] as string)) return false
  }
  return (record.issued_at as string) < (record.expires_at as string)
}

function isCompetent(source: CompetentSource, inputs: VectorInputs, principal: string): boolean {
  const scope = source.competent_for
  return scope.principals.includes(principal) &&
    scope.scopes.includes(inputs.context.scope) &&
    scope.domains.includes(inputs.context.domain)
}

// Returns null when the signer is one the profile knows and the signature
// verifies under that signer's key, else the reason.
function signerAccepted(statement: AssociationStatement, profile: AssociationProfile): { limb: Limb; code: string } | null {
  const source = profile.competent_sources.find((s) => s.source_id === statement.source_id)
  if (!source) return { limb: 'source', code: CODES.sourceUnrecognized }
  const { signature, ...body } = statement
  if (!verify(statementSigningInput(body), signature, source.verification_key_hex)) {
    return { limb: 'source', code: CODES.signatureUnverified }
  }
  return null
}

type StatementOutcome =
  | { accepted: true; relation: Relation }
  | { accepted: false; step: number; limb: Limb; code: string }

function evaluateStatement(
  value: unknown,
  inputs: VectorInputs,
  principal: string,
  rootId: string,
): StatementOutcome {
  const now = inputs.evaluation_instant
  const profile = inputs.association_profile
  // 1. shape
  if (!wellFormed(value)) return { accepted: false, step: 1, limb: 'source', code: CODES.malformed }
  const st = value
  // 2. a signer the profile knows, and a signature that verifies under its key
  const signer = signerAccepted(st, profile)
  if (signer) return { accepted: false, step: 2, ...signer }
  // 3. the statement is about this principal and this root
  if (st.principal_ref !== principal || st.root_ref !== rootId) {
    return { accepted: false, step: 3, limb: 'coverage', code: CODES.refsNotCovered }
  }
  // 4. the signer is competent for this principal, scope and domain
  const source = profile.competent_sources.find((s) => s.source_id === st.source_id) as CompetentSource
  if (!isCompetent(source, inputs, principal)) {
    return { accepted: false, step: 4, limb: 'source', code: CODES.sourceNotCompetent }
  }
  // 5. not dated after the evaluation instant
  if (st.issued_at > now) return { accepted: false, step: 5, limb: 'source', code: CODES.datedAfterEvaluation }
  // 6. not past its declared expiry at the evaluation instant
  if (!(now < st.expires_at)) return { accepted: false, step: 6, limb: 'freshness', code: CODES.expired }
  return { accepted: true, relation: st.relation }
}

function notEstablished(limb: Limb, code: string): AssociationResult {
  return { result: 'not_established', limb, reason_code: code, aps_04_defined_shape: true }
}

function inconsistent(): AssociationResult {
  return { result: 'inconsistent', reason_code: CODES.differentContext, aps_04_defined_shape: false }
}

function established(): AssociationResult {
  return { result: 'established', reason_code: CODES.established, aps_04_defined_shape: false }
}

export function evaluateAssociation(inputs: VectorInputs, principal: string, rootId: string): AssociationResult {
  const evidence = inputs.association_evidence
  if (evidence.length === 0) return notEstablished('source', CODES.notPresented)
  const outcomes = evidence.map((v) => evaluateStatement(v, inputs, principal, rootId))
  const relations = new Set(outcomes.flatMap((o) => (o.accepted ? [o.relation] : [])))
  const sameSeen = relations.has('same_authority_context')
  const differentSeen = relations.has('different_authority_context')
  if (sameSeen && differentSeen) return notEstablished('source', CODES.sourcesConflict)
  if (differentSeen) return inconsistent()
  if (sameSeen) return established()
  // Nothing accepted. Report the statement that got furthest through the checks.
  let furthest: Extract<StatementOutcome, { accepted: false }> | null = null
  for (const o of outcomes) if (!o.accepted && (!furthest || o.step > furthest.step)) furthest = o
  const last = furthest as Extract<StatementOutcome, { accepted: false }>
  return notEstablished(last.limb, last.code)
}

export async function checkVector(inputs: VectorInputs): Promise<CheckResult> {
  const now = inputs.evaluation_instant
  const keys = inputs.trust_anchors.verification_keys
  const binding = inputs.principal_binding
  const root = inputs.root_delegation

  const bindingResult = await verifyPrincipalBindingV1(binding, {
    now,
    resolve_key: ({ verification_method }) =>
      keys[verification_method] ? { state: 'resolved', public_key_hex: keys[verification_method] } : { state: 'not_found' },
  })
  const bindingAccepted = bindingResult.state === 'valid' &&
    binding.agent_id === root.subject &&
    binding.audiences.includes(inputs.context.audience)

  if (inputs.revocation_state.every_delegation !== 'active') throw new Error('unsupported revocation_state')
  const rootResult = verifyAuthorityDelegationChain([root], {
    now,
    resolveVerificationKey: (_issuer, verificationMethod) => keys[verificationMethod] ?? null,
    trustRoot: (r) => inputs.trust_anchors.root_issuers.includes(r.issuer),
    resolveRevocation: () => 'active',
  })
  const rootAccepted = rootResult.state === 'valid'

  const out: CheckResult = {
    binding: {
      result: bindingAccepted ? 'accepted' : 'not_accepted',
      sdk_state: bindingResult.state,
      sdk_code: bindingResult.code,
    },
    root_basis: {
      result: rootAccepted ? 'accepted' : 'not_accepted',
      sdk_state: rootResult.state,
      sdk_failures: rootResult.failures.map((f) => f.code),
    },
    association: { result: 'not_evaluated', reason_code: CODES.boundaryPrecondition, aps_04_defined_shape: false },
    boundary: { outcome: 'not_established', reason_code: CODES.boundaryPrecondition, authorized_for_named_principal: false },
  }
  if (!bindingAccepted || !rootAccepted) return out

  out.association = evaluateAssociation(inputs, binding.principal_id, root.delegation_id)
  switch (out.association.result) {
    case 'established':
      out.boundary = { outcome: 'authorized', reason_code: CODES.boundaryAuthorized, authorized_for_named_principal: true }
      break
    case 'inconsistent':
      out.boundary = { outcome: 'denied', reason_code: CODES.boundaryInconsistent, authorized_for_named_principal: false }
      break
    default:
      out.boundary = { outcome: 'not_established', reason_code: CODES.boundaryNotEstablished, authorized_for_named_principal: false }
  }
  return out
}
