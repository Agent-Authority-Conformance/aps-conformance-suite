// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the lifecycle-subdelegation-edges candidate family.
//
// WHAT THIS IS. Three named verification policies over one presented chain,
// plus the record writer the LC-H-009 vectors check against each other. It
// reads no clock and makes no network call: every instant comes from the
// vector.
//
// The `reference` policy is the SDK's own chain verifier, called once. The
// other two are deliberately defective and exist so that a vector can state
// which implementation shape passes it wrongly, and why. A policy that merely
// reached a different verdict would prove nothing; each defective policy
// differs from the reference along exactly one declared axis.
//
// WHAT IT MODELS, in the vocabulary of the proposed text it is written
// against (aeoess/agent-authority-lifecycle, commit 2bf5c7e):
//
//   Authority path and dependency   which parent a presented child names, and
//                                   whether the verifier compares the two.
//   Status observation              one party's answer about one delegation,
//                                   and the instant it was known correct.
//   Notice                          the gap between a revocation recorded at
//                                   the source and the same revocation being
//                                   visible to an issuer.
//   Evidence                        the record a boundary writes. A later
//                                   finding is a new record naming the
//                                   earlier one. It never rewrites it.

import { createHash } from 'node:crypto'

import {
  verifyAuthorityDelegationChain,
  verifyAuthorityDelegationSignature,
} from 'agent-passport-system'

import { canonicalizeJCS } from '../../runners/ts/canonicalize.js'

/** The settled verdict vocabulary this family uses. Only these appear in a
 *  recorded result, and `not established` is never spelled as a failure. */
export type AuthorityVerdict =
  | 'valid'
  | 'invalid'
  | 'not established'
  | 'not yet effective'
  | 'suspended'
  | 'restricted'

export type PolicyName = 'reference' | 'per-artifact-only' | 'issuer-attestation-trusting'

export interface ChainsFixture {
  _placeholder?: boolean
  mint_now: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chains: Record<string, any[]>
  refusals: Record<string, { raised: boolean; code: string | null; message: string | null }>
  issuer_observation_p9: {
    record_type: string
    about_delegation_id: string
    observed_by: string
    as_of: string
    answer: string
    used_to_issue: string
  }
  p9_revocation: { recorded_at_source: string; visible_to_issuer_at: string }
}

export interface Outcome {
  authority_verdict: AuthorityVerdict
  failure_code: string | null
  failure_index: number | null
}

/** A boundary record. Every field is always present, so two records are
 *  comparable byte for byte without an absent-field rule. */
export interface BoundaryRecord {
  record_type: 'aac:subdelegation-edge-observation:v0'
  vector_id: string
  boundary_at: string
  chain: string
  authority_verdict: AuthorityVerdict
  failure_code: string | null
  failure_index: number | null
  prior_record_sha256: string | null
}

function roleIndex(fixture: ChainsFixture): Map<string, string> {
  const byId = new Map<string, string>()
  for (const [role, id] of Object.entries(fixture.roles)) byId.set(id, role)
  return byId
}

/** The reference policy: one ordinary call to the SDK chain verifier. */
function referencePolicy(
  fixture: ChainsFixture,
  chainName: string,
  now: string,
  answerFor: (delegation: any) => string,
): Outcome {
  const result: any = verifyAuthorityDelegationChain(fixture.chains[chainName], {
    now,
    resolveVerificationKey: (_issuer: string, verificationMethod: string) =>
      fixture.verification_keys[verificationMethod] ?? null,
    trustRoot: () => true,
    resolveRevocation: answerFor as any,
  })
  const first = Array.isArray(result.failures) ? result.failures[0] : undefined
  const verdict: AuthorityVerdict =
    result.state === 'valid'
      ? 'valid'
      : result.state === 'indeterminate'
        ? 'not established'
        : 'invalid'
  return {
    authority_verdict: verdict,
    failure_code: first?.code ?? null,
    failure_index: typeof first?.index === 'number' ? first.index : null,
  }
}

/** The per-artifact-only policy.
 *
 *  Each presented record is checked on its own and no two records are ever
 *  compared: no parent linkage, no facet comparison, no depth accounting. The
 *  three checks it does run are the ones a widely used base path algorithm
 *  specifies per certificate (see README, Sources): the signature verifies
 *  under the resolved key, the record's own validity period includes the
 *  verification instant, and the record is not revoked at that instant. */
function perArtifactOnlyPolicy(
  fixture: ChainsFixture,
  chainName: string,
  now: string,
  answerFor: (delegation: any) => string,
): Outcome {
  const chain = fixture.chains[chainName]
  for (let i = 0; i < chain.length; i += 1) {
    const record = chain[i]
    const key = fixture.verification_keys[record.verification_method]
    if (typeof key !== 'string' || !verifyAuthorityDelegationSignature(record, key)) {
      return { authority_verdict: 'invalid', failure_code: 'SIGNATURE_INVALID', failure_index: i }
    }
    const time = record.authority.time
    if (now < time.not_before) {
      return { authority_verdict: 'invalid', failure_code: 'NOT_YET_VALID', failure_index: i }
    }
    if (now > time.not_after) {
      return { authority_verdict: 'invalid', failure_code: 'EXPIRED', failure_index: i }
    }
    const answer = answerFor(record)
    if (answer === 'revoked') {
      return { authority_verdict: 'invalid', failure_code: 'REVOKED', failure_index: i }
    }
    if (answer !== 'active') {
      return { authority_verdict: 'not established', failure_code: 'REVOCATION_UNKNOWN', failure_index: i }
    }
  }
  return { authority_verdict: 'valid', failure_code: null, failure_index: null }
}

/** Build the revocation answer function a vector declares, keyed by role. */
export function answerFunction(
  fixture: ChainsFixture,
  revocation: Record<string, string>,
): (delegation: any) => string {
  const byId = roleIndex(fixture)
  return (delegation: any) => {
    const role = byId.get(delegation?.delegation_id)
    if (role === undefined) {
      throw new Error('subdelegation-edges resolver received a delegation with no registered role')
    }
    return revocation[role] ?? 'active'
  }
}

/** Run one vector under one policy. */
export function runPolicy(
  fixture: ChainsFixture,
  policy: PolicyName,
  chainName: string,
  now: string,
  revocation: Record<string, string>,
): Outcome {
  const declared = answerFunction(fixture, revocation)
  if (policy === 'reference') return referencePolicy(fixture, chainName, now, declared)
  if (policy === 'per-artifact-only') return perArtifactOnlyPolicy(fixture, chainName, now, declared)

  // issuer-attestation-trusting: identical to the reference policy except that
  // a member the fixture holds a pinned issuer observation for takes its status
  // from that observation. One axis, named here and nowhere else.
  const observation = fixture.issuer_observation_p9
  const trusting = (delegation: any) =>
    delegation?.delegation_id === observation.about_delegation_id
      ? observation.answer
      : declared(delegation)
  return referencePolicy(fixture, chainName, now, trusting)
}

export function writeRecord(
  vectorId: string,
  boundaryAt: string,
  chainName: string,
  outcome: Outcome,
  priorRecordSha256: string | null,
): BoundaryRecord {
  return {
    record_type: 'aac:subdelegation-edge-observation:v0',
    vector_id: vectorId,
    boundary_at: boundaryAt,
    chain: chainName,
    authority_verdict: outcome.authority_verdict,
    failure_code: outcome.failure_code,
    failure_index: outcome.failure_index,
    prior_record_sha256: priorRecordSha256,
  }
}

/** RFC 8785 canonical bytes of a record, then SHA-256 over them. */
export function recordDigest(record: BoundaryRecord): string {
  return createHash('sha256').update(canonicalizeJCS(record), 'utf8').digest('hex')
}
