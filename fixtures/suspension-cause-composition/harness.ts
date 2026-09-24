// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The composed-cause gate this family supplies, in five configurations.
//
// WHAT IS SDK AND WHAT IS NOT. The gate calls the real agent-passport-system
// chain verifier for the grant, and the real SDK Ed25519 verify plus RFC 8785
// canonicalizer for each release record's signature. Everything after that --
// the cause set, the cause kinds, the cause-standing registry, the release
// rules, the evaluation-instant comparison and the four verdict names -- is
// implemented here, because neither reference SDK exposes an API for any of it.
// The npm SDK's RevocationResolution is exactly 'active' | 'revoked' |
// 'unknown', with no suspended state of any arity. A pass is a result about
// this gate, not a conformance result about either SDK. README says this again,
// at length.
//
// VERDICT NAMES ARE NOT SUITE VOCABULARY. exercisable, suspended, restricted
// and not_established are this family's own local labels for discussion.
// CONTRIBUTING.md reserves failure-class names and verifier semantics to the
// maintainer, so these names are a proposal and not a minted taxonomy.

import {
  canonicalizeJCS,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

export type Verdict = 'exercisable' | 'suspended' | 'restricted' | 'not_established' | 'invalid'
export type Stage = 'chain' | 'causes'

export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface CauseRecord {
  record_type: string
  cause_id: string
  cause_kind: 'suspension' | 'restriction'
  imposed_at: string
  imposed_by: string
  record_id: string
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface ReleaseRecord {
  record_type: string
  released_at: string
  released_causes: string[]
  releaser: string
  record_id: string
  signature: string
  verification_method: string
  [key: string]: unknown
}

export interface ChainFixture {
  clock: Record<string, string>
  verification_keys: Record<string, string>
  cause_standing: Record<string, string[]>
  cause_sets: Record<string, string[]>
  revocation_timeline_note: { grant_delegation_id: string; recorded_at: string; note: string }
  roles: Record<string, string>
  chains: Record<string, unknown[]>
  causes: Record<string, CauseRecord>
  releases: Record<string, ReleaseRecord>
}

export interface GateResult {
  verdict: Verdict
  stage: Stage
  code: string
  /** Sorted cause labels still standing. The set, not a flag: this is the
   *  member the single-boolean control cannot reproduce. */
  remaining_causes: string[]
  chain_state: string
  chain_failure_index: number | null
  /** One entry per presented release, in presentation order. */
  release_notes: string[]
}

export interface GateOptions {
  /** N1: hold one suspended flag, so any effective release clears everything. */
  singleSuspensionFlag?: boolean
  /** N2: accept any correctly signed release, whoever signed it. */
  ignoreCauseStanding?: boolean
  /** N3: treat a fully released grant as exercisable without consulting the
   *  chain's revocation state. */
  releaseClearsRevocation?: boolean
  /** N4: read standing as authorship, so only the source that imposed a cause
   *  may release it. */
  standingIsAuthorship?: boolean
}

/** Rebuild the signed preimage: the body with no record_id and no signature
 *  member, canonicalized under RFC 8785 by the SDK's own canonicalizer. */
export function recordPreimage(record: Record<string, unknown>): string {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (key === 'record_id' || key === 'signature') continue
    body[key] = value
  }
  return canonicalizeJCS(body)
}

export function signatureVerifies(fixture: ChainFixture, record: Record<string, unknown>): boolean {
  const method = record.verification_method
  if (typeof method !== 'string') return false
  const publicKey = fixture.verification_keys[method]
  if (typeof publicKey !== 'string') return false
  try {
    return verifyEd25519(recordPreimage(record), record.signature as string, publicKey)
  } catch {
    return false
  }
}

/** Apply one release record to the cause set. Returns the labels it released
 *  and a per-cause note. A record-level rejection releases nothing. */
function applyRelease(
  fixture: ChainFixture,
  release: ReleaseRecord,
  causeLabels: string[],
  evaluatedAt: string,
  options: GateOptions,
): { released: string[]; note: string } {
  // 1. Signature, using the SDK's Ed25519 verify over the SDK's canonical bytes.
  if (!signatureVerifies(fixture, release as unknown as Record<string, unknown>)) {
    return { released: [], note: 'release_signature_unverified' }
  }

  // 2. The verification method has to belong to the releaser the body names, or
  //    a valid signature would say nothing about who released.
  if (!release.verification_method.startsWith(`${release.releaser}#`)) {
    return { released: [], note: 'release_releaser_binding_mismatch' }
  }

  // 3. A release recorded after the instant being evaluated is not in evidence
  //    at that instant. It is in evidence at a later one, which is the only
  //    difference between CR-15 and CR-16.
  if (release.released_at > evaluatedAt) {
    return { released: [], note: 'release_after_evaluation_instant' }
  }

  // 4. Per named cause. One record can name several causes, and each is decided
  //    on its own, so a record with standing over two of three causes releases
  //    exactly those two.
  const causeIdToLabel = new Map<string, string>()
  for (const label of causeLabels) causeIdToLabel.set(fixture.causes[label].cause_id, label)

  const released: string[] = []
  const perCause: string[] = []
  for (const causeId of release.released_causes) {
    const label = causeIdToLabel.get(causeId)
    if (label === undefined) {
      perCause.push(`${causeId}:cause_not_on_grant`)
      continue
    }
    const cause = fixture.causes[label]
    if (release.released_at < cause.imposed_at) {
      perCause.push(`${label}:release_precedes_imposition`)
      continue
    }
    let hasStanding: boolean
    if (options.ignoreCauseStanding) {
      hasStanding = true
    } else if (options.standingIsAuthorship) {
      hasStanding = release.releaser === cause.imposed_by
    } else {
      hasStanding = (fixture.cause_standing[label] ?? []).includes(release.releaser)
    }
    if (!hasStanding) {
      perCause.push(`${label}:releaser_without_standing`)
      continue
    }
    released.push(label)
    perCause.push(`${label}:released`)
  }

  return { released, note: perCause.join(',') }
}

function causeStage(
  fixture: ChainFixture,
  grantName: string,
  presentedReleases: string[],
  evaluatedAt: string,
  options: GateOptions,
  chainState: string,
): GateResult {
  const causeLabels = fixture.cause_sets[grantName]
  if (causeLabels === undefined) {
    throw new Error(`suspension-cause-composition: no cause set declared for ${grantName}`)
  }

  const notes: string[] = []
  const released = new Set<string>()

  if (causeLabels.length === 0) {
    for (const label of presentedReleases) {
      notes.push(`${label}=no_cause_on_grant`)
    }
    return {
      verdict: 'exercisable',
      stage: 'causes',
      code: 'no_cause_outstanding',
      remaining_causes: [],
      chain_state: chainState,
      chain_failure_index: null,
      release_notes: notes,
    }
  }

  for (const label of presentedReleases) {
    const release = fixture.releases[label]
    if (release === undefined) {
      throw new Error(`suspension-cause-composition: unknown release ${label}`)
    }
    const outcome = applyRelease(fixture, release, causeLabels, evaluatedAt, options)
    for (const causeLabel of outcome.released) released.add(causeLabel)
    notes.push(`${label}=${outcome.note}`)
  }

  // N1's one flaw, and the whole of it. A single flag cannot hold a set, so any
  // effective release clears the lot. This is the LC-B-024 representation
  // mistake, isolated.
  if (options.singleSuspensionFlag && released.size > 0) {
    for (const label of causeLabels) released.add(label)
  }

  const remaining = causeLabels.filter(label => !released.has(label)).sort()

  if (remaining.length === 0) {
    return {
      verdict: 'exercisable',
      stage: 'causes',
      code: 'all_causes_released',
      remaining_causes: [],
      chain_state: chainState,
      chain_failure_index: null,
      release_notes: notes,
    }
  }

  // Any remaining cause of kind suspension holds the grant suspended. With only
  // restrictions left the grant is restricted, which is the distinction L8 of
  // the proposed text draws and this family's reason for two names here.
  const anySuspension = remaining.some(label => fixture.causes[label].cause_kind === 'suspension')
  return {
    verdict: anySuspension ? 'suspended' : 'restricted',
    stage: 'causes',
    code: 'causes_outstanding',
    remaining_causes: remaining,
    chain_state: chainState,
    chain_failure_index: null,
    release_notes: notes,
  }
}

export function evaluate(
  fixture: ChainFixture,
  grantName: string,
  presentedReleases: string[],
  evaluatedAt: string,
  revocation: RevocationAnswer,
  options: GateOptions = {},
): GateResult {
  const chain = fixture.chains[grantName]
  if (chain === undefined) throw new Error(`suspension-cause-composition: unknown grant ${grantName}`)

  // Stage one, the real SDK. Chain verification decides valid, invalid,
  // indeterminate or unsupported before the cause question is asked. A release
  // record is a later record about the grant. It never rewrites the chain
  // result, and no release in this family is presented to the SDK at all.
  const chainResult = verifyAuthorityDelegationChain(chain as never, {
    now: evaluatedAt,
    resolveVerificationKey: ((_issuer: string, method: string) =>
      fixture.verification_keys[method] ?? null) as never,
    trustRoot: () => true,
    resolveRevocation: () => revocation,
  })
  const firstFailure = Array.isArray(chainResult.failures) ? chainResult.failures[0] : undefined
  const chainFailureIndex = typeof firstFailure?.index === 'number' ? firstFailure.index : null

  if (chainResult.state !== 'valid') {
    // N3's one flaw, and the whole of it. When every cause has been released it
    // treats the grant as restored and stops reading the chain's revocation
    // answer. That is exactly the failure OPEN-QUESTIONS.md names: lifting a
    // suspension must not bypass a revocation that happened while the agent was
    // suspended. The chain state is still reported, so the divergence is
    // visible in the run output rather than hidden.
    if (options.releaseClearsRevocation) {
      const afterRelease = causeStage(
        fixture,
        grantName,
        presentedReleases,
        evaluatedAt,
        options,
        chainResult.state,
      )
      if (afterRelease.remaining_causes.length === 0) {
        return { ...afterRelease, chain_failure_index: chainFailureIndex }
      }
    }

    // invalid stays invalid. indeterminate and unsupported are not established:
    // the verifier could not establish current authority, which is not a claim
    // that the grant is bad and not a claim about any cause.
    return {
      verdict: chainResult.state === 'invalid' ? 'invalid' : 'not_established',
      stage: 'chain',
      code: firstFailure?.code ?? 'CHAIN_NOT_VALID',
      remaining_causes: [],
      chain_state: chainResult.state,
      chain_failure_index: chainFailureIndex,
      release_notes: [],
    }
  }

  return causeStage(fixture, grantName, presentedReleases, evaluatedAt, options, chainResult.state)
}

export const GATES: Record<string, GateOptions> = {
  'reference-gate': {},
  'N1-single-suspension-flag': { singleSuspensionFlag: true },
  'N2-ignores-cause-standing': { ignoreCauseStanding: true },
  'N3-release-clears-revocation': { releaseClearsRevocation: true },
  'N4-standing-is-authorship': { standingIsAuthorship: true },
}
