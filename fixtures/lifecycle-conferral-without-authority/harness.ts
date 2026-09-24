// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Three verifier configurations for the lifecycle-conferral-without-authority family.
//
// The reference configuration is thin on purpose. It transports the presented chain and
// the fixture's three resolvers into the SDK's own chain verifier and returns what came
// back, unchanged. Nothing in this file decides the reference verdict, which is what
// keeps the reference record's recomputation implementation the SDK rather than this
// harness (CONTRIBUTING.md, "Independence follows the implementation that supplies the
// substantive recomputation").
//
// The two defective configurations are the opposite. Each one constructs a verdict this
// family claims is wrong, so each one is part of the recomputation implementation for
// its own claim. They exist to make the family falsifiable: without them, a reader has
// only this fixture's word that a naive implementation would admit CWA-02 through
// CWA-05 and CWA-08.

import {
  scopeGrantCovers,
  verifyAuthorityDelegationChain,
  verifyAuthorityDelegationSignature,
} from 'agent-passport-system'

export type VerifierName =
  | 'reference-verifier'
  | 'defective-verifier-narrowing-without-depth'
  | 'defective-verifier-scope-coverage-only'

export interface Failure {
  code: string
  index?: number
  facet?: string
  message?: string
}

export interface Verdict {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  failures: Failure[]
}

export interface Resolvers {
  now: string
  verificationKeys: Record<string, string>
  trustedRootIssuer: string
}

function options(resolvers: Resolvers) {
  return {
    now: resolvers.now,
    resolveVerificationKey: (_issuer: string, verificationMethod: string) =>
      resolvers.verificationKeys[verificationMethod] ?? null,
    trustRoot: (root: { issuer: string }) => root.issuer === resolvers.trustedRootIssuer,
    resolveRevocation: () => 'active' as const,
  }
}

/**
 * The reference verifier. The SDK decides; this function only hands it the chain.
 */
export function referenceVerifier(chain: unknown[], resolvers: Resolvers): Verdict {
  const result = verifyAuthorityDelegationChain(chain as never, options(resolvers) as never)
  return { state: result.state, failures: result.failures as Failure[] }
}

/**
 * Monotonic narrowing enforced, conferral authority never asked about.
 *
 * This is the failure the proposed text exists to block, written out. It is the
 * reference verdict with every depth failure removed, which is exactly what an
 * implementation that compares six of the seven facets would produce. It still catches
 * scope widening, a broken signature, a broken parent link and a malformed record,
 * because those are real checks it does run: it is a plausible implementation, not a
 * strawman that checks nothing.
 */
export function narrowingWithoutDepthVerifier(chain: unknown[], resolvers: Resolvers): Verdict {
  const result = verifyAuthorityDelegationChain(chain as never, options(resolvers) as never)
  const failures = (result.failures as Failure[]).filter((f) => !f.code.startsWith('DEPTH_'))
  if (failures.length === (result.failures as Failure[]).length) {
    return { state: result.state, failures }
  }
  return { state: failures.length > 0 ? 'invalid' : 'valid', failures }
}

/**
 * Signatures plus scope coverage, and nothing else.
 *
 * The shape of a deployment that reads the scope array and treats the rest of the
 * authority vector as metadata. It verifies every record's signature, so a forged record
 * is still refused, and it checks that every child grant is covered by some parent
 * grant, using the SDK's own coverage predicate. It never reads depth, so it admits
 * every conferral this family rejects, and it never reads the schema, so it admits the
 * record whose depth facet is absent.
 */
export function scopeCoverageOnlyVerifier(chain: unknown[], resolvers: Resolvers): Verdict {
  const failures: Failure[] = []
  const records = chain as Array<Record<string, any>>

  for (let i = 0; i < records.length; i++) {
    const record = records[i]
    const publicKey = resolvers.verificationKeys[record.verification_method]
    if (!publicKey || !verifyAuthorityDelegationSignature(record as never, publicKey)) {
      failures.push({ code: 'SIGNATURE_INVALID', index: i })
      continue
    }
    if (i === 0) continue
    const parentGrants: string[] = records[i - 1].authority?.scope?.grants ?? []
    const childGrants: string[] = record.authority?.scope?.grants ?? []
    for (const needed of childGrants) {
      if (!parentGrants.some((granted) => scopeGrantCovers(granted, needed))) {
        failures.push({ code: 'SCOPE_WIDENING', index: i, facet: 'scope' })
        break
      }
    }
  }

  return { state: failures.length > 0 ? 'invalid' : 'valid', failures }
}

export const VERIFIERS: Record<VerifierName, (chain: unknown[], resolvers: Resolvers) => Verdict> = {
  'reference-verifier': referenceVerifier,
  'defective-verifier-narrowing-without-depth': narrowingWithoutDepthVerifier,
  'defective-verifier-scope-coverage-only': scopeCoverageOnlyVerifier,
}
