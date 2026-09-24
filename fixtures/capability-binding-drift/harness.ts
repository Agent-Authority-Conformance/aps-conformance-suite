// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// The capability-binding boundary this family supplies, plus the declared defective
// negative control it is measured against.
//
// Neither reference SDK exposes an API that decides whether an action through a tool
// is established under a grant that pins that tool, so this boundary is the fixture's
// own code, not an SDK conformance result. It calls the SDK for the three things the
// SDK does decide: the grant chain's structural, temporal and revocation state
// (verifyAuthorityDelegationChain), the tool registry entry's attestor signature and
// implementation-hash match (verifyToolIntegrity), and RFC 8785 JCS canonical bytes
// for the metadata digest (canonicalizeJCS). See README "What exists".

import { createHash } from 'node:crypto'

import {
  canonicalizeJCS,
  verifyAuthorityDelegationChain,
  verifyToolIntegrity,
  type AuthorityDelegationV1,
  type RevocationResolution,
  type ToolRegistryEntry,
} from 'agent-passport-system'

export type Verdict = 'admitted' | 'not_established' | 'invalid'

export interface Outcome {
  verdict: Verdict
  reason: string
  detail?: string
}

export interface Presentation {
  label: string
  grant: AuthorityDelegationV1
  registryEntry: ToolRegistryEntry
  /** The implementation actually reachable behind the tool name at this instant. */
  currentImplementation: string
  /** The metadata block actually declared for the tool at this instant. */
  currentMetadata: unknown
  requestedToolName: string
  requestedScopeRequired: readonly string[]
  now: string
  resolveRevocation: () => RevocationResolution
}

export interface BoundaryOptions {
  resolveDelegationVerificationKey: (issuer: string, method: string) => string | null
  /** The attestor key the boundary trusts for this tool name. It is resolved from the
   *  tool, never from the attestorId the presented entry asserts about itself. */
  resolveTrustedAttestorKey: (toolName: string) => string | undefined
  trustRoot: (root: AuthorityDelegationV1) => boolean
  metadataDigestDomain: string
}

/** sha256: over DOMAIN || 0x00 || JCS(metadata). The preimage mint.ts uses. */
export function metadataDigest(metadata: unknown, domain: string): string {
  const preimage = Buffer.concat([
    Buffer.from(domain, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(metadata), 'utf8'),
  ])
  return `sha256:${createHash('sha256').update(preimage).digest('hex')}`
}

function grantsOf(grant: AuthorityDelegationV1): string[] {
  return grant.authority.scope.grants
}

function pinsUnder(grant: AuthorityDelegationV1, prefix: string): string[] {
  return grantsOf(grant)
    .filter((entry) => entry.startsWith(prefix))
    .map((entry) => entry.slice(prefix.length))
}

export class CapabilityBindingBoundary {
  readonly name: string
  private readonly options: BoundaryOptions
  /** When true, the metadata pin is never compared and its absence is not recorded. */
  private readonly skipMetadataPin: boolean
  /** When true, an absent implementation pin is treated as satisfied. */
  private readonly absentPinAdmits: boolean
  /** When true, verifyToolIntegrity's implementationVerified result is ignored. */
  private readonly skipRunningImplementationCheck: boolean

  constructor(
    name: string,
    options: BoundaryOptions,
    defects: {
      skipMetadataPin: boolean
      absentPinAdmits: boolean
      skipRunningImplementationCheck: boolean
    },
  ) {
    this.name = name
    this.options = options
    this.skipMetadataPin = defects.skipMetadataPin
    this.absentPinAdmits = defects.absentPinAdmits
    this.skipRunningImplementationCheck = defects.skipRunningImplementationCheck
  }

  admit(presentation: Presentation): Outcome {
    const {
      grant,
      registryEntry,
      currentImplementation,
      currentMetadata,
      requestedToolName,
      requestedScopeRequired,
      now,
      resolveRevocation,
    } = presentation

    // Step 0. The grant itself. Every configuration runs this step: a family that
    // skipped it would be testing capability binding on top of nothing.
    const chainResult = verifyAuthorityDelegationChain([grant], {
      now,
      resolveVerificationKey: (issuer, method) => this.options.resolveDelegationVerificationKey(issuer, method),
      trustRoot: this.options.trustRoot,
      resolveRevocation: () => resolveRevocation(),
    })
    if (chainResult.state !== 'valid') {
      return {
        verdict: 'invalid',
        reason: 'authority_chain_not_valid',
        detail: `${chainResult.state}/${chainResult.failures[0]?.code ?? 'none'}`,
      }
    }

    // Step 1. Does the grant name this tool at all, and does it carry the scopes the
    // action declares it needs.
    const grants = grantsOf(grant)
    const toolGrant = `tool:${requestedToolName}`
    if (!grants.includes(toolGrant)) {
      return { verdict: 'not_established', reason: 'tool_not_in_grant_scope', detail: toolGrant }
    }
    const missingScopes = requestedScopeRequired.filter((scope) => !grants.includes(scope))
    if (missingScopes.length > 0) {
      return { verdict: 'not_established', reason: 'scope_not_granted', detail: missingScopes.join(',') }
    }

    // Step 2. The tool attestation, decided by the SDK.
    const attestorKey = this.options.resolveTrustedAttestorKey(requestedToolName)
    if (attestorKey === undefined) {
      return { verdict: 'not_established', reason: 'tool_attestor_key_unresolved', detail: requestedToolName }
    }
    const integrity = verifyToolIntegrity({
      registryEntry,
      currentImplementation,
      attestorPublicKey: attestorKey,
    })
    if (!integrity.attestorSignatureValid) {
      return { verdict: 'not_established', reason: 'tool_attestation_signature_invalid' }
    }
    if (registryEntry.toolName !== requestedToolName) {
      return {
        verdict: 'not_established',
        reason: 'registry_entry_tool_name_mismatch',
        detail: `${registryEntry.toolName}!=${requestedToolName}`,
      }
    }
    if (!this.skipRunningImplementationCheck && !integrity.implementationVerified) {
      // The registry entry is a claim about an implementation. This step is what says
      // the claim still describes the implementation reachable right now.
      return { verdict: 'not_established', reason: 'registry_entry_implementation_mismatch' }
    }

    // Step 3. The implementation pin carried by the grant.
    const implementationPins = pinsUnder(grant, `${toolGrant}:impl:`)
    if (implementationPins.length === 0) {
      if (!this.absentPinAdmits) {
        // The grant gives the verifier no basis to establish that the implementation
        // behind this name is the one the principal granted against. That is recorded,
        // not resolved either way.
        return { verdict: 'not_established', reason: 'no_capability_pin_in_grant', detail: toolGrant }
      }
    } else if (!implementationPins.includes(registryEntry.implementationHash)) {
      return {
        verdict: 'not_established',
        reason: 'pinned_implementation_digest_mismatch',
        detail: `pinned=${implementationPins.join('|')} attested=${registryEntry.implementationHash}`,
      }
    }

    // Step 4. The metadata pin carried by the grant. A tool can keep both its name and
    // its implementation digest while its declared schema and permissions change.
    if (!this.skipMetadataPin) {
      const metadataPins = pinsUnder(grant, `${toolGrant}:meta:`)
      const currentMetadataDigest = metadataDigest(currentMetadata, this.options.metadataDigestDomain)
      if (metadataPins.length === 0) {
        return { verdict: 'not_established', reason: 'metadata_not_pinned_in_grant', detail: toolGrant }
      }
      if (!metadataPins.includes(currentMetadataDigest)) {
        return {
          verdict: 'not_established',
          reason: 'pinned_metadata_digest_mismatch',
          detail: `pinned=${metadataPins.join('|')} current=${currentMetadataDigest}`,
        }
      }
    }

    return { verdict: 'admitted', reason: 'capability_continuity_established' }
  }
}

export function makeReferenceBoundary(options: BoundaryOptions): CapabilityBindingBoundary {
  return new CapabilityBindingBoundary('reference-boundary', options, {
    skipMetadataPin: false,
    absentPinAdmits: false,
    skipRunningImplementationCheck: false,
  })
}

/** The declared negative control. It removes exactly three steps: the metadata pin
 *  comparison, the rule that an absent pin is recorded rather than admitted, and the
 *  check that the signed registry entry still describes the implementation reachable
 *  now. Everything else, including the grant chain and the attestor signature, is
 *  identical to the reference boundary. This is what an implementation that pins a
 *  tool by its registry entry's declared digest and stops there looks like. */
export function makeDefectiveBoundary(options: BoundaryOptions): CapabilityBindingBoundary {
  return new CapabilityBindingBoundary('defective-boundary-trusts-registry-entry-digest', options, {
    skipMetadataPin: true,
    absentPinAdmits: true,
    skipRunningImplementationCheck: true,
  })
}
