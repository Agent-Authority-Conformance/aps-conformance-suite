// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for the capability-binding-drift family.
//
// Mints, with the pinned TypeScript SDK `agent-passport-system`:
//   - three one-hop AuthorityDelegationV1 grants that differ only in nonce and in
//     which capability pins their scope carries
//   - four ToolRegistryEntry records over two endpoint descriptors for one tool name
//   - one aps-action-ref-v2 action reference
//   - the fixture's own metadata digests over two declared tool metadata blocks
//
// Every key is an Ed25519 seed derived from a published label, every nonce is derived
// the same way, and every timestamp is pinned, so `git diff` on chain.json is empty
// after a second run. No secret material is in the file.
//
// Run from the suite root:
//
//     npx tsx fixtures/capability-binding-drift/mint.ts

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalize,
  canonicalizeJCS,
  computeActionRefV2,
  computePayloadRefV1,
  createActionReferenceInputV2,
  createToolRegistryEntry,
  issueAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
  verifyAuthorityDelegationChain,
  verifyToolIntegrity,
  type AuthorityDelegationBodyV1,
  type AuthorityDelegationV1,
  type ToolRegistryEntry,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

const SEED_PREFIX = 'aps-conformance-suite:capability-binding-drift'
const SDK_VERSION = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version as string

const GENERATED_AT = '2026-09-23'
const NOW = '2026-09-23T12:00:00.000Z'
const DELEGATION_ISSUED_AT = '2026-09-23T09:00:00.000Z'
const NOT_AFTER = '2026-09-24T00:00:00.000Z'
const ATTESTED_AT = '2026-09-23T10:00:00.000Z'
const ACTION_ISSUED_AT = '2026-09-23T11:00:00.000Z'

const PRINCIPAL = 'did:aps:example:cbd-principal'
const AGENT = 'did:aps:example:cbd-agent'
const TOOL_ATTESTOR = 'did:aps:example:cbd-tool-attestor'
const OTHER_ATTESTOR = 'did:aps:example:cbd-other-attestor'

const TOOL_NAME = 'ledger.export'
const TOOL_TARGET = 'https://ledger.example/v1/export'

/** Domain separation for this family's own metadata digest. The reachable SDK
 *  tool-integrity surface digests an implementation and nothing else, so the
 *  metadata digest is defined here. See README "What this family defines itself". */
const METADATA_DIGEST_DOMAIN = 'APS-CBD-TOOL-METADATA-V0'

function seed(label: string): string {
  return createHash('sha256').update(`${SEED_PREFIX}:${label}`).digest('hex')
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

/** sha256: over the raw implementation bytes, the same preimage
 *  createToolRegistryEntry uses. */
function implementationDigest(implementation: string): string {
  return `sha256:${sha256Hex(implementation)}`
}

/** sha256: over DOMAIN || 0x00 || JCS(metadata), following the draft's
 *  domain-separated digest style. Defined by this family, not by the SDK. */
function metadataDigest(metadata: unknown): string {
  const preimage = Buffer.concat([
    Buffer.from(METADATA_DIGEST_DOMAIN, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(metadata), 'utf8'),
  ])
  return `sha256:${createHash('sha256').update(preimage).digest('hex')}`
}

// ── the tool, in two revisions ───────────────────────────────────────────────
//
// The implementation is an endpoint descriptor, which is one of the three things
// the SDK's tool-integrity surface documents as hashable content. Revision 2 keeps
// the tool name and the endpoint and changes the build, so its implementation
// digest changes. The metadata block is the tool's declared schema and permissions,
// which is what a planner or a gateway reads to decide what the tool can do.

const IMPLEMENTATION_V1 = JSON.stringify({
  build: 'ledger-export@1.4.2',
  endpoint: TOOL_TARGET,
  method: 'POST',
})

const IMPLEMENTATION_V2 = JSON.stringify({
  build: 'ledger-export@2.0.0',
  endpoint: TOOL_TARGET,
  method: 'POST',
})

const METADATA_V1 = {
  description: 'Export a ledger range as CSV.',
  permissions: ['ledger:read'],
  schema: {
    properties: {
      range: { type: 'string' },
    },
    required: ['range'],
    type: 'object',
  },
}

/** Same tool name. Same endpoint. Gains a destructive parameter and a destructive
 *  declared permission. Presented in CBD-03 against the byte-identical
 *  IMPLEMENTATION_V1 descriptor, which is the whole point of that vector. */
const METADATA_V2 = {
  description: 'Export a ledger range as CSV, optionally purging it after export.',
  permissions: ['ledger:delete', 'ledger:read'],
  schema: {
    properties: {
      purge: { type: 'boolean' },
      range: { type: 'string' },
    },
    required: ['range'],
    type: 'object',
  },
}

const IMPL_DIGEST_V1 = implementationDigest(IMPLEMENTATION_V1)
const IMPL_DIGEST_V2 = implementationDigest(IMPLEMENTATION_V2)
const META_DIGEST_V1 = metadataDigest(METADATA_V1)
const META_DIGEST_V2 = metadataDigest(METADATA_V2)

// ── capability pins as scope grants ──────────────────────────────────────────
//
// draft-pidlisnyi-aps-03 section 3.2 says scope grants use ASCII colon-separated
// segments, so a pin is expressed as further segments under the tool grant rather
// than as a new facet or a new record field. The draft defines no pin syntax; this
// encoding is this family's own. See README "What this family defines itself".

const GRANT_TOOL = `tool:${TOOL_NAME}`
const pinImpl = (digest: string) => `${GRANT_TOOL}:impl:${digest}`
const pinMeta = (digest: string) => `${GRANT_TOOL}:meta:${digest}`

function sortGrants(grants: string[]): string[] {
  const unique = [...new Set(grants)]
  return unique.sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')))
}

const GRANTS_PINNED = sortGrants([
  'ledger:read',
  GRANT_TOOL,
  pinImpl(IMPL_DIGEST_V1),
  pinMeta(META_DIGEST_V1),
])

const GRANTS_IMPL_PIN_ONLY = sortGrants(['ledger:read', GRANT_TOOL, pinImpl(IMPL_DIGEST_V1)])

const GRANTS_UNPINNED = sortGrants(['ledger:read', GRANT_TOOL])

function authority(grants: string[]) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: 0 },
    time: { not_before: DELEGATION_ISSUED_AT, not_after: NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

function delegationBody(grants: string[], nonceLabel: string): AuthorityDelegationBodyV1 {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject: AGENT,
    verification_method: `${PRINCIPAL}#key-1`,
    issued_at: DELEGATION_ISSUED_AT,
    nonce: seed(nonceLabel).slice(0, 32),
    authority: authority(grants),
  }
}

// ── tool registry entries ────────────────────────────────────────────────────
//
// createToolRegistryEntry stamps verifiedAt from the wall clock and offers no
// override, so a fixture cannot get reproducible bytes out of it directly. The
// entry is minted with the SDK, then re-stamped at the pinned instant and
// re-signed over the SDK's own canonicalization with the SDK's own sign(). The
// assertion below holds the re-signed record to the SDK's own verifier.
// See README "SDK findings".

function mintRegistryEntry(input: {
  implementation: string
  attestorId: string
  attestorPrivateKey: string
}): ToolRegistryEntry {
  const fromSdk = createToolRegistryEntry({
    toolName: TOOL_NAME,
    implementation: input.implementation,
    attestorId: input.attestorId,
    attestorPrivateKey: input.attestorPrivateKey,
  })
  const body = {
    toolName: fromSdk.toolName,
    implementationHash: fromSdk.implementationHash,
    attestorId: fromSdk.attestorId,
    verifiedAt: ATTESTED_AT,
  }
  return { ...body, signature: sign(canonicalize(body), input.attestorPrivateKey) }
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`capability-binding-drift mint: ${message}`)
    process.exit(2)
  }
}

function main(): void {
  const principalPriv = seed('principal:v1')
  const toolAttestorPriv = seed('tool-attestor:v1')
  const otherAttestorPriv = seed('other-attestor:v1')

  const principalPub = publicKeyFromPrivate(principalPriv)
  const toolAttestorPub = publicKeyFromPrivate(toolAttestorPriv)
  const otherAttestorPub = publicKeyFromPrivate(otherAttestorPriv)

  const verificationKeys: Record<string, string> = {
    [`${PRINCIPAL}#key-1`]: principalPub,
  }
  const attestorKeys: Record<string, string> = {
    [TOOL_ATTESTOR]: toolAttestorPub,
    [OTHER_ATTESTOR]: otherAttestorPub,
  }

  const delegations = {
    pinned: issueAuthorityDelegation(delegationBody(GRANTS_PINNED, 'nonce:pinned:v1'), principalPriv),
    impl_pin_only: issueAuthorityDelegation(
      delegationBody(GRANTS_IMPL_PIN_ONLY, 'nonce:impl-pin-only:v1'),
      principalPriv,
    ),
    unpinned: issueAuthorityDelegation(delegationBody(GRANTS_UNPINNED, 'nonce:unpinned:v1'), principalPriv),
  }

  // Every grant must verify valid at NOW with an active resolver, or no vector below
  // is testing what it says it tests.
  for (const [name, delegation] of Object.entries(delegations)) {
    const result = verifyAuthorityDelegationChain([delegation as AuthorityDelegationV1], {
      now: NOW,
      resolveVerificationKey: (_issuer, method) => verificationKeys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: () => 'active',
    })
    assert(
      result.state === 'valid',
      `grant "${name}" did not verify valid: ${JSON.stringify(result.failures)}`,
    )
  }

  const registryEntries = {
    v1: mintRegistryEntry({
      implementation: IMPLEMENTATION_V1,
      attestorId: TOOL_ATTESTOR,
      attestorPrivateKey: toolAttestorPriv,
    }),
    v2: mintRegistryEntry({
      implementation: IMPLEMENTATION_V2,
      attestorId: TOOL_ATTESTOR,
      attestorPrivateKey: toolAttestorPriv,
    }),
    v1_other_attestor: mintRegistryEntry({
      implementation: IMPLEMENTATION_V1,
      attestorId: OTHER_ATTESTOR,
      attestorPrivateKey: otherAttestorPriv,
    }),
  }

  // The re-stamped, re-signed entries must still satisfy the SDK's own verifier,
  // and must report the drift the vectors rely on.
  const v1SelfCheck = verifyToolIntegrity({
    registryEntry: registryEntries.v1,
    currentImplementation: IMPLEMENTATION_V1,
    attestorPublicKey: toolAttestorPub,
  })
  assert(v1SelfCheck.valid, `entry v1 did not verify: ${JSON.stringify(v1SelfCheck.errors)}`)
  assert(v1SelfCheck.attestorSignatureValid, 're-signed entry v1 failed the SDK attestor signature check')

  const v1AgainstV2 = verifyToolIntegrity({
    registryEntry: registryEntries.v1,
    currentImplementation: IMPLEMENTATION_V2,
    attestorPublicKey: toolAttestorPub,
  })
  assert(
    v1AgainstV2.attestorSignatureValid && !v1AgainstV2.implementationVerified,
    'entry v1 against implementation v2 should be signature-valid and implementation-mismatched',
  )

  const wrongAttestor = verifyToolIntegrity({
    registryEntry: registryEntries.v1_other_attestor,
    currentImplementation: IMPLEMENTATION_V1,
    attestorPublicKey: toolAttestorPub,
  })
  assert(
    !wrongAttestor.attestorSignatureValid,
    'entry signed by the other attestor should not verify against the tool attestor key',
  )

  assert(registryEntries.v1.implementationHash === IMPL_DIGEST_V1, 'entry v1 implementationHash drifted')
  assert(registryEntries.v2.implementationHash === IMPL_DIGEST_V2, 'entry v2 implementationHash drifted')
  assert(IMPL_DIGEST_V1 !== IMPL_DIGEST_V2, 'the two implementations must have different digests')
  assert(META_DIGEST_V1 !== META_DIGEST_V2, 'the two metadata blocks must have different digests')

  const payloadRef = computePayloadRefV1({ range: '2026-Q2' })
  const actionInput = createActionReferenceInputV2({
    agent_id: AGENT,
    action_type: 'ledger.export',
    target: TOOL_TARGET,
    payload_ref: payloadRef,
    scope_required: ['ledger:read'],
    issued_at: ACTION_ISSUED_AT,
    nonce: seed('action-nonce:v1').slice(0, 32),
  })
  const actionRef = computeActionRefV2(actionInput)

  const fixture = {
    _placeholder: false,
    profile: 'aps-capability-binding-drift-v0',
    generated_at: GENERATED_AT,
    generator: 'fixtures/capability-binding-drift/mint.ts',
    sdk: { typescript: `agent-passport-system@${SDK_VERSION}` },
    seed_prefix: SEED_PREFIX,
    now: NOW,
    metadata_digest_domain: METADATA_DIGEST_DOMAIN,
    identities: {
      principal: PRINCIPAL,
      acting_agent: AGENT,
      tool_attestor: TOOL_ATTESTOR,
      other_attestor: OTHER_ATTESTOR,
    },
    verification_keys: verificationKeys,
    attestor_keys: attestorKeys,
    tool: {
      name: TOOL_NAME,
      target: TOOL_TARGET,
      /** The attestor a boundary trusts for this tool name. A registry entry that
       *  asserts a different attestorId does not get to select its own key. */
      trusted_attestor: TOOL_ATTESTOR,
      implementations: { v1: IMPLEMENTATION_V1, v2: IMPLEMENTATION_V2 },
      implementation_digests: { v1: IMPL_DIGEST_V1, v2: IMPL_DIGEST_V2 },
      metadata: { v1: METADATA_V1, v2: METADATA_V2 },
      metadata_digests: { v1: META_DIGEST_V1, v2: META_DIGEST_V2 },
    },
    pins: {
      grant_tool: GRANT_TOOL,
      implementation_pin_prefix: `${GRANT_TOOL}:impl:`,
      metadata_pin_prefix: `${GRANT_TOOL}:meta:`,
    },
    delegations,
    registry_entries: registryEntries,
    action: {
      input: actionInput,
      payload: { range: '2026-Q2' },
      payload_ref: payloadRef,
      action_ref: actionRef,
    },
  }

  fs.writeFileSync(
    path.join(here, 'chain.json'),
    JSON.stringify(fixture, null, 2) + '\n',
    'utf8',
  )
  console.log('capability-binding-drift: chain.json written')
}

main()
