// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for the lifecycle-agent-side-events family.
//
// Mints, with the pinned TypeScript SDK `agent-passport-system`:
//   - four one-hop AuthorityDelegationV1 grants: one to the agent, one to a copy of
//     the agent, one naming an executor no registry resolves, and one narrower in
//     scope than the capability a presented memory record claims
//   - two attestor-signed executor lifecycle records for one executor id, one live
//     and open-ended, one retired part way through the window the vectors evaluate
//   - four principal-signed action-authorization credentials with a declared
//     freshness window, for the replay vectors
//   - two agent-signed authority-claim records, the shape a transferred memory store
//     carries when it says "I am authorized to do X"
//   - two principal-signed capability-consent records, one before and one after an
//     update added a capability
//   - two principal-signed revocation records with different effective instants
//
// Every Ed25519 key is the SHA-256 of a published label, every nonce is derived the
// same way, and every timestamp is pinned, so `git diff` on chain.json is empty after
// a second run. No secret material is in the file.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-agent-side-events/mint.ts

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  issueAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
  verifyAuthorityDelegationChain,
  type AuthorityDelegationBodyV1,
  type AuthorityDelegationV1,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-agent-side-events'
const SDK_VERSION = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version as string

const GENERATED_AT = '2026-09-23'
const NOW = '2026-09-23T12:00:00.000Z'
const DELEGATION_ISSUED_AT = '2026-09-19T09:00:00.000Z'
const NOT_AFTER = '2026-09-30T00:00:00.000Z'

/** The declared freshness window for an action-authorization credential, ten
 *  minutes, which is also the interval a lost replay cache has to be refused for. */
const FRESHNESS_MS = 600000

const PRINCIPAL = 'did:aps:example:ase-principal'
const AGENT = 'did:aps:example:ase-agent'
const COPY = 'did:aps:example:ase-agent-copy'
const NEW_INSTANCE = 'did:aps:example:ase-agent-new-instance'
const EXECUTOR_ATTESTOR = 'did:aps:example:ase-executor-attestor'

const EXECUTOR_PINNED = 'exec-pinned-2026-06'
const EXECUTOR_UNKNOWN = 'exec-never-registered'

const CAP_SUMMARIZE = 'cap:summarize'
const CAP_TOOL_INVOKE = 'cap:tool-invoke'

const EXECUTOR_DIGEST_DOMAIN = 'APS-ASE-EXECUTOR-LIFECYCLE-V0'
const CREDENTIAL_DIGEST_DOMAIN = 'APS-ASE-ACTION-AUTHORIZATION-V0'
const CLAIM_DIGEST_DOMAIN = 'APS-ASE-AUTHORITY-CLAIM-V0'
const CONSENT_DIGEST_DOMAIN = 'APS-ASE-CAPABILITY-CONSENT-V0'
const REVOCATION_DIGEST_DOMAIN = 'APS-ASE-REVOCATION-NOTICE-V0'

function seed(label: string): string {
  return createHash('sha256').update(`${SEED_PREFIX}:${label}`).digest('hex')
}

function digest(domain: string, body: unknown): string {
  const preimage = Buffer.concat([
    Buffer.from(domain, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(body), 'utf8'),
  ])
  return `sha256:${createHash('sha256').update(preimage).digest('hex')}`
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`lifecycle-agent-side-events mint: ${message}`)
    process.exit(2)
  }
}

function sortGrants(grants: string[]): string[] {
  return [...new Set(grants)].sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')))
}

function delegationBody(subject: string, grants: string[], nonceLabel: string): AuthorityDelegationBodyV1 {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject,
    verification_method: `${PRINCIPAL}#key-1`,
    issued_at: DELEGATION_ISSUED_AT,
    nonce: seed(nonceLabel).slice(0, 32),
    authority: {
      scope: { profile: 'aps-hierarchical-v1' as const, grants: sortGrants(grants) },
      spend: { mode: 'unbounded' as const },
      depth: { remaining: 0 },
      time: { not_before: DELEGATION_ISSUED_AT, not_after: NOT_AFTER },
      reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
      reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
    },
  }
}

function executorRecord(input: {
  label: string
  executorId: string
  liveFrom: string
  retiredFrom: string | null
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:executor-lifecycle:v0',
    executor_id: input.executorId,
    live_from: input.liveFrom,
    retired_from: input.retiredFrom,
    attestor: EXECUTOR_ATTESTOR,
    nonce: seed(`executor:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    executor_record_id: digest(EXECUTOR_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

function credential(input: {
  label: string
  subject: string
  capability: string
  issuedAt: string
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:action-authorization-credential:v0',
    issuer: PRINCIPAL,
    subject: input.subject,
    capability: input.capability,
    issued_at: input.issuedAt,
    freshness_ms: FRESHNESS_MS,
    nonce: seed(`credential:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    credential_id: digest(CREDENTIAL_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

/** The shape a transferred memory store carries when it says, about itself, what it
 *  is authorized to do. It is a record, it is signed, and it is not a grant. */
function authorityClaim(input: {
  label: string
  asserter: string
  about: string
  claimedGrants: string[]
  assertedAt: string
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:self-asserted-authority-claim:v0',
    asserter: input.asserter,
    about: input.about,
    claimed_grants: sortGrants(input.claimedGrants),
    asserted_at: input.assertedAt,
    nonce: seed(`claim:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    claim_id: digest(CLAIM_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

function consent(input: {
  label: string
  subject: string
  consented: string[]
  asOf: string
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:capability-consent:v0',
    principal: PRINCIPAL,
    subject: input.subject,
    consented_capabilities: sortGrants(input.consented),
    as_of: input.asOf,
    nonce: seed(`consent:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    consent_id: digest(CONSENT_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

function revocationNotice(input: {
  label: string
  delegationId: string
  effectiveAt: string
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:revocation-notice:v0',
    issuer: PRINCIPAL,
    delegation_id: input.delegationId,
    effective_at: input.effectiveAt,
    nonce: seed(`revocation:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    revocation_id: digest(REVOCATION_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

function main(): void {
  const principalPriv = seed('principal:v1')
  const agentPriv = seed('agent:v1')
  const executorAttestorPriv = seed('executor-attestor:v1')

  const verificationKeys: Record<string, string> = {
    [`${PRINCIPAL}#key-1`]: publicKeyFromPrivate(principalPriv),
  }
  const recordKeys: Record<string, string> = {
    [PRINCIPAL]: publicKeyFromPrivate(principalPriv),
    [AGENT]: publicKeyFromPrivate(agentPriv),
    [EXECUTOR_ATTESTOR]: publicKeyFromPrivate(executorAttestorPriv),
  }

  const baseGrants = ['ledger:read', `executor:${EXECUTOR_PINNED}`, CAP_SUMMARIZE, CAP_TOOL_INVOKE]

  const grants = {
    G_AGENT: issueAuthorityDelegation(delegationBody(AGENT, baseGrants, 'nonce:agent:v1'), principalPriv),
    // Issued to the copy in its own right. Same scope, different subject, no
    // relationship to G_AGENT beyond sharing a principal.
    G_COPY: issueAuthorityDelegation(delegationBody(COPY, baseGrants, 'nonce:copy:v1'), principalPriv),
    // Names an executor no registry record resolves.
    G_AGENT_UNKNOWN_EXECUTOR: issueAuthorityDelegation(
      delegationBody(
        AGENT,
        ['ledger:read', `executor:${EXECUTOR_UNKNOWN}`, CAP_SUMMARIZE, CAP_TOOL_INVOKE],
        'nonce:agent-unknown-executor:v1',
      ),
      principalPriv,
    ),
    // Carries cap:summarize and not cap:tool-invoke, which is exactly the capability
    // the memory record claims.
    G_AGENT_NARROW: issueAuthorityDelegation(
      delegationBody(AGENT, ['ledger:read', `executor:${EXECUTOR_PINNED}`, CAP_SUMMARIZE], 'nonce:agent-narrow:v1'),
      principalPriv,
    ),
  }

  for (const [name, grant] of Object.entries(grants)) {
    const result = verifyAuthorityDelegationChain([grant as AuthorityDelegationV1], {
      now: NOW,
      resolveVerificationKey: (_issuer, method) => verificationKeys[method] ?? null,
      trustRoot: () => true,
      resolveRevocation: () => 'active',
    })
    assert(result.state === 'valid', `grant ${name} must verify valid at ${NOW}, got ${result.state}`)
  }
  assert(
    !grants.G_AGENT_NARROW.authority.scope.grants.includes(CAP_TOOL_INVOKE),
    'G_AGENT_NARROW must not carry the capability the memory record claims',
  )

  const executors = {
    X_PINNED_LIVE: executorRecord({
      label: 'pinned-live',
      executorId: EXECUTOR_PINNED,
      liveFrom: '2026-01-01T00:00:00.000Z',
      retiredFrom: null,
      privateKey: executorAttestorPriv,
    }),
    // The provider retires the named executor on a published schedule. Nobody
    // revoked anything, nothing expired, and nobody suspended anything.
    X_PINNED_RETIRED: executorRecord({
      label: 'pinned-retired',
      executorId: EXECUTOR_PINNED,
      liveFrom: '2026-01-01T00:00:00.000Z',
      retiredFrom: '2026-09-22T00:00:00.000Z',
      privateKey: executorAttestorPriv,
    }),
  }

  const credentials = {
    // Fresh at NOW: window is 11:55 to 12:05.
    K_MAIN: credential({
      label: 'main',
      subject: AGENT,
      capability: CAP_SUMMARIZE,
      issuedAt: '2026-09-23T11:55:00.000Z',
      privateKey: principalPriv,
    }),
    // Fresh at 12:20, after a replay cache lost at 11:58 has aged out.
    K_LATE: credential({
      label: 'late',
      subject: AGENT,
      capability: CAP_SUMMARIZE,
      issuedAt: '2026-09-23T12:20:00.000Z',
      privateKey: principalPriv,
    }),
    // Fresh at an instant before the executor retires.
    K_BEFORE_RETIREMENT: credential({
      label: 'before-retirement',
      subject: AGENT,
      capability: CAP_SUMMARIZE,
      issuedAt: '2026-09-21T11:55:00.000Z',
      privateKey: principalPriv,
    }),
    // Fresh at an instant before the revocation takes effect.
    K_PRE_REVOCATION: credential({
      label: 'pre-revocation',
      subject: AGENT,
      capability: CAP_SUMMARIZE,
      issuedAt: '2026-09-23T04:55:00.000Z',
      privateKey: principalPriv,
    }),
    // The copy's own credential under its own grant.
    K_COPY: credential({
      label: 'copy',
      subject: COPY,
      capability: CAP_SUMMARIZE,
      issuedAt: '2026-09-23T11:55:00.000Z',
      privateKey: principalPriv,
    }),
    // For the capability vectors, which request cap:tool-invoke.
    K_TOOL_INVOKE: credential({
      label: 'tool-invoke',
      subject: AGENT,
      capability: CAP_TOOL_INVOKE,
      issuedAt: '2026-09-23T11:55:00.000Z',
      privateKey: principalPriv,
    }),
    // The same capability at an instant before the extended consent was given.
    K_TOOL_INVOKE_EARLY: credential({
      label: 'tool-invoke-early',
      subject: AGENT,
      capability: CAP_TOOL_INVOKE,
      issuedAt: '2026-09-23T04:55:00.000Z',
      privateKey: principalPriv,
    }),
  }

  const claims = {
    // The old instance's memory, carried onto a new instance, saying what it was
    // authorized to do. Signed by the agent, about the new instance.
    C_CARRIED_ONTO_NEW_INSTANCE: authorityClaim({
      label: 'carried-onto-new-instance',
      asserter: AGENT,
      about: NEW_INSTANCE,
      claimedGrants: ['ledger:read', CAP_SUMMARIZE, CAP_TOOL_INVOKE],
      assertedAt: '2026-09-22T10:00:00.000Z',
      privateKey: agentPriv,
    }),
    // The same shape, about itself, claiming a capability its own grant does not
    // carry. This is "I am authorized to approve invoices under $500" as a record.
    C_ABOUT_ITSELF: authorityClaim({
      label: 'about-itself',
      asserter: AGENT,
      about: AGENT,
      claimedGrants: [CAP_TOOL_INVOKE],
      assertedAt: '2026-09-22T10:00:00.000Z',
      privateKey: agentPriv,
    }),
  }

  const consents = {
    S_BASE: consent({
      label: 'base',
      subject: AGENT,
      consented: [CAP_SUMMARIZE],
      asOf: '2026-09-19T09:00:00.000Z',
      privateKey: principalPriv,
    }),
    // Consent to the capability an update added, given only at 06:00. Nothing in
    // this record reaches an action evaluated before that instant.
    S_EXTENDED: consent({
      label: 'extended',
      subject: AGENT,
      consented: [CAP_SUMMARIZE, CAP_TOOL_INVOKE],
      asOf: '2026-09-23T06:00:00.000Z',
      privateKey: principalPriv,
    }),
    // The copy's own consent under its own grant.
    S_BASE_COPY: consent({
      label: 'base-copy',
      subject: COPY,
      consented: [CAP_SUMMARIZE],
      asOf: '2026-09-19T09:00:00.000Z',
      privateKey: principalPriv,
    }),
  }

  const revocations = {
    V_EFFECTIVE_EARLY: revocationNotice({
      label: 'effective-early',
      delegationId: grants.G_AGENT.delegation_id,
      effectiveAt: '2026-09-23T06:00:00.000Z',
      privateKey: principalPriv,
    }),
  }

  assert(
    credentials.K_MAIN.credential_id !== credentials.K_LATE.credential_id,
    'the replay vectors need two distinct credentials',
  )
  assert(
    consents.S_BASE.consented_capabilities.includes(CAP_SUMMARIZE) &&
      !consents.S_BASE.consented_capabilities.includes(CAP_TOOL_INVOKE),
    'the base consent must cover the old capability and not the one the update added',
  )
  assert(
    consents.S_EXTENDED.consented_capabilities.includes(CAP_TOOL_INVOKE),
    'the extended consent must cover the capability the update added',
  )
  assert(
    consents.S_EXTENDED.as_of > '2026-09-23T05:00:00.000Z' && consents.S_EXTENDED.as_of < NOW,
    'the extended consent must be given after the early capability vector and before NOW',
  )
  assert(
    revocations.V_EFFECTIVE_EARLY.effective_at < NOW &&
      revocations.V_EFFECTIVE_EARLY.effective_at > '2026-09-23T04:55:00.000Z',
    'the revocation must take effect after the pre-revocation credential and before NOW',
  )

  const fixture = {
    _placeholder: false,
    generated_at: GENERATED_AT,
    sdk: { npm: `agent-passport-system@${SDK_VERSION}` },
    seed_prefix: SEED_PREFIX,
    now: NOW,
    freshness_ms: FRESHNESS_MS,
    digest_domains: {
      executor_lifecycle: EXECUTOR_DIGEST_DOMAIN,
      action_authorization_credential: CREDENTIAL_DIGEST_DOMAIN,
      self_asserted_authority_claim: CLAIM_DIGEST_DOMAIN,
      capability_consent: CONSENT_DIGEST_DOMAIN,
      revocation_notice: REVOCATION_DIGEST_DOMAIN,
    },
    parties: {
      principal: PRINCIPAL,
      agent: AGENT,
      copy: COPY,
      new_instance: NEW_INSTANCE,
      executor_attestor: EXECUTOR_ATTESTOR,
    },
    /** The one attestor this boundary resolves for executor lifecycle records, and
     *  the one issuer it resolves for consent and revocation records. Resolved from
     *  the role, never from the field a presented record asserts about itself. */
    standing: {
      executor_lifecycle: EXECUTOR_ATTESTOR,
      capability_consent: PRINCIPAL,
      revocation_notice: PRINCIPAL,
    },
    executor_ids: { pinned: EXECUTOR_PINNED, unknown: EXECUTOR_UNKNOWN },
    capability_declarations: {
      D_BASE: [CAP_SUMMARIZE],
      D_UPDATED: [CAP_SUMMARIZE, CAP_TOOL_INVOKE],
    },
    verification_keys: verificationKeys,
    record_keys: recordKeys,
    roles: Object.fromEntries(Object.entries(grants).map(([name, grant]) => [name, grant.delegation_id])),
    grants,
    executors,
    credentials,
    claims,
    consents,
    revocations,
  }

  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
  console.log('lifecycle-agent-side-events: chain.json written')
}

main()
