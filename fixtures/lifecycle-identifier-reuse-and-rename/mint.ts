// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for the lifecycle-identifier-reuse-and-rename family.
//
// Mints, with the pinned TypeScript SDK `agent-passport-system`:
//   - five one-hop AuthorityDelegationV1 grants that differ only in nonce and in
//     which external-identifier dependency their scope declares and pins
//   - eleven custodian-signed identifier-binding records over three identifiers of
//     three kinds, covering a current binding, a lapsed binding, a re-registration
//     by an unrelated controller, a routine reassignment with no gap at all, a
//     resumption by the original controller after a gap, and two records from one
//     custodian that overlap and name different controllers
//   - three custodian-signed retention records: one covering a gap exactly, one
//     stopping short of it, and one covering it from an identity with no standing
//
// Every Ed25519 key is the SHA-256 of a published label, every nonce is derived the
// same way, and every timestamp is pinned, so `git diff` on chain.json is empty after
// a second run. No secret material is in the file.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-identifier-reuse-and-rename/mint.ts

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

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-identifier-reuse-and-rename'
const SDK_VERSION = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version as string

const GENERATED_AT = '2026-09-23'
const NOW = '2026-09-23T12:00:00.000Z'
const DELEGATION_ISSUED_AT = '2026-09-19T09:00:00.000Z'
const NOT_AFTER = '2026-09-30T00:00:00.000Z'

const PRINCIPAL = 'did:aps:example:irr-principal'
const AGENT = 'did:aps:example:irr-agent'

const REGISTRAR = 'did:aps:example:irr-registrar'
const PACKAGE_HOST = 'did:aps:example:irr-package-host'
const CARRIER = 'did:aps:example:irr-carrier'
const OUTSIDER = 'did:aps:example:irr-outsider'

const ORG = 'did:aps:example:irr-org'
const NEW_PARTY = 'did:aps:example:irr-newparty'
const PUBLISHER = 'did:aps:example:irr-publisher'
const CLAIMER = 'did:aps:example:irr-claimer'
const SUBSCRIBER_A = 'did:aps:example:irr-subscriber-a'
const SUBSCRIBER_B = 'did:aps:example:irr-subscriber-b'

const MAIL_DOMAIN = 'acme-legal.example'
const PACKAGE_NAMESPACE = 'acme'
const PHONE = '+15550100'

const BINDING_DIGEST_DOMAIN = 'APS-IRR-IDENTIFIER-BINDING-V0'
const RETENTION_DIGEST_DOMAIN = 'APS-IRR-IDENTIFIER-RETENTION-V0'

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
    console.error(`lifecycle-identifier-reuse-and-rename mint: ${message}`)
    process.exit(2)
  }
}

// ── scope encoding ───────────────────────────────────────────────────────────
//
// A dependency on an external identifier is expressed as further colon-separated
// segments, so it stays inside the scope grammar draft-03 already defines rather
// than inventing a record field. draft-03 defines no such encoding.

function dependencyGrant(kind: string, identifier: string): string {
  return `extid:${kind}:${identifier}`
}

function controllerPin(kind: string, identifier: string, controller: string): string {
  return `${dependencyGrant(kind, identifier)}:controller:${controller}`
}

function sortGrants(grants: string[]): string[] {
  return [...new Set(grants)].sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')))
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

// ── custodian records ────────────────────────────────────────────────────────

function binding(input: {
  label: string
  kind: string
  identifier: string
  controller: string
  boundFrom: string
  boundUntil: string | null
  custodian: string
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:identifier-binding:v0',
    identifier_kind: input.kind,
    identifier: input.identifier,
    controller: input.controller,
    bound_from: input.boundFrom,
    bound_until: input.boundUntil,
    custodian: input.custodian,
    nonce: seed(`binding:${input.label}`).slice(0, 32),
  }
  return { ...body, binding_id: digest(BINDING_DIGEST_DOMAIN, body), signature: sign(canonicalizeJCS(body), input.privateKey) }
}

function retention(input: {
  label: string
  kind: string
  identifier: string
  retainedFrom: string
  retainedUntil: string
  custodian: string
  privateKey: string
  reason: string
}) {
  const body = {
    record_type: 'aps-lab:identifier-retention:v0',
    identifier_kind: input.kind,
    identifier: input.identifier,
    retained_from: input.retainedFrom,
    retained_until: input.retainedUntil,
    custodian: input.custodian,
    reason: input.reason,
    nonce: seed(`retention:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    retention_id: digest(RETENTION_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

function main(): void {
  const principalPriv = seed('principal:v1')
  const registrarPriv = seed('registrar:v1')
  const packageHostPriv = seed('package-host:v1')
  const carrierPriv = seed('carrier:v1')
  const outsiderPriv = seed('outsider:v1')

  const verificationKeys: Record<string, string> = {
    [`${PRINCIPAL}#key-1`]: publicKeyFromPrivate(principalPriv),
    [`${AGENT}#key-1`]: publicKeyFromPrivate(seed('agent:v1')),
  }
  const custodianKeys: Record<string, string> = {
    [REGISTRAR]: publicKeyFromPrivate(registrarPriv),
    [PACKAGE_HOST]: publicKeyFromPrivate(packageHostPriv),
    [CARRIER]: publicKeyFromPrivate(carrierPriv),
    [OUTSIDER]: publicKeyFromPrivate(outsiderPriv),
  }

  const grants = {
    // Declares the mail domain as a dependency and pins its controller.
    G_MAIL_PINNED: issueAuthorityDelegation(
      delegationBody(
        [
          'account:recover',
          dependencyGrant('mail-domain', MAIL_DOMAIN),
          controllerPin('mail-domain', MAIL_DOMAIN, ORG),
        ],
        'nonce:mail-pinned:v1',
      ),
      principalPriv,
    ),
    // The same recovery authority, with the mail domain the recovery path in fact
    // depends on named nowhere in the grant. This is the graph never modelling it.
    G_MAIL_UNDECLARED: issueAuthorityDelegation(
      delegationBody(['account:recover'], 'nonce:mail-undeclared:v1'),
      principalPriv,
    ),
    G_PACKAGE_PINNED: issueAuthorityDelegation(
      delegationBody(
        [
          'package:install',
          dependencyGrant('package-namespace', PACKAGE_NAMESPACE),
          controllerPin('package-namespace', PACKAGE_NAMESPACE, PUBLISHER),
        ],
        'nonce:package-pinned:v1',
      ),
      principalPriv,
    ),
    G_PHONE_PINNED: issueAuthorityDelegation(
      delegationBody(
        ['account:recover', dependencyGrant('phone-e164', PHONE), controllerPin('phone-e164', PHONE, SUBSCRIBER_A)],
        'nonce:phone-pinned:v1',
      ),
      principalPriv,
    ),
    // Declares the number as a dependency and says nothing about who holds it.
    G_PHONE_UNPINNED: issueAuthorityDelegation(
      delegationBody(['account:recover', dependencyGrant('phone-e164', PHONE)], 'nonce:phone-unpinned:v1'),
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

  const bindings = {
    // mail-domain. The org holds it, open-ended.
    B_MAIL_ORG_CURRENT: binding({
      label: 'mail-org-current',
      kind: 'mail-domain',
      identifier: MAIL_DOMAIN,
      controller: ORG,
      boundFrom: '2026-01-01T00:00:00.000Z',
      boundUntil: null,
      custodian: REGISTRAR,
      privateKey: registrarPriv,
    }),
    // The same holding, allowed to lapse.
    B_MAIL_ORG_LAPSED: binding({
      label: 'mail-org-lapsed',
      kind: 'mail-domain',
      identifier: MAIL_DOMAIN,
      controller: ORG,
      boundFrom: '2026-01-01T00:00:00.000Z',
      boundUntil: '2026-09-21T00:00:00.000Z',
      custodian: REGISTRAR,
      privateKey: registrarPriv,
    }),
    // An unrelated party registers the same string the next day.
    B_MAIL_NEWPARTY: binding({
      label: 'mail-newparty',
      kind: 'mail-domain',
      identifier: MAIL_DOMAIN,
      controller: NEW_PARTY,
      boundFrom: '2026-09-22T00:00:00.000Z',
      boundUntil: null,
      custodian: REGISTRAR,
      privateKey: registrarPriv,
    }),

    // package-namespace. The publisher's holding ends when the account is renamed.
    B_PACKAGE_PUBLISHER_ENDED: binding({
      label: 'package-publisher-ended',
      kind: 'package-namespace',
      identifier: PACKAGE_NAMESPACE,
      controller: PUBLISHER,
      boundFrom: '2026-01-01T00:00:00.000Z',
      boundUntil: '2026-09-20T00:00:00.000Z',
      custodian: PACKAGE_HOST,
      privateKey: packageHostPriv,
    }),
    // Someone else claims the vacated name.
    B_PACKAGE_CLAIMER: binding({
      label: 'package-claimer',
      kind: 'package-namespace',
      identifier: PACKAGE_NAMESPACE,
      controller: CLAIMER,
      boundFrom: '2026-09-21T00:00:00.000Z',
      boundUntil: null,
      custodian: PACKAGE_HOST,
      privateKey: packageHostPriv,
    }),
    // Or the original publisher takes it back, two days later.
    B_PACKAGE_PUBLISHER_RESUMED: binding({
      label: 'package-publisher-resumed',
      kind: 'package-namespace',
      identifier: PACKAGE_NAMESPACE,
      controller: PUBLISHER,
      boundFrom: '2026-09-22T00:00:00.000Z',
      boundUntil: null,
      custodian: PACKAGE_HOST,
      privateKey: packageHostPriv,
    }),

    // phone-e164. Subscriber A holds it, open-ended.
    B_PHONE_A_CURRENT: binding({
      label: 'phone-a-current',
      kind: 'phone-e164',
      identifier: PHONE,
      controller: SUBSCRIBER_A,
      boundFrom: '2026-01-01T00:00:00.000Z',
      boundUntil: null,
      custodian: CARRIER,
      privateKey: carrierPriv,
    }),
    // A disconnects and the carrier reassigns, with no gap at all: this is routine
    // numbering-plan behaviour and not a lapse anyone failed to prevent.
    B_PHONE_A_ENDED: binding({
      label: 'phone-a-ended',
      kind: 'phone-e164',
      identifier: PHONE,
      controller: SUBSCRIBER_A,
      boundFrom: '2026-01-01T00:00:00.000Z',
      boundUntil: '2026-09-22T00:00:00.000Z',
      custodian: CARRIER,
      privateKey: carrierPriv,
    }),
    B_PHONE_B: binding({
      label: 'phone-b',
      kind: 'phone-e164',
      identifier: PHONE,
      controller: SUBSCRIBER_B,
      boundFrom: '2026-09-22T00:00:00.000Z',
      boundUntil: null,
      custodian: CARRIER,
      privateKey: carrierPriv,
    }),
    // One custodian, two open records that overlap and name different holders.
    B_PHONE_B_OVERLAPPING: binding({
      label: 'phone-b-overlapping',
      kind: 'phone-e164',
      identifier: PHONE,
      controller: SUBSCRIBER_B,
      boundFrom: '2026-09-01T00:00:00.000Z',
      boundUntil: null,
      custodian: CARRIER,
      privateKey: carrierPriv,
    }),
  }

  const retentions = {
    // Covers the whole interval the publisher did not hold the name.
    R_PACKAGE_FULL: retention({
      label: 'package-full',
      kind: 'package-namespace',
      identifier: PACKAGE_NAMESPACE,
      retainedFrom: '2026-09-20T00:00:00.000Z',
      retainedUntil: '2026-09-22T00:00:00.000Z',
      custodian: PACKAGE_HOST,
      privateKey: packageHostPriv,
      reason: 'namespace withheld from re-registration while dependents resolve it',
    }),
    // Stops a day short of the resumption.
    R_PACKAGE_SHORT: retention({
      label: 'package-short',
      kind: 'package-namespace',
      identifier: PACKAGE_NAMESPACE,
      retainedFrom: '2026-09-20T00:00:00.000Z',
      retainedUntil: '2026-09-21T00:00:00.000Z',
      custodian: PACKAGE_HOST,
      privateKey: packageHostPriv,
      reason: 'namespace withheld from re-registration while dependents resolve it',
    }),
    // Covers the whole interval, signed by an identity this boundary does not
    // resolve as the custodian for this identifier kind.
    R_PACKAGE_NO_STANDING: retention({
      label: 'package-no-standing',
      kind: 'package-namespace',
      identifier: PACKAGE_NAMESPACE,
      retainedFrom: '2026-09-20T00:00:00.000Z',
      retainedUntil: '2026-09-22T00:00:00.000Z',
      custodian: OUTSIDER,
      privateKey: outsiderPriv,
      reason: 'namespace withheld from re-registration while dependents resolve it',
    }),
  }

  // The reassignment in B_PHONE_A_ENDED and B_PHONE_B is adjacent, not gapped. That
  // is what separates LC-I-003 from LC-I-001: nothing lapsed and nobody walked away.
  assert(
    bindings.B_PHONE_A_ENDED.bound_until === bindings.B_PHONE_B.bound_from,
    'the phone reassignment must be adjacent, with no uncovered interval',
  )
  assert(
    bindings.B_MAIL_ORG_LAPSED.bound_until !== null &&
      bindings.B_MAIL_ORG_LAPSED.bound_until < bindings.B_MAIL_NEWPARTY.bound_from,
    'the mail domain must actually lapse before the new registration',
  )
  assert(
    bindings.B_PACKAGE_PUBLISHER_ENDED.bound_until === retentions.R_PACKAGE_FULL.retained_from &&
      bindings.B_PACKAGE_PUBLISHER_RESUMED.bound_from === retentions.R_PACKAGE_FULL.retained_until,
    'the full retention record must cover the publisher gap exactly',
  )
  assert(
    retentions.R_PACKAGE_SHORT.retained_until < bindings.B_PACKAGE_PUBLISHER_RESUMED.bound_from,
    'the short retention record must stop before the resumption',
  )

  const fixture = {
    _placeholder: false,
    generated_at: GENERATED_AT,
    sdk: { npm: `agent-passport-system@${SDK_VERSION}` },
    seed_prefix: SEED_PREFIX,
    now: NOW,
    digest_domains: { identifier_binding: BINDING_DIGEST_DOMAIN, identifier_retention: RETENTION_DIGEST_DOMAIN },
    parties: {
      principal: PRINCIPAL,
      agent: AGENT,
      registrar: REGISTRAR,
      package_host: PACKAGE_HOST,
      carrier: CARRIER,
      outsider: OUTSIDER,
      org: ORG,
      new_party: NEW_PARTY,
      publisher: PUBLISHER,
      claimer: CLAIMER,
      subscriber_a: SUBSCRIBER_A,
      subscriber_b: SUBSCRIBER_B,
    },
    identifiers: {
      'mail-domain': MAIL_DOMAIN,
      'package-namespace': PACKAGE_NAMESPACE,
      'phone-e164': PHONE,
    },
    /** The one custodian this boundary resolves for each identifier kind. Resolved
     *  from the kind, never from the custodian a presented record claims to be. */
    custodian_standing: {
      'mail-domain': REGISTRAR,
      'package-namespace': PACKAGE_HOST,
      'phone-e164': CARRIER,
    },
    scope_encoding: {
      dependency: 'extid:<kind>:<identifier>',
      controller_pin: 'extid:<kind>:<identifier>:controller:<did>',
    },
    verification_keys: verificationKeys,
    custodian_keys: custodianKeys,
    roles: Object.fromEntries(Object.entries(grants).map(([name, grant]) => [name, grant.delegation_id])),
    grants,
    bindings,
    retentions,
  }

  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
  console.log('lifecycle-identifier-reuse-and-rename: chain.json written')
}

main()
