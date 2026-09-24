// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-expiry-and-renewal family, byte for byte.
//
// WHAT THIS FAMILY TESTS. The "Expiry and renewal" section of CASES.md in
// aeoess/agent-authority-lifecycle, cases LC-I-007, LC-I-008 and LC-I-009, against the
// proposed text in AUTHORITY-LIFECYCLE.md at commit 7796e22 or later, principally
// invariant L10 (expiry is not revocation), invariant L3 (reauthorization creates new
// authority) and the open question on office vacancy and succession. Every vector is
// labelled candidate_against_proposed.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are
// pinned constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-expiry-and-renewal/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  computeActionRefV2,
  computeAuthorityDelegationId,
  computePayloadRefV1,
  createActionReferenceInputV2,
  publicKeyFromPrivate,
  sign,
  signAuthorityDelegation,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-expiry-and-renewal:'
const seed = (label: string): string =>
  createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')

const OFFICE = 'did:aps:example:ler-issuing-office'
const AGENT = 'did:aps:example:ler-subject-agent'
const INTERIM = 'did:aps:example:ler-interim-holder'
const BOUNDARY = 'did:aps:example:ler-enforcement-boundary'
// A party with a real key and no recorded lifecycle standing over anything here.
const OUTSIDER = 'did:aps:example:ler-outsider'

const IDS = { OFFICE, AGENT, INTERIM, BOUNDARY, OUTSIDER }
const KEY_ID: Record<string, string> = Object.fromEntries(Object.values(IDS).map((d) => [d, `${d}#key-1`]))
const PRIVATE: Record<string, string> = Object.fromEntries(
  Object.entries(IDS).map(([label, d]) => [d, seed(`identity:${label.toLowerCase()}:v1`)]),
)
const PUBLIC: Record<string, string> = Object.fromEntries(
  Object.entries(PRIVATE).map(([d, k]) => [d, publicKeyFromPrivate(k)]),
)
const VERIFICATION_KEYS: Record<string, string> = Object.fromEntries(
  Object.values(IDS).map((d) => [KEY_ID[d], PUBLIC[d]]),
)

// ---------------------------------------------------------------------------
// The timeline. One pinned grant window and one pinned renewal cutover.
// ---------------------------------------------------------------------------

const ISSUED = '2026-09-01T00:00:00.000Z'
const NOT_AFTER = '2026-10-01T00:00:00.000Z'
const T2 = '2026-09-10T09:00:00.000Z'
const T3 = '2026-09-10T10:00:00.000Z'
const T4 = '2026-09-10T11:00:00.000Z'
const T5 = '2026-09-10T12:00:00.000Z'

function authorityVector(grants: string[], notBefore: string, notAfter: string, depth: number) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: depth },
    time: { not_before: notBefore, not_after: notAfter },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] as string[] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

function mintGrant(opts: {
  label: string
  parent: string | null
  issuer: string
  subject: string
  grants: string[]
  notBefore?: string
  notAfter?: string
  depth?: number
  issuedAt?: string
}) {
  const body = {
    record_type: 'aps:authority-delegation:v1' as const,
    version: '1.0' as const,
    parent_delegation_id: opts.parent,
    issuer: opts.issuer,
    subject: opts.subject,
    verification_method: KEY_ID[opts.issuer],
    issued_at: opts.issuedAt ?? ISSUED,
    nonce: seed(`grant-nonce:${opts.label}:v1`).slice(0, 32),
    authority: authorityVector(opts.grants, opts.notBefore ?? ISSUED, opts.notAfter ?? NOT_AFTER, opts.depth ?? 0),
  }
  const delegation_id = computeAuthorityDelegationId(body)
  const draft = { ...body, delegation_id }
  return { ...draft, signature: signAuthorityDelegation(draft, PRIVATE[opts.issuer]) }
}

// LC-I-007. One grant that reaches its declared end and one that is ended early for cause.
const EXPIRING = mintGrant({ label: 'expiring', parent: null, issuer: OFFICE, subject: AGENT, grants: ['ops:grant:*'], notAfter: T4 })
const REVOKED_FOR_CAUSE = mintGrant({ label: 'revoked-for-cause', parent: null, issuer: OFFICE, subject: AGENT, grants: ['ops:grant:*'] })
// Ended early for cause and then, later, its declared end passes too. The later event
// must not rewrite the earlier record.
const REVOKED_THEN_EXPIRED = mintGrant({ label: 'revoked-then-expired', parent: null, issuer: OFFICE, subject: AGENT, grants: ['ops:grant:*'], notAfter: T4 })

// LC-I-008. The old certificate and the artifact a renewal issues in its place. They are
// two artifacts with two delegation_ids and two windows, and the renewal does not touch
// the old one, which continues to its own unchanged end.
const OLD_CERTIFICATE = mintGrant({ label: 'old-certificate', parent: null, issuer: OFFICE, subject: AGENT, grants: ['ops:cert:*'], notAfter: T4 })
const NEW_CERTIFICATE = mintGrant({ label: 'new-certificate', parent: null, issuer: OFFICE, subject: AGENT, grants: ['ops:cert:*'], notBefore: T3, issuedAt: T3 })

// An attempt to extend in place: the old certificate's bytes with a later not_after and
// its original delegation_id left alone. draft-03 derives the id from the content, so
// this cannot be expressed, and the SDK says exactly why. That is the finding, not a
// trick: a protocol whose identifier binds its content has no extend-in-place operation.
const TAMPERED_EXTENSION = {
  ...OLD_CERTIFICATE,
  authority: { ...OLD_CERTIFICATE.authority, time: { not_before: ISSUED, not_after: NOT_AFTER } },
}

// LC-I-008-e. A renewal issued under a parent, widening past what the parent allows.
const CERT_PARENT = mintGrant({ label: 'cert-parent', parent: null, issuer: OFFICE, subject: INTERIM, grants: ['ops:cert:read'], depth: 1 })
const CERT_CHILD_WIDENED = mintGrant({ label: 'cert-child-widened', parent: CERT_PARENT.delegation_id, issuer: INTERIM, subject: AGENT, grants: ['ops:cert:*'] })

// LC-I-009. An interim mandate, bounded in scope and in time, and two children.
const INTERIM_PARENT = mintGrant({ label: 'interim-parent', parent: null, issuer: OFFICE, subject: INTERIM, grants: ['ops:interim:*'], notAfter: T4, depth: 1 })
const INTERIM_CHILD_OK = mintGrant({ label: 'interim-child-ok', parent: INTERIM_PARENT.delegation_id, issuer: INTERIM, subject: AGENT, grants: ['ops:interim:routine'], notAfter: T4 })
const INTERIM_CHILD_TIME_WIDENED = mintGrant({ label: 'interim-child-time-widened', parent: INTERIM_PARENT.delegation_id, issuer: INTERIM, subject: AGENT, grants: ['ops:interim:routine'] })

const CHAINS = {
  expiring: [EXPIRING],
  revoked_for_cause: [REVOKED_FOR_CAUSE],
  revoked_then_expired: [REVOKED_THEN_EXPIRED],
  old_certificate: [OLD_CERTIFICATE],
  new_certificate: [NEW_CERTIFICATE],
  tampered_extension: [TAMPERED_EXTENSION],
  cert_renewal_widened: [CERT_PARENT, CERT_CHILD_WIDENED],
  interim_ok: [INTERIM_PARENT, INTERIM_CHILD_OK],
  interim_time_widened: [INTERIM_PARENT, INTERIM_CHILD_TIME_WIDENED],
}

// ---------------------------------------------------------------------------
// Fixture-local signed records. Same envelope as the sibling family, one `kind`
// discriminator. This shape is this fixture's invention: neither AUTHORITY-LIFECYCLE.md
// nor draft-03 defines a wire shape for an ending kind, a renewal claim or an interim
// instrument.
// ---------------------------------------------------------------------------

const RECORD_PROFILE = 'aps-conformance-suite:lifecycle-expiry-and-renewal:record-v0'
const RECORD_SIG_DOMAIN = 'APS-CONFORMANCE-LIFECYCLE-EXPIRY-RECORD-V0'

interface SignedRecord {
  profile: string
  kind: string
  record_id: string
  issuer: string
  verification_method: string
  issued_at: string
  body: Record<string, unknown>
  signature: string
}

function mintRecord(recordId: string, kind: string, issuer: string, issuedAt: string, body: Record<string, unknown>): SignedRecord {
  const unsigned = {
    profile: RECORD_PROFILE,
    kind,
    record_id: recordId,
    issuer,
    verification_method: KEY_ID[issuer],
    issued_at: issuedAt,
    body,
  }
  return { ...unsigned, signature: sign(`${RECORD_SIG_DOMAIN} ${canonicalizeJCS(unsigned)}`, PRIVATE[issuer]) }
}

const R: Record<string, SignedRecord> = {}
const add = (rec: SignedRecord) => {
  R[rec.record_id] = rec
  return rec
}

add(
  mintRecord('standing_registry', 'standing_registry', OFFICE, ISSUED, {
    // Who may end an artifact early, and who may extend an interim mandate. A signature
    // establishes who signed. Standing is a separate statement by the office.
    lifecycle_standing: [OFFICE],
    renewal_author: [OFFICE],
    interim_instrument_author: [OFFICE],
    decision_attestor: [BOUNDARY],
  }),
)

// --- LC-I-007 --------------------------------------------------------------

add(
  mintRecord('i007_revocation_for_cause', 'revocation_notice', OFFICE, T2, {
    grant: REVOKED_FOR_CAUSE.delegation_id,
    cause: 'credential-obtained-through-misstatement',
    actor: OFFICE,
    recorded_at: T2,
  }),
)
add(
  mintRecord('i007_revocation_then_expiry', 'revocation_notice', OFFICE, T2, {
    grant: REVOKED_THEN_EXPIRED.delegation_id,
    cause: 'credential-obtained-through-misstatement',
    actor: OFFICE,
    recorded_at: T2,
  }),
)
// The same claim, signed by a party the office's registry does not give standing to.
add(
  mintRecord('i007_revocation_without_standing', 'revocation_notice', OUTSIDER, T2, {
    grant: REVOKED_FOR_CAUSE.delegation_id,
    cause: 'credential-obtained-through-misstatement',
    actor: OUTSIDER,
    recorded_at: T2,
  }),
)

// --- LC-I-008 --------------------------------------------------------------

add(
  mintRecord('i008_renewal', 'renewal', OFFICE, T3, {
    supersedes: OLD_CERTIFICATE.delegation_id,
    issues: NEW_CERTIFICATE.delegation_id,
    mode: 'reissue',
  }),
)
add(
  mintRecord('i008_cached_decision_on_old_artifact', 'cached_decision', BOUNDARY, T2, {
    delegation_ref: OLD_CERTIFICATE.delegation_id,
    decided_at: T2,
    verdict: 'permit',
  }),
)

// --- LC-I-009 --------------------------------------------------------------

add(
  mintRecord('i009_instrument', 'interim_instrument', OFFICE, ISSUED, {
    office: OFFICE,
    interim_holder: INTERIM,
    caretaking_scope: ['ops:interim:routine'],
    mandate_not_after: T4,
    // Who may extend or replace the interim mandate. The interim role is not on this list.
    may_extend: [OFFICE],
  }),
)
add(mintRecord('i009_extension_by_office', 'interim_extension', OFFICE, T4, { mandate: INTERIM_PARENT.delegation_id, new_not_after: NOT_AFTER }))
add(mintRecord('i009_extension_self', 'interim_extension', INTERIM, T4, { mandate: INTERIM_PARENT.delegation_id, new_not_after: NOT_AFTER }))

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

const ACTION_SPECS: Array<[string, string, string]> = [
  ['grant_use', 'ops:grant:use', 'grant.use'],
  ['cert_use', 'ops:cert:use', 'cert.use'],
  ['cert_read', 'ops:cert:read', 'cert.read'],
  ['interim_routine', 'ops:interim:routine', 'interim.routine'],
  ['interim_bind', 'ops:interim:bind', 'interim.bind'],
]

const ACTIONS = Object.fromEntries(
  ACTION_SPECS.map(([label, scope, type]) => {
    const input = createActionReferenceInputV2({
      agent_id: AGENT,
      action_type: type,
      target: `https://issuer.example/api/v1/${label.replace(/_/g, '/')}`,
      payload_ref: computePayloadRefV1({ action: label }),
      scope_required: [scope],
      issued_at: ISSUED,
      nonce: seed(`action-nonce:${label}:v1`).slice(0, 32),
    })
    return [label, { input, action_ref: computeActionRefV2(input), requested_scope: scope }]
  }),
)

// ---------------------------------------------------------------------------
// Mint-time assertions
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

for (const [label, rec] of Object.entries(R)) {
  const { signature, ...unsigned } = rec
  assert(
    verifyEd25519(`${RECORD_SIG_DOMAIN} ${canonicalizeJCS(unsigned)}`, signature, PUBLIC[rec.issuer]),
    `${label} does not verify under the harness rule`,
  )
}

assert(
  OLD_CERTIFICATE.delegation_id !== NEW_CERTIFICATE.delegation_id,
  'the renewal reuses the old artifact\'s delegation_id, which would defeat LC-I-008',
)
assert(
  TAMPERED_EXTENSION.delegation_id === OLD_CERTIFICATE.delegation_id,
  'the extend-in-place attempt does not keep the old delegation_id',
)

const chainOpts = (now: string, revocation: 'active' | 'revoked' = 'active') => ({
  now,
  resolveVerificationKey: (_issuer: string, method: string) => VERIFICATION_KEYS[method] ?? null,
  trustRoot: (root: { issuer?: string }) => root.issuer === OFFICE,
  resolveRevocation: () => revocation as 'active' | 'revoked',
})

const probe: Record<string, { state: string; code: string | null }> = {}
function record(label: string, chain: unknown[], now: string, revocation: 'active' | 'revoked' = 'active') {
  const r = verifyAuthorityDelegationChain(chain as never, chainOpts(now, revocation))
  probe[label] = { state: r.state, code: r.failures[0]?.code ?? null }
  return probe[label]
}

assert(record('expiring_inside', CHAINS.expiring, T3).state === 'valid', 'the expiring grant is not valid inside its window')
assert(record('expiring_after', CHAINS.expiring, T5).code === 'EXPIRED', 'past not_after did not give EXPIRED')
assert(record('revoked_for_cause_inside', CHAINS.revoked_for_cause, T3, 'revoked').code === 'REVOKED', 'a revoked resolution did not give REVOKED')
assert(record('revoked_for_cause_active', CHAINS.revoked_for_cause, T3).state === 'valid', 'the for-cause grant is not valid before revocation')
// The overlap case. Recorded, not assumed: draft-03 section 3.3 runs the validity phase
// before the revocation phase, so the SDK reports the expiry here even though a
// revocation record was signed earlier. The lifecycle verdict does not follow it.
assert(record('revoked_then_expired', CHAINS.revoked_then_expired, T5, 'revoked').state !== 'valid', 'the doubly ended grant still verifies valid')
assert(record('old_certificate_after', CHAINS.old_certificate, T5).code === 'EXPIRED', 'the old certificate did not expire')
assert(record('new_certificate_inside', CHAINS.new_certificate, T4).state === 'valid', 'the new certificate is not valid in its own window')
assert(record('tampered_extension', CHAINS.tampered_extension, T4).code === 'ID_MISMATCH', 'the extend-in-place attempt did not give ID_MISMATCH')
assert(record('cert_renewal_widened', CHAINS.cert_renewal_widened, T4).code === 'SCOPE_WIDENING', 'the widened renewal did not give SCOPE_WIDENING')
assert(record('interim_ok', CHAINS.interim_ok, T3).state === 'valid', 'the interim chain is not valid inside its mandate')
assert(record('interim_ok_after_mandate', CHAINS.interim_ok, T5).code === 'EXPIRED', 'the interim chain did not expire with its mandate')
assert(record('interim_time_widened', CHAINS.interim_time_widened, T3).code === 'TIME_WIDENING', 'the self-extending child did not give TIME_WIDENING')

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) out[key] = sortKeys((value as Record<string, unknown>)[key])
    return out
  }
  return value
}

const chain = {
  profile: 'aps-lifecycle-expiry-and-renewal-v0',
  description:
    'Three expiry and renewal lifecycle cases. Nine AuthorityDelegationV1 chains, one ' +
    'signed standing registry, seven fixture-local signed lifecycle records (a ' +
    'fixture-local profile, not a protocol object) and five draft-03 action references, ' +
    'minted and verified with agent-passport-system 7.1.0.',
  minted_by: 'fixtures/lifecycle-expiry-and-renewal/mint.ts',
  seed_label_prefix: SEED_PREFIX,
  sdk: { typescript: 'agent-passport-system@7.1.0' },
  identities: IDS,
  verification_keys: VERIFICATION_KEYS,
  record_profile: RECORD_PROFILE,
  record_signature_domain: RECORD_SIG_DOMAIN,
  timeline: { issued: ISSUED, not_after: NOT_AFTER, T2, T3, T4, T5 },
  chains: CHAINS,
  records: R,
  actions: ACTIONS,
  mint_time_sdk_observations: probe,
}

fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('lifecycle-expiry-and-renewal: chain.json minted')
console.log(`  chains: ${Object.keys(CHAINS).length}, records: ${Object.keys(R).length}, actions: ${Object.keys(ACTIONS).length}`)
for (const [k, v] of Object.entries(probe)) console.log(`  ${k}: ${v.state}/${v.code}`)
