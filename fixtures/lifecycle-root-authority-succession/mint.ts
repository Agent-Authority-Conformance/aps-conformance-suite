// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-root-authority-succession family.
//
// WHAT THIS FAMILY TESTS. Whether a delegation is bound to an office or to a
// person, what each binding mode does when the person filling the office
// changes, and what a verifier should return when the delegation is silent
// about which mode applies or when nobody currently holds the office.
//
// The proposed text is aeoess/agent-authority-lifecycle, AUTHORITY-LIFECYCLE.md
// at commit 7796e22 or later, sections "Lifecycle concepts are separate"
// (Parties and standing > Principal binding; Authority and dependencies >
// Target binding), "What changes when a person leaves", invariants L2, L3 and
// L4, and OPEN-QUESTIONS.md, "Office vacancy and succession". Every vector is
// labelled candidate_against_proposed. CASES.md case id: LC-C-007.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/lifecycle-root-authority-succession/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  issueAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

const CLOCK: Record<string, string> = {
  T_ISSUE: '2026-09-20T08:00:00.000Z',
  T_NOT_AFTER: '2026-09-30T00:00:00.000Z',
  T_HOLDER_A_FROM: '2026-09-20T08:00:00.000Z',
  T_HOLDER_A_THROUGH: '2026-09-22T00:00:00.000Z',
  T_ACTION_UNDER_A: '2026-09-21T10:00:00.000Z',
  T_TURNOVER: '2026-09-22T00:00:00.000Z',
  T_HOLDER_B_THROUGH: '2026-09-30T00:00:00.000Z',
  T_ACTION_UNDER_B: '2026-09-23T10:00:00.000Z',
  T_VACANCY_FROM: '2026-09-22T00:00:00.000Z',
  T_VACANCY_THROUGH: '2026-09-26T00:00:00.000Z',
  T_ACTION_IN_VACANCY: '2026-09-24T10:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:lras-principal'
const OFFICE_TREASURER = 'did:aps:example:lras-office-treasurer'
const OFFICE_AUDITOR = 'did:aps:example:lras-office-auditor'
const HOLDER_A = 'did:aps:example:lras-holder-a'
const HOLDER_B = 'did:aps:example:lras-holder-b'
const OFFICE_REGISTRAR = 'did:aps:example:lras-office-registrar'
const IMPOSTOR = 'did:aps:example:lras-impostor'

const EVENT_STANDING: Record<string, string> = {
  office_holder_record: 'office-registrar',
  office_vacancy: 'office-registrar',
}

const ATTESTOR_ROLE_REGISTRY: Record<string, string> = {
  [OFFICE_REGISTRAR]: 'office-registrar',
  [IMPOSTOR]: 'unaffiliated-observer',
}

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:lras:${label}`).digest('hex')
}
function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}
function authorityVector() {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: ['treasury:sign'] },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: 0 },
    time: { not_before: CLOCK.T_ISSUE, not_after: CLOCK.T_NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}
function mintGrantTerms(
  label: string,
  delegationId: string,
  terms: Record<string, unknown>,
  privateKey: string,
) {
  const body = {
    record_type: 'fixture:grant-terms:v0' as const,
    version: '0.1' as const,
    delegation_id: delegationId,
    issuer: PRINCIPAL,
    issued_at: CLOCK.T_ISSUE,
    terms,
    verification_method: `${PRINCIPAL}#key-1`,
    nonce: seed(`${label}-terms-nonce:v1`).slice(0, 32),
  }
  const preimage = canonicalizeJCS(body)
  return { ...body, terms_id: sha256Hex(preimage), signature: sign(preimage, privateKey) }
}
function mintEvent(
  label: string,
  eventType: string,
  attestor: string,
  attestorRole: string,
  subjectRef: string,
  occurredAt: string,
  payload: Record<string, unknown>,
  privateKey: string,
) {
  const body = {
    record_type: 'fixture:office-event:v0' as const,
    version: '0.1' as const,
    event_type: eventType,
    attestor,
    attestor_role: attestorRole,
    subject_ref: subjectRef,
    occurred_at: occurredAt,
    recorded_at: occurredAt,
    payload,
    verification_method: `${attestor}#key-1`,
    nonce: seed(`${label}-event-nonce:v1`).slice(0, 32),
  }
  const preimage = canonicalizeJCS(body)
  return { ...body, event_id: sha256Hex(preimage), signature: sign(preimage, privateKey) }
}

function main(): void {
  const priv: Record<string, string> = {}
  for (const [name, did] of Object.entries({
    principal: PRINCIPAL,
    'office-treasurer': OFFICE_TREASURER,
    'office-auditor': OFFICE_AUDITOR,
    'holder-a': HOLDER_A,
    'holder-b': HOLDER_B,
    'office-registrar': OFFICE_REGISTRAR,
    impostor: IMPOSTOR,
  })) {
    priv[did] = seed(`${name}:v1`)
  }
  const verificationKeys: Record<string, string> = {}
  for (const did of Object.keys(priv)) {
    verificationKeys[`${did}#key-1`] = publicKeyFromPrivate(priv[did])
  }

  const root = (label: string, subject: string) =>
    issueAuthorityDelegation(
      {
        record_type: 'aps:authority-delegation:v1',
        version: '1.0',
        parent_delegation_id: null,
        issuer: PRINCIPAL,
        subject,
        verification_method: `${PRINCIPAL}#key-1`,
        issued_at: CLOCK.T_ISSUE,
        nonce: seed(`${label}-nonce:v1`).slice(0, 32),
        authority: authorityVector(),
      } as never,
      priv[PRINCIPAL],
    ) as Record<string, unknown>

  const gRoleBound = root('g-role-bound', OFFICE_TREASURER)
  const gIdentityBound = root('g-identity-bound', HOLDER_A)
  const gSilent = root('g-silent', OFFICE_TREASURER)
  const gRoleBoundVacant = root('g-role-bound-vacant', OFFICE_AUDITOR)

  const terms = {
    G_ROLE_BOUND: mintGrantTerms('g-role-bound', gRoleBound.delegation_id as string, {
      subject_binding_mode: 'role_bound',
      office_ref: OFFICE_TREASURER,
    }, priv[PRINCIPAL]),
    G_IDENTITY_BOUND: mintGrantTerms('g-identity-bound', gIdentityBound.delegation_id as string, {
      subject_binding_mode: 'identity_bound',
      office_ref: OFFICE_TREASURER,
    }, priv[PRINCIPAL]),
    // The one grant that declares nothing. Its subject looks like an office and
    // its issuer never said whether that was the point.
    G_SILENT: mintGrantTerms('g-silent', gSilent.delegation_id as string, {
      office_ref: OFFICE_TREASURER,
    }, priv[PRINCIPAL]),
    G_ROLE_BOUND_VACANT: mintGrantTerms(
      'g-role-bound-vacant', gRoleBoundVacant.delegation_id as string,
      { subject_binding_mode: 'role_bound', office_ref: OFFICE_AUDITOR },
      priv[PRINCIPAL],
    ),
  }

  const events = {
    HOLDER_A_RECORD: mintEvent('holder-a', 'office_holder_record', OFFICE_REGISTRAR,
      'office-registrar', OFFICE_TREASURER, CLOCK.T_HOLDER_A_FROM,
      { office_ref: OFFICE_TREASURER, holder: HOLDER_A, from: CLOCK.T_HOLDER_A_FROM,
        through: CLOCK.T_HOLDER_A_THROUGH }, priv[OFFICE_REGISTRAR]),
    HOLDER_B_RECORD: mintEvent('holder-b', 'office_holder_record', OFFICE_REGISTRAR,
      'office-registrar', OFFICE_TREASURER, CLOCK.T_TURNOVER,
      { office_ref: OFFICE_TREASURER, holder: HOLDER_B, from: CLOCK.T_TURNOVER,
        through: CLOCK.T_HOLDER_B_THROUGH }, priv[OFFICE_REGISTRAR]),
    HOLDER_B_RECORD_NO_STANDING: mintEvent('holder-b-no-standing', 'office_holder_record', IMPOSTOR,
      'office-registrar', OFFICE_TREASURER, CLOCK.T_TURNOVER,
      { office_ref: OFFICE_TREASURER, holder: HOLDER_B, from: CLOCK.T_TURNOVER,
        through: CLOCK.T_HOLDER_B_THROUGH }, priv[IMPOSTOR]),
    AUDITOR_HOLDER_A_RECORD: mintEvent('auditor-holder-a', 'office_holder_record', OFFICE_REGISTRAR,
      'office-registrar', OFFICE_AUDITOR, CLOCK.T_HOLDER_A_FROM,
      { office_ref: OFFICE_AUDITOR, holder: HOLDER_A, from: CLOCK.T_HOLDER_A_FROM,
        through: CLOCK.T_VACANCY_FROM }, priv[OFFICE_REGISTRAR]),
    AUDITOR_VACANCY: mintEvent('auditor-vacancy', 'office_vacancy', OFFICE_REGISTRAR,
      'office-registrar', OFFICE_AUDITOR, CLOCK.T_VACANCY_FROM,
      { office_ref: OFFICE_AUDITOR, from: CLOCK.T_VACANCY_FROM, through: CLOCK.T_VACANCY_THROUGH },
      priv[OFFICE_REGISTRAR]),
  }

  const fixture = {
    _placeholder: false,
    profile: 'aac-lifecycle-root-authority-succession-v0',
    clock: CLOCK,
    verification_keys: verificationKeys,
    attestor_role_registry: ATTESTOR_ROLE_REGISTRY,
    event_standing: EVENT_STANDING,
    terms_by_chain: {
      G_ROLE_BOUND: 'G_ROLE_BOUND',
      G_IDENTITY_BOUND: 'G_IDENTITY_BOUND',
      G_SILENT: 'G_SILENT',
      G_ROLE_BOUND_VACANT: 'G_ROLE_BOUND_VACANT',
    },
    grant_terms: terms,
    events,
    chains: {
      G_ROLE_BOUND: [gRoleBound],
      G_IDENTITY_BOUND: [gIdentityBound],
      G_SILENT: [gSilent],
      G_ROLE_BOUND_VACANT: [gRoleBoundVacant],
    },
  }
  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
}

main()
