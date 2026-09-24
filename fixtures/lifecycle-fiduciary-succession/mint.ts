// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-fiduciary-succession family, byte for byte.
//
// WHAT THIS FAMILY TESTS. Three questions about authority held by fiduciaries
// and about validating an act after the fact: a quorum rule over co-holders of
// one instrument when they disagree or when one of them drops out; a mandate
// that is narrower than ordinary successor authority and that ends on an
// external event rather than on a clock or a revocation; and ratification, as a
// mechanism distinct from both reauthorization and revocation, bounded by a
// third party's intervening interest, by atomicity and by the principal's
// capacity at the moment of ratifying.
//
// The proposed text is aeoess/agent-authority-lifecycle, AUTHORITY-LIFECYCLE.md
// at commit 7796e22 or later, sections "Lifecycle concepts are separate"
// (Parties and standing > Lifecycle standing; Authority lifecycle state >
// Expiry or exhaustion, External restriction; Decisions and effects > Approval;
// Verification and evidence > Evidence), and invariants L3, L8 and L10. Every
// vector is labelled candidate_against_proposed. See README.md for the verbatim
// source quotes and the exact case ids in CASES.md.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/lifecycle-fiduciary-succession/mint.ts
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
  T_INTEREST_PRIOR: '2026-09-20T09:00:00.000Z',
  T_APPROVE_EARLY: '2026-09-20T10:00:00.000Z',
  T_ACT: '2026-09-20T11:00:00.000Z',
  T_CAPACITY_EARLIER: '2026-09-20T11:30:00.000Z',
  T_INTEREST_INTERVENING: '2026-09-21T09:00:00.000Z',
  T_VACATE: '2026-09-21T10:00:00.000Z',
  T_APPROVE: '2026-09-21T11:00:00.000Z',
  T_ACTION_1: '2026-09-21T12:00:00.000Z',
  T_RESOLUTION: '2026-09-22T09:00:00.000Z',
  T_ACTION_BEFORE_RESOLUTION: '2026-09-21T13:00:00.000Z',
  T_ACTION_AFTER_RESOLUTION: '2026-09-22T12:00:00.000Z',
  T_RATIFY: '2026-09-23T09:00:00.000Z',
  T_EVALUATE_AFTER_RATIFY: '2026-09-23T12:00:00.000Z',
  T_EVALUATE_BEFORE_RATIFY: '2026-09-22T18:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:lfs-principal'
const HOLDER_1 = 'did:aps:example:lfs-holder-1'
const HOLDER_2 = 'did:aps:example:lfs-holder-2'
const HOLDER_3 = 'did:aps:example:lfs-holder-3'
const HOLDER_4 = 'did:aps:example:lfs-holder-4'
const TEMP_ADMIN = 'did:aps:example:lfs-temp-admin'
const AGENT_2 = 'did:aps:example:lfs-agent-2'
const REGISTRAR = 'did:aps:example:lfs-registrar'
const COURT = 'did:aps:example:lfs-court'
const CAPACITY_EXAMINER = 'did:aps:example:lfs-capacity-examiner'
const INTEREST_REGISTRY = 'did:aps:example:lfs-interest-registry'
const IMPOSTOR = 'did:aps:example:lfs-impostor'

const ACT_ID = 'lfs-act-sell-press-line-3'
const ACTION_REF = 'lfs-act-ledger-close'
const TARGET = 'lfs:asset:press-line-3'

// grant-principal and named-co-holder are not registry roles. The gate reads
// the first off the chain's own root issuer and the second off the instrument's
// declared co-holder list, because neither is a fact about the wider registry.
const EVENT_STANDING: Record<string, string> = {
  holder_vacancy: 'org-registrar',
  co_holder_approval: 'named-co-holder',
  co_holder_dissent: 'named-co-holder',
  dispute_resolution: 'court-of-record',
  principal_ratification: 'grant-principal',
  principal_capacity_finding: 'capacity-examiner',
  intervening_interest: 'property-registry',
}

const ATTESTOR_ROLE_REGISTRY: Record<string, string> = {
  [REGISTRAR]: 'org-registrar',
  [COURT]: 'court-of-record',
  [CAPACITY_EXAMINER]: 'capacity-examiner',
  [INTEREST_REGISTRY]: 'property-registry',
  [IMPOSTOR]: 'unaffiliated-observer',
}

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:lfs:${label}`).digest('hex')
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function authorityVector(grants: string[]) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants },
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
  issuer: string,
  terms: Record<string, unknown>,
  privateKey: string,
) {
  const body = {
    record_type: 'fixture:grant-terms:v0' as const,
    version: '0.1' as const,
    delegation_id: delegationId,
    issuer,
    issued_at: CLOCK.T_ISSUE,
    terms,
    verification_method: `${issuer}#key-1`,
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
  recordedAt: string,
  payload: Record<string, unknown>,
  privateKey: string,
) {
  const body = {
    record_type: 'fixture:succession-event:v0' as const,
    version: '0.1' as const,
    event_type: eventType,
    attestor,
    attestor_role: attestorRole,
    subject_ref: subjectRef,
    // When the thing happened.
    occurred_at: occurredAt,
    // When the record itself was written. A verifier holding this record at an
    // earlier instant than recorded_at does not hold it at all.
    recorded_at: recordedAt,
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
    'holder-1': HOLDER_1,
    'holder-2': HOLDER_2,
    'holder-3': HOLDER_3,
    'holder-4': HOLDER_4,
    'temp-admin': TEMP_ADMIN,
    'agent-2': AGENT_2,
    registrar: REGISTRAR,
    court: COURT,
    'capacity-examiner': CAPACITY_EXAMINER,
    'interest-registry': INTEREST_REGISTRY,
    impostor: IMPOSTOR,
  })) {
    priv[did] = seed(`${name}:v1`)
  }
  const verificationKeys: Record<string, string> = {}
  for (const did of Object.keys(priv)) {
    verificationKeys[`${did}#key-1`] = publicKeyFromPrivate(priv[did])
  }

  const root = (label: string, subject: string, grants: string[]) =>
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
        authority: authorityVector(grants),
      } as never,
      priv[PRINCIPAL],
    ) as Record<string, unknown>

  const gCoholderH1 = root('g-coholder-h1', HOLDER_1, ['ledger:close'])
  const gCoholderH2 = root('g-coholder-h2', HOLDER_2, ['ledger:close'])
  const gCoholder4H1 = root('g-coholder4-h1', HOLDER_1, ['ledger:close'])
  const gTempAdmin = root('g-temp-admin', TEMP_ADMIN, ['estate:manage'])
  const gRatify = root('g-ratify', AGENT_2, ['estate:manage'])

  const threeHolderTerms = {
    co_holders: [HOLDER_1, HOLDER_2, HOLDER_3],
    decision_rule: 'majority_of_current_holders',
    action_ref: ACTION_REF,
    permitted_action_classes: ['ledger_close'],
  }
  const fourHolderTerms = {
    co_holders: [HOLDER_1, HOLDER_2, HOLDER_3, HOLDER_4],
    decision_rule: 'majority_of_current_holders',
    action_ref: ACTION_REF,
    permitted_action_classes: ['ledger_close'],
  }

  const terms = {
    G_COHOLDER_H1: mintGrantTerms('g-coholder-h1', gCoholderH1.delegation_id as string, PRINCIPAL,
      threeHolderTerms, priv[PRINCIPAL]),
    G_COHOLDER_H2: mintGrantTerms('g-coholder-h2', gCoholderH2.delegation_id as string, PRINCIPAL,
      threeHolderTerms, priv[PRINCIPAL]),
    G_COHOLDER4_H1: mintGrantTerms('g-coholder4-h1', gCoholder4H1.delegation_id as string, PRINCIPAL,
      fourHolderTerms, priv[PRINCIPAL]),
    G_TEMP_ADMIN: mintGrantTerms('g-temp-admin', gTempAdmin.delegation_id as string, PRINCIPAL, {
      // Narrower than ordinary successor authority by construction, and ending
      // on an external event rather than on a clock or a revocation record.
      mandate: {
        mandate_class: 'temporary_preservation',
        permitted_action_classes: ['preserve'],
        ends_on_event: 'dispute_resolution',
        dispute_ref: 'lfs-dispute-2026-09',
      },
    }, priv[PRINCIPAL]),
    G_RATIFY: mintGrantTerms('g-ratify', gRatify.delegation_id as string, PRINCIPAL, {
      permitted_action_classes: ['reconcile'],
      // The components of the one integrated act this family ratifies, named in
      // the grant's own terms so atomicity is checkable rather than asserted.
      integrated_acts: { [ACT_ID]: { components: ['transfer_title', 'receive_payment'], target: TARGET } },
    }, priv[PRINCIPAL]),
  }

  const events = {
    APPROVE_H1_EARLY: mintEvent('approve-h1-early', 'co_holder_approval', HOLDER_1, 'named-co-holder',
      ACTION_REF, CLOCK.T_APPROVE_EARLY, CLOCK.T_APPROVE_EARLY, { action_ref: ACTION_REF }, priv[HOLDER_1]),
    APPROVE_H1: mintEvent('approve-h1', 'co_holder_approval', HOLDER_1, 'named-co-holder', ACTION_REF,
      CLOCK.T_APPROVE, CLOCK.T_APPROVE, { action_ref: ACTION_REF }, priv[HOLDER_1]),
    APPROVE_H2: mintEvent('approve-h2', 'co_holder_approval', HOLDER_2, 'named-co-holder', ACTION_REF,
      CLOCK.T_APPROVE, CLOCK.T_APPROVE, { action_ref: ACTION_REF }, priv[HOLDER_2]),
    APPROVE_H3: mintEvent('approve-h3', 'co_holder_approval', HOLDER_3, 'named-co-holder', ACTION_REF,
      CLOCK.T_APPROVE, CLOCK.T_APPROVE, { action_ref: ACTION_REF }, priv[HOLDER_3]),
    DISSENT_H3: mintEvent('dissent-h3', 'co_holder_dissent', HOLDER_3, 'named-co-holder', ACTION_REF,
      CLOCK.T_APPROVE, CLOCK.T_APPROVE, { action_ref: ACTION_REF }, priv[HOLDER_3]),
    DISSENT_H4: mintEvent('dissent-h4', 'co_holder_dissent', HOLDER_4, 'named-co-holder', ACTION_REF,
      CLOCK.T_APPROVE, CLOCK.T_APPROVE, { action_ref: ACTION_REF }, priv[HOLDER_4]),
    APPROVE_IMPOSTOR: mintEvent('approve-impostor', 'co_holder_approval', IMPOSTOR, 'named-co-holder',
      ACTION_REF, CLOCK.T_APPROVE, CLOCK.T_APPROVE, { action_ref: ACTION_REF }, priv[IMPOSTOR]),
    VACANCY_H1: mintEvent('vacancy-h1', 'holder_vacancy', REGISTRAR, 'org-registrar', HOLDER_1,
      CLOCK.T_VACATE, CLOCK.T_VACATE, { basis: 'resigned' }, priv[REGISTRAR]),
    VACANCY_H3: mintEvent('vacancy-h3', 'holder_vacancy', REGISTRAR, 'org-registrar', HOLDER_3,
      CLOCK.T_VACATE, CLOCK.T_VACATE, { basis: 'resigned' }, priv[REGISTRAR]),
    DISPUTE_RESOLUTION: mintEvent('dispute-resolution', 'dispute_resolution', COURT, 'court-of-record',
      TEMP_ADMIN, CLOCK.T_RESOLUTION, CLOCK.T_RESOLUTION,
      { dispute_ref: 'lfs-dispute-2026-09', outcome: 'permanent_successor_appointed' }, priv[COURT]),
    DISPUTE_RESOLUTION_NO_STANDING: mintEvent('dispute-resolution-no-standing', 'dispute_resolution',
      IMPOSTOR, 'court-of-record', TEMP_ADMIN, CLOCK.T_RESOLUTION, CLOCK.T_RESOLUTION,
      { dispute_ref: 'lfs-dispute-2026-09', outcome: 'permanent_successor_appointed' }, priv[IMPOSTOR]),
    RATIFICATION_FULL: mintEvent('ratification-full', 'principal_ratification', PRINCIPAL,
      'grant-principal', ACT_ID, CLOCK.T_RATIFY, CLOCK.T_RATIFY,
      { act_id: ACT_ID, covers_components: ['receive_payment', 'transfer_title'] }, priv[PRINCIPAL]),
    RATIFICATION_PARTIAL: mintEvent('ratification-partial', 'principal_ratification', PRINCIPAL,
      'grant-principal', ACT_ID, CLOCK.T_RATIFY, CLOCK.T_RATIFY,
      { act_id: ACT_ID, covers_components: ['receive_payment'] }, priv[PRINCIPAL]),
    RATIFICATION_FROM_IMPOSTOR: mintEvent('ratification-impostor', 'principal_ratification', IMPOSTOR,
      'grant-principal', ACT_ID, CLOCK.T_RATIFY, CLOCK.T_RATIFY,
      { act_id: ACT_ID, covers_components: ['receive_payment', 'transfer_title'] }, priv[IMPOSTOR]),
    CAPACITY_LACKS_AT_RATIFICATION: mintEvent('capacity-lacks-at-ratification',
      'principal_capacity_finding', CAPACITY_EXAMINER, 'capacity-examiner', PRINCIPAL,
      CLOCK.T_RATIFY, CLOCK.T_RATIFY,
      { finding: 'lacks_capacity', covers_from: CLOCK.T_RATIFY, covers_through: CLOCK.T_EVALUATE_AFTER_RATIFY },
      priv[CAPACITY_EXAMINER]),
    CAPACITY_LACKS_EARLIER: mintEvent('capacity-lacks-earlier', 'principal_capacity_finding',
      CAPACITY_EXAMINER, 'capacity-examiner', PRINCIPAL, CLOCK.T_CAPACITY_EARLIER,
      CLOCK.T_CAPACITY_EARLIER,
      { finding: 'lacks_capacity', covers_from: CLOCK.T_CAPACITY_EARLIER, covers_through: CLOCK.T_VACATE },
      priv[CAPACITY_EXAMINER]),
    INTERVENING_INTEREST: mintEvent('intervening-interest', 'intervening_interest', INTEREST_REGISTRY,
      'property-registry', TARGET, CLOCK.T_INTEREST_INTERVENING, CLOCK.T_INTEREST_INTERVENING,
      { target: TARGET, acquired_at: CLOCK.T_INTEREST_INTERVENING, holder: 'lfs:third-party:blue-co' },
      priv[INTEREST_REGISTRY]),
    PRIOR_INTEREST: mintEvent('prior-interest', 'intervening_interest', INTEREST_REGISTRY,
      'property-registry', TARGET, CLOCK.T_INTEREST_PRIOR, CLOCK.T_INTEREST_PRIOR,
      { target: TARGET, acquired_at: CLOCK.T_INTEREST_PRIOR, holder: 'lfs:third-party:green-co' },
      priv[INTEREST_REGISTRY]),
  }

  const fixture = {
    _placeholder: false,
    profile: 'aac-lifecycle-fiduciary-succession-v0',
    clock: CLOCK,
    act_id: ACT_ID,
    action_ref: ACTION_REF,
    target: TARGET,
    verification_keys: verificationKeys,
    attestor_role_registry: ATTESTOR_ROLE_REGISTRY,
    event_standing: EVENT_STANDING,
    terms_by_chain: {
      G_COHOLDER_H1: 'G_COHOLDER_H1',
      G_COHOLDER_H2: 'G_COHOLDER_H2',
      G_COHOLDER4_H1: 'G_COHOLDER4_H1',
      G_TEMP_ADMIN: 'G_TEMP_ADMIN',
      G_RATIFY: 'G_RATIFY',
    },
    grant_terms: terms,
    events,
    chains: {
      G_COHOLDER_H1: [gCoholderH1],
      G_COHOLDER_H2: [gCoholderH2],
      G_COHOLDER4_H1: [gCoholder4H1],
      G_TEMP_ADMIN: [gTempAdmin],
      G_RATIFY: [gRatify],
    },
  }

  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
}

main()
