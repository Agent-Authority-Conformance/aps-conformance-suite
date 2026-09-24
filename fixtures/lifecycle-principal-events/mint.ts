// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-principal-events family, byte for byte.
//
// WHAT THIS FAMILY TESTS. What happens to an agent's authority when something
// happens to the principal: death, incapacity, the end of a relationship the
// designation depended on, a finding that retroactively strips a fiduciary, the
// appointment of an authority from outside the delegation chain, a claim that a
// grant survives the principal's death, and a successor named inside the
// original instrument.
//
// The proposed text is aeoess/agent-authority-lifecycle, AUTHORITY-LIFECYCLE.md
// at commit 7796e22 or later, sections "Lifecycle concepts are separate"
// (Parties and standing; Authority lifecycle state; Verification and evidence),
// "What changes when a person leaves", and invariants L1, L3, L8 and L10; plus
// OPEN-QUESTIONS.md, "Office vacancy and succession". Every vector in this
// family is labelled candidate_against_proposed. See README.md for the verbatim
// source quotes and for the exact case ids in CASES.md.
//
// Every key is an Ed25519 seed derived from a published label, so the file
// carries no secret material and anyone can regenerate it. Timestamps, nonces
// and payloads are pinned constants: no clock is read and no randomness drawn.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/lifecycle-principal-events/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// One clock for the whole family. Every action instant in vectors.json and
// every record timestamp below is one of these names.
const CLOCK: Record<string, string> = {
  T_ISSUE: '2026-09-20T08:00:00.000Z',
  T_NOT_AFTER: '2026-09-30T00:00:00.000Z',
  T_INTEREST: '2026-09-20T09:00:00.000Z',
  T_A1: '2026-09-20T10:00:00.000Z',
  T_DEATH: '2026-09-21T09:00:00.000Z',
  T_INCAPACITY: '2026-09-21T09:30:00.000Z',
  T_A2: '2026-09-21T12:00:00.000Z',
  T_NOTICE: '2026-09-21T15:00:00.000Z',
  T_A3: '2026-09-21T18:00:00.000Z',
  T_GUARDIAN: '2026-09-22T08:00:00.000Z',
  T_FILING: '2026-09-22T09:00:00.000Z',
  T_PRIMARY_EXIT: '2026-09-22T09:00:00.000Z',
  T_A8: '2026-09-22T10:00:00.000Z',
  T_A12: '2026-09-22T10:30:00.000Z',
  T_A4: '2026-09-22T12:00:00.000Z',
  T_A6: '2026-09-22T15:00:00.000Z',
  T_SUSPEND_ORDER: '2026-09-22T18:00:00.000Z',
  T_A9: '2026-09-23T06:00:00.000Z',
  T_DECREE: '2026-09-23T09:00:00.000Z',
  T_A5: '2026-09-23T12:00:00.000Z',
  T_TERMINATE_ORDER: '2026-09-23T18:00:00.000Z',
  T_A10: '2026-09-24T06:00:00.000Z',
  T_KILLING_FINDING: '2026-09-24T09:00:00.000Z',
  T_A7: '2026-09-24T15:00:00.000Z',
  T_A11: '2026-09-21T10:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:lpe-principal'
const AGENT = 'did:aps:example:lpe-agent'
const SPOUSE_AGENT = 'did:aps:example:lpe-spouse-agent'
const FIDUCIARY = 'did:aps:example:lpe-fiduciary'
const FIDUCIARY_SUB = 'did:aps:example:lpe-fiduciary-sub-agent'
const LENDER = 'did:aps:example:lpe-lender'
const PRIMARY = 'did:aps:example:lpe-primary-agent'
const PRIMARY_SUB = 'did:aps:example:lpe-primary-sub-agent'
const SUCCESSOR_1 = 'did:aps:example:lpe-successor-1'
const SUCCESSOR_2 = 'did:aps:example:lpe-successor-2'

const VITAL_RECORDS = 'did:aps:example:lpe-vital-records'
const CAPACITY_EXAMINER = 'did:aps:example:lpe-capacity-examiner'
const COURT = 'did:aps:example:lpe-court'
const COLLATERAL_REGISTRY = 'did:aps:example:lpe-collateral-registry'
const ORG_REGISTRAR = 'did:aps:example:lpe-org-registrar'
const IMPOSTOR = 'did:aps:example:lpe-impostor'

// Which role the model accepts for each event type. A record of the right
// event type from an attestor the registry places in some other role is not
// evidence in either direction: it cannot establish the event and it cannot
// establish that the event did not happen.
const EVENT_STANDING: Record<string, string> = {
  principal_death: 'vital-records-registrar',
  principal_incapacity: 'capacity-examiner',
  notice_of_principal_death: 'grant-subject',
  marriage_dissolution_filing: 'court-of-record',
  marriage_dissolution_decree: 'court-of-record',
  felonious_killing_finding: 'court-of-record',
  guardian_appointment: 'court-of-record',
  court_order_suspend_delegation: 'court-of-record',
  court_order_terminate_delegation: 'court-of-record',
  collateral_interest_in_subject_matter: 'collateral-registry',
  collateral_interest_in_proceeds_only: 'collateral-registry',
  agent_exit: 'org-registrar',
}

// Who the model places in which role. grant-subject is not listed here: the
// gate checks a notice record's attestor against the grant's own subject,
// because "the subject of this grant" is not a registry fact.
const ATTESTOR_ROLE_REGISTRY: Record<string, string> = {
  [VITAL_RECORDS]: 'vital-records-registrar',
  [CAPACITY_EXAMINER]: 'capacity-examiner',
  [COURT]: 'court-of-record',
  [COLLATERAL_REGISTRY]: 'collateral-registry',
  [ORG_REGISTRAR]: 'org-registrar',
  // The impostor is registered, and honestly, in a role that has standing for
  // nothing in EVENT_STANDING. It is not an unknown party: the registry
  // disagrees with what its records claim, which is the point.
  [IMPOSTOR]: 'unaffiliated-observer',
}

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:lpe:${label}`).digest('hex')
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function authorityVector(grants: string[], depth: number) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: depth },
    time: { not_before: CLOCK.T_ISSUE, not_after: CLOCK.T_NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

/** A fixture-local record. AuthorityDelegationV1's AuthorityVectorV1 is a
 *  closed set of seven facets with no slot for durability, a relationship
 *  binding, a coupled-interest claim or a successor order, so those terms live
 *  in their own record, signed by the delegation's own issuer and bound to its
 *  delegation_id. This is NOT an APS record type and no SDK claims it. */
function mintGrantTerms(
  label: string,
  delegationId: string,
  issuer: string,
  verificationMethod: string,
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
    verification_method: verificationMethod,
    nonce: seed(`${label}-terms-nonce:v1`).slice(0, 32),
  }
  const preimage = canonicalizeJCS(body)
  return { ...body, terms_id: sha256Hex(preimage), signature: sign(preimage, privateKey) }
}

/** A fixture-local principal-event record. Also NOT an APS record type. */
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
  verificationMethodOverride?: string,
) {
  const body = {
    record_type: 'fixture:principal-event:v0' as const,
    version: '0.1' as const,
    event_type: eventType,
    attestor,
    // The attestor's own claim about its role. The registry, not this member,
    // is what the reference gate reads.
    attestor_role: attestorRole,
    subject_ref: subjectRef,
    occurred_at: occurredAt,
    recorded_at: recordedAt,
    payload,
    verification_method: verificationMethodOverride ?? `${attestor}#key-1`,
    nonce: seed(`${label}-event-nonce:v1`).slice(0, 32),
  }
  const preimage = canonicalizeJCS(body)
  return { ...body, event_id: sha256Hex(preimage), signature: sign(preimage, privateKey) }
}

function main(): void {
  const priv: Record<string, string> = {}
  for (const [name, did] of Object.entries({
    principal: PRINCIPAL,
    agent: AGENT,
    spouse_agent: SPOUSE_AGENT,
    fiduciary: FIDUCIARY,
    fiduciary_sub: FIDUCIARY_SUB,
    lender: LENDER,
    primary: PRIMARY,
    primary_sub: PRIMARY_SUB,
    successor_1: SUCCESSOR_1,
    successor_2: SUCCESSOR_2,
    vital_records: VITAL_RECORDS,
    capacity_examiner: CAPACITY_EXAMINER,
    court: COURT,
    collateral_registry: COLLATERAL_REGISTRY,
    org_registrar: ORG_REGISTRAR,
    impostor: IMPOSTOR,
  })) {
    priv[did] = seed(`${name}:v1`)
  }

  const verificationKeys: Record<string, string> = {}
  for (const did of Object.keys(priv)) {
    verificationKeys[`${did}#key-1`] = publicKeyFromPrivate(priv[did])
  }

  const resolveKey = ((_issuer: string, method: string) => verificationKeys[method] ?? null) as never
  const alwaysActive = (() => 'active') as never

  const root = (label: string, issuer: string, subject: string, grants: string[], depth: number) =>
    issueAuthorityDelegation(
      {
        record_type: 'aps:authority-delegation:v1',
        version: '1.0',
        parent_delegation_id: null,
        issuer,
        subject,
        verification_method: `${issuer}#key-1`,
        issued_at: CLOCK.T_ISSUE,
        nonce: seed(`${label}-nonce:v1`).slice(0, 32),
        authority: authorityVector(grants, depth),
      } as never,
      priv[issuer],
    ) as Record<string, unknown>

  const sub = (
    label: string,
    parent: Record<string, unknown>,
    issuer: string,
    subject: string,
    grants: string[],
  ) =>
    issueSubAuthorityDelegation(
      parent as never,
      {
        record_type: 'aps:authority-delegation:v1',
        version: '1.0',
        parent_delegation_id: parent.delegation_id as string,
        issuer,
        subject,
        verification_method: `${issuer}#key-1`,
        issued_at: CLOCK.T_ISSUE,
        nonce: seed(`${label}-nonce:v1`).slice(0, 32),
        authority: authorityVector(grants, 0),
      } as never,
      priv[issuer],
      {
        now: CLOCK.T_ISSUE,
        resolveVerificationKey: resolveKey,
        trustRoot: () => true,
        resolveRevocation: alwaysActive,
      } as never,
    ) as Record<string, unknown>

  // --- grants -------------------------------------------------------------
  const gPlain = root('g-plain', PRINCIPAL, AGENT, ['ledger:write'], 0)
  const gDurable = root('g-durable', PRINCIPAL, AGENT, ['ledger:write'], 0)
  const gSpousalDecree = root('g-spousal-decree', PRINCIPAL, SPOUSE_AGENT, ['ledger:write'], 0)
  const gSpousalFiling = root('g-spousal-filing', PRINCIPAL, SPOUSE_AGENT, ['ledger:write'], 0)
  const gSpousalSilent = root('g-spousal-silent', PRINCIPAL, SPOUSE_AGENT, ['ledger:write'], 0)
  const gFiduciary = root('g-fiduciary', PRINCIPAL, FIDUCIARY, ['ledger:write'], 1)
  const gFiduciarySub = sub('g-fiduciary-sub', gFiduciary, FIDUCIARY, FIDUCIARY_SUB, ['ledger:write'])
  const gCoupled = root('g-coupled', PRINCIPAL, LENDER, ['collateral:dispose'], 0)
  const gSuccession = root('g-succession', PRINCIPAL, PRIMARY, ['ledger:write'], 1)
  const gPrimaryPersonal = sub('g-primary-personal', gSuccession, PRIMARY, PRIMARY_SUB, ['ledger:write'])

  // --- grant terms --------------------------------------------------------
  const terms = {
    G_PLAIN: mintGrantTerms('g-plain', gPlain.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`, {
      durability: 'not_durable',
    }, priv[PRINCIPAL]),
    G_DURABLE: mintGrantTerms('g-durable', gDurable.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`, {
      // The declared scope of durability, stated in the terms rather than
      // assumed by the gate: surviving incapacity, never surviving death.
      durability: 'durable',
      durability_scope: 'survives_incapacity_only',
    }, priv[PRINCIPAL]),
    G_SPOUSAL_DECREE: mintGrantTerms(
      'g-spousal-decree', gSpousalDecree.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`,
      {
        durability: 'not_durable',
        relationship_binding: {
          relationship: 'marriage',
          counterparty: SPOUSE_AGENT,
          termination_trigger: 'marriage_dissolution_decree',
        },
      },
      priv[PRINCIPAL],
    ),
    G_SPOUSAL_FILING: mintGrantTerms(
      'g-spousal-filing', gSpousalFiling.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`,
      {
        durability: 'not_durable',
        relationship_binding: {
          relationship: 'marriage',
          counterparty: SPOUSE_AGENT,
          termination_trigger: 'marriage_dissolution_filing',
        },
      },
      priv[PRINCIPAL],
    ),
    G_SPOUSAL_SILENT: mintGrantTerms(
      'g-spousal-silent', gSpousalSilent.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`,
      {
        durability: 'not_durable',
        // The binding names the relationship it depends on and says nothing
        // about which event ends it.
        relationship_binding: { relationship: 'marriage', counterparty: SPOUSE_AGENT },
      },
      priv[PRINCIPAL],
    ),
    G_FIDUCIARY: mintGrantTerms('g-fiduciary', gFiduciary.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`, {
      durability: 'not_durable',
      appointment: { capacity: 'fiduciary', appointed_at: CLOCK.T_ISSUE },
    }, priv[PRINCIPAL]),
    G_COUPLED: mintGrantTerms('g-coupled', gCoupled.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`, {
      durability: 'not_durable',
      // The issuer's own claim that this grant survives the principal's death.
      // Nothing outside this record supports it until an interest record does.
      survives_principal_death: true,
      survival_basis: 'interest_coupled',
      subject_matter_ref: 'lpe:collateral:press-line-3',
    }, priv[PRINCIPAL]),
    G_SUCCESSION: mintGrantTerms(
      'g-succession', gSuccession.delegation_id as string, PRINCIPAL, `${PRINCIPAL}#key-1`,
      {
        durability: 'not_durable',
        successor_order: [PRIMARY, SUCCESSOR_1, SUCCESSOR_2],
      },
      priv[PRINCIPAL],
    ),
    G_PRIMARY_PERSONAL: mintGrantTerms(
      'g-primary-personal', gPrimaryPersonal.delegation_id as string, PRIMARY, `${PRIMARY}#key-1`,
      { durability: 'not_durable' },
      priv[PRIMARY],
    ),
  }

  // --- principal events ---------------------------------------------------
  const events = {
    DEATH: mintEvent('death', 'principal_death', VITAL_RECORDS, 'vital-records-registrar', PRINCIPAL,
      CLOCK.T_DEATH, CLOCK.T_DEATH, { register_entry: 'lpe-vr-0001' }, priv[VITAL_RECORDS]),
    DEATH_NO_STANDING: mintEvent('death-no-standing', 'principal_death', IMPOSTOR, 'unaffiliated-observer',
      PRINCIPAL, CLOCK.T_DEATH, CLOCK.T_DEATH, { register_entry: 'lpe-vr-0001' }, priv[IMPOSTOR]),
    DEATH_ROLE_CLAIM_CONFLICT: mintEvent('death-role-claim', 'principal_death', IMPOSTOR,
      'vital-records-registrar', PRINCIPAL, CLOCK.T_DEATH, CLOCK.T_DEATH,
      { register_entry: 'lpe-vr-0001' }, priv[IMPOSTOR]),
    INCAPACITY: mintEvent('incapacity', 'principal_incapacity', CAPACITY_EXAMINER, 'capacity-examiner',
      PRINCIPAL, CLOCK.T_INCAPACITY, CLOCK.T_INCAPACITY, { finding: 'lacks_capacity' }, priv[CAPACITY_EXAMINER]),
    NOTICE_AGENT: mintEvent('notice-agent', 'notice_of_principal_death', AGENT, 'grant-subject', PRINCIPAL,
      CLOCK.T_NOTICE, CLOCK.T_NOTICE, { received_from: VITAL_RECORDS }, priv[AGENT]),
    NOTICE_WRONG_SUBJECT: mintEvent('notice-wrong-subject', 'notice_of_principal_death', SPOUSE_AGENT,
      'grant-subject', PRINCIPAL, CLOCK.T_NOTICE, CLOCK.T_NOTICE, { received_from: VITAL_RECORDS },
      priv[SPOUSE_AGENT]),
    FILING: mintEvent('filing', 'marriage_dissolution_filing', COURT, 'court-of-record', PRINCIPAL,
      CLOCK.T_FILING, CLOCK.T_FILING, { docket: 'lpe-dr-2026-114', counterparty: SPOUSE_AGENT }, priv[COURT]),
    DECREE: mintEvent('decree', 'marriage_dissolution_decree', COURT, 'court-of-record', PRINCIPAL,
      CLOCK.T_DECREE, CLOCK.T_DECREE, { docket: 'lpe-dr-2026-114', counterparty: SPOUSE_AGENT }, priv[COURT]),
    KILLING_FINDING: mintEvent('killing-finding', 'felonious_killing_finding', COURT, 'court-of-record',
      FIDUCIARY, CLOCK.T_KILLING_FINDING, CLOCK.T_KILLING_FINDING,
      { decedent: PRINCIPAL, disposition: 'adjudicated' }, priv[COURT]),
    KILLING_FINDING_NO_STANDING: mintEvent('killing-finding-no-standing', 'felonious_killing_finding',
      IMPOSTOR, 'unaffiliated-observer', FIDUCIARY, CLOCK.T_KILLING_FINDING, CLOCK.T_KILLING_FINDING,
      { decedent: PRINCIPAL, disposition: 'alleged' }, priv[IMPOSTOR]),
    GUARDIAN: mintEvent('guardian', 'guardian_appointment', COURT, 'court-of-record', PRINCIPAL,
      CLOCK.T_GUARDIAN, CLOCK.T_GUARDIAN, { guardian_of: 'estate' }, priv[COURT]),
    SUSPEND_ORDER: mintEvent('suspend-order', 'court_order_suspend_delegation', COURT, 'court-of-record',
      gPlain.delegation_id as string, CLOCK.T_SUSPEND_ORDER, CLOCK.T_SUSPEND_ORDER,
      { order: 'lpe-ord-2026-31' }, priv[COURT]),
    TERMINATE_ORDER: mintEvent('terminate-order', 'court_order_terminate_delegation', COURT, 'court-of-record',
      gPlain.delegation_id as string, CLOCK.T_TERMINATE_ORDER, CLOCK.T_TERMINATE_ORDER,
      { order: 'lpe-ord-2026-44' }, priv[COURT]),
    SUSPEND_ORDER_NO_STANDING: mintEvent('suspend-order-no-standing', 'court_order_suspend_delegation',
      IMPOSTOR, 'court-of-record', gPlain.delegation_id as string, CLOCK.T_SUSPEND_ORDER,
      CLOCK.T_SUSPEND_ORDER, { order: 'lpe-ord-2026-31' }, priv[IMPOSTOR]),
    INTEREST_IN_SUBJECT_MATTER: mintEvent('interest-subject', 'collateral_interest_in_subject_matter',
      COLLATERAL_REGISTRY, 'collateral-registry', LENDER, CLOCK.T_INTEREST, CLOCK.T_INTEREST,
      { holder: LENDER, subject_matter_ref: 'lpe:collateral:press-line-3' }, priv[COLLATERAL_REGISTRY]),
    INTEREST_IN_PROCEEDS: mintEvent('interest-proceeds', 'collateral_interest_in_proceeds_only',
      COLLATERAL_REGISTRY, 'collateral-registry', LENDER, CLOCK.T_INTEREST, CLOCK.T_INTEREST,
      { holder: LENDER, subject_matter_ref: 'lpe:collateral:press-line-3' }, priv[COLLATERAL_REGISTRY]),
    INTEREST_WRONG_SUBJECT_MATTER: mintEvent('interest-wrong-subject', 'collateral_interest_in_subject_matter',
      COLLATERAL_REGISTRY, 'collateral-registry', LENDER, CLOCK.T_INTEREST, CLOCK.T_INTEREST,
      { holder: LENDER, subject_matter_ref: 'lpe:collateral:press-line-9' }, priv[COLLATERAL_REGISTRY]),
    PRIMARY_EXIT: mintEvent('primary-exit', 'agent_exit', ORG_REGISTRAR, 'org-registrar', PRIMARY,
      CLOCK.T_PRIMARY_EXIT, CLOCK.T_PRIMARY_EXIT, { basis: 'resigned' }, priv[ORG_REGISTRAR]),
    SUCCESSOR_1_EXIT: mintEvent('successor-1-exit', 'agent_exit', ORG_REGISTRAR, 'org-registrar', SUCCESSOR_1,
      CLOCK.T_PRIMARY_EXIT, CLOCK.T_PRIMARY_EXIT, { basis: 'declined_to_serve' }, priv[ORG_REGISTRAR]),
  }

  const fixture = {
    _placeholder: false,
    profile: 'aac-lifecycle-principal-events-v0',
    clock: CLOCK,
    verification_keys: verificationKeys,
    attestor_role_registry: ATTESTOR_ROLE_REGISTRY,
    event_standing: EVENT_STANDING,
    // Which grant-terms record belongs to which chain. A chain with no entry
    // has no terms record at all.
    terms_by_chain: {
      G_PLAIN: 'G_PLAIN',
      G_DURABLE: 'G_DURABLE',
      G_SPOUSAL_DECREE: 'G_SPOUSAL_DECREE',
      G_SPOUSAL_FILING: 'G_SPOUSAL_FILING',
      G_SPOUSAL_SILENT: 'G_SPOUSAL_SILENT',
      G_FIDUCIARY: 'G_FIDUCIARY',
      G_FIDUCIARY_SUB: 'G_FIDUCIARY',
      G_COUPLED: 'G_COUPLED',
      G_SUCCESSION: 'G_SUCCESSION',
      G_PRIMARY_PERSONAL: 'G_PRIMARY_PERSONAL',
    },
    grant_terms: terms,
    events,
    chains: {
      G_PLAIN: [gPlain],
      G_DURABLE: [gDurable],
      G_SPOUSAL_DECREE: [gSpousalDecree],
      G_SPOUSAL_FILING: [gSpousalFiling],
      G_SPOUSAL_SILENT: [gSpousalSilent],
      G_FIDUCIARY: [gFiduciary],
      G_FIDUCIARY_SUB: [gFiduciary, gFiduciarySub],
      G_COUPLED: [gCoupled],
      G_SUCCESSION: [gSuccession],
      G_PRIMARY_PERSONAL: [gSuccession, gPrimaryPersonal],
    },
  }

  fs.writeFileSync(
    path.join(here, 'chain.json'),
    JSON.stringify(fixture, null, 2) + '\n',
    'utf8',
  )
}

main()
