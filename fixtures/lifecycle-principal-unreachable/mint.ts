// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-principal-unreachable family.
//
// WHAT THIS FAMILY TESTS. A grant whose terms make a particular action class
// effective only once an agreed confirmation procedure with the principal has
// actually been completed, and what a verifier returns for one such action
// while the principal cannot be reached to complete it. Nothing is revoked in
// any vector here and the chain verifies valid at every action instant, so the
// question is not whether authority ended. It is whether this action was ever
// established as authorized in the first place.
//
// The proposed text is aeoess/agent-authority-lifecycle, AUTHORITY-LIFECYCLE.md
// at commit 7796e22 or later, sections "Lifecycle concepts are separate"
// (Decisions and effects > Approval, Authorization decision; Verification and
// evidence > Status observation, Notice, Coverage and completeness), and
// invariant L7. Every vector is labelled candidate_against_proposed. CASES.md
// case id: LC-H-012.
//
// HOW THIS DIFFERS FROM THE WAVE 2 activation-not-established FAMILY. That
// family gates the grant: an activation condition decides when already issued
// authority becomes exercisable at all. This family gates one action under an
// already exercisable grant, and the confirmation is per action rather than per
// grant. The README says this again, with the delta spelled out.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/lifecycle-principal-unreachable/mint.ts
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
  T_ORDER: '2026-09-21T09:00:00.000Z',
  T_CONFIRM: '2026-09-21T09:30:00.000Z',
  T_ACTION: '2026-09-21T10:00:00.000Z',
  T_UNREACHABLE_THROUGH: '2026-09-21T12:00:00.000Z',
  T_DEADLINE: '2026-09-21T12:00:00.000Z',
  T_ACTION_AFTER_DEADLINE: '2026-09-21T13:00:00.000Z',
  T_LATE_CONFIRM: '2026-09-21T14:00:00.000Z',
  T_LATER_ACTION: '2026-09-21T15:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:lpu-principal'
const AGENT = 'did:aps:example:lpu-agent'
const OPS_DESK = 'did:aps:example:lpu-ops-desk'
const DELEGATE_CONFIRMER = 'did:aps:example:lpu-delegate-confirmer'
const IMPOSTOR = 'did:aps:example:lpu-impostor'

const PROCEDURE_ID = 'lpu-callback-v1'
const ORDER_REF = 'lpu-order-2026-09-21-a'
const OTHER_ORDER_REF = 'lpu-order-2026-09-21-b'

// grant-principal is read off the chain, not the registry.
const EVENT_STANDING: Record<string, string> = {
  principal_confirmation: 'grant-principal',
  unreachability_observation: 'operations-desk',
  deadline_elapsed_observation: 'operations-desk',
}

const ATTESTOR_ROLE_REGISTRY: Record<string, string> = {
  [OPS_DESK]: 'operations-desk',
  [DELEGATE_CONFIRMER]: 'operations-desk',
  [IMPOSTOR]: 'unaffiliated-observer',
}

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:lpu:${label}`).digest('hex')
}
function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
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
    record_type: 'fixture:confirmation-event:v0' as const,
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
function mintGrantTerms(delegationId: string, terms: Record<string, unknown>, privateKey: string) {
  const body = {
    record_type: 'fixture:grant-terms:v0' as const,
    version: '0.1' as const,
    delegation_id: delegationId,
    issuer: PRINCIPAL,
    issued_at: CLOCK.T_ISSUE,
    terms,
    verification_method: `${PRINCIPAL}#key-1`,
    nonce: seed('terms-nonce:v1').slice(0, 32),
  }
  const preimage = canonicalizeJCS(body)
  return { ...body, terms_id: sha256Hex(preimage), signature: sign(preimage, privateKey) }
}

function main(): void {
  const priv: Record<string, string> = {}
  for (const [name, did] of Object.entries({
    principal: PRINCIPAL,
    agent: AGENT,
    'ops-desk': OPS_DESK,
    'delegate-confirmer': DELEGATE_CONFIRMER,
    impostor: IMPOSTOR,
  })) {
    priv[did] = seed(`${name}:v1`)
  }
  const verificationKeys: Record<string, string> = {}
  for (const did of Object.keys(priv)) {
    verificationKeys[`${did}#key-1`] = publicKeyFromPrivate(priv[did])
  }

  const grant = issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: PRINCIPAL,
      subject: AGENT,
      verification_method: `${PRINCIPAL}#key-1`,
      issued_at: CLOCK.T_ISSUE,
      nonce: seed('grant-nonce:v1').slice(0, 32),
      authority: {
        scope: { profile: 'aps-hierarchical-v1', grants: ['payments:submit', 'statements:read'] },
        spend: { mode: 'unbounded' },
        depth: { remaining: 0 },
        time: { not_before: CLOCK.T_ISSUE, not_after: CLOCK.T_NOT_AFTER },
        reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
        values: { profile: 'aps-values-identifiers-v1', required: [] },
        reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
      },
    } as never,
    priv[PRINCIPAL],
  ) as Record<string, unknown>

  const terms = mintGrantTerms(grant.delegation_id as string, {
    confirmation_procedure: {
      procedure_id: PROCEDURE_ID,
      required_confirmer: PRINCIPAL,
      applies_to_action_classes: ['payment_order'],
      // Recorded so the family can state that a deadline exists and still show
      // that its passing decides nothing on its own.
      deadline: CLOCK.T_DEADLINE,
    },
  }, priv[PRINCIPAL])

  const events = {
    CONFIRM_OK: mintEvent('confirm-ok', 'principal_confirmation', PRINCIPAL, 'grant-principal',
      ORDER_REF, CLOCK.T_CONFIRM,
      { procedure_id: PROCEDURE_ID, order_ref: ORDER_REF, confirmed_at: CLOCK.T_CONFIRM },
      priv[PRINCIPAL]),
    CONFIRM_LATE: mintEvent('confirm-late', 'principal_confirmation', PRINCIPAL, 'grant-principal',
      ORDER_REF, CLOCK.T_LATE_CONFIRM,
      { procedure_id: PROCEDURE_ID, order_ref: ORDER_REF, confirmed_at: CLOCK.T_LATE_CONFIRM },
      priv[PRINCIPAL]),
    CONFIRM_OTHER_ORDER: mintEvent('confirm-other-order', 'principal_confirmation', PRINCIPAL,
      'grant-principal', OTHER_ORDER_REF, CLOCK.T_CONFIRM,
      { procedure_id: PROCEDURE_ID, order_ref: OTHER_ORDER_REF, confirmed_at: CLOCK.T_CONFIRM },
      priv[PRINCIPAL]),
    CONFIRM_OTHER_PROCEDURE: mintEvent('confirm-other-procedure', 'principal_confirmation',
      PRINCIPAL, 'grant-principal', ORDER_REF, CLOCK.T_CONFIRM,
      { procedure_id: 'lpu-email-reply-v0', order_ref: ORDER_REF, confirmed_at: CLOCK.T_CONFIRM },
      priv[PRINCIPAL]),
    CONFIRM_FROM_DELEGATE: mintEvent('confirm-from-delegate', 'principal_confirmation',
      DELEGATE_CONFIRMER, 'grant-principal', ORDER_REF, CLOCK.T_CONFIRM,
      { procedure_id: PROCEDURE_ID, order_ref: ORDER_REF, confirmed_at: CLOCK.T_CONFIRM },
      priv[DELEGATE_CONFIRMER]),
    UNREACHABLE: mintEvent('unreachable', 'unreachability_observation', OPS_DESK, 'operations-desk',
      PRINCIPAL, CLOCK.T_ORDER,
      { order_ref: ORDER_REF, attempts: 3, through: CLOCK.T_UNREACHABLE_THROUGH }, priv[OPS_DESK]),
    UNREACHABLE_NO_STANDING: mintEvent('unreachable-no-standing', 'unreachability_observation',
      IMPOSTOR, 'operations-desk', PRINCIPAL, CLOCK.T_ORDER,
      { order_ref: ORDER_REF, attempts: 3, through: CLOCK.T_UNREACHABLE_THROUGH }, priv[IMPOSTOR]),
    DEADLINE_ELAPSED: mintEvent('deadline-elapsed', 'deadline_elapsed_observation', OPS_DESK,
      'operations-desk', PRINCIPAL, CLOCK.T_DEADLINE,
      { order_ref: ORDER_REF, deadline: CLOCK.T_DEADLINE }, priv[OPS_DESK]),
  }

  const fixture = {
    _placeholder: false,
    profile: 'aac-lifecycle-principal-unreachable-v0',
    clock: CLOCK,
    order_ref: ORDER_REF,
    verification_keys: verificationKeys,
    attestor_role_registry: ATTESTOR_ROLE_REGISTRY,
    event_standing: EVENT_STANDING,
    terms_by_chain: { G_PAYMENT: 'G_PAYMENT' },
    grant_terms: { G_PAYMENT: terms },
    events,
    chains: { G_PAYMENT: [grant] },
  }
  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
}

main()
