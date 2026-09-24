// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-agent-renunciation family.
//
// WHAT THIS FAMILY TESTS. An agent ending its own role. When that takes effect,
// whether the principal's acceptance is part of it, what a stated later
// effective date or a stated triggering event does, and whether a renunciation
// that breaches some other obligation takes effect any differently from a clean
// one.
//
// The proposed text is aeoess/agent-authority-lifecycle, AUTHORITY-LIFECYCLE.md
// at commit 7796e22 or later, sections "Lifecycle concepts are separate"
// (Parties and standing > Sponsor or responsible owner; Authority lifecycle
// state > Revocation; Verification and evidence > Notice, Accountability
// record), "What changes when a person leaves", and invariants L3 and L4. Every
// vector is labelled candidate_against_proposed. CASES.md case ids: LC-H-010,
// LC-H-011.
//
// NOTE ON LIABILITY. Whether a renunciation breached some other obligation is
// not an authority verdict and this family does not produce one. The gate has
// no liability field and one vector asserts that directly.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/lifecycle-agent-renunciation/mint.ts
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
  T_BEFORE: '2026-09-20T10:00:00.000Z',
  T_DELIVER: '2026-09-21T09:00:00.000Z',
  T_AFTER_DELIVERY: '2026-09-21T10:00:00.000Z',
  T_ACCEPTANCE: '2026-09-21T11:00:00.000Z',
  T_STATED_EFFECTIVE: '2026-09-23T09:00:00.000Z',
  T_BEFORE_STATED_EFFECTIVE: '2026-09-22T09:00:00.000Z',
  T_AFTER_STATED_EFFECTIVE: '2026-09-23T10:00:00.000Z',
  T_HANDOVER: '2026-09-22T12:00:00.000Z',
  T_AFTER_HANDOVER: '2026-09-22T13:00:00.000Z',
  T_LIABILITY: '2026-09-24T09:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:lar-principal'
const AGENT = 'did:aps:example:lar-agent'
const OTHER_AGENT = 'did:aps:example:lar-other-agent'
const ORG_REGISTRAR = 'did:aps:example:lar-org-registrar'
const CONTRACT_REGISTRY = 'did:aps:example:lar-contract-registry'
const IMPOSTOR = 'did:aps:example:lar-impostor'

// grant-subject and grant-principal are read off the chain, not the registry.
const EVENT_STANDING: Record<string, string> = {
  agent_renunciation: 'grant-subject',
  principal_acceptance: 'grant-principal',
  handover_complete: 'org-registrar',
  no_exit_agreement: 'contract-registry',
  liability_determination: 'contract-registry',
}

const ATTESTOR_ROLE_REGISTRY: Record<string, string> = {
  [ORG_REGISTRAR]: 'org-registrar',
  [CONTRACT_REGISTRY]: 'contract-registry',
  [IMPOSTOR]: 'unaffiliated-observer',
}

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:lar:${label}`).digest('hex')
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
    record_type: 'fixture:renunciation-event:v0' as const,
    version: '0.1' as const,
    event_type: eventType,
    attestor,
    attestor_role: attestorRole,
    subject_ref: subjectRef,
    // For a renunciation this is the instant the notice was delivered to the
    // principal, which is a separate fact from when the renunciation becomes
    // effective. The payload carries the second one when the record states it.
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
    agent: AGENT,
    'other-agent': OTHER_AGENT,
    'org-registrar': ORG_REGISTRAR,
    'contract-registry': CONTRACT_REGISTRY,
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
        scope: { profile: 'aps-hierarchical-v1', grants: ['board:sign'] },
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

  const events = {
    RENOUNCE_PLAIN: mintEvent('renounce-plain', 'agent_renunciation', AGENT, 'grant-subject',
      grant.delegation_id as string, CLOCK.T_DELIVER,
      { delivered_to: PRINCIPAL, delivered_at: CLOCK.T_DELIVER }, priv[AGENT]),
    RENOUNCE_LATER_DATE: mintEvent('renounce-later-date', 'agent_renunciation', AGENT,
      'grant-subject', grant.delegation_id as string, CLOCK.T_DELIVER,
      { delivered_to: PRINCIPAL, delivered_at: CLOCK.T_DELIVER,
        effective_date: CLOCK.T_STATED_EFFECTIVE }, priv[AGENT]),
    RENOUNCE_ON_EVENT: mintEvent('renounce-on-event', 'agent_renunciation', AGENT, 'grant-subject',
      grant.delegation_id as string, CLOCK.T_DELIVER,
      { delivered_to: PRINCIPAL, delivered_at: CLOCK.T_DELIVER,
        effective_on_event: 'handover_complete', event_ref: 'lar-handover-2026-09' }, priv[AGENT]),
    RENOUNCE_WRONGFUL: mintEvent('renounce-wrongful', 'agent_renunciation', AGENT, 'grant-subject',
      grant.delegation_id as string, CLOCK.T_DELIVER,
      { delivered_to: PRINCIPAL, delivered_at: CLOCK.T_DELIVER,
        agreement_ref: 'lar-agreement-2026-04' }, priv[AGENT]),
    RENOUNCE_FROM_OTHER: mintEvent('renounce-from-other', 'agent_renunciation', OTHER_AGENT,
      'grant-subject', grant.delegation_id as string, CLOCK.T_DELIVER,
      { delivered_to: PRINCIPAL, delivered_at: CLOCK.T_DELIVER }, priv[OTHER_AGENT]),
    ACCEPTANCE: mintEvent('acceptance', 'principal_acceptance', PRINCIPAL, 'grant-principal',
      grant.delegation_id as string, CLOCK.T_ACCEPTANCE, { accepts: 'renunciation' },
      priv[PRINCIPAL]),
    HANDOVER_COMPLETE: mintEvent('handover-complete', 'handover_complete', ORG_REGISTRAR,
      'org-registrar', grant.delegation_id as string, CLOCK.T_HANDOVER,
      { event_ref: 'lar-handover-2026-09' }, priv[ORG_REGISTRAR]),
    HANDOVER_COMPLETE_NO_STANDING: mintEvent('handover-complete-no-standing', 'handover_complete',
      IMPOSTOR, 'org-registrar', grant.delegation_id as string, CLOCK.T_HANDOVER,
      { event_ref: 'lar-handover-2026-09' }, priv[IMPOSTOR]),
    NO_EXIT_AGREEMENT: mintEvent('no-exit-agreement', 'no_exit_agreement', CONTRACT_REGISTRY,
      'contract-registry', AGENT, CLOCK.T_ISSUE,
      { agreement_ref: 'lar-agreement-2026-04', no_exit_through: CLOCK.T_NOT_AFTER },
      priv[CONTRACT_REGISTRY]),
    LIABILITY_DETERMINATION: mintEvent('liability-determination', 'liability_determination',
      CONTRACT_REGISTRY, 'contract-registry', AGENT, CLOCK.T_LIABILITY,
      { agreement_ref: 'lar-agreement-2026-04', outcome: 'recorded' }, priv[CONTRACT_REGISTRY]),
  }

  const fixture = {
    _placeholder: false,
    profile: 'aac-lifecycle-agent-renunciation-v0',
    clock: CLOCK,
    verification_keys: verificationKeys,
    attestor_role_registry: ATTESTOR_ROLE_REGISTRY,
    event_standing: EVENT_STANDING,
    events,
    chains: { G_AGENT: [grant] },
  }
  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
}

main()
