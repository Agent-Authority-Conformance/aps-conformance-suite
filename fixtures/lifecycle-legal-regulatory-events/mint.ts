// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-legal-regulatory-events family, byte for byte.
//
// WHAT THIS FAMILY TESTS. An authority change that arrives from outside the delegation
// graph: a record made by a party the verifier's trust policy recognises, which ends,
// suspends, narrows, gates or releases authority without any delegation record changing.
// The proposed text is aeoess/agent-authority-lifecycle at commit 7796e22, the entries
// "External restriction", "Suspension", "Lifecycle standing", "Status observation",
// "Notice", "Target binding", "Authority path and dependency" and "Verifier trust
// policy", invariants L8 and L10, and the OPEN-QUESTIONS.md sections "Release from
// suspension" and "Critical revocation". The cases are the "Legal and regulatory events"
// section of CASES.md at commit 2bf5c7e.
//
// Every vector in this family is labelled candidate_against_proposed. draft-pidlisnyi-aps-03
// states no rule for an external authority event, for suspension or for a restricted
// state, and neither reference SDK exports one. See README.md.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are
// pinned constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-legal-regulatory-events/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  InMemoryAuthorityRevocationStore,
  canonicalizeJCS,
  computeActionRefV2,
  computeAuthorityDelegationId,
  computePayloadRefV1,
  createActionReferenceInputV2,
  createAuthorityRevocationResolver,
  createReceiptV1,
  issueAuthorityRevocation,
  publicKeyFromPrivate,
  recordAuthorityRevocation,
  scopeGrantCovers,
  sign,
  signAuthorityDelegation,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
  verifyAuthorityRevocation,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Published seed labels. Nothing here is secret and nothing here is random.
// ---------------------------------------------------------------------------

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-legal-regulatory-events:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

// ---------------------------------------------------------------------------
// Identities. Offices and organizations, never named people: this family says nothing
// about what happens when an individual issuer leaves, which the proposed text leaves
// open under "Office vacancy and succession".
// ---------------------------------------------------------------------------

const ORG = 'did:aps:example:lre-org'
const OFFICER = 'did:aps:example:lre-finance-office'
const AGENT_PROC = 'did:aps:example:lre-procurement-agent'
const AGENT_SUB = 'did:aps:example:lre-procurement-subagent'
const AGENT_REPORT = 'did:aps:example:lre-reporting-agent'
const PAYCO = 'did:aps:example:lre-payments-company'
const AGENT_PAY_A = 'did:aps:example:lre-payments-agent-a'
const AGENT_PAY_B = 'did:aps:example:lre-payments-agent-b'
const AGENT_PAY_C = 'did:aps:example:lre-payments-agent-c'
const FIRM = 'did:aps:example:lre-firm'
const REP_OFFICE = 'did:aps:example:lre-representative-office'
const AGENT_ADVICE = 'did:aps:example:lre-advice-agent'
const COMPANY = 'did:aps:example:lre-company'
const AGENT_TREASURY = 'did:aps:example:lre-treasury-agent'
const AGENT_COLLECT = 'did:aps:example:lre-collections-agent'

// External authorities. Each one is an issuer of external authority events, and whether
// it has standing for a given effect is decided by the verifier trust policy below, never
// by anything inside its own record.
const COURT = 'did:aps:example:lre-court'
const REGULATOR = 'did:aps:example:lre-regulator'
const RECEIVER = 'did:aps:example:lre-receiver'
const TRUSTEE = 'did:aps:example:lre-trustee'
const CERTIFIER = 'did:aps:example:lre-responsible-official'
// A real key with no entry in the trust policy for any effect. Its records are genuinely
// signed, so a rejection is about standing and never about authenticity.
const UNREGISTERED = 'did:aps:example:lre-unregistered-authority'

const kid = (did: string) => `${did}#key-1`

const PRIVATE: Record<string, string> = {}
const PUBLIC: Record<string, string> = {}
for (const did of [
  ORG, OFFICER, AGENT_PROC, AGENT_SUB, AGENT_REPORT, PAYCO, AGENT_PAY_A, AGENT_PAY_B,
  AGENT_PAY_C, FIRM, REP_OFFICE, AGENT_ADVICE, COMPANY, AGENT_TREASURY, AGENT_COLLECT,
  COURT, REGULATOR, RECEIVER, TRUSTEE, CERTIFIER, UNREGISTERED,
]) {
  PRIVATE[did] = seed(`identity:${did}:v1`)
  PUBLIC[kid(did)] = publicKeyFromPrivate(PRIVATE[did])
}

// ---------------------------------------------------------------------------
// Off-graph targets. None of these is an APS record. A counterparty, a resource and a
// licence are the three things the proposed text's "Target binding" and "Authority path
// and dependency" entries describe and that a delegation graph does not contain.
// ---------------------------------------------------------------------------

const COUNTERPARTY_LISTED = 'counterparty:lre-vendor-v'
const COUNTERPARTY_UNLISTED = 'counterparty:lre-vendor-w'
const RESOURCE_ACCOUNT = 'resource:lre-account-1'
const DEPENDENCY_LICENCE = 'dependency:lre-money-transmitter-licence'

// ---------------------------------------------------------------------------
// The timeline. One pinned clock, six observation times, plus a seventh for a grant that
// is recorded now and effective later.
//
//   T0  every grant issued
//   T1  before any external event exists
//   T2  the first external events take effect
//   T3  the first external events become observable (recorded_at)
//   T4  after observation
//   T5  releases take effect and become observable
//   T6  after release, and after the consent decree's own sunset
//   T7  the not_before of the trustee's deferred replacement grant
// ---------------------------------------------------------------------------

const T0 = '2026-09-21T00:00:00.000Z'
const T1 = '2026-09-22T09:00:00.000Z'
const T2 = '2026-09-22T12:00:00.000Z'
const T3 = '2026-09-22T15:00:00.000Z'
const T4 = '2026-09-23T09:00:00.000Z'
const T5 = '2026-09-24T12:00:00.000Z'
const T6 = '2026-09-25T09:00:00.000Z'
const T7 = '2026-09-28T00:00:00.000Z'
const NOT_AFTER = '2026-10-01T00:00:00.000Z'

// The decree's own sunset, between T5 and T6, so T6 is after it and T4 is before it.
const DECREE_SUNSET = '2026-09-24T18:00:00.000Z'

// ---------------------------------------------------------------------------
// Delegations. Signed directly with computeAuthorityDelegationId + signAuthorityDelegation,
// the two steps cooperative issuance performs internally, because one chain here is
// deliberately mis-signed and the cooperative path would refuse to produce it. Every
// other chain is an ordinary, correctly signed record.
// ---------------------------------------------------------------------------

type Spend = { mode: 'unbounded' }
const UNBOUNDED: Spend = { mode: 'unbounded' }

function authorityVector(grants: string[], depthRemaining: number, notBefore: string): unknown {
  return {
    scope: { profile: 'aps-hierarchical-v1', grants },
    spend: UNBOUNDED,
    depth: { remaining: depthRemaining },
    time: { not_before: notBefore, not_after: NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1', required: [] as string[] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
  }
}

interface DelegationBody {
  record_type: 'aps:authority-delegation:v1'
  version: '1.0'
  parent_delegation_id: string | null
  issuer: string
  subject: string
  verification_method: string
  issued_at: string
  nonce: string
  authority: unknown
}

function signRecord(body: DelegationBody, privateKey: string) {
  const delegation_id = computeAuthorityDelegationId(body as never)
  const draft = { ...body, delegation_id }
  const signature = signAuthorityDelegation(draft as never, privateKey)
  return { ...draft, signature }
}

interface HopSpec {
  issuer: string
  subject: string
  grants: string[]
  nonceLabel: string
  /** Defaults to the issuer's own key. Set to sign a record the issuer did not sign. */
  signWith?: string
  /** Defaults to T0. */
  notBefore?: string
  issuedAt?: string
}

/** Mint a root-to-leaf chain. depth.remaining counts down to 0 at the leaf. */
function mintChain(hops: HopSpec[]) {
  const records: Array<ReturnType<typeof signRecord>> = []
  let parent: string | null = null
  hops.forEach((hop, index) => {
    const body: DelegationBody = {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: parent,
      issuer: hop.issuer,
      subject: hop.subject,
      verification_method: kid(hop.issuer),
      issued_at: hop.issuedAt ?? T0,
      nonce: seed(`delegation-nonce:${hop.nonceLabel}:v1`).slice(0, 32),
      authority: authorityVector(hop.grants, hops.length - 1 - index, hop.notBefore ?? T0),
    }
    const record = signRecord(body, PRIVATE[hop.signWith ?? hop.issuer])
    records.push(record)
    parent = record.delegation_id
  })
  return records
}

const SCOPE_PROCUREMENT = 'procurement:purchase'
const SCOPE_REPORT = 'compliance:report'
const SCOPE_PAYMENTS = 'payments:transfer'
const SCOPE_ADVICE = 'advice:issue'
const SCOPE_TREASURY = 'treasury:move-funds'
const SCOPE_COLLECT = 'collections:pursue'

const CHAINS = {
  // org -> finance office -> procurement agent. The chain the approval-gate,
  // external-termination, principal-replacement and evidence-coverage vectors use.
  officer: mintChain([
    { issuer: ORG, subject: OFFICER, grants: [SCOPE_PROCUREMENT], nonceLabel: 'org-to-officer' },
    { issuer: OFFICER, subject: AGENT_PROC, grants: [SCOPE_PROCUREMENT], nonceLabel: 'officer-to-proc' },
  ]),
  // The same root and office with one further hop, so a gate on the office's authority
  // can be shown not to pause a descendant delegation.
  officer_deep: mintChain([
    { issuer: ORG, subject: OFFICER, grants: [SCOPE_PROCUREMENT], nonceLabel: 'org-to-officer-deep' },
    { issuer: OFFICER, subject: AGENT_PROC, grants: [SCOPE_PROCUREMENT], nonceLabel: 'officer-to-proc-deep' },
    { issuer: AGENT_PROC, subject: AGENT_SUB, grants: [SCOPE_PROCUREMENT], nonceLabel: 'proc-to-sub-deep' },
  ]),
  // org -> reporting agent, for the consent-decree certification gate.
  decree: mintChain([
    { issuer: ORG, subject: AGENT_REPORT, grants: [SCOPE_REPORT], nonceLabel: 'org-to-report' },
  ]),
  // A payments chain whose action names an off-graph counterparty.
  payments: mintChain([
    { issuer: PAYCO, subject: AGENT_PAY_A, grants: [SCOPE_PAYMENTS], nonceLabel: 'payco-to-pay-a' },
  ]),
  // Two independently issued chains that both declare a dependency on the same off-graph
  // licence, and a third that declares none.
  licence_a: mintChain([
    { issuer: PAYCO, subject: AGENT_PAY_A, grants: [SCOPE_PAYMENTS], nonceLabel: 'licence-a' },
  ]),
  licence_b: mintChain([
    { issuer: PAYCO, subject: AGENT_PAY_B, grants: [SCOPE_PAYMENTS], nonceLabel: 'licence-b' },
  ]),
  licence_c: mintChain([
    { issuer: PAYCO, subject: AGENT_PAY_C, grants: [SCOPE_PAYMENTS], nonceLabel: 'licence-c' },
  ]),
  // firm -> representative office -> advice agent, for the two independent suspensions.
  suspension: mintChain([
    { issuer: FIRM, subject: REP_OFFICE, grants: [SCOPE_ADVICE], nonceLabel: 'firm-to-rep' },
    { issuer: REP_OFFICE, subject: AGENT_ADVICE, grants: [SCOPE_ADVICE], nonceLabel: 'rep-to-advice' },
  ]),
  // company -> treasury agent over one named account, for restriction against ownership.
  resource: mintChain([
    { issuer: COMPANY, subject: AGENT_TREASURY, grants: [SCOPE_TREASURY], nonceLabel: 'company-to-treasury' },
  ]),
  // A second, later grant from the same principal over the same account, issued after the
  // ownership transfer. Nothing about it is defective: it is a valid grant over a resource
  // its issuer no longer owns.
  resource_regrant: mintChain([
    { issuer: COMPANY, subject: AGENT_TREASURY, grants: [SCOPE_TREASURY], nonceLabel: 'company-to-treasury-regrant', issuedAt: T5 },
  ]),
  // A chain rooted at the court-appointed receiver, an identity that appears nowhere in
  // any other chain here.
  receiver: mintChain([
    { issuer: RECEIVER, subject: AGENT_COLLECT, grants: [SCOPE_COLLECT], nonceLabel: 'receiver-to-collect' },
  ]),
  // A chain rooted at the trustee, effective from T0, for the replaced-principal case.
  trustee: mintChain([
    { issuer: TRUSTEE, subject: AGENT_PROC, grants: [SCOPE_PROCUREMENT], nonceLabel: 'trustee-to-proc' },
  ]),
  // The same trustee grant with not_before at T7, recorded now and exercisable later.
  trustee_deferred: mintChain([
    { issuer: TRUSTEE, subject: AGENT_PROC, grants: [SCOPE_PROCUREMENT], nonceLabel: 'trustee-to-proc-deferred', notBefore: T7 },
  ]),
  // A record naming ORG as issuer and signed with a key that is not ORG's. Schema-valid,
  // delegation_id recomputes, signature does not verify. This is the delegation the
  // historical act in the ratification vectors cited.
  unsigned_claim: mintChain([
    { issuer: ORG, subject: AGENT_PROC, grants: [SCOPE_PROCUREMENT], nonceLabel: 'unsigned-claim', signWith: UNREGISTERED },
  ]),
} as const

type ChainName = keyof typeof CHAINS

// ---------------------------------------------------------------------------
// Dependency bindings. A fixture-local profile, not a protocol object.
//
// The proposed text's "Authority path and dependency" entry says a grant depends on other
// authority and that "Historical provenance and current dependency are not necessarily
// the same thing." It does not say how a grant declares a dependency on something outside
// the delegation graph, and draft-03's authority vector is a closed seven-facet set with
// no slot for one. This family therefore declares its own, signed by the grant's own
// issuer, and says plainly in README.md that the shape is this fixture's invention.
// ---------------------------------------------------------------------------

const DEPENDENCY_BINDING_PROFILE = `${SEED_PREFIX}dependency-binding-v0`
const DEPENDENCY_BINDING_DOMAIN = 'APS-CONFORMANCE-LRE-DEPENDENCY-BINDING-V0'

function mintDependencyBinding(delegationId: string, issuer: string, dependsOn: string[]) {
  const body = {
    profile: DEPENDENCY_BINDING_PROFILE,
    delegation_id: delegationId,
    issuer,
    verification_method: kid(issuer),
    issued_at: T0,
    depends_on: dependsOn,
  }
  const signature = sign(`${DEPENDENCY_BINDING_DOMAIN} ${canonicalizeJCS(body)}`, PRIVATE[issuer])
  return { ...body, signature }
}

const DEPENDENCY_BINDINGS = {
  licence_a: mintDependencyBinding(CHAINS.licence_a[0].delegation_id, PAYCO, [DEPENDENCY_LICENCE]),
  licence_b: mintDependencyBinding(CHAINS.licence_b[0].delegation_id, PAYCO, [DEPENDENCY_LICENCE]),
  licence_c: mintDependencyBinding(CHAINS.licence_c[0].delegation_id, PAYCO, []),
}

// ---------------------------------------------------------------------------
// External authority events. A fixture-local profile, not a protocol object.
//
// The proposed text names the concept in "External restriction": "A block from outside the
// grant chain, such as a sanction, a court order, or a legal hold that blocks a deletion.
// It can stop some effects while the grant itself stays valid." It defines no record for
// one, no effect vocabulary, and no way to say when the effect began as against when the
// record was made. Both times are here because "Status observation" and "Notice" are
// separate entries in the same text: recorded_at is when a verifier could observe the
// event, effective_at is when its effect began, and the two are not the same.
// ---------------------------------------------------------------------------

const EXTERNAL_EVENT_PROFILE = `${SEED_PREFIX}external-authority-event-v0`
const EXTERNAL_EVENT_DOMAIN = 'APS-CONFORMANCE-LRE-EXTERNAL-EVENT-V0'

type TargetKind = 'principal' | 'counterparty' | 'resource' | 'dependency' | 'action' | 'root' | 'event'

type Effect =
  | 'terminate_principal_authority'
  | 'replace_principal'
  | 'restrict_execution'
  | 'release_restriction'
  | 'add_approval_gate'
  | 'suspend_principal'
  | 'release_suspension'
  | 'revoke_dependency'
  | 'transfer_resource_ownership'
  | 'ratify_action'
  | 'establish_trust_root'

interface EventSpec {
  label: string
  issuer: string
  effect: Effect
  target: { kind: TargetKind; id: string }
  parameters?: Record<string, unknown>
  effective_at: string
  recorded_at: string
  standing_basis: string
  /** Defaults to the issuer's own key. */
  signWith?: string
}

function mintEvent(spec: EventSpec) {
  const body = {
    profile: EXTERNAL_EVENT_PROFILE,
    issuer: spec.issuer,
    verification_method: kid(spec.issuer),
    effect: spec.effect,
    target: spec.target,
    parameters: spec.parameters ?? {},
    effective_at: spec.effective_at,
    recorded_at: spec.recorded_at,
    standing_basis: spec.standing_basis,
  }
  const preimage = `${EXTERNAL_EVENT_DOMAIN} ${canonicalizeJCS(body)}`
  const event_id = 'sha256:' + createHash('sha256').update(preimage, 'utf8').digest('hex')
  const signature = sign(preimage, PRIVATE[spec.signWith ?? spec.issuer])
  return { ...body, event_id, signature }
}

// Actions. One action reference per presentation, so no two presentations share an
// identity and a certification cannot be replayed across them.
function mintAction(label: string, agent: string, scope: string, target: string, issuedAt: string) {
  return createActionReferenceInputV2({
    agent_id: agent,
    action_type: scope.replace(':', '.'),
    target: `https://example.invalid/${target}`,
    payload_ref: computePayloadRefV1({ action_label: label }),
    scope_required: [scope],
    issued_at: issuedAt,
    nonce: seed(`action-nonce:${label}:v1`).slice(0, 32),
  })
}

const ACTION_SPECS: Array<[string, string, string, string, string]> = [
  ['proc-small', AGENT_PROC, SCOPE_PROCUREMENT, 'orders/small', T0],
  ['proc-large', AGENT_PROC, SCOPE_PROCUREMENT, 'orders/large', T0],
  ['proc-historical', AGENT_PROC, SCOPE_PROCUREMENT, 'orders/historical', T0],
  ['proc-later', AGENT_PROC, SCOPE_PROCUREMENT, 'orders/later', T0],
  ['proc-sub', AGENT_SUB, SCOPE_PROCUREMENT, 'orders/sub', T0],
  ['report-in-scope', AGENT_REPORT, SCOPE_REPORT, 'reports/quarterly', T0],
  ['pay-listed', AGENT_PAY_A, SCOPE_PAYMENTS, 'payments/listed', T0],
  ['pay-unlisted', AGENT_PAY_A, SCOPE_PAYMENTS, 'payments/unlisted', T0],
  ['pay-licence-a', AGENT_PAY_A, SCOPE_PAYMENTS, 'payments/licence-a', T0],
  ['pay-licence-b', AGENT_PAY_B, SCOPE_PAYMENTS, 'payments/licence-b', T0],
  ['pay-licence-c', AGENT_PAY_C, SCOPE_PAYMENTS, 'payments/licence-c', T0],
  ['advice-issue', AGENT_ADVICE, SCOPE_ADVICE, 'advice/issue', T0],
  ['treasury-move', AGENT_TREASURY, SCOPE_TREASURY, 'treasury/move', T0],
  ['collect-pursue', AGENT_COLLECT, SCOPE_COLLECT, 'collections/pursue', T0],
]

const ACTIONS: Record<string, { input: unknown; action_ref: string }> = {}
for (const [label, agent, scope, target, issuedAt] of ACTION_SPECS) {
  const input = mintAction(label, agent, scope, target, issuedAt)
  ACTIONS[label] = { input, action_ref: computeActionRefV2(input) }
}

const EVENTS = Object.fromEntries(
  (
    [
      // LC-B-008. A receiver steps into the office's authority by an external instrument.
      {
        label: 'terminate_officer_by_receiver',
        issuer: RECEIVER,
        effect: 'terminate_principal_authority',
        target: { kind: 'principal', id: OFFICER },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'appointment-of-receiver:lre-2026-0001',
      },
      // The same statement from a party with no entry in the trust policy.
      {
        label: 'terminate_officer_no_standing',
        issuer: UNREGISTERED,
        effect: 'terminate_principal_authority',
        target: { kind: 'principal', id: OFFICER },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'asserted-by-the-record-itself',
      },
      // LC-B-018. An execution block naming one off-graph counterparty.
      {
        label: 'restrict_counterparty_v',
        issuer: REGULATOR,
        effect: 'restrict_execution',
        target: { kind: 'counterparty', id: COUNTERPARTY_LISTED },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'listing-order:lre-2026-0002',
      },
      // LC-B-019. Its release, by the same authority, on its own trigger.
      {
        label: 'release_counterparty_v',
        issuer: REGULATOR,
        effect: 'release_restriction',
        target: { kind: 'event', id: '' },
        effective_at: T5,
        recorded_at: T5,
        standing_basis: 'delisting-order:lre-2026-0003',
      },
      // LC-B-009. A restriction recorded at T3 whose effect began at T2, and a second one
      // recorded at T3 whose effect begins at T5. The first is the observation gap, the
      // second is a recorded event that is not yet effective.
      {
        label: 'restrict_resource_account_backdated',
        issuer: COURT,
        effect: 'restrict_execution',
        target: { kind: 'resource', id: RESOURCE_ACCOUNT },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'restraining-order:lre-2026-0004',
      },
      {
        label: 'restrict_counterparty_w_future',
        issuer: REGULATOR,
        effect: 'restrict_execution',
        target: { kind: 'counterparty', id: COUNTERPARTY_UNLISTED },
        effective_at: T5,
        recorded_at: T3,
        standing_basis: 'listing-order:lre-2026-0005',
      },
      // LC-B-027. The release of the account restriction, and separately an ownership
      // transfer of the same account to a different owner.
      {
        label: 'release_resource_account',
        issuer: COURT,
        effect: 'release_restriction',
        target: { kind: 'event', id: '' },
        effective_at: T5,
        recorded_at: T5,
        standing_basis: 'order-dismissing-case:lre-2026-0006',
      },
      {
        label: 'transfer_resource_account',
        issuer: COURT,
        effect: 'transfer_resource_ownership',
        target: { kind: 'resource', id: RESOURCE_ACCOUNT },
        parameters: { new_owner: 'owner:lre-forfeiture-beneficiary' },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'forfeiture-order:lre-2026-0007',
      },
      {
        label: 'release_resource_transfer',
        issuer: COURT,
        effect: 'release_restriction',
        target: { kind: 'event', id: '' },
        effective_at: T5,
        recorded_at: T5,
        standing_basis: 'order-on-motion:lre-2026-0008',
      },
      // LC-B-010 and LC-B-031. A threshold approval gate on the office's authority, with
      // no sunset, and a principal replacement on the same office.
      {
        label: 'gate_officer_threshold',
        issuer: COURT,
        effect: 'add_approval_gate',
        target: { kind: 'principal', id: OFFICER },
        parameters: {
          certifier: CERTIFIER,
          gate_scope: SCOPE_PROCUREMENT,
          threshold_minor: '500000',
          sunset: null,
        },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'order-authorising-operations:lre-2026-0009',
      },
      // LC-B-011. Its release, on an external trigger rather than an internal grant.
      {
        label: 'release_gate_officer',
        issuer: COURT,
        effect: 'release_restriction',
        target: { kind: 'event', id: '' },
        effective_at: T5,
        recorded_at: T5,
        standing_basis: 'order-confirming-plan:lre-2026-0010',
      },
      {
        label: 'replace_officer_by_trustee',
        issuer: COURT,
        effect: 'replace_principal',
        target: { kind: 'principal', id: OFFICER },
        parameters: { successor: TRUSTEE },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'order-appointing-trustee:lre-2026-0011',
      },
      // LC-B-026. A gate imposed by a settlement, with the decree's own sunset date.
      {
        label: 'gate_decree_certification',
        issuer: COURT,
        effect: 'add_approval_gate',
        target: { kind: 'principal', id: ORG },
        parameters: {
          certifier: CERTIFIER,
          gate_scope: SCOPE_REPORT,
          threshold_minor: null,
          sunset: DECREE_SUNSET,
        },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'consent-decree:lre-2026-0012',
      },
      // LC-B-024. Two suspensions of the same principal, from two authorities, for two
      // unrelated causes, and the release of only one of them.
      {
        label: 'suspend_rep_regulatory',
        issuer: REGULATOR,
        effect: 'suspend_principal',
        target: { kind: 'principal', id: REP_OFFICE },
        parameters: { cause_id: 'cause:regulatory-2026-0013' },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'sanction-order:lre-2026-0013',
      },
      {
        label: 'suspend_rep_internal',
        issuer: FIRM,
        effect: 'suspend_principal',
        target: { kind: 'principal', id: REP_OFFICE },
        parameters: { cause_id: 'cause:firm-internal-2026-0014' },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'firm-supervisory-record:lre-2026-0014',
      },
      {
        label: 'release_rep_regulatory',
        issuer: REGULATOR,
        effect: 'release_suspension',
        target: { kind: 'principal', id: REP_OFFICE },
        parameters: { cause_id: 'cause:regulatory-2026-0013' },
        effective_at: T5,
        recorded_at: T5,
        standing_basis: 'expiry-of-sanction-period:lre-2026-0015',
      },
      {
        label: 'release_rep_internal',
        issuer: FIRM,
        effect: 'release_suspension',
        target: { kind: 'principal', id: REP_OFFICE },
        parameters: { cause_id: 'cause:firm-internal-2026-0014' },
        effective_at: T6,
        recorded_at: T6,
        standing_basis: 'firm-supervisory-record:lre-2026-0016',
      },
      // LC-B-025. One revocation of an off-graph dependency many chains declare.
      {
        label: 'revoke_licence',
        issuer: REGULATOR,
        effect: 'revoke_dependency',
        target: { kind: 'dependency', id: DEPENDENCY_LICENCE },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'final-order-of-revocation:lre-2026-0017',
      },
      // LC-B-017. The court order that puts the receiver's root inside the verifier's
      // trust basis, for a root that appears in no other chain.
      {
        label: 'establish_receiver_root',
        issuer: COURT,
        effect: 'establish_trust_root',
        target: { kind: 'root', id: RECEIVER },
        effective_at: T2,
        recorded_at: T3,
        standing_basis: 'order-appointing-receiver:lre-2026-0018',
      },
      // LC-B-007. Ratification of one named past act, by the principal the act named.
      {
        label: 'ratify_historical_act',
        issuer: ORG,
        effect: 'ratify_action',
        target: { kind: 'action', id: ACTIONS['proc-historical'].action_ref },
        effective_at: T3,
        recorded_at: T3,
        standing_basis: 'principal-ratification-record:lre-2026-0019',
      },
      {
        label: 'ratify_historical_act_no_standing',
        issuer: UNREGISTERED,
        effect: 'ratify_action',
        target: { kind: 'action', id: ACTIONS['proc-historical'].action_ref },
        effective_at: T3,
        recorded_at: T3,
        standing_basis: 'asserted-by-the-record-itself',
      },
    ] as EventSpec[]
  ).map((spec) => [spec.label, mintEvent(spec)]),
)

// The four release events name the event they release, which is only knowable once that
// event has an event_id. Minting them in two passes keeps every record content-addressed:
// the release's own event_id covers the id of the event it releases.
function remintRelease(label: string, releases: string): void {
  const base = EVENTS[label]
  EVENTS[label] = mintEvent({
    label,
    issuer: base.issuer,
    effect: base.effect as Effect,
    target: { kind: 'event', id: EVENTS[releases].event_id },
    parameters: base.parameters as Record<string, unknown>,
    effective_at: base.effective_at,
    recorded_at: base.recorded_at,
    standing_basis: base.standing_basis,
  })
}
remintRelease('release_counterparty_v', 'restrict_counterparty_v')
remintRelease('release_resource_account', 'restrict_resource_account_backdated')
remintRelease('release_resource_transfer', 'transfer_resource_account')
remintRelease('release_gate_officer', 'gate_officer_threshold')

// ---------------------------------------------------------------------------
// Certifications. The record a gate's named certifier produces for one action.
// ---------------------------------------------------------------------------

const CERTIFICATION_PROFILE = `${SEED_PREFIX}gate-certification-v0`
const CERTIFICATION_DOMAIN = 'APS-CONFORMANCE-LRE-GATE-CERTIFICATION-V0'

function mintCertification(label: string, gateEventId: string, actionRef: string, certifier: string) {
  const body = {
    profile: CERTIFICATION_PROFILE,
    gate_event_id: gateEventId,
    action_ref: actionRef,
    certifier,
    verification_method: kid(certifier),
    issued_at: T4,
  }
  const signature = sign(`${CERTIFICATION_DOMAIN} ${canonicalizeJCS(body)}`, PRIVATE[certifier])
  return { ...body, signature, _label: label }
}

const CERTIFICATIONS = {
  proc_large: mintCertification('proc_large', EVENTS['gate_officer_threshold'].event_id, ACTIONS['proc-large'].action_ref, CERTIFIER),
  report_in_scope: mintCertification('report_in_scope', EVENTS['gate_decree_certification'].event_id, ACTIONS['report-in-scope'].action_ref, CERTIFIER),
}
for (const value of Object.values(CERTIFICATIONS)) delete (value as { _label?: string })._label

// ---------------------------------------------------------------------------
// The historical act. A real draft-03 action-intent receipt citing the delegation whose
// signature does not verify, which is what makes the act unauthorized at the time.
// Ratification never touches this record: the vectors assert its digest is unchanged.
// ---------------------------------------------------------------------------

const HISTORICAL_RECEIPT = createReceiptV1(
  {
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action-intent:v1',
    issuer: AGENT_PROC,
    subject_agent: AGENT_PROC,
    action_ref: ACTIONS['proc-historical'].action_ref,
    delegation_ref: CHAINS.unsigned_claim[0].delegation_id,
    issued_at: T1,
    evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  } as never,
  [{ signer: AGENT_PROC, key_id: kid(AGENT_PROC), private_key: PRIVATE[AGENT_PROC] }],
) as unknown as Record<string, unknown>

const HISTORICAL_RECEIPT_DIGEST =
  'sha256:' + createHash('sha256').update(canonicalizeJCS(HISTORICAL_RECEIPT), 'utf8').digest('hex')

// ---------------------------------------------------------------------------
// A real draft-03 section 3.5.1 revocation of the officer's own grant, by its own issuer,
// for the evidence-coverage vectors. This is the one lifecycle transition in this family
// that the reference SDKs do implement, and it is used as such.
// ---------------------------------------------------------------------------

const OFFICER_LEAF = CHAINS.officer[1]
const OFFICER_LEAF_REVOCATION = issueAuthorityRevocation(
  OFFICER_LEAF as never,
  {
    now: T2,
    revoker: OFFICER,
    verification_method: kid(OFFICER),
    reason_code: 'external_order',
    nonce: seed('revocation-nonce:officer-leaf:v1').slice(0, 32),
  },
  PRIVATE[OFFICER],
)

// ---------------------------------------------------------------------------
// Verifier trust policy. This fixture's own, because the proposed text names the concept
// and defines no shape for it:
//
//     "Verifier trust policy.  Which issuers, roots, status sources and rules a verifier
//     accepts.  A verifier can stop trusting an issuer without anything being revoked."
//
// lifecycle_standing is keyed by effect, not by issuer, because the same text separates
// issuer standing from lifecycle standing: a party can have standing to end an authority
// artifact it never issued, and standing for one effect is not standing for another.
// ---------------------------------------------------------------------------

const VERIFIER_TRUST_POLICY = {
  lifecycle_standing: {
    terminate_principal_authority: [RECEIVER],
    replace_principal: [COURT],
    restrict_execution: [REGULATOR, COURT],
    release_restriction: [REGULATOR, COURT],
    add_approval_gate: [COURT],
    suspend_principal: [REGULATOR, FIRM],
    release_suspension: [REGULATOR, FIRM],
    revoke_dependency: [REGULATOR],
    transfer_resource_ownership: [COURT],
    ratify_action: [ORG, COMPANY, PAYCO, FIRM],
    establish_trust_root: [COURT],
  },
  trust_roots: {
    // The policy a verifier holds before any court order reaches it: the roots of the
    // organizations whose governance it already knows. RECEIVER is absent.
    closed_to_original_governance: [ORG, PAYCO, FIRM, COMPANY, TRUSTEE],
    // The same policy plus any root an observed, effective establish_trust_root event from
    // a party with standing names. Evaluated by the harness, not listed here.
    accepts_established_roots: [ORG, PAYCO, FIRM, COMPANY, TRUSTEE],
  },
}

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written. Every claim this family
// makes about what an SDK returns is checked here and recorded in chain.json, so the
// README quotes a recorded value rather than a remembered one.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

const resolveVerificationKey = (_issuer: string, method: string) => PUBLIC[method] ?? null

const trackedStore = new InMemoryAuthorityRevocationStore()
for (const chain of Object.values(CHAINS)) for (const record of chain) trackedStore.track(record.delegation_id)
const trackedResolver = createAuthorityRevocationResolver(trackedStore, { resolveVerificationKey })

const prunedStore = new InMemoryAuthorityRevocationStore()
for (const chain of Object.values(CHAINS)) {
  for (const record of chain) {
    if (record.delegation_id !== OFFICER_LEAF.delegation_id) prunedStore.track(record.delegation_id)
  }
}
const prunedResolver = createAuthorityRevocationResolver(prunedStore, { resolveVerificationKey })

const chainOpts = (now: string, resolveRevocation: typeof trackedResolver, trusted: string[]) => ({
  now,
  resolveVerificationKey,
  trustRoot: (root: { issuer: string }) => trusted.includes(root.issuer),
  resolveRevocation,
})

const ALL_ROOTS = [ORG, PAYCO, FIRM, COMPANY, TRUSTEE, RECEIVER]

// Every chain but two verifies valid at T1 and T4 with a fully trusting policy: the
// load-bearing fact of the whole family is that an external event changes the authority
// verdict while the chain itself keeps verifying valid.
const chainStatesT4: Record<string, { state: string; code: string | null }> = {}
for (const [name, chain] of Object.entries(CHAINS)) {
  const result = verifyAuthorityDelegationChain(chain as never, chainOpts(T4, trackedResolver, ALL_ROOTS))
  chainStatesT4[name] = { state: result.state, code: result.failures[0]?.code ?? null }
}
for (const name of ['officer', 'officer_deep', 'decree', 'payments', 'licence_a', 'licence_b', 'licence_c', 'suspension', 'resource', 'resource_regrant', 'receiver', 'trustee'] as ChainName[]) {
  assert(chainStatesT4[name].state === 'valid', `chain ${name} does not verify valid at T4: ${JSON.stringify(chainStatesT4[name])}`)
}
assert(chainStatesT4.unsigned_claim.state === 'invalid' && chainStatesT4.unsigned_claim.code === 'SIGNATURE_INVALID',
  `unsigned_claim should be invalid SIGNATURE_INVALID: ${JSON.stringify(chainStatesT4.unsigned_claim)}`)
assert(chainStatesT4.trustee_deferred.state === 'invalid' && chainStatesT4.trustee_deferred.code === 'NOT_YET_VALID',
  `trustee_deferred should be invalid NOT_YET_VALID at T4: ${JSON.stringify(chainStatesT4.trustee_deferred)}`)

// The receiver-rooted chain under the closed trust policy, and under a policy that also
// accepts the root the court order names. Both answers are the SDK's own.
const receiverClosed = verifyAuthorityDelegationChain(
  CHAINS.receiver as never,
  chainOpts(T4, trackedResolver, VERIFIER_TRUST_POLICY.trust_roots.closed_to_original_governance),
)
assert(receiverClosed.state === 'invalid' && receiverClosed.failures[0]?.code === 'ROOT_UNTRUSTED',
  `receiver chain under the closed policy should be ROOT_UNTRUSTED: ${JSON.stringify(receiverClosed)}`)
const receiverEstablished = verifyAuthorityDelegationChain(
  CHAINS.receiver as never,
  chainOpts(T4, trackedResolver, [...VERIFIER_TRUST_POLICY.trust_roots.accepts_established_roots, RECEIVER]),
)
assert(receiverEstablished.state === 'valid', `receiver chain with the root established should be valid: ${JSON.stringify(receiverEstablished)}`)

// Evidence coverage, both directions, both from the SDK's own resolver contract: a store
// that tracks the delegation and holds no record answers 'active'; a store that has never
// heard of it answers 'unknown', which chain verification reports as indeterminate.
const officerComplete = verifyAuthorityDelegationChain(CHAINS.officer as never, chainOpts(T4, trackedResolver, ALL_ROOTS))
assert(officerComplete.state === 'valid', 'officer chain with complete evidence is not valid')
const officerPruned = verifyAuthorityDelegationChain(CHAINS.officer as never, chainOpts(T4, prunedResolver, ALL_ROOTS))
assert(officerPruned.state === 'indeterminate' && officerPruned.failures[0]?.code === 'REVOCATION_UNKNOWN',
  `officer chain with pruned evidence should be indeterminate REVOCATION_UNKNOWN: ${JSON.stringify(officerPruned)}`)

// The revocation of the officer's leaf verifies, records into the tracked store, and the
// chain then reads invalid REVOKED. This is the one transition here the SDKs implement.
const revocationVerification = verifyAuthorityRevocation(OFFICER_LEAF_REVOCATION, OFFICER_LEAF as never, { resolveVerificationKey })
assert(revocationVerification.state === 'valid', `officer leaf revocation does not verify: ${JSON.stringify(revocationVerification)}`)
const revokedStore = new InMemoryAuthorityRevocationStore()
for (const chain of Object.values(CHAINS)) for (const record of chain) revokedStore.track(record.delegation_id)
const recordResult = recordAuthorityRevocation(revokedStore, OFFICER_LEAF as never, OFFICER_LEAF_REVOCATION, { resolveVerificationKey })
assert(recordResult.recorded, `officer leaf revocation was not recorded: ${JSON.stringify(recordResult)}`)
const revokedResolver = createAuthorityRevocationResolver(revokedStore, { resolveVerificationKey })
const officerRevoked = verifyAuthorityDelegationChain(CHAINS.officer as never, chainOpts(T4, revokedResolver, ALL_ROOTS))
assert(officerRevoked.state === 'invalid' && officerRevoked.failures[0]?.code === 'REVOKED',
  `officer chain after revocation should be invalid REVOKED: ${JSON.stringify(officerRevoked)}`)

// What the SDK refuses. draft-03 section 3.5 names exactly one party who may revoke a
// delegation, its issuer, so an external authority with standing to end the authority
// cannot express that as an AuthorityRevocationV1 at all. Recorded as an SDK answer,
// because it is the sharpest thing this family found.
let externalRevocationRefusal = 'not-refused'
try {
  issueAuthorityRevocation(
    OFFICER_LEAF as never,
    { now: T2, revoker: RECEIVER, verification_method: kid(RECEIVER), reason_code: 'receiver_appointed', nonce: seed('revocation-nonce:external:v1').slice(0, 32) },
    PRIVATE[RECEIVER],
  )
  assert(false, 'issueAuthorityRevocation minted a revocation for a non-issuer revoker')
} catch (error) {
  externalRevocationRefusal = (error as Error).message
}
assert(externalRevocationRefusal.includes('REVOKER_NOT_ISSUER'),
  `expected REVOKER_NOT_ISSUER, got: ${externalRevocationRefusal}`)

// Every external event, dependency binding and certification verifies under exactly the
// rule harness.ts applies.
for (const [label, event] of Object.entries(EVENTS)) {
  const { event_id, signature, ...body } = event
  const preimage = `${EXTERNAL_EVENT_DOMAIN} ${canonicalizeJCS(body)}`
  assert(event_id === 'sha256:' + createHash('sha256').update(preimage, 'utf8').digest('hex'), `${label} event_id does not recompute`)
  assert(verifyEd25519(preimage, signature, PUBLIC[event.verification_method]), `${label} signature does not verify`)
}
for (const [label, binding] of Object.entries(DEPENDENCY_BINDINGS)) {
  const { signature, ...body } = binding
  assert(verifyEd25519(`${DEPENDENCY_BINDING_DOMAIN} ${canonicalizeJCS(body)}`, signature, PUBLIC[binding.verification_method]),
    `dependency binding ${label} does not verify`)
}
for (const [label, cert] of Object.entries(CERTIFICATIONS)) {
  const { signature, ...body } = cert
  assert(verifyEd25519(`${CERTIFICATION_DOMAIN} ${canonicalizeJCS(body)}`, signature, PUBLIC[cert.verification_method]),
    `certification ${label} does not verify`)
}

// Distinct identities everywhere it matters.
const allDelegationIds = Object.values(CHAINS).flat().map((r) => r.delegation_id)
assert(new Set(allDelegationIds).size === allDelegationIds.length, 'two delegations share a delegation_id')
const allEventIds = Object.values(EVENTS).map((e) => e.event_id)
assert(new Set(allEventIds).size === allEventIds.length, 'two external events share an event_id')
const allActionRefs = Object.values(ACTIONS).map((a) => a.action_ref)
assert(new Set(allActionRefs).size === allActionRefs.length, 'two actions share an action_ref')

// The gate scope match is the SDK's own scope primitive, not a string compare.
assert(scopeGrantCovers(SCOPE_PROCUREMENT, SCOPE_PROCUREMENT), 'scopeGrantCovers rejected an exact grant match')
assert(!scopeGrantCovers(SCOPE_REPORT, SCOPE_PROCUREMENT), 'scopeGrantCovers accepted a scope the gate does not name')

// ---------------------------------------------------------------------------
// Write. Keys are sorted at every depth so the file is a function of its content.
// ---------------------------------------------------------------------------

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

const chain = {
  profile: 'aps-lifecycle-legal-regulatory-events-v0',
  description:
    'External authority events that end, suspend, narrow, gate, release or re-root ' +
    'authority without any delegation record changing. Thirteen chains, three dependency ' +
    'bindings, twenty-one external authority events, two gate certifications, one ' +
    'draft-03 revocation and one historical action-intent receipt, minted and verified ' +
    'with agent-passport-system 7.1.0.',
  minted_by: 'fixtures/lifecycle-legal-regulatory-events/mint.ts',
  seed_label_prefix: SEED_PREFIX,
  sdk: { typescript: 'agent-passport-system@7.1.0' },
  identities: {
    org: ORG, finance_office: OFFICER, procurement_agent: AGENT_PROC, procurement_subagent: AGENT_SUB,
    reporting_agent: AGENT_REPORT, payments_company: PAYCO, payments_agent_a: AGENT_PAY_A,
    payments_agent_b: AGENT_PAY_B, payments_agent_c: AGENT_PAY_C, firm: FIRM,
    representative_office: REP_OFFICE, advice_agent: AGENT_ADVICE, company: COMPANY,
    treasury_agent: AGENT_TREASURY, collections_agent: AGENT_COLLECT, court: COURT,
    regulator: REGULATOR, receiver: RECEIVER, trustee: TRUSTEE, certifier: CERTIFIER,
    unregistered_authority: UNREGISTERED,
  },
  off_graph_targets: {
    counterparty_listed: COUNTERPARTY_LISTED,
    counterparty_unlisted: COUNTERPARTY_UNLISTED,
    resource_account: RESOURCE_ACCOUNT,
    dependency_licence: DEPENDENCY_LICENCE,
  },
  verification_keys: PUBLIC,
  timeline: { t0_issued: T0, t1_before: T1, t2_effective: T2, t3_recorded: T3, t4_after: T4, t5_release: T5, t6_after_release: T6, t7_deferred_not_before: T7, not_after: NOT_AFTER, decree_sunset: DECREE_SUNSET },
  signature_domains: {
    external_authority_event: EXTERNAL_EVENT_DOMAIN,
    dependency_binding: DEPENDENCY_BINDING_DOMAIN,
    gate_certification: CERTIFICATION_DOMAIN,
  },
  profiles: {
    external_authority_event: EXTERNAL_EVENT_PROFILE,
    dependency_binding: DEPENDENCY_BINDING_PROFILE,
    gate_certification: CERTIFICATION_PROFILE,
  },
  verifier_trust_policy: VERIFIER_TRUST_POLICY,
  chains: CHAINS,
  dependency_bindings: DEPENDENCY_BINDINGS,
  external_events: EVENTS,
  certifications: CERTIFICATIONS,
  revocations: { officer_leaf: OFFICER_LEAF_REVOCATION },
  actions: ACTIONS,
  historical_receipt: HISTORICAL_RECEIPT,
  historical_receipt_digest: HISTORICAL_RECEIPT_DIGEST,
  mint_time_sdk_observations: {
    chain_state_at_t4: chainStatesT4,
    receiver_root_under_closed_policy: { state: receiverClosed.state, first_failure_code: receiverClosed.failures[0]?.code ?? null },
    receiver_root_with_established_root: { state: receiverEstablished.state, first_failure_code: receiverEstablished.failures[0]?.code ?? null },
    officer_chain_complete_evidence: { state: officerComplete.state, first_failure_code: officerComplete.failures[0]?.code ?? null },
    officer_chain_pruned_evidence: { state: officerPruned.state, first_failure_code: officerPruned.failures[0]?.code ?? null },
    officer_leaf_revocation_verification: revocationVerification.state,
    officer_chain_after_revocation: { state: officerRevoked.state, first_failure_code: officerRevoked.failures[0]?.code ?? null },
    external_revoker_refusal: externalRevocationRefusal,
  },
}

fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('lifecycle-legal-regulatory-events: chain.json minted')
console.log(`  chains verifying valid at T4: ${Object.entries(chainStatesT4).filter(([, v]) => v.state === 'valid').length}/${Object.keys(chainStatesT4).length}`)
console.log(`  receiver root under the closed trust policy: ${receiverClosed.state}/${receiverClosed.failures[0]?.code ?? null}`)
console.log(`  officer chain with pruned evidence: ${officerPruned.state}/${officerPruned.failures[0]?.code ?? null}`)
console.log(`  external revoker refusal: ${externalRevocationRefusal}`)
