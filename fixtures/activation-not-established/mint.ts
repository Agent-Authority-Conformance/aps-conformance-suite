// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mints chain.json for the activation-not-established fixture, byte for byte.
//
// Keys are Ed25519 seeds derived from the published labels below, so the file
// carries no secret material and anyone can regenerate it. The seed convention
// is the one docs/fixture-format.md records for this suite:
//
//   seed = SHA-256("aps-conformance-suite:acx:" + label)
//
// v2 of this family. v1 had one negative verdict. This version separates two:
// not_yet_effective, where the verifier establishes the condition has not been
// met, and not_established, where the verifier cannot tell whether it was met
// or the only evidence comes from a source the model does not accept. The
// no-retroactive-activation records are built on the condition's own occurrence
// instant rather than on the instant the attestation was written.
//
// What this mints, and why each artifact exists:
//
//   GRANT               one-hop principal -> agent AuthorityDelegationV1, valid
//                       window open over every action instant in vectors.json.
//                       Carries the recorded-event activation condition.
//   GRANT_DATED         same window, same subject, carrying a date activation
//                       condition whose activation_date falls between T_ACTION
//                       and T_LATER_ACTION. The chain is valid at both, so the
//                       verdict difference between the two instants comes from
//                       the condition and not from the chain.
//   GRANT_FUTURE_WINDOW one-hop principal -> agent, no activation condition,
//                       whose time facet not_before is the same instant as
//                       GRANT_DATED's activation_date. That equality is asserted
//                       at mint time: the two records differ only in which
//                       mechanism carries the wait, and they get different
//                       answers from different deciders.
//   ten attestations    fixture-local records, record_type
//                       "fixture:activation-attestation:v0". This is NOT an APS
//                       record type and no SDK claims it. Each is canonicalized
//                       under RFC 8785 with the SDK's own canonicalizeJCS and
//                       signed with the SDK's own Ed25519 primitive, so both
//                       runners rebuild the same preimage bytes.
//
// Each attestation carries an "assertion" member that is either
// condition_occurred, which names the instant the event occurred in
// occurred_at, or condition_not_occurred_through, which names the instant
// through which the attestor states the event had not occurred in
// not_occurred_through. attested_at, when the record itself was written, is
// separate from both and never decides a verdict.
//
// The activation condition itself is a fixture-supplied object. It is not a
// facet of AuthorityDelegationV1: that record's AuthorityVectorV1 is a closed
// set of seven facets (scope, spend, depth, time, reputation, values,
// reversibility) and neither reference SDK exposes any activation-condition,
// attestor-role or attestation-acceptance API. The README says so at length.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/activation-not-established/mint.ts
//
// Then `git diff` on chain.json should be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  issueAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
  verify,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// One clock for the whole family. Every vector's action instant is one of
// these, and every attestation timestamp is one of these.
const CLOCK = {
  T_GRANT_ISSUED: '2026-09-20T08:00:00.000Z',
  T_GRANT_NOT_AFTER: '2026-09-22T00:00:00.000Z',
  T_STALE_THROUGH: '2026-09-20T08:30:00.000Z',
  T_EVENT: '2026-09-20T09:00:00.000Z',
  T_ATTESTED: '2026-09-20T09:05:00.000Z',
  T_ACTION: '2026-09-20T10:00:00.000Z',
  T_LATE_EVENT: '2026-09-20T10:30:00.000Z',
  T_LATE_ATTESTED: '2026-09-20T11:00:00.000Z',
  T_ACTIVATION_DATE: '2026-09-20T11:30:00.000Z',
  T_LATER_ACTION: '2026-09-20T12:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:acx-principal'
const AGENT = 'did:aps:example:acx-agent'
const MONITOR_A = 'did:aps:example:acx-monitor-a'
const AUDITOR_B = 'did:aps:example:acx-auditor-b'

const REQUIRED_ROLE = 'outage-monitor'
const AUDITOR_ROLE = 'billing-auditor'

const EVENT_CONDITION = {
  condition_id: 'acx-cond-outage-1',
  condition_type: 'recorded_event',
  description:
    'This grant becomes exercisable for an action only once an attestor holding the required role has attested that the named outage event had occurred at or before that action instant.',
  event_type: 'service_outage_declared',
  event_id: 'acx-outage-2026-09-20',
  required_attestor_role: REQUIRED_ROLE,
}

const DATE_CONDITION = {
  condition_id: 'acx-cond-date-1',
  condition_type: 'date',
  description:
    'This grant becomes exercisable at the stated activation date. No attestation is involved: the verifier reads the date off the condition and compares it with the action instant.',
  activation_date: CLOCK.T_ACTIVATION_DATE,
}

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:acx:${label}`).digest('hex')
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function authorityVector(notBefore: string, notAfter: string) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: ['failover:execute'] },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: 0 },
    time: { not_before: notBefore, not_after: notAfter },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

type OccurredBody = {
  record_type: 'fixture:activation-attestation:v0'
  version: '0.1'
  assertion: 'condition_occurred'
  attestor: string
  attestor_role: string
  condition_id: string
  event_id: string
  event_type: string
  occurred_at: string
  attested_at: string
  verification_method: string
}

type NotOccurredBody = {
  record_type: 'fixture:activation-attestation:v0'
  version: '0.1'
  assertion: 'condition_not_occurred_through'
  attestor: string
  attestor_role: string
  condition_id: string
  event_id: string
  event_type: string
  not_occurred_through: string
  attested_at: string
  verification_method: string
}

function mintAttestation(
  label: string,
  body: OccurredBody | NotOccurredBody,
  signingPrivateKey: string,
) {
  const full = {
    ...body,
    attestation_id_note:
      'attestation_id is SHA-256 over the RFC 8785 canonical bytes of this body, with no id or signature member present.',
    nonce: seed(`${label}-nonce:v1`).slice(0, 32),
  }
  const preimage = canonicalizeJCS(full)
  return {
    ...full,
    attestation_id: sha256Hex(preimage),
    signature: sign(preimage, signingPrivateKey),
  }
}

function main(): void {
  const principalPriv = seed('principal:v1')
  const agentPriv = seed('agent:v1')
  const monitorAPriv = seed('monitor-a:v1')
  const auditorBPriv = seed('auditor-b:v1')

  const verificationKeys: Record<string, string> = {
    [`${PRINCIPAL}#key-1`]: publicKeyFromPrivate(principalPriv),
    // The agent never issues a further delegation here (depth.remaining is 0),
    // so no verification resolves this key. It is published so the fixture
    // states, rather than merely implies, that the subject has one identity.
    [`${AGENT}#key-1`]: publicKeyFromPrivate(agentPriv),
    [`${MONITOR_A}#key-1`]: publicKeyFromPrivate(monitorAPriv),
    [`${AUDITOR_B}#key-1`]: publicKeyFromPrivate(auditorBPriv),
  }

  const grant = issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: PRINCIPAL,
      subject: AGENT,
      verification_method: `${PRINCIPAL}#key-1`,
      issued_at: CLOCK.T_GRANT_ISSUED,
      nonce: seed('grant-nonce:v1').slice(0, 32),
      authority: authorityVector(CLOCK.T_GRANT_ISSUED, CLOCK.T_GRANT_NOT_AFTER),
    },
    principalPriv,
  )

  const grantDated = issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: PRINCIPAL,
      subject: AGENT,
      verification_method: `${PRINCIPAL}#key-1`,
      issued_at: CLOCK.T_GRANT_ISSUED,
      nonce: seed('grant-dated-nonce:v1').slice(0, 32),
      authority: authorityVector(CLOCK.T_GRANT_ISSUED, CLOCK.T_GRANT_NOT_AFTER),
    },
    principalPriv,
  )

  const grantFutureWindow = issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: PRINCIPAL,
      subject: AGENT,
      verification_method: `${PRINCIPAL}#key-1`,
      issued_at: CLOCK.T_GRANT_ISSUED,
      nonce: seed('grant-future-window-nonce:v1').slice(0, 32),
      authority: authorityVector(CLOCK.T_ACTIVATION_DATE, CLOCK.T_GRANT_NOT_AFTER),
    },
    principalPriv,
  )

  function occurred(
    attestor: string,
    role: string,
    eventId: string,
    occurredAt: string,
    attestedAt: string,
    verificationMethod: string,
  ): OccurredBody {
    return {
      record_type: 'fixture:activation-attestation:v0',
      version: '0.1',
      assertion: 'condition_occurred',
      attestor,
      attestor_role: role,
      condition_id: EVENT_CONDITION.condition_id,
      event_id: eventId,
      event_type: EVENT_CONDITION.event_type,
      occurred_at: occurredAt,
      attested_at: attestedAt,
      verification_method: verificationMethod,
    }
  }

  function notOccurred(
    attestor: string,
    role: string,
    through: string,
    attestedAt: string,
    verificationMethod: string,
  ): NotOccurredBody {
    return {
      record_type: 'fixture:activation-attestation:v0',
      version: '0.1',
      assertion: 'condition_not_occurred_through',
      attestor,
      attestor_role: role,
      condition_id: EVENT_CONDITION.condition_id,
      event_id: EVENT_CONDITION.event_id,
      event_type: EVENT_CONDITION.event_type,
      not_occurred_through: through,
      attested_at: attestedAt,
      verification_method: verificationMethod,
    }
  }

  const attestations = {
    // Acceptable, and the occurrence precedes T_ACTION. Registry role matches
    // the required role, the self-declared role agrees with the registry, the
    // condition binding matches.
    ATT_MONITOR_OCCURRED_ON_TIME: mintAttestation(
      'att-monitor-occurred-on-time',
      occurred(
        MONITOR_A,
        REQUIRED_ROLE,
        EVENT_CONDITION.event_id,
        CLOCK.T_EVENT,
        CLOCK.T_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      monitorAPriv,
    ),
    // The same occurrence instant, written down after the action. Evidence
    // created after an action may still establish a condition that obtained
    // before it, so the reference gate accepts this for an action at T_ACTION.
    // A gate that keys on the attestation date rejects it, which is the defect
    // N2 exists to expose.
    ATT_MONITOR_OCCURRED_ATTESTED_LATE: mintAttestation(
      'att-monitor-occurred-attested-late',
      occurred(
        MONITOR_A,
        REQUIRED_ROLE,
        EVENT_CONDITION.event_id,
        CLOCK.T_EVENT,
        CLOCK.T_LATE_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      monitorAPriv,
    ),
    // Acceptable evidence whose occurrence instant is after T_ACTION. For an
    // action at T_ACTION this establishes that the condition had not been met
    // yet, which is not yet effective and not the same finding as an absence of
    // evidence. For an action at T_LATER_ACTION the same record establishes the
    // condition.
    ATT_MONITOR_OCCURRED_AFTER_ACTION: mintAttestation(
      'att-monitor-occurred-after-action',
      occurred(
        MONITOR_A,
        REQUIRED_ROLE,
        EVENT_CONDITION.event_id,
        CLOCK.T_LATE_EVENT,
        CLOCK.T_LATE_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      monitorAPriv,
    ),
    // Wrong role, honestly declared. A source the model does not accept for
    // this condition, so nothing it says is evidence either way.
    ATT_AUDITOR_HONEST_ROLE: mintAttestation(
      'att-auditor-honest-role',
      occurred(
        AUDITOR_B,
        AUDITOR_ROLE,
        EVENT_CONDITION.event_id,
        CLOCK.T_EVENT,
        CLOCK.T_ATTESTED,
        `${AUDITOR_B}#key-1`,
      ),
      auditorBPriv,
    ),
    // The negative control. A genuine signature from auditor_b over a body that
    // claims the required role. Everything an implementation can read off the
    // record itself looks right. Only the attestor-role registry says
    // otherwise.
    ATT_AUDITOR_CLAIMS_MONITOR_ROLE: mintAttestation(
      'att-auditor-claims-monitor-role',
      occurred(
        AUDITOR_B,
        REQUIRED_ROLE,
        EVENT_CONDITION.event_id,
        CLOCK.T_EVENT,
        CLOCK.T_ATTESTED,
        `${AUDITOR_B}#key-1`,
      ),
      auditorBPriv,
    ),
    // Right attestor, right role, wrong event: the condition names one event id
    // and this attestation names another.
    ATT_MONITOR_WRONG_EVENT: mintAttestation(
      'att-monitor-wrong-event',
      occurred(
        MONITOR_A,
        REQUIRED_ROLE,
        'acx-outage-2026-08-11',
        CLOCK.T_EVENT,
        CLOCK.T_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      monitorAPriv,
    ),
    // A body that names monitor_a and monitor_a's verification method, signed
    // with auditor_b's private key. The signature does not verify under the key
    // the body points at.
    ATT_MONITOR_FORGED_SIGNATURE: mintAttestation(
      'att-monitor-forged-signature',
      occurred(
        MONITOR_A,
        REQUIRED_ROLE,
        EVENT_CONDITION.event_id,
        CLOCK.T_EVENT,
        CLOCK.T_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      auditorBPriv,
    ),
    // The accepted negative. The required role states the event had not
    // occurred through T_ACTION, so an action at T_ACTION is not yet effective
    // rather than not established. Written after the action, which the gate
    // does not hold against it.
    ATT_MONITOR_NOT_OCCURRED_THROUGH_ACTION: mintAttestation(
      'att-monitor-not-occurred-through-action',
      notOccurred(
        MONITOR_A,
        REQUIRED_ROLE,
        CLOCK.T_ACTION,
        CLOCK.T_LATE_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      monitorAPriv,
    ),
    // A negative from the right role that stops short of the action instant. It
    // says nothing about the interval between T_STALE_THROUGH and T_ACTION, so
    // it leaves the verifier unable to tell.
    ATT_MONITOR_NOT_OCCURRED_STALE: mintAttestation(
      'att-monitor-not-occurred-stale',
      notOccurred(
        MONITOR_A,
        REQUIRED_ROLE,
        CLOCK.T_STALE_THROUGH,
        CLOCK.T_ATTESTED,
        `${MONITOR_A}#key-1`,
      ),
      monitorAPriv,
    ),
    // The same negative statement, covering the action instant, from a source
    // the model does not accept for this condition. A negative from an
    // unaccepted source does not establish the known negative any more than a
    // positive from one establishes the condition.
    ATT_AUDITOR_NOT_OCCURRED_THROUGH_ACTION: mintAttestation(
      'att-auditor-not-occurred-through-action',
      notOccurred(
        AUDITOR_B,
        AUDITOR_ROLE,
        CLOCK.T_ACTION,
        CLOCK.T_LATE_ATTESTED,
        `${AUDITOR_B}#key-1`,
      ),
      auditorBPriv,
    ),
  }

  // Mint-time assertions. If any fails, chain.json is not written, so a broken
  // fixture cannot be committed silently.
  const resolveKey = (_issuer: string, method: string) => verificationKeys[method] ?? null
  const assertions: Array<[string, boolean]> = []

  function chainAt(records: unknown[], now: string) {
    return verifyAuthorityDelegationChain(records as never, {
      now,
      resolveVerificationKey: resolveKey as never,
      trustRoot: () => true,
      resolveRevocation: () => 'active',
    })
  }

  assertions.push([
    'GRANT verifies valid at T_ACTION with an active resolver',
    chainAt([grant], CLOCK.T_ACTION).state === 'valid',
  ])
  assertions.push([
    'GRANT verifies valid at T_LATER_ACTION with an active resolver',
    chainAt([grant], CLOCK.T_LATER_ACTION).state === 'valid',
  ])
  // The dated grant's chain must be valid at both instants, so that the verdict
  // difference between them comes from the activation condition alone.
  assertions.push([
    'GRANT_DATED verifies valid at T_ACTION, so its not-yet-effective verdict is not a chain result',
    chainAt([grantDated], CLOCK.T_ACTION).state === 'valid',
  ])
  assertions.push([
    'GRANT_DATED verifies valid at T_LATER_ACTION',
    chainAt([grantDated], CLOCK.T_LATER_ACTION).state === 'valid',
  ])

  const futureAtAction = chainAt([grantFutureWindow], CLOCK.T_ACTION)
  assertions.push([
    'GRANT_FUTURE_WINDOW verifies invalid/NOT_YET_VALID at T_ACTION',
    futureAtAction.state === 'invalid' && futureAtAction.failures[0]?.code === 'NOT_YET_VALID',
  ])
  // The contrast the family is built on: one instant, two mechanisms, two
  // deciders, two answers. If these ever drift apart the contrast is gone and
  // the fixture should not mint.
  assertions.push([
    "GRANT_FUTURE_WINDOW's not_before is the same instant as GRANT_DATED's activation_date",
    grantFutureWindow.authority.time.not_before === DATE_CONDITION.activation_date,
  ])
  assertions.push([
    'the activation date falls strictly between T_ACTION and T_LATER_ACTION',
    CLOCK.T_ACTION < DATE_CONDITION.activation_date && DATE_CONDITION.activation_date < CLOCK.T_LATER_ACTION,
  ])
  assertions.push([
    'the late occurrence instant falls strictly between T_ACTION and T_LATER_ACTION',
    CLOCK.T_ACTION < CLOCK.T_LATE_EVENT && CLOCK.T_LATE_EVENT < CLOCK.T_LATER_ACTION,
  ])
  assertions.push([
    'the stale negative stops strictly before T_ACTION',
    CLOCK.T_STALE_THROUGH < CLOCK.T_ACTION,
  ])
  assertions.push([
    'ATT_MONITOR_OCCURRED_ATTESTED_LATE was written after the action it is presented for',
    attestations.ATT_MONITOR_OCCURRED_ATTESTED_LATE.attested_at > CLOCK.T_ACTION &&
      attestations.ATT_MONITOR_OCCURRED_ATTESTED_LATE.occurred_at < CLOCK.T_ACTION,
  ])

  const delegationIds = [grant.delegation_id, grantDated.delegation_id, grantFutureWindow.delegation_id]
  assertions.push([
    'the three grants have distinct delegation ids',
    new Set(delegationIds).size === delegationIds.length,
  ])

  const ids = Object.values(attestations).map(a => a.attestation_id)
  assertions.push(['every attestation has a distinct attestation_id', new Set(ids).size === ids.length])

  for (const [label, att] of Object.entries(attestations)) {
    const { attestation_id: _id, signature, ...body } = att
    const preimage = canonicalizeJCS(body)
    assertions.push([`${label} attestation_id recomputes from its body`, sha256Hex(preimage) === _id])
    const signatureVerifies = verify(preimage, signature, verificationKeys[att.verification_method])
    const shouldVerify = label !== 'ATT_MONITOR_FORGED_SIGNATURE'
    assertions.push([
      `${label} signature verifies under its own verification_method: expected ${shouldVerify}`,
      signatureVerifies === shouldVerify,
    ])
  }

  const failed = assertions.filter(([, ok]) => !ok)
  if (failed.length > 0) {
    for (const [name] of failed) console.error(`MINT ASSERTION FAILED: ${name}`)
    process.exit(2)
  }

  const fixture = {
    _note:
      'Generated by fixtures/activation-not-established/mint.ts. Do not hand-edit: every signature and id here recomputes from the published seed labels.',
    fixture_version: 'v2',
    fixture_version_note:
      'v2 separates not_yet_effective from not_established and keys the no-retroactive-activation records on the occurrence instant rather than the attestation instant. v1 had one negative verdict and keyed on attested_at.',
    sdk: {
      npm_package: 'agent-passport-system',
      npm_version: '7.1.0',
      note: 'The AuthorityDelegationV1 records and every signature here were minted by this package. The activation conditions, the attestor-role registry and the attestation record type are supplied by this fixture, not by the SDK.',
    },
    seed_convention: 'sha256("aps-conformance-suite:acx:" + label)',
    seed_labels: [
      'principal:v1',
      'agent:v1',
      'monitor-a:v1',
      'auditor-b:v1',
      'grant-nonce:v1',
      'grant-dated-nonce:v1',
      'grant-future-window-nonce:v1',
      'att-monitor-occurred-on-time-nonce:v1',
      'att-monitor-occurred-attested-late-nonce:v1',
      'att-monitor-occurred-after-action-nonce:v1',
      'att-auditor-honest-role-nonce:v1',
      'att-auditor-claims-monitor-role-nonce:v1',
      'att-monitor-wrong-event-nonce:v1',
      'att-monitor-forged-signature-nonce:v1',
      'att-monitor-not-occurred-through-action-nonce:v1',
      'att-monitor-not-occurred-stale-nonce:v1',
      'att-auditor-not-occurred-through-action-nonce:v1',
    ],
    clock: CLOCK,
    verification_keys: verificationKeys,
    // The registry is what the reference gate treats as authoritative about a
    // role. An attestation's own attestor_role member is the attestor's claim
    // about itself, which is exactly what the AX-04 negative control turns on.
    attestor_role_registry: {
      [MONITOR_A]: REQUIRED_ROLE,
      [AUDITOR_B]: AUDITOR_ROLE,
    },
    activation_conditions: {
      GRANT: EVENT_CONDITION,
      GRANT_DATED: DATE_CONDITION,
      GRANT_FUTURE_WINDOW: null,
    },
    roles: {
      PRINCIPAL_TO_AGENT: grant.delegation_id,
      PRINCIPAL_TO_AGENT_DATED: grantDated.delegation_id,
      PRINCIPAL_TO_AGENT_FUTURE_WINDOW: grantFutureWindow.delegation_id,
    },
    chains: {
      GRANT: [grant],
      GRANT_DATED: [grantDated],
      GRANT_FUTURE_WINDOW: [grantFutureWindow],
    },
    attestations,
  }

  fs.writeFileSync(
    path.join(here, 'chain.json'),
    JSON.stringify(fixture, null, 2) + '\n',
    'utf8',
  )
  console.log(`activation-not-established mint: ${assertions.length} mint-time assertions passed, chain.json written`)
}

main()
