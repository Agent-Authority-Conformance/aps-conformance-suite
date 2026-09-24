// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for the lifecycle-policy-change family.
//
// Mints, with the pinned TypeScript SDK `agent-passport-system`:
//   - one one-hop AuthorityDelegationV1 grant, issued while policy version v1 was
//     operative and never revoked, expired or suspended
//   - three signed policy-version records for one policy_id. v3 carries rules that
//     are byte-identical to v1's under RFC 8785 JCS, and is still a different
//     version record with a different version digest
//   - six signed operative-pointer records, including a competing pair that share
//     one effective_from, a pointer claiming a rollback to a version that did not
//     exist before it, and a pointer signed by a key with no policy standing
//   - four authorization-decision records, three pinned to the policy version they
//     were evaluated against and one carrying no pin at all
//
// Every Ed25519 key is the SHA-256 of a published label, every nonce is derived the
// same way, and every timestamp is pinned, so `git diff` on chain.json is empty after
// a second run. No secret material is in the file.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-policy-change/mint.ts

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

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-policy-change'
const SDK_VERSION = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version as string

const GENERATED_AT = '2026-09-23'
const NOW = '2026-09-23T12:00:00.000Z'

const DELEGATION_ISSUED_AT = '2026-09-20T09:00:00.000Z'
const NOT_AFTER = '2026-09-30T00:00:00.000Z'

const PRINCIPAL = 'did:aps:example:lpc-principal'
const AGENT = 'did:aps:example:lpc-agent'
const POLICY_AUTHORITY = 'did:aps:example:lpc-policy-authority'
const OUTSIDER = 'did:aps:example:lpc-outsider'

const POLICY_ID = 'ledger-export-policy'

// Domain-separated digests, in the style draft-pidlisnyi-aps-03 uses for payload_ref
// and action_ref. No SDK computes either of these; see README "SDK findings".
const POLICY_VERSION_DIGEST_DOMAIN = 'APS-LPC-POLICY-VERSION-V0'
const POLICY_RULES_DIGEST_DOMAIN = 'APS-LPC-POLICY-RULES-V0'
const POINTER_DIGEST_DOMAIN = 'APS-LPC-OPERATIVE-POINTER-V0'
const DECISION_DIGEST_DOMAIN = 'APS-LPC-DECISION-RECORD-V0'

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
    console.error(`lifecycle-policy-change mint: ${message}`)
    process.exit(2)
  }
}

// ── the grant ────────────────────────────────────────────────────────────────

function delegationBody(): AuthorityDelegationBodyV1 {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject: AGENT,
    verification_method: `${PRINCIPAL}#key-1`,
    issued_at: DELEGATION_ISSUED_AT,
    nonce: seed('nonce:grant:v1').slice(0, 32),
    authority: {
      scope: { profile: 'aps-hierarchical-v1' as const, grants: ['ledger:export', 'ledger:read'] },
      spend: { mode: 'unbounded' as const },
      depth: { remaining: 0 },
      time: { not_before: DELEGATION_ISSUED_AT, not_after: NOT_AFTER },
      reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
      reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
    },
  }
}

// ── policy versions ──────────────────────────────────────────────────────────
//
// A rule set this family can evaluate mechanically: a ceiling on the exported
// amount, and whether an approval record is required for the action at all.

type Rules = { max_amount: number; approval_required: boolean }

const RULES_PERMISSIVE: Rules = { approval_required: false, max_amount: 5000 }
const RULES_TIGHTENED: Rules = { approval_required: true, max_amount: 1000 }

function policyVersion(versionId: string, authoredAt: string, rules: Rules, privateKey: string) {
  const body = {
    record_type: 'aps-lab:policy-version:v0',
    policy_id: POLICY_ID,
    version_id: versionId,
    action: 'ledger:export',
    authored_at: authoredAt,
    authority: POLICY_AUTHORITY,
    rules,
  }
  return {
    ...body,
    rules_digest: digest(POLICY_RULES_DIGEST_DOMAIN, rules),
    version_digest: digest(POLICY_VERSION_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), privateKey),
  }
}

// ── operative pointers ───────────────────────────────────────────────────────

function pointer(input: {
  label: string
  operativeVersionId: string
  effectiveFrom: string
  kind: 'initial' | 'upgrade' | 'rollback'
  supersedes: string | null
  authority: string
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:operative-pointer:v0',
    policy_id: POLICY_ID,
    operative_version_id: input.operativeVersionId,
    effective_from: input.effectiveFrom,
    kind: input.kind,
    supersedes: input.supersedes,
    authority: input.authority,
    nonce: seed(`pointer:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    pointer_id: digest(POINTER_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

// ── decision records ─────────────────────────────────────────────────────────

function decision(input: {
  label: string
  decidedAt: string
  amount: number
  approvalPresented: boolean
  outcome: 'allow' | 'deny'
  policyVersionId: string | null
  policyVersionDigest: string | null
  privateKey: string
}) {
  const body = {
    record_type: 'aps-lab:authorization-decision:v0',
    policy_id: POLICY_ID,
    action: 'ledger:export',
    subject: AGENT,
    amount: input.amount,
    approval_presented: input.approvalPresented,
    decided_at: input.decidedAt,
    outcome: input.outcome,
    policy_version_id: input.policyVersionId,
    policy_version_digest: input.policyVersionDigest,
    nonce: seed(`decision:${input.label}`).slice(0, 32),
  }
  return {
    ...body,
    decision_id: digest(DECISION_DIGEST_DOMAIN, body),
    signature: sign(canonicalizeJCS(body), input.privateKey),
  }
}

/** The one rule evaluator this family has. Both runners reimplement it. */
function evaluate(rules: Rules, amount: number, approvalPresented: boolean): 'allow' | 'deny' {
  if (amount > rules.max_amount) return 'deny'
  if (rules.approval_required && !approvalPresented) return 'deny'
  return 'allow'
}

function main(): void {
  const principalPriv = seed('principal:v1')
  const policyAuthorityPriv = seed('policy-authority:v1')
  const outsiderPriv = seed('outsider:v1')
  const gatewayPriv = seed('gateway:v1')

  const verificationKeys: Record<string, string> = {
    [`${PRINCIPAL}#key-1`]: publicKeyFromPrivate(principalPriv),
    [`${AGENT}#key-1`]: publicKeyFromPrivate(seed('agent:v1')),
  }
  const recordKeys: Record<string, string> = {
    [POLICY_AUTHORITY]: publicKeyFromPrivate(policyAuthorityPriv),
    [OUTSIDER]: publicKeyFromPrivate(outsiderPriv),
    'did:aps:example:lpc-gateway': publicKeyFromPrivate(gatewayPriv),
  }

  const grant = issueAuthorityDelegation(delegationBody(), principalPriv)

  const chainResult = verifyAuthorityDelegationChain([grant as AuthorityDelegationV1], {
    now: NOW,
    resolveVerificationKey: (_issuer, method) => verificationKeys[method] ?? null,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  })
  assert(
    chainResult.state === 'valid',
    `the grant must verify valid at ${NOW} with an active resolver, got ${chainResult.state}`,
  )

  const v1 = policyVersion('v1', '2026-09-19T08:00:00.000Z', RULES_PERMISSIVE, policyAuthorityPriv)
  const v2 = policyVersion('v2', '2026-09-21T08:00:00.000Z', RULES_TIGHTENED, policyAuthorityPriv)
  // v3 carries the same rules object as v1, authored later. Its rules digest equals
  // v1's. Its version digest does not. This is the "fresh edit that happens to
  // reproduce old text" the family exists to separate from a rollback.
  const v3 = policyVersion('v3', '2026-09-22T20:00:00.000Z', RULES_PERMISSIVE, policyAuthorityPriv)

  assert(v3.rules_digest === v1.rules_digest, 'v3 must carry byte-identical rules to v1')
  assert(v3.version_digest !== v1.version_digest, 'v3 must still be a distinct policy version record')
  assert(v2.rules_digest !== v1.rules_digest, 'v2 must differ from v1 in rules')

  const pointers = {
    P1_initial_v1: pointer({
      label: 'p1',
      operativeVersionId: 'v1',
      effectiveFrom: '2026-09-19T12:00:00.000Z',
      kind: 'initial',
      supersedes: null,
      authority: POLICY_AUTHORITY,
      privateKey: policyAuthorityPriv,
    }),
    P2_upgrade_v2: pointer({
      label: 'p2',
      operativeVersionId: 'v2',
      effectiveFrom: '2026-09-21T12:00:00.000Z',
      kind: 'upgrade',
      supersedes: null,
      authority: POLICY_AUTHORITY,
      privateKey: policyAuthorityPriv,
    }),
    P3_rollback_v1: pointer({
      label: 'p3',
      operativeVersionId: 'v1',
      effectiveFrom: '2026-09-22T12:00:00.000Z',
      kind: 'rollback',
      supersedes: null,
      authority: POLICY_AUTHORITY,
      privateKey: policyAuthorityPriv,
    }),
    // Shares P3's effective_from exactly. Two signed pointers, one instant, nothing
    // in either record that orders them.
    P4_competing_v2: pointer({
      label: 'p4',
      operativeVersionId: 'v2',
      effectiveFrom: '2026-09-22T12:00:00.000Z',
      kind: 'rollback',
      supersedes: null,
      authority: POLICY_AUTHORITY,
      privateKey: policyAuthorityPriv,
    }),
    // Claims kind rollback while naming v3, a version authored after every pointer
    // it could be rolling back to.
    P5_claimed_rollback_to_v3: pointer({
      label: 'p5',
      operativeVersionId: 'v3',
      effectiveFrom: '2026-09-23T06:00:00.000Z',
      kind: 'rollback',
      supersedes: null,
      authority: POLICY_AUTHORITY,
      privateKey: policyAuthorityPriv,
    }),
    // Correctly formed, signed by a key this family does not resolve for the policy.
    P6_no_standing_v1: pointer({
      label: 'p6',
      operativeVersionId: 'v1',
      effectiveFrom: '2026-09-23T06:00:00.000Z',
      kind: 'rollback',
      supersedes: null,
      authority: OUTSIDER,
      privateKey: outsiderPriv,
    }),
  }

  const decisions = {
    // Decided while v1 was operative, pinned to v1. 4000 is under v1's ceiling.
    D1_allow_under_v1_pinned: decision({
      label: 'd1',
      decidedAt: '2026-09-20T12:00:00.000Z',
      amount: 4000,
      approvalPresented: false,
      outcome: 'allow',
      policyVersionId: 'v1',
      policyVersionDigest: v1.version_digest,
      privateKey: gatewayPriv,
    }),
    // Decided while v2 was operative, pinned to v2. 4000 is over v2's ceiling.
    D2_deny_under_v2_pinned: decision({
      label: 'd2',
      decidedAt: '2026-09-21T18:00:00.000Z',
      amount: 4000,
      approvalPresented: true,
      outcome: 'deny',
      policyVersionId: 'v2',
      policyVersionDigest: v2.version_digest,
      privateKey: gatewayPriv,
    }),
    // Decided while v1 was operative and carrying no policy pin at all: an outcome
    // and nothing that says what it was evaluated against. Its inputs deliberately
    // re-derive to the same outcome under both v1 and v2, so a reader who renders it
    // under whatever is operative now gets a clean-looking answer and never learns
    // that the record never said which rule produced it.
    D3_allow_unpinned: decision({
      label: 'd3',
      decidedAt: '2026-09-20T12:00:00.000Z',
      amount: 500,
      approvalPresented: true,
      outcome: 'allow',
      policyVersionId: null,
      policyVersionDigest: null,
      privateKey: gatewayPriv,
    }),
    // Pins a digest no policy version in this fixture carries. Same inputs as D3, so
    // the same clean-looking answer is available to anyone who ignores the pin.
    D4_allow_pinned_unresolvable: decision({
      label: 'd4',
      decidedAt: '2026-09-20T12:00:00.000Z',
      amount: 500,
      approvalPresented: true,
      outcome: 'allow',
      policyVersionId: 'v1',
      policyVersionDigest: `sha256:${'0'.repeat(64)}`,
      privateKey: gatewayPriv,
    }),
  }

  // The decision records must actually be what they claim, or no rendering vector
  // below is testing what it says it tests.
  assert(
    evaluate(RULES_PERMISSIVE, 4000, false) === 'allow',
    'D1 must re-derive allow under v1',
  )
  assert(
    evaluate(RULES_TIGHTENED, 4000, true) === 'deny',
    'D2 must re-derive deny under v2',
  )
  // This is the whole point of pinning: the same decision re-derives differently
  // under a version it was never evaluated against.
  assert(
    evaluate(RULES_TIGHTENED, 4000, false) === 'deny',
    'D1 must re-derive deny under v2, which is why the pin matters',
  )
  // D3 and D4 are the opposite shape: their inputs re-derive identically under both
  // versions, so ignoring the pin is invisible in the outcome and visible only in
  // whether the record ever said what it was evaluated against.
  assert(
    evaluate(RULES_PERMISSIVE, 500, true) === 'allow' && evaluate(RULES_TIGHTENED, 500, true) === 'allow',
    'D3 and D4 inputs must re-derive allow under both v1 and v2',
  )

  const fixture = {
    _placeholder: false,
    generated_at: GENERATED_AT,
    sdk: { npm: `agent-passport-system@${SDK_VERSION}` },
    seed_prefix: SEED_PREFIX,
    now: NOW,
    policy_id: POLICY_ID,
    digest_domains: {
      policy_version: POLICY_VERSION_DIGEST_DOMAIN,
      policy_rules: POLICY_RULES_DIGEST_DOMAIN,
      operative_pointer: POINTER_DIGEST_DOMAIN,
      decision_record: DECISION_DIGEST_DOMAIN,
    },
    parties: {
      principal: PRINCIPAL,
      agent: AGENT,
      policy_authority: POLICY_AUTHORITY,
      outsider: OUTSIDER,
      gateway: 'did:aps:example:lpc-gateway',
    },
    /** The only issuer this family's boundary resolves for policy records. */
    policy_standing: [POLICY_AUTHORITY],
    verification_keys: verificationKeys,
    record_keys: recordKeys,
    roles: { PRINCIPAL_TO_AGENT: grant.delegation_id },
    chains: { GRANT: [grant] },
    policy_versions: { v1, v2, v3 },
    pointers,
    decisions,
  }

  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
  console.log('lifecycle-policy-change: chain.json written')
}

main()
