// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mint chain.json for the lifecycle-third-party-reliance-notice family, byte for byte.
//
// WHAT THIS FAMILY TESTS. That a chain's verification state and whether a named outside
// party was given notice of a termination are two separate records with two separate
// answers, that a broadcast record and an individually addressed record are not
// interchangeable, and that a later grant is not a revocation of an earlier one.
//
// The proposed text is aeoess/agent-authority-lifecycle at commit 7796e22: the "Notice"
// and "Status observation" entries, invariant L5, and OPEN-QUESTIONS.md's "Notice and
// relying parties". The cases are the "Third-party reliance and notice" section of CASES.md
// at commit 2bf5c7e.
//
// WHAT THIS FAMILY DOES NOT TEST. Whether an outside party's reliance is protected, or
// what that party is entitled to. That is a legal effect, decided off the wire, and no
// verifier can compute it from records. This fixture tests only the record-level
// distinction: what a verifier can establish about the chain, and separately what it can
// establish about notice. See README.md.
//
// Every key is an Ed25519 seed derived from a published label, so the file carries no
// secret material and anyone can regenerate it. Timestamps, nonces and payloads are pinned
// constants: no clock is read and no randomness is drawn.
//
// Run from the suite root:
//
//     npx tsx fixtures/lifecycle-third-party-reliance-notice/mint.ts
//
// Then `git diff` on chain.json must be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  InMemoryAuthorityRevocationStore,
  canonicalizeJCS,
  computeAuthorityDelegationId,
  computeAuthorityRevocationCascadeTransactionIdForWrite,
  computeAuthorityRevocationIdForWrite,
  createAuthorityRevocationResolver,
  issueAuthorityRevocation,
  publicKeyFromPrivate,
  recordAuthorityRevocation,
  sign,
  signAuthorityDelegation,
  signAuthorityRevocation,
  verify as verifyEd25519,
  verifyAuthorityDelegationChain,
  verifyAuthorityRevocation,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

const SEED_PREFIX = 'aps-conformance-suite:lifecycle-third-party-reliance-notice:'

function seed(label: string): string {
  return createHash('sha256').update(SEED_PREFIX + label, 'utf8').digest('hex')
}

// ---------------------------------------------------------------------------
// Identities. Two principals with real keys and one agent. The second principal exists so
// that a record signed by somebody with no standing is genuinely signed: a rejection in
// this family is always about standing and never about a broken signature.
// ---------------------------------------------------------------------------

const PRINCIPAL = 'did:aps:example:tpr-principal'
const OTHER_PRINCIPAL = 'did:aps:example:tpr-other-principal'
const AGENT = 'did:aps:example:tpr-agent'

const kid = (did: string) => `${did}#key-1`

const PRIVATE: Record<string, string> = {}
const PUBLIC: Record<string, string> = {}
for (const did of [PRINCIPAL, OTHER_PRINCIPAL, AGENT]) {
  PRIVATE[did] = seed(`identity:${did}:v1`)
  PUBLIC[kid(did)] = publicKeyFromPrivate(PRIVATE[did])
}

// Counterparties are outside parties, not signers: they receive notice and never produce a
// record here, so they have identifiers and no keys.
const COUNTERPARTY_REPEAT = 'counterparty:tpr-repeat'
const COUNTERPARTY_STRANGER = 'counterparty:tpr-stranger'
const COUNTERPARTY_OTHER = 'counterparty:tpr-other'

// ---------------------------------------------------------------------------
// The timeline.
//
//   T0  the older grant and the terminated grant are issued
//   T1  before any revocation
//   T2  the revocations are recorded, and the newer grant is issued
//   T3  after revocation, before any notice record exists
//   T4  the notice records are issued
//   T5  after notice
// ---------------------------------------------------------------------------

const T0 = '2026-09-21T00:00:00.000Z'
const T1 = '2026-09-22T09:00:00.000Z'
const T2 = '2026-09-22T12:00:00.000Z'
const T3 = '2026-09-23T09:00:00.000Z'
const T4 = '2026-09-24T09:00:00.000Z'
const T5 = '2026-09-25T09:00:00.000Z'
const NOT_AFTER = '2026-10-01T00:00:00.000Z'

const SCOPE_PLACE = 'orders:place'
const SCOPE_CANCEL = 'orders:cancel'
const SCOPE_ADVICE = 'advice:issue'

// ---------------------------------------------------------------------------
// Delegations. One-hop grants so that each grant's own issuer is also the only party
// draft-03 section 3.5 admits as its revoker, which keeps the standing question about
// notice rather than about who may revoke.
// ---------------------------------------------------------------------------

function authorityVector(grants: string[], issuedAt: string): unknown {
  return {
    scope: { profile: 'aps-hierarchical-v1', grants },
    spend: { mode: 'unbounded' },
    depth: { remaining: 0 },
    time: { not_before: issuedAt, not_after: NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1', required: [] as string[] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
  }
}

function mintGrant(nonceLabel: string, grants: string[], issuedAt: string) {
  const body = {
    record_type: 'aps:authority-delegation:v1' as const,
    version: '1.0' as const,
    parent_delegation_id: null,
    issuer: PRINCIPAL,
    subject: AGENT,
    verification_method: kid(PRINCIPAL),
    issued_at: issuedAt,
    nonce: seed(`delegation-nonce:${nonceLabel}:v1`).slice(0, 32),
    authority: authorityVector(grants, issuedAt),
  }
  const delegation_id = computeAuthorityDelegationId(body as never)
  const draft = { ...body, delegation_id }
  return { ...draft, signature: signAuthorityDelegation(draft as never, PRIVATE[PRINCIPAL]) }
}

// The grant whose actual authority is ended by a revocation from its own issuer. Everything
// in the notice half of this family is about this one.
const GRANT_TERMINATED = mintGrant('terminated', [SCOPE_ADVICE], T0)
// The older grant, and a newer, broader grant to the same subject issued two days later.
// Nothing in either says anything about the other.
const GRANT_OLDER = mintGrant('older', [SCOPE_PLACE], T0)
const GRANT_NEWER = mintGrant('newer', [SCOPE_CANCEL, SCOPE_PLACE], T2)

const CHAINS = {
  terminated: [GRANT_TERMINATED],
  older: [GRANT_OLDER],
  newer: [GRANT_NEWER],
}

// ---------------------------------------------------------------------------
// Revocations. Real draft-03 section 3.5.1 records.
//
// Two of the three are minted through issueAuthorityRevocation, the supported path. The
// third names a revoker who is not the target delegation's issuer, which that function
// refuses outright (REVOKER_NOT_ISSUER), so it is built from the same public canonical
// primitives issuance uses internally: cascade transaction id, then revocation id, then
// signature. The result is a well-formed, correctly signed AuthorityRevocationV1 that no
// resolver may ever read as 'revoked'. See the README for why that record exists.
// ---------------------------------------------------------------------------

const REVOKE_TERMINATED = issueAuthorityRevocation(
  GRANT_TERMINATED as never,
  { now: T2, revoker: PRINCIPAL, verification_method: kid(PRINCIPAL), reason_code: 'principal_terminated_authority', nonce: seed('revocation-nonce:terminated:v1').slice(0, 32) },
  PRIVATE[PRINCIPAL],
)

const REVOKE_OLDER_EXPRESS = issueAuthorityRevocation(
  GRANT_OLDER as never,
  { now: T2, revoker: PRINCIPAL, verification_method: kid(PRINCIPAL), reason_code: 'express_revocation_of_earlier_grant', nonce: seed('revocation-nonce:older-express:v1').slice(0, 32) },
  PRIVATE[PRINCIPAL],
)

function mintRevocationWithRevoker(delegationId: string, revoker: string, reasonCode: string, nonceLabel: string, signerPrivate: string) {
  const origin = {
    record_type: 'aps:authority-revocation:v1' as const,
    version: '1.0' as const,
    delegation_id: delegationId,
    revoker,
    verification_method: kid(revoker),
    revoked_at: T2,
    reason_code: reasonCode,
    nonce: seed(`revocation-nonce:${nonceLabel}:v1`).slice(0, 32),
  }
  const cascade_transaction_id = computeAuthorityRevocationCascadeTransactionIdForWrite(origin as never)
  const body = { ...origin, cascade_transaction_id }
  const revocation_id = computeAuthorityRevocationIdForWrite(body as never)
  const unsigned = { ...body, revocation_id }
  return { ...unsigned, signature: signAuthorityRevocation(unsigned as never, signerPrivate) }
}

const REVOKE_OLDER_WRONG_REVOKER = mintRevocationWithRevoker(
  GRANT_OLDER.delegation_id,
  OTHER_PRINCIPAL,
  'asserted_revocation_by_another_principal',
  'older-wrong-revoker',
  PRIVATE[OTHER_PRINCIPAL],
)

const REVOCATIONS = {
  revoke_terminated: REVOKE_TERMINATED,
  revoke_older_express: REVOKE_OLDER_EXPRESS,
  revoke_older_wrong_revoker: REVOKE_OLDER_WRONG_REVOKER,
}

// ---------------------------------------------------------------------------
// Notice records and the prior-dealing register. Both fixture-local profiles, neither a
// protocol object.
//
// The proposed text names the concept and defines no record for it:
//
//     "Notice.  That a particular party or enforcement point learned of a transition at a
//     particular time.  Recording a transition and observing it are different events."
//
// It does not say who may give notice, how a notice record names its recipient, whether a
// broadcast counts, or how a verifier would tell a first-time counterparty from one with a
// dealing history. This family declares its own shapes for all of that and says so.
// ---------------------------------------------------------------------------

const NOTICE_PROFILE = `${SEED_PREFIX}notice-record-v0`
const NOTICE_DOMAIN = 'APS-CONFORMANCE-TPR-NOTICE-RECORD-V0'
const REGISTER_PROFILE = `${SEED_PREFIX}prior-dealing-register-v0`
const REGISTER_DOMAIN = 'APS-CONFORMANCE-TPR-PRIOR-DEALING-REGISTER-V0'

/** `counterparty` is null on a publication record: it names no recipient at all. */
function mintNotice(label: string, issuer: string, mode: 'individual' | 'publication', counterparty: string | null, revocationId: string) {
  const body = {
    profile: NOTICE_PROFILE,
    issuer,
    verification_method: kid(issuer),
    mode,
    counterparty,
    revocation_id: revocationId,
    issued_at: T4,
  }
  const signature = sign(`${NOTICE_DOMAIN} ${canonicalizeJCS(body)}`, PRIVATE[issuer])
  return { ...body, signature, _label: label }
}

const NOTICES = {
  publication_all: mintNotice('publication_all', PRINCIPAL, 'publication', null, REVOKE_TERMINATED.revocation_id),
  individual_repeat: mintNotice('individual_repeat', PRINCIPAL, 'individual', COUNTERPARTY_REPEAT, REVOKE_TERMINATED.revocation_id),
  individual_other: mintNotice('individual_other', PRINCIPAL, 'individual', COUNTERPARTY_OTHER, REVOKE_TERMINATED.revocation_id),
  individual_repeat_no_standing: mintNotice('individual_repeat_no_standing', OTHER_PRINCIPAL, 'individual', COUNTERPARTY_REPEAT, REVOKE_TERMINATED.revocation_id),
}
for (const value of Object.values(NOTICES)) delete (value as { _label?: string })._label

function mintRegister(delegationId: string, counterparties: string[]) {
  const body = {
    profile: REGISTER_PROFILE,
    issuer: PRINCIPAL,
    verification_method: kid(PRINCIPAL),
    delegation_id: delegationId,
    counterparties,
    as_of: T1,
  }
  const signature = sign(`${REGISTER_DOMAIN} ${canonicalizeJCS(body)}`, PRIVATE[PRINCIPAL])
  return { ...body, signature }
}

// One counterparty had dealt with this agent under this grant before the termination. The
// other two had not. That is the only fact this record carries.
const PRIOR_DEALING_REGISTER = mintRegister(GRANT_TERMINATED.delegation_id, [COUNTERPARTY_REPEAT])

// ---------------------------------------------------------------------------
// Mint-time assertions. A failure aborts with nothing written.
// ---------------------------------------------------------------------------

function assert(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`mint.ts: ${message}`)
    process.exit(1)
  }
}

const resolveVerificationKey = (_issuer: string, method: string) => PUBLIC[method] ?? null

function storeWith(revocationLabels: Array<keyof typeof REVOCATIONS>) {
  const store = new InMemoryAuthorityRevocationStore()
  for (const chain of Object.values(CHAINS)) for (const record of chain) store.track(record.delegation_id)
  for (const label of revocationLabels) {
    const revocation = REVOCATIONS[label]
    const target = Object.values(CHAINS).flat().find((r) => r.delegation_id === revocation.delegation_id)
    assert(target !== undefined, `revocation ${label} names a delegation no chain holds`)
    const result = recordAuthorityRevocation(store, target as never, revocation, { resolveVerificationKey })
    if (!result.recorded) {
      // The supported path verifies first and refuses. For the wrong-revoker record that
      // refusal is the point, so the record is placed through the store's raw persistence
      // primitive instead. The SDK's own documentation names this caller as the one
      // asserting the record was verified, and the resolver's re-verification on the way
      // out is what still keeps the answer away from 'revoked'.
      store.insertVerifiedRevocation(revocation as never)
    }
  }
  return store
}

const chainOpts = (now: string, store: InMemoryAuthorityRevocationStore) => ({
  now,
  resolveVerificationKey,
  trustRoot: (root: { issuer: string }) => root.issuer === PRINCIPAL,
  resolveRevocation: createAuthorityRevocationResolver(store, { resolveVerificationKey }),
})

const cleanStore = storeWith([])
for (const [name, chain] of Object.entries(CHAINS)) {
  const now = name === 'newer' ? T3 : T1
  const result = verifyAuthorityDelegationChain(chain as never, chainOpts(now, cleanStore))
  assert(result.state === 'valid', `chain ${name} does not verify valid with no revocation recorded: ${JSON.stringify(result)}`)
}

// The two supported revocations verify and record.
for (const [label, revocation] of Object.entries({ revoke_terminated: REVOKE_TERMINATED, revoke_older_express: REVOKE_OLDER_EXPRESS })) {
  const target = Object.values(CHAINS).flat().find((r) => r.delegation_id === revocation.delegation_id)!
  const verification = verifyAuthorityRevocation(revocation, target as never, { resolveVerificationKey })
  assert(verification.state === 'valid', `${label} does not verify: ${JSON.stringify(verification)}`)
}

const terminatedStore = storeWith(['revoke_terminated'])
const terminatedAfter = verifyAuthorityDelegationChain(CHAINS.terminated as never, chainOpts(T3, terminatedStore))
assert(terminatedAfter.state === 'invalid' && terminatedAfter.failures[0]?.code === 'REVOKED',
  `terminated chain after revocation should be invalid REVOKED: ${JSON.stringify(terminatedAfter)}`)

// The express revocation reaches the delegation it names and no other, which is the whole
// content of the newer-instrument case: the newer grant is untouched.
const expressStore = storeWith(['revoke_older_express'])
const olderAfterExpress = verifyAuthorityDelegationChain(CHAINS.older as never, chainOpts(T3, expressStore))
assert(olderAfterExpress.state === 'invalid' && olderAfterExpress.failures[0]?.code === 'REVOKED',
  `older chain after its express revocation should be invalid REVOKED: ${JSON.stringify(olderAfterExpress)}`)
const newerAfterExpress = verifyAuthorityDelegationChain(CHAINS.newer as never, chainOpts(T3, expressStore))
assert(newerAfterExpress.state === 'valid', `newer chain should stay valid: ${JSON.stringify(newerAfterExpress)}`)
const olderWithNoRevocation = verifyAuthorityDelegationChain(CHAINS.older as never, chainOpts(T3, cleanStore))
assert(olderWithNoRevocation.state === 'valid',
  `older chain should stay valid at T3 with the newer grant issued and no revocation record: ${JSON.stringify(olderWithNoRevocation)}`)

// The wrong-revoker record. verifyAuthorityRevocation refuses it against its target, and
// once it is in a store anyway the resolver answers unknown rather than revoked, which
// chain verification reports as indeterminate.
const wrongRevokerVerification = verifyAuthorityRevocation(REVOKE_OLDER_WRONG_REVOKER, GRANT_OLDER as never, { resolveVerificationKey })
assert(wrongRevokerVerification.state === 'invalid', `wrong-revoker record should not verify: ${JSON.stringify(wrongRevokerVerification)}`)
const wrongRevokerCode = wrongRevokerVerification.failures[0]?.code ?? null
assert(wrongRevokerCode === 'REVOKER_NOT_ISSUER', `expected REVOKER_NOT_ISSUER, got ${String(wrongRevokerCode)}`)
const wrongRevokerStore = storeWith(['revoke_older_wrong_revoker'])
const wrongRevokerResolution = createAuthorityRevocationResolver(wrongRevokerStore, { resolveVerificationKey })(GRANT_OLDER as never)
assert(wrongRevokerResolution === 'unknown', `expected the resolver to answer unknown, got ${wrongRevokerResolution}`)
const olderAfterWrongRevoker = verifyAuthorityDelegationChain(CHAINS.older as never, chainOpts(T3, wrongRevokerStore))
assert(olderAfterWrongRevoker.state === 'indeterminate' && olderAfterWrongRevoker.failures[0]?.code === 'REVOCATION_UNKNOWN',
  `older chain with the wrong-revoker record should be indeterminate REVOCATION_UNKNOWN: ${JSON.stringify(olderAfterWrongRevoker)}`)

// issueAuthorityRevocation refuses the same construction outright.
let issuanceRefusal = 'not-refused'
try {
  issueAuthorityRevocation(
    GRANT_OLDER as never,
    { now: T2, revoker: OTHER_PRINCIPAL, verification_method: kid(OTHER_PRINCIPAL), reason_code: 'asserted', nonce: seed('revocation-nonce:refused:v1').slice(0, 32) },
    PRIVATE[OTHER_PRINCIPAL],
  )
  assert(false, 'issueAuthorityRevocation minted a revocation for a non-issuer revoker')
} catch (error) {
  issuanceRefusal = (error as Error).message
}
assert(issuanceRefusal.includes('REVOKER_NOT_ISSUER'), `expected REVOKER_NOT_ISSUER on issuance, got ${issuanceRefusal}`)

// Every notice record and the register verify under exactly the rule harness.ts applies.
for (const [label, notice] of Object.entries(NOTICES)) {
  const { signature, ...body } = notice
  assert(verifyEd25519(`${NOTICE_DOMAIN} ${canonicalizeJCS(body)}`, signature, PUBLIC[notice.verification_method]), `notice ${label} does not verify`)
}
{
  const { signature, ...body } = PRIOR_DEALING_REGISTER
  assert(verifyEd25519(`${REGISTER_DOMAIN} ${canonicalizeJCS(body)}`, signature, PUBLIC[PRIOR_DEALING_REGISTER.verification_method]), 'prior dealing register does not verify')
}

// The no-standing notice is genuinely signed, so a rejection is about standing alone.
{
  const { signature, ...body } = NOTICES.individual_repeat_no_standing
  assert(
    verifyEd25519(`${NOTICE_DOMAIN} ${canonicalizeJCS(body)}`, signature, PUBLIC[kid(OTHER_PRINCIPAL)]),
    'the no-standing notice should verify under its own signer key',
  )
  assert(
    !verifyEd25519(`${NOTICE_DOMAIN} ${canonicalizeJCS(body)}`, signature, PUBLIC[kid(PRINCIPAL)]),
    'the no-standing notice should not verify under the principal key',
  )
}

const allDelegationIds = Object.values(CHAINS).flat().map((r) => r.delegation_id)
assert(new Set(allDelegationIds).size === allDelegationIds.length, 'two delegations share a delegation_id')
const allRevocationIds = Object.values(REVOCATIONS).map((r) => r.revocation_id)
assert(new Set(allRevocationIds).size === allRevocationIds.length, 'two revocations share a revocation_id')

// ---------------------------------------------------------------------------
// Write.
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
  profile: 'aps-lifecycle-third-party-reliance-notice-v0',
  description:
    'Chain state and notice state as two separate records with two separate answers, a ' +
    'two-tier notice rule, and a newer grant that is not a revocation of an earlier one. ' +
    'Three one-hop AuthorityDelegationV1 grants, three draft-03 section 3.5.1 revocations ' +
    '(one of them deliberately naming a revoker who is not the target issuer), four ' +
    'notice records and one prior-dealing register, minted and verified with ' +
    'agent-passport-system 7.1.0.',
  minted_by: 'fixtures/lifecycle-third-party-reliance-notice/mint.ts',
  seed_label_prefix: SEED_PREFIX,
  sdk: { typescript: 'agent-passport-system@7.1.0' },
  identities: { principal: PRINCIPAL, other_principal: OTHER_PRINCIPAL, agent: AGENT },
  counterparties: {
    repeat: COUNTERPARTY_REPEAT,
    stranger: COUNTERPARTY_STRANGER,
    other: COUNTERPARTY_OTHER,
  },
  verification_keys: PUBLIC,
  timeline: { t0_issued: T0, t1_before: T1, t2_revoked: T2, t3_after_revocation: T3, t4_notice: T4, t5_after_notice: T5, not_after: NOT_AFTER },
  signature_domains: { notice_record: NOTICE_DOMAIN, prior_dealing_register: REGISTER_DOMAIN },
  profiles: { notice_record: NOTICE_PROFILE, prior_dealing_register: REGISTER_PROFILE },
  chains: CHAINS,
  revocations: REVOCATIONS,
  notices: NOTICES,
  prior_dealing_register: PRIOR_DEALING_REGISTER,
  mint_time_sdk_observations: {
    terminated_chain_before_revocation: 'valid',
    terminated_chain_after_revocation: { state: terminatedAfter.state, first_failure_code: terminatedAfter.failures[0]?.code ?? null },
    older_chain_with_newer_grant_and_no_revocation: { state: olderWithNoRevocation.state, first_failure_code: olderWithNoRevocation.failures[0]?.code ?? null },
    older_chain_after_express_revocation: { state: olderAfterExpress.state, first_failure_code: olderAfterExpress.failures[0]?.code ?? null },
    newer_chain_after_older_express_revocation: { state: newerAfterExpress.state, first_failure_code: newerAfterExpress.failures[0]?.code ?? null },
    wrong_revoker_record_verification: { state: wrongRevokerVerification.state, first_failure_code: wrongRevokerCode },
    wrong_revoker_resolver_answer: wrongRevokerResolution,
    older_chain_with_wrong_revoker_record: { state: olderAfterWrongRevoker.state, first_failure_code: olderAfterWrongRevoker.failures[0]?.code ?? null },
    external_revoker_issuance_refusal: issuanceRefusal,
  },
}

fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(sortKeys(chain), null, 2) + '\n', 'utf8')

console.log('lifecycle-third-party-reliance-notice: chain.json minted')
console.log(`  terminated chain after revocation: ${terminatedAfter.state}/${terminatedAfter.failures[0]?.code ?? null}`)
console.log(`  older chain with the newer grant issued and no revocation: ${olderWithNoRevocation.state}`)
console.log(`  wrong-revoker record verification: ${wrongRevokerVerification.state}/${String(wrongRevokerCode)}`)
console.log(`  wrong-revoker resolver answer: ${wrongRevokerResolution}`)
console.log(`  older chain with that record in the store: ${olderAfterWrongRevoker.state}/${olderAfterWrongRevoker.failures[0]?.code ?? null}`)
