// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the authority-epoch-rollback candidate family.
//
// WHAT IS SDK AND WHAT IS FIXTURE. The delegations, the revocation record, the
// revocation store, the resolver contract and the chain verdict all come from the
// published `agent-passport-system` package. Neither reference SDK has an API for
// an authority epoch, a fencing token or a withdrawal of a recorded revocation,
// so the three gates below are fixture code:
//
//   1. the epoch gate, which decides whether the state view in front of the
//      verifier is behind what the verifier has already observed
//   2. the publication store, which decides whether an authority-state write
//      carrying a fencing token is accepted
//   3. the withdrawal check, which decides whether a record withdrawing a
//      revocation is accepted, and what an accepted one does
//
// Every verdict this family reports is still produced by the SDK's own
// verifyAuthorityDelegationChain. The gates decide what answer the resolver gives
// it, never what the verdict is.
//
// Nothing here reads a clock, the network or a random source. `now` is a constant
// in chains.json.

import {
  InMemoryAuthorityRevocationStore,
  canonicalizeJCS,
  createAuthorityRevocationResolver,
  recordAuthorityRevocation,
  verify as verifyEd25519Signature,
  verifyAuthorityRevocation,
} from 'agent-passport-system'

export type RevocationAnswer = 'active' | 'revoked' | 'unknown'

export interface EpochView {
  epoch: number
  description: string
  tracked: string[]
  revocations: string[]
  withdrawals: string[]
}

export interface ChainsFixture {
  profile: string
  now: string
  withdrawal_record_type: string
  withdrawal_signature_domain: string
  verification_keys: Record<string, string>
  roles: Record<string, string>
  chain: any[]
  records: Record<string, any>
  views: Record<string, EpochView>
  digests: {
    algorithm: string
    chain: string[]
    records: Record<string, string>
  }
}

/** The four policies the runner replays. Only one field differs per control. */
export interface Policy {
  name: string
  /** Compare the presented view's epoch against what the verifier has observed. */
  compareEpochs: boolean
  /** On a stale view, consult the records the verifier retained at its high-water mark. */
  consultRetainedRecords: boolean
  /** Refuse an authority-state write whose fencing token has gone backwards. */
  checkFencingToken: boolean
  /** Treat an accepted withdrawal as removing the revocation from the record set. */
  withdrawalRemovesRevocation: boolean
}

export const REFERENCE_POLICY: Policy = {
  name: 'reference',
  compareEpochs: true,
  consultRetainedRecords: true,
  checkFencingToken: true,
  withdrawalRemovesRevocation: false,
}

/** N1. Reads whatever is presented. The epoch-comparison axis, removed. */
export const LATEST_READ_POLICY: Policy = {
  ...REFERENCE_POLICY,
  name: 'latest-read',
  compareEpochs: false,
  consultRetainedRecords: false,
}

/** N2. Accepts every write. The fencing axis, removed. */
export const UNFENCED_WRITER_POLICY: Policy = {
  ...REFERENCE_POLICY,
  name: 'unfenced-writer',
  checkFencingToken: false,
}

/** N3. An accepted withdrawal deletes the revocation. The resurrection defect. */
export const CORRECTION_AS_DELETION_POLICY: Policy = {
  ...REFERENCE_POLICY,
  name: 'correction-as-deletion',
  withdrawalRemovesRevocation: true,
}

export interface WithdrawalOutcome {
  record_name: string
  accepted: boolean
  reason: string | null
}

export type KeyResolver = (issuer: string, verificationMethod: string, issuedAt: string) => string | null

export function keyResolverFor(fixture: ChainsFixture): KeyResolver {
  return (_issuer, verificationMethod) => fixture.verification_keys[verificationMethod] ?? null
}

/**
 * Decide whether one fixture-local withdrawal record is accepted.
 *
 * Three things have to hold, and they are separate questions kept separate:
 * the record names a revocation this view actually holds, its signature verifies
 * over the domain-tagged JCS preimage, and its signer is the party the
 * revocation itself names as revoker. The last one is standing, and a genuine
 * signature from a party without standing fails it. The reason is returned
 * rather than swallowed: a withdrawal that changes nothing in silence is
 * indistinguishable from one that was never submitted.
 */
export function evaluateWithdrawal(
  fixture: ChainsFixture,
  withdrawalName: string,
  heldRevocationNames: string[],
): WithdrawalOutcome {
  const withdrawal = fixture.records[withdrawalName]
  if (withdrawal === undefined) {
    throw new Error(`fixture is broken: no record named ${withdrawalName}`)
  }

  const target = heldRevocationNames
    .map(name => fixture.records[name])
    .find(record => record?.revocation_id === withdrawal.revocation_id)

  if (target === undefined) {
    return { record_name: withdrawalName, accepted: false, reason: 'withdrawal_names_no_held_revocation' }
  }

  const publicKey = fixture.verification_keys[withdrawal.verification_method]
  if (publicKey === undefined) {
    return { record_name: withdrawalName, accepted: false, reason: 'withdrawal_key_unresolvable' }
  }

  const { signature, ...body } = withdrawal
  const preimage = `${fixture.withdrawal_signature_domain}\n${canonicalizeJCS(body)}`
  if (!verifyEd25519Signature(preimage, signature, publicKey)) {
    return { record_name: withdrawalName, accepted: false, reason: 'withdrawal_signature_invalid' }
  }

  if (withdrawal.withdrawn_by !== target.revoker) {
    return { record_name: withdrawalName, accepted: false, reason: 'withdrawal_signer_is_not_the_revoker' }
  }

  return { record_name: withdrawalName, accepted: true, reason: null }
}

export interface MaterializedView {
  name: string
  epoch: number
  store: InstanceType<typeof InMemoryAuthorityRevocationStore>
  withdrawals: WithdrawalOutcome[]
  /** Revocation record names this view still holds after the policy's withdrawal rule. */
  heldRevocations: string[]
}

/**
 * Turn a named view into a real revocation store.
 *
 * Every revocation goes in through recordAuthorityRevocation(), which verifies it
 * against its target delegation first, so a 'revoked' answer from this store is
 * earned by the SDK rather than asserted by the fixture. Tracked delegations are
 * registered explicitly, because absence from a store is not 'active' in this
 * SDK: a store that never heard of a delegation answers 'unknown'.
 *
 * Under the correction-as-deletion control, a revocation named by an accepted
 * withdrawal is never written. The SDK store has no removal method at all, which
 * is itself worth recording: in this SDK a revocation cannot be taken out of a
 * store, so modelling resurrection means building the store without it.
 */
export function materializeView(
  fixture: ChainsFixture,
  viewName: string,
  policy: Policy,
): MaterializedView {
  const view = fixture.views[viewName]
  if (view === undefined) throw new Error(`fixture is broken: no view named ${viewName}`)

  const withdrawals = view.withdrawals.map(name => evaluateWithdrawal(fixture, name, view.revocations))

  const deleted = new Set<string>()
  if (policy.withdrawalRemovesRevocation) {
    for (const outcome of withdrawals) {
      if (!outcome.accepted) continue
      const withdrawal = fixture.records[outcome.record_name]
      for (const name of view.revocations) {
        if (fixture.records[name]?.revocation_id === withdrawal.revocation_id) deleted.add(name)
      }
    }
  }

  const heldRevocations = view.revocations.filter(name => !deleted.has(name))
  const store = new InMemoryAuthorityRevocationStore()
  for (const delegationId of view.tracked) store.track(delegationId)

  const options = { resolveVerificationKey: keyResolverFor(fixture) }
  for (const name of heldRevocations) {
    const revocation = fixture.records[name]
    const target = fixture.chain.find(member => member.delegation_id === revocation.delegation_id)
    if (target === undefined) {
      throw new Error(`fixture is broken: revocation ${name} names a delegation outside the chain`)
    }
    const result = recordAuthorityRevocation(store, target, revocation, options)
    if (!result.recorded) {
      throw new Error(
        `fixture is broken: revocation ${name} did not verify against its target: ` +
          JSON.stringify(result.verification.failures),
      )
    }
  }

  return { name: viewName, epoch: view.epoch, store, withdrawals, heldRevocations }
}

/** Whether a revocation record still verifies against its target, read directly. */
export function revocationStillVerifies(fixture: ChainsFixture, recordName: string): boolean {
  const revocation = fixture.records[recordName]
  const target = fixture.chain.find(member => member.delegation_id === revocation.delegation_id)
  const result = verifyAuthorityRevocation(revocation, target, {
    resolveVerificationKey: keyResolverFor(fixture),
  })
  return result.state === 'valid'
}

export interface EpochGateInput {
  observedEpoch: number | null
  retainedViewName: string | null
  presentedViewName: string
  policy: Policy
}

export interface EpochGateResult {
  resolve: (delegation: any) => RevocationAnswer
  presentedEpoch: number
  stale: boolean
  highWaterMarkAfter: number
  presentedView: MaterializedView
  /** What the presented view alone would have answered, recorded for the report. */
  presentedAnswerForRoot: RevocationAnswer
}

/**
 * The epoch gate. This is the candidate mechanism, and it is fixture code.
 *
 * A view whose epoch is behind what the verifier has already observed is stale.
 * The gate then has two honest outcomes and they are not the same:
 *
 *   - the verifier retained the records it saw at its high-water mark, one of
 *     them verifies as a revocation of this delegation, and the answer is
 *     'revoked'
 *   - the verifier retained only the epoch number, cannot establish a
 *     revocation from records, and the answer is 'unknown'
 *
 * 'unknown' becomes indeterminate in the SDK's chain verifier, which is the
 * "not established" result rather than a claim that nothing was revoked. The
 * gate never answers 'active' from a stale view.
 */
export function epochGate(fixture: ChainsFixture, input: EpochGateInput): EpochGateResult {
  const presentedView = materializeView(fixture, input.presentedViewName, input.policy)
  const presentedResolver = createAuthorityRevocationResolver(presentedView.store, {
    resolveVerificationKey: keyResolverFor(fixture),
  })

  const stale =
    input.policy.compareEpochs &&
    input.observedEpoch !== null &&
    presentedView.epoch < input.observedEpoch

  const retainedResolver =
    stale && input.policy.consultRetainedRecords && input.retainedViewName !== null
      ? createAuthorityRevocationResolver(
          materializeView(fixture, input.retainedViewName, input.policy).store,
          { resolveVerificationKey: keyResolverFor(fixture) },
        )
      : null

  const resolve = (delegation: any): RevocationAnswer => {
    if (!stale) return presentedResolver(delegation) as RevocationAnswer
    if (retainedResolver !== null) {
      const retained = retainedResolver(delegation) as RevocationAnswer
      if (retained === 'revoked') return 'revoked'
    }
    return 'unknown'
  }

  const root = fixture.chain[0]
  return {
    resolve,
    presentedEpoch: presentedView.epoch,
    stale,
    highWaterMarkAfter:
      input.observedEpoch === null
        ? presentedView.epoch
        : Math.max(input.observedEpoch, presentedView.epoch),
    presentedView,
    presentedAnswerForRoot: presentedResolver(root) as RevocationAnswer,
  }
}

export interface WriteOutcome {
  token: number
  view: string
  accepted: boolean
  reason: string | null
}

/**
 * The publication store for authority state, with a fencing-token gate.
 *
 * The rule is the one the Kleppmann source states: reject a write whose token
 * has gone backwards. A token equal to the highest seen has not gone backwards,
 * so it is the same holder retrying and it is accepted.
 */
export class EpochPublicationStore {
  private highestToken: number | null = null
  private publishedViewName: string | null = null

  constructor(private readonly checkFencingToken: boolean) {}

  write(token: number, viewName: string): WriteOutcome {
    if (this.checkFencingToken && this.highestToken !== null && token < this.highestToken) {
      return { token, view: viewName, accepted: false, reason: 'stale_fencing_token' }
    }
    this.highestToken = this.highestToken === null ? token : Math.max(this.highestToken, token)
    this.publishedViewName = viewName
    return { token, view: viewName, accepted: true, reason: null }
  }

  published(): string {
    if (this.publishedViewName === null) {
      throw new Error('fixture is broken: a case read the publication store before any write landed')
    }
    return this.publishedViewName
  }
}
