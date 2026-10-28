# OWASP AIMM Pillar 2 test mapping

This proposed mapping compares the L4 and L5 negative tests in section 5.1 of the OWASP AIMM working draft, as read on 2026-10-25, with published lab cases at [`a560b1e`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/a560b1e1e1263a0b883ef6367bf2c6b9d7f70543). The fixtures and candidates are unchanged since the earlier pin `47fd146`. The cases added in this revision were already published and had been missed.

The mapping has no OWASP approval and is not part of AIMM. A match here does not establish that an implementation meets an AIMM level.

## Reading the tables

**Direct** means the case exercises the named failure. **Partial** means it covers only part of the test. Each row states its limits.

- **Conformance** cases target a rule in draft-pidlisnyi-aps-03.
- **Candidate** cases target proposed text. The case sources below name the text and record format.
- **Outside candidate** cases are MoltyCel's AAE vectors. They are published as a candidate, have not been admitted as reviewed fixtures, and do not run in lab CI.

Each case links to its source and verification notes. Most use APS records and need an adapter for other formats. A run by the vector author is author-produced evidence, not an independent run. Runtime enforcement needs a test of the running system as well as records.

A verdict of `not_established` or `indeterminate` means the verifier could not establish authority. It is a refusal to accept, not a finding that authority was revoked or refused.

## L4

| Failure tested | Match | Cases and limits | Status |
|---|---|---|---|
| Child granted more than its parent | Direct | [single-chain selection][scs] `SCS-03-reject-needs-both-scopes-presented-chain-1`, `SCS-04-reject-needs-both-scopes-presented-chain-2`, `SCS-05-reject-amount-exceeds-chain-1-ceiling-chain-2-must-not-count`. The action check refuses SCS-03 and SCS-04 as `scope_not_covered` and SCS-05 as `PER_ACTION_EXCEEDED`. A synthetic child hop that adds the extra scope or amount fails as `SCOPE_WIDENING` or `SPEND_WIDENING` at index 1. | Conformance |
| Child granted more than its parent | Direct | [AAE vectors][aae] `aae-vector-07`, `aae-vector-08`. A delegated envelope with an action its parent lacks is rejected as `delegated_actions_not_subset`. One with a value cap above its parent's is rejected as `delegated_constraint_relaxed`. | Outside candidate |
| Child valid longer than its parent | Direct | [subdelegation edges][sde] `LC-H-007-c`, `LC-H-007-d`, `LC-H-007-e`. Verification fails with `TIME_WIDENING` at index 1 in -c and -d. Issuance is refused with `TIME_WIDENING` in -e. In -c both records are current on their own, so a check of each record's window alone would admit it. | Candidate |
| Reuse of a consumed approval | Direct | [single-use approval][asu] `ASU-02-reject-already-consumed`. A permit already consumed is not admitted, `already_consumed`. | Conformance |
| Reuse of a consumed approval | Direct | [AAE vectors][aae] `aae-vector-05`. A single-use envelope presented after a recorded authorization is rejected as `single_use_already_consumed`. | Outside candidate |
| Use of an expired approval | Direct | [single-use approval][asu] `ASU-03-reject-expired`. A permit presented after its own `valid_until` is not admitted, `expired`. | Conformance |
| Critical action without two required approvals | Partial | [multiple principals][lmp] `LC-C-011-b` to `LC-C-011-g`. These cover missing, stale, same-role or refused concurrence in a two-role gate, tested on records. In -b, -c, -f and -g the second role has no valid approval: it is silent, or is replaced by more approvals from the first role, by a senior principal, or by a record claiming a role its author does not hold. These are `not_established` with `CONCURRENCE_MISSING`. In -d the approval is stale, `not_established` with `CONCURRENCE_STALE`. A recorded dissent in -e is `invalid` with `CONCURRENCE_REFUSED`. LC-C-011-a is the control. The freshness bound of 3600 seconds is the fixture's own choice. No critical operation is attempted, no execution or effect is observed, and no just-in-time authority is modelled. | Candidate |
| Descendant use after parent revocation beyond the propagation limit | Partial | [cached authorization][car] `CAR-02-revoked-credential-across-reuse-surfaces`, `CAR-03-denied-before-downstream-after-propagation-limit`. At supplied call times past the 5000 ms propagation limit the revoked grant is denied as `grant_revoked` on the retained session, after reconnecting and on a second worker. The downstream test double records no attempt. These are finite observations against an in-process authority, not a general or distributed propagation bound. No parent-child chain is modelled. `CAR-05-inside-propagation-window-residual-exposure` leaves the in-window outcome unconstrained and checks that residual exposure is recorded if the call is allowed. It is not rejection evidence. | Candidate |
| Descendant use after parent revocation | Partial | [ancestor revocation][arc] `AAC-02-root-revoked-full-chain`, `AAC-03-root-revoked-leaf-not-in-recorded-children`, `AAC-04-middle-delegation-revoked`. Each chain is `invalid` with `REVOKED` at the revoked ancestor's index, 0 or 1. Revocation takes effect at once, so no propagation limit is tested. | Conformance |
| Descendant use after parent revocation | Partial | [subdelegation edges][sde] `LC-H-009-b`, `LC-H-009-c`. A child is minted after its parent's revocation was recorded but before the issuer could see it. At a later boundary the chain fails with `REVOKED` at index 0, the parent. In -c an issuer's earlier observation that the parent was active does not rescue it. No maximum delay is asserted. | Candidate |
| Simultaneous use of a single-use approval | Partial | [single-use approval][asu] `ASU-07a-accept-race-first-consumption`, `ASU-07b-reject-race-second-consumption`. One permit is presented twice at the same modelled instant. The first is admitted and the second is refused as `already_consumed`. The calls run one after the other on one instance, so this does not test real concurrency. | Conformance |
| Retry after refusal | Partial | [denial continuity][rad] `A2-deny-then-identical-retry`. A literal retry of a denied call stays denied as `denied_effect_continuity`. It retries a denied effect, not a consumed permit or a shared limit. | Candidate |
| Recovery against a single-use limit | Partial | [agent-side events][ase] `ASE-07-LC-E-012-c-replay-record-lost-inside-the-window-not-established`. Given a supplied replay-cache-loss time inside a skew window, the boundary refuses as `not_established`, `replay_cache_lost_within_skew_window`. ASE-08 is the control a full window later. The loss is an input. No crash, restart, retry, persistence or shared-limit accounting is exercised. | Candidate |

## L5

| Failure tested | Match | Cases and limits | Status |
|---|---|---|---|
| Issuer the verifier should not accept | Direct | [legal and regulatory events][lre] `LRE-B-017-a`, `LRE-B-017-c`. Root trust only. In -a the verifier's closed trust policy does not list the signed chain's root issuer, and the chain is `invalid` with `ROOT_UNTRUSTED`. In -c the policy could accept the root once established, but the establishing record is not yet recorded at the evaluation instant, so the root is still outside the accepted set and the result is the same. `LRE-B-017-b`, the same chain after that record, is the valid control. Intermediate issuers are not covered. | Candidate |
| Issuer the verifier should not accept | Partial | [AAE vectors][aae] `aae-vector-12`. Rejects an envelope naming one issuer but signed by another key, `signing_authority_mismatch`. This is a signer mismatch, not a trusted-issuer policy. | Outside candidate |
| Issuer the verifier should not accept | Partial | [AAE vectors][aae] `aae-enforce-vector-23`. An otherwise correct, validly signed ratification from a party the mandate does not name has status `REJECTED`. Its `decision` field still reads `APPROVED` because that is what the party attempted. It concerns a ratifier, not a grant issuer. | Outside candidate |
| Malformed delegation chain | Partial | [single-chain selection][scs] `SCS-06-reject-concatenated-chain-is-malformed-not-unioned`. A presentation that joins two chains' roots fails as `PARENT_MISMATCH` at index 1 on the synthetic path. No action check runs on it. | Conformance |
| Malformed delegation chain | Partial | [AAE vectors][aae] `aae-vector-10`. A chain that revisits an envelope is rejected as `delegation_cycle_detected`. | Outside candidate |
| Malformed delegation chain | Partial | [organization events][loe] `LC-B-004-c`, `LC-B-004-d`. A departed officer's unchanged child presented under a successor's root fails as `PARENT_MISMATCH`. A child re-pointed to the new root but still signed by the departed officer fails as `CHAIN_CONTINUITY`. Both fail at index 1. | Candidate |
| Authority wider than granted | Direct | [single-chain selection][scs] `SCS-03`, `SCS-04`, `SCS-05`, the same cases as the L4 row. Refuses a scope or amount the chain did not grant. | Conformance |
| Authority wider than granted | Direct | [AAE vectors][aae] `aae-vector-07`, `aae-vector-08`. Rejects a delegated envelope with an added action or a higher value cap than its parent. | Outside candidate |
| Authority wider than granted | Direct | [token exchange][tea] `widening-scope-invalid`, `widening-scope-invalid-single-token`. An exchanged token whose scope is not a subset of the subject token's makes the vector invalid, `t2_scope_not_subset_of_t1`, and it is rejected before its requests are evaluated. This is not a runtime rejection of a minted token. Other cases deny requests that need scope or attributes present only on the subject token. Uses unsigned claim structures. | Candidate |
| Used at the wrong audience or by the wrong party | Partial | [ARAP binding][arap] `A6`. Signed approval state whose `aud` names a different decision point is `approval_unverifiable` in a synthetic verifier, even when that point trusts the same signing key. This is approval-state audience rejection, not presenter or grant audience. | Candidate |
| Used at the wrong audience or by the wrong party | Partial | [token exchange][tea] `audience-mismatch`, `actor-not-permitted`. Denies a wrong audience as `audience_mismatch` and a disallowed actor as `actor_not_permitted`. The actor check uses only the outer current actor. No `act` history is checked, and there is no proof that the presenter holds a bound key. | Candidate |
| Used at the wrong audience or by the wrong party | Partial | [agent-side events][ase] `ASE-12-LC-E-025-a-a-copy-presents-the-originals-grant-not-established`. A supplied presenter identity that differs from the grant subject is `not_established`, `presenter_not_grant_subject`. The presenter is not authenticated and no key proof is checked. | Candidate |
| Revoked or outdated authority | Direct | [lease and revocation][lra] `LRA-02`, live standing read profile. After revocation at 10 s, calls at 30, 60 and 119 s read the source, are not accepted, and are denied before downstream with the revision 3 reason `authority_revoked`. | Candidate |
| Revoked or outdated authority | Partial | [lease and revocation][lra] `LRA-02`, cached lease profile. After revocation, verification still accepts the unexpired cached evidence and current validity is `not_established`. The action policy P1 denies dispatch as `authority_not_determined` because it requires an observation at the call instant. That is the reason an unreachable source also gets in LRA-03, so it is not a finding of revocation. The retained model and SDK primitive run records are author-produced. | Candidate |
| Revoked or outdated authority | Direct | [single-use approval][asu] `ASU-05-reject-revoked-at-consumption`. A chain revoked after the decision is rechecked at consumption and the permit is not admitted, `authority_chain_not_valid_at_consumption`. | Conformance |
| Revoked or outdated authority | Partial | [approval authority expiry][aex] `AEX-04-reject-authority-expired-approval-unexpired`, `AEX-05-reject-authority-at-exact-not-after`. The approval is still live but the authority behind it has expired, chain `invalid/EXPIRED`. Not admitted, `authority_chain_not_valid_at_consumption`. `AEX-02-reject-authority-revoked-at-consumption` is the revocation case, chain `invalid/REVOKED`. | Conformance |
| Revoked or outdated authority | Partial | [epoch rollback][aer] `AER-03-restored-snapshot-with-retained-record` and `AER-04-lagging-replica-epoch-only` assume the verifier has already observed a higher epoch. AER-03 stays `invalid` with `REVOKED` when a restored snapshot would show the grant active. AER-04 returns `indeterminate` with `REVOCATION_UNKNOWN`. It refuses the stale view but does not find a revocation. `AER-06-first-contact-no-prior-observation` returns `valid` on first contact, so stale state on first contact is not detected. No real restore or replica is tested. | Candidate |
| Revoked or outdated authority | Partial | [AAE vectors][aae] `aae-vector-04`, `aae-vector-11`. These are two different findings. In 04 the revocation endpoint answers 503 and the envelope is rejected as `revocation_status_indeterminate`, a fail-closed unknown status. In 11 a revoked parent leads to `ancestor_revoked`. | Outside candidate |
| Reuse of a consumed approval | Direct | [single-use approval][asu] `ASU-02-reject-already-consumed`. Rejects reuse of a consumed permit. | Conformance |
| Reuse of a consumed approval | Direct | [AAE vectors][aae] `aae-vector-05`. Rejects a single-use envelope presented after a recorded authorization. | Outside candidate |
| Approval used for a different action | Direct | [single-use approval][asu] `ASU-04-reject-action-binding-mismatch`. A permit presented for a different action than it names is not admitted, `action_binding_mismatch`. | Conformance |
| Approval used for a different action | Partial | [ARAP binding][arap] `A2`. A known approval presented for a different resource than it names is `out_of_scope` in a synthetic verification call, with next action `request`. The action verb is unchanged and no operation runs. | Candidate |
| Denied effect reached by another path | Partial | [denial continuity][rad] `A3-deny-then-alias-tool`, `A4-deny-then-delegate`, `A6-reauthorization-of-different-effect-does-not-unlock`, `A7-reauthorization-rejects-stale-denial-ref`, `B1-decomposition-composes-denied-effect`. An alias tool (A3) or a delegated path (A4) stays denied as `denied_effect_continuity`. A6 and A7 test what it takes to release an earlier denial. In A6, reauthorizing record 43 does not release the denial on record 42, and the same tool is retried. In A7, a stale denial reference is refused as `reauthorize_denial_ref_not_found`, and the retry later succeeds with the current reference. B1 refuses the last of three writes that complete one modelled decomposition of the denied effect, `composed_effect_denied_continuity`, only when composed-effect identification is declared. Without it the expected outcome is allow. All need an injected prior denial. | Candidate |
| Grant refused by the receiving domain's own policy | Partial | [policy change][lpc] `PC-11-LC-I-006-b-tightened-policy-restricts-the-action-not-the-grant`. After the same domain tightens its policy, the action is `restricted`, `denied_under_operative_policy_version`, while the chain stays `valid`. There is no grant from another domain. | Candidate |
| Grant refused by the receiving domain's own policy | Partial | [ARAP binding][arap] `A7`. An otherwise applicable approval is `policy_denied` because policy disables the subject. This is not a prohibition on the operation, and there is no grant from another domain. | Candidate |

## Delegation rights and unconfirmed completion

**Delegation rights. Partial.** No matching case identified in the inspected lab corpus withdraws a delegator's right to delegate later while its own scope stays usable. The nearest cases test zero remaining delegation depth at one fixed instant. In [conferral without authority][cwa], a delegator holds a valid grant with no remaining hops. A child with exactly the parent's scope (CWA-02), a strictly narrower child (CWA-03), a child at the second hop (CWA-04) and a self-issued child naming the agent itself (CWA-08) are all `invalid` with `DEPTH_EXHAUSTED` (candidate). [Subdelegation edges][sde] `LC-H-008-b` (`DEPTH_EXHAUSTED`, candidate) and [AAE vectors][aae] `aae-vector-09` (`delegation_depth_exceeded`, outside candidate) test exhausted depth. [Issuance refusal][irx] `IRX-02-reject-parent-expired` and `IRX-04-reject-parent-revoked` refuse to mint under an expired or revoked parent (conformance).

**Unconfirmed completion. Partial.** [Purpose exhaustion][pxe] `PXE-08-reject-unauthenticated-completion` and `PXE-09-reject-completion-from-party-without-standing` reject a completion record with an invalid signature or an attestor without standing. `PXE-10-reject-purchase-after-unauthenticated-completion` and `PXE-11-reject-purchase-after-completion-without-standing` refuse another purchase under the same purpose-bound grant as `bound_state_not_established`. Refusal in this uncertain exhaustion state is the fixture's chosen policy. These are candidates against the authority lifecycle text, using APS grant and receipt records plus a fixture-defined purpose bound. They do not test an action requiring successful completion of an earlier operation. Rejecting a completion record does not show that no effect happened.

## Remaining gaps

Each line names a test with no matching case identified in the inspected lab corpus, and says what the nearest rows lack.

- Critical operation without both required approvals (L4). LC-C-011 tests the two-role gate on records and never attempts the operation or checks that it does not run.
- Just-in-time grant (L4). A fresh grant required for one critical call, with the call refused without it.
- Concurrent single-use consumption (L4). ASU-07 runs its two calls one after the other on one instance.
- Concurrent shared-limit accounting (L4). Two distinct valid approvals drawing on one shared budget at the same time. ASU-07 and the denial continuity cases use no shared budget.
- Crash and restart recovery against single-use or shared limits (L4). ASE-07 takes cache loss as an input and never restarts a boundary after a permit or budget was used, then retries.
- Descendant use after parent revocation beyond the propagation limit, in one case (L4). CAR checks supplied call times beyond the propagation limit but models no chain. AAC and LC-H-009 check chains without a maximum propagation delay.
- Proof that the presenter holds the bound key (L5). ASE-12 and the token exchange actor check compare identities only.
- A valid grant from another domain refused by the receiving domain's own policy (L5). PC-11 and ARAP A7 refuse inside one domain, and A7's reason is a disabled subject.
- Later loss of the right to delegate while the delegator's own scope stays usable. CWA tests zero remaining depth at one instant.
- An action requiring successful completion of an earlier operation whose outcome remains unresolved. PXE-10 and PXE-11 check uncertain purpose exhaustion before another purchase, rather than a successful completion prerequisite.

Anyone can contribute a candidate for these gaps under [CONTRIBUTING.md](../../CONTRIBUTING.md), using their own record format and terms.

## Case sources

Each linked source records the target revision and the evidence available. Candidate status applies even where a case also exercises behavior already implemented by an SDK.

| Case family | Target and format |
|---|---|
| [Single-chain selection][scs], [single-use approval][asu], [ancestor revocation][arc], [approval authority expiry][aex], [issuance refusal][irx] | Conformance cases against draft-pidlisnyi-aps-03, in APS format. |
| [AAE vectors][aae] | Outside candidate against the Agent Authorization Envelope Internet-Draft, in AAE format. |
| [Subdelegation edges][sde], [purpose exhaustion][pxe], [epoch rollback][aer], [multiple principals][lmp], [legal and regulatory events][lre], [organization events][loe], [agent-side events][ase], [policy change][lpc], [conferral without authority][cwa] | Candidates against the named authority lifecycle documents and revisions in their READMEs. They use APS delegation records together with family-specific record shapes or model inputs. Some also cite a draft-03 rule. That does not make them conformance cases. |
| [Cached authorization][car] | Candidate against OWASP MCP Top 10 PR #63, using a neutral harness. |
| [Denial continuity][rad] | Candidate against OWASP agentic-skills-top-10 issue #71, using a neutral harness. |
| [ARAP binding][arap] | Candidate against the AuthZEN Access Request Approval Profile text at openid/authzen commit `2e9412c`, recorded in PR #658. That PR later merged. These cases stay tied to that pin and make no conformance claim about the merged profile. Uses a lab reference harness, not an AuthZEN implementation. |
| [Token exchange][tea] | Candidate against the ToolHive attenuation criterion in stacklok/toolhive #6424 and #6511. Uses plain, unsigned claim structures. RFC 8693 does not impose this invariant. |
| [Lease and revocation][lra] | Candidate against the lab's revision 3 proposal, using a format-neutral reference model. The model and SDK primitive run records are author-produced. They do not establish another system's cached or live behavior, or P1 dispatch at a real enforcement boundary. No independent run. |


[scs]: ../../fixtures/single-chain-selection/README.md
[asu]: ../../fixtures/approval-single-use/README.md
[arc]: ../../fixtures/ancestor-revocation-chain/README.md
[aex]: ../../fixtures/approval-authority-expiry/README.md
[irx]: ../../fixtures/issuance-refusal-expiry/README.md
[aae]: ../../candidates/moltycel-aae-vectors/CANDIDATE.md
[sde]: ../../fixtures/lifecycle-subdelegation-edges/README.md
[pxe]: ../../fixtures/lifecycle-purpose-exhaustion/README.md
[aer]: ../../fixtures/authority-epoch-rollback/README.md
[lmp]: ../../fixtures/lifecycle-multiple-principals-and-conflict/README.md
[lre]: ../../fixtures/lifecycle-legal-regulatory-events/README.md
[loe]: ../../fixtures/lifecycle-organization-events/README.md
[ase]: ../../fixtures/lifecycle-agent-side-events/README.md
[lpc]: ../../fixtures/lifecycle-policy-change/README.md
[cwa]: ../../fixtures/lifecycle-conferral-without-authority/README.md
[car]: ../../fixtures/cached-authorization-revocation/README.md
[rad]: ../../fixtures/runtime-authority-denial-continuity/README.md
[arap]: ../../fixtures/arap-binding/README.md
[tea]: ../../fixtures/cross-stack/token-exchange-attenuation-v0/SOURCE.md
[lra]: ../../fixtures/lease-revocation-axes/README.md
