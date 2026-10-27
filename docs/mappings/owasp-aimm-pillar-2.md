# OWASP AIMM Pillar 2 test mapping

This proposed mapping compares the L4 and L5 negative tests in section 5.1 of the OWASP AIMM working draft, as read on 2026-10-25, with published lab cases at [`47fd146`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/47fd14696bacb0991f16056242d73887a3362b0f).

The mapping has no OWASP approval and is not part of AIMM. A match here does not establish that an implementation meets an AIMM level.

## Reading the tables

**Direct** means the case exercises the named failure. **Partial** means it covers only part of the test. Each row states its limits.

- **Conformance** cases target a rule in draft-pidlisnyi-aps-03.
- **Candidate** cases target proposed text. The case sources below name the text and record format.
- **Outside candidate** cases are MoltyCel's AAE vectors. They are published as a candidate, have not been admitted as reviewed fixtures, and do not run in lab CI.

Each case links to its source and verification notes. Most use APS records and need an adapter for other formats. A run by the vector author is author-produced evidence, not an independent run. Runtime enforcement needs a test of the running system as well as records.

## L4

| Failure tested | Match | Cases and limits | Status |
|---|---|---|---|
| Child granted more than its parent | Direct | [single-chain selection][scs] SCS-03, SCS-04. A hop that adds a scope its parent never granted is rejected with `SCOPE_WIDENING`. | Conformance |
| Child granted more than its parent | Direct | [AAE vectors][aae] 07, 08. A delegated envelope with an action its parent lacks, or a value cap above the parent's, is rejected. | Outside candidate |
| Child valid longer than its parent | Direct | [subdelegation edges][sde] LC-H-007. Refuses issuance when the child's validity outlasts its parent's and reports `TIME_WIDENING` at verification. LC-H-007-c distinguishes this from checking each record's window on its own. | Candidate |
| Reuse of a consumed approval | Direct | [single-use approval][asu] ASU-02. A permit already consumed is not admitted again. | Conformance |
| Reuse of a consumed approval | Direct | [AAE vectors][aae] 05. A single-use envelope presented after a recorded authorization is rejected. | Outside candidate |
| Use of an expired approval | Direct | [single-use approval][asu] ASU-03. A permit presented after its own `valid_until` is not admitted. | Conformance |
| Child use after parent revocation, past a propagation limit | Partial | [cached authorization][car] CAR-03, CAR-05. CAR-03 denies use of the revoked grant past the propagation limit, with no attempt recorded by the downstream test double. No parent-child chain is modelled. CAR-05 records exposure inside the window. Neither tests a child's use after its parent is revoked. | Candidate |
| Child use after parent revocation | Partial | [ancestor revocation][arc]. A revoked ancestor fails the whole chain at its index, however deep. Revocation takes effect at once, so no propagation limit is tested. | Conformance |
| Child use after parent revocation | Partial | [subdelegation edges][sde] LC-H-009. Models a child minted after ancestor revocation was recorded but before the issuer could see it. This is a hypothetical case. | Candidate |
| Simultaneous use of a single-use approval | Partial | [single-use approval][asu] ASU-07a, ASU-07b. Presents one permit twice at the same modelled instant. The second is refused as `already_consumed`. The calls run sequentially on one instance, so this does not test real concurrency. | Conformance |
| Retry after refusal | Partial | [denial continuity][rad] A2. Retries a denied call and keeps it denied. Does not test retry or recovery against a single-use or shared limit. | Candidate |

## L5

| Failure tested | Match | Cases and limits | Status |
|---|---|---|---|
| Issuer the verifier should not accept | Partial | [AAE vectors][aae] 12. Rejects an envelope naming one issuer but signed by another key. Does not test an otherwise valid issuer outside the relying party's trust. | Outside candidate |
| Issuer the verifier should not accept | Partial | [AAE vectors][aae] enforce 23. Rejects an otherwise correct, validly signed ratification from a party the mandate does not name. | Outside candidate |
| Malformed delegation chain | Partial | [single-chain selection][scs] SCS-06. A chain spliced from two chains' roots is rejected with `PARENT_MISMATCH`. One malformed form only. | Conformance |
| Malformed delegation chain | Partial | [AAE vectors][aae] 10. A chain that revisits an envelope is rejected as a cycle. | Outside candidate |
| Authority wider than granted | Direct | [single-chain selection][scs] SCS-03, SCS-04. Rejects a child scope its parent did not grant. | Conformance |
| Authority wider than granted | Direct | [AAE vectors][aae] 07, 08. Rejects a delegated envelope with an added action or a higher value cap than its parent. | Outside candidate |
| Authority wider than granted | Direct | [token exchange][tea]. Tests scope widening and access to claims available only in the subject token, including `act` chains of depth 2 and 3. Uses unsigned claim structures. | Candidate |
| Used at the wrong audience or by the wrong party | Partial | [token exchange][tea] audience-mismatch, actor-not-permitted. Denies a wrong audience as `audience_mismatch` and a disallowed actor as `actor_not_permitted`. Does not test proof that the presenter holds a bound key. | Candidate |
| Revoked or outdated authority | Direct | [lease and revocation][lra]. Compares cached and live revocation reads on a fixed timeline, scored on three axes. Revision 3 distinguishes an unreachable source from a revoked grant. All three outside run records are author-produced. | Candidate |
| Revoked or outdated authority | Direct | [single-use approval][asu] ASU-05. A chain revoked after the decision is rechecked at consumption and the permit is not admitted. | Conformance |
| Revoked or outdated authority | Partial | [approval authority expiry][aex]. Authority that expires between approval and consumption is rechecked at consumption. Expiry only. | Conformance |
| Revoked or outdated authority | Partial | [epoch rollback][aer]. A restored snapshot or lagging replica must not revive authority revoked at a later epoch. Rollback only. | Candidate |
| Revoked or outdated authority | Partial | [AAE vectors][aae] 04, 11. A revocation endpoint that answers 503 leads to rejection, and so does a revoked parent. | Outside candidate |
| Reuse of a consumed approval | Direct | [single-use approval][asu] ASU-02. Rejects reuse of a consumed permit. | Conformance |
| Reuse of a consumed approval | Direct | [AAE vectors][aae] 05. Rejects a single-use envelope presented after a recorded authorization. | Outside candidate |
| Approval used for a different action | Direct | [single-use approval][asu] ASU-04. A permit presented for a different action than it names is not admitted. | Conformance |
| Denied effect reached by another path | Partial | [denial continuity][rad] A3, A4. Keeps the same effect denied through an alias tool or a delegated path. Does not cover a bypass without a prior denial. | Candidate |

## Delegation rights and unconfirmed completion

**Delegation rights. Partial.** No case removes a delegator's right to delegate while its own scope stays unchanged. The nearest cases test exhausted delegation depth in [subdelegation edges][sde] LC-H-008 (`DEPTH_EXHAUSTED`, candidate) and [AAE vectors][aae] 09 (`max_depth`, outside candidate). [Issuance refusal][irx] IRX-02 and IRX-04 refuse to mint under an expired or revoked parent (conformance).

**Unconfirmed completion. Partial.** [Purpose exhaustion][pxe] PXE-08 and PXE-09 reject a completion record with an invalid signature or an attestor without standing. PXE-10 and PXE-11 refuse a dependent action as `bound_state_not_established`. These are candidates against the authority lifecycle text, in APS format.

## Coverage gaps

- A critical action that needs a just-in-time grant or two approvals, attempted without them (L4).
- Real concurrent consumption, and recovery or retry against single-use or shared limits (L4). ASU-07 is sequential. A2 retries a denied call rather than a consumed permit.
- A child's use after its parent is revoked, past a propagation limit, in one combined case (L4). CAR-03 tests the limit for the revoked grant itself. The ancestor-chain cases do not test a propagation limit.
- An otherwise valid issuer outside the relying party's trust (L5).
- Proof that the presenter holds the bound key (L5).
- A valid grant from another domain asking for an action the receiving domain's own policy forbids (L5).
- A delegator losing its right to delegate while its own scope stays unchanged.

Anyone can contribute a candidate for these gaps under [CONTRIBUTING.md](../../CONTRIBUTING.md), using their own record format and terms.

## Case sources

Each linked source records the target revision and the evidence available. Candidate status applies even where a case also exercises behavior already implemented by an SDK.

| Case family | Target and format |
|---|---|
| [Single-chain selection][scs], [single-use approval][asu], [ancestor revocation][arc], [approval authority expiry][aex], [issuance refusal][irx] | Conformance cases against draft-pidlisnyi-aps-03, in APS format. |
| [AAE vectors][aae] | Outside candidate against the Agent Authorization Envelope Internet-Draft, in AAE format. |
| [Subdelegation edges][sde], [purpose exhaustion][pxe], [epoch rollback][aer] | Candidates against the named authority lifecycle documents and revisions in their READMEs, in APS format. |
| [Cached authorization][car] | Candidate against OWASP MCP Top 10 PR #63, using a neutral harness. |
| [Denial continuity][rad] | Candidate against OWASP agentic-skills-top-10 issue #71, using a neutral harness. |
| [Token exchange][tea] | Candidate against the ToolHive attenuation criterion in stacklok/toolhive #6424 and #6511. Uses plain, unsigned claim structures. RFC 8693 does not impose this invariant. |
| [Lease and revocation][lra] | Candidate against the lab's revision 3 proposal, using a format-neutral reference model. Three outside run records, all author-produced. No independent run. |


[scs]: ../../fixtures/single-chain-selection/README.md
[asu]: ../../fixtures/approval-single-use/README.md
[arc]: ../../fixtures/ancestor-revocation-chain/README.md
[aex]: ../../fixtures/approval-authority-expiry/README.md
[irx]: ../../fixtures/issuance-refusal-expiry/README.md
[aae]: ../../candidates/moltycel-aae-vectors/CANDIDATE.md
[sde]: ../../fixtures/lifecycle-subdelegation-edges/README.md
[pxe]: ../../fixtures/lifecycle-purpose-exhaustion/README.md
[aer]: ../../fixtures/authority-epoch-rollback/README.md
[car]: ../../fixtures/cached-authorization-revocation/README.md
[rad]: ../../fixtures/runtime-authority-denial-continuity/README.md
[tea]: ../../fixtures/cross-stack/token-exchange-attenuation-v0/SOURCE.md
[lra]: ../../fixtures/lease-revocation-axes/README.md
