# SDK runs for lifecycle-subdelegation-edges

Both reference SDKs were run against this family on 2026-09-23. This file
records the exact commands, exit codes and verbatim output. It is a record of
four runs, not a conformance verdict on either implementation.

Both runs are **author-produced**: the vectors, the harness, both runners and
both probes were written in this lab, and neither SDK was reviewed by anyone
outside it. The two SDKs also share an author, so agreement between them is
weaker evidence than agreement between two independently authored
implementations would be.

| field | value |
|---|---|
| date | 2026-09-23 |
| corpus commit | the commit this file is committed in, on branch `candidate/lifecycle-cases-g8` |
| npm implementation | `agent-passport-system` 7.1.0, installed by `npm ci --include=dev` from the pinned `package-lock.json` |
| PyPI implementation | `agent-passport-system` 4.1.0, installed into a local venv |
| node | v24.11.1 |
| python | 3.14.6 |
| operating system | darwin 25.5.0 |
| network during the runs | none after install |

## Claim table

Every `not_supported` row names the API that is missing. Nothing was simulated
to fill one in.

| claim | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|
| 1. chain verdict for a presented chain under the vector's revocation answers | supported, 10/10 verify vectors | supported, 10/10 verify vectors |
| 2. a child's declared validity period compared against its parent's at verification time | supported, TIME_WIDENING at the child's index | supported, TIME_WIDENING at the child's index |
| 3. a chain's declared maximum subdelegation depth enforced across the whole chain | supported, DEPTH_EXHAUSTED at the deepest index | supported, DEPTH_EXHAUSTED at the deepest index |
| 4. issuer refusal to mint a child outside its parent's window or past its declared depth | not exercised, the refusals were minted with the PyPI SDK | supported, TIME_WIDENING and DEPTH_EXHAUSTED raised at issuance |
| 5. a per-artifact-only verification mode, for the negative control | not_supported, no API in this SDK. Built in harness.ts | not_supported, no API in this SDK. Built in verify.py |
| 6. taking a member's status from a pinned issuer observation, for the negative control | not_supported, no API in this SDK. Built in harness.ts | not_supported, no API in this SDK. Built in verify.py |
| 7. a boundary record naming the earlier record it follows by digest | not_supported, no API in this SDK. Built on the vendored RFC 8785 canonicalizer | not_supported, no API in this SDK. Built on the verify.py canonicalizer |

## The two digests both runners produced

The LC-H-009 record-continuity vector is the only place this family compares
two independently computed canonical digests. Both runners produced the same
pair, which is recorded here because a divergence would have meant the two
canonicalizers disagree:

    LC-H-009-a  cb9e4007477880df24d1a28b2e3ddaa0cf0369cd76cb9941d5582cde011e5589
    LC-H-009-b  5aff4238c2b517e9cc59367e8656db29c159b3ee0c9a0a1d4c7ee6ca2433a244

Both are pinned in `vectors.json`.

## TypeScript

    $ npm ci --include=dev
    $ npx tsx fixtures/lifecycle-subdelegation-edges/verify.ts
    # exit code 0

    PASS LC-H-007-a reference=valid per-artifact-only=valid(agrees=true) issuer-attestation-trusting=valid(agrees=true)
    PASS LC-H-007-b reference=valid per-artifact-only=valid(agrees=true) issuer-attestation-trusting=valid(agrees=true)
    PASS LC-H-007-c reference=invalid/TIME_WIDENING@1 per-artifact-only=valid(agrees=false) issuer-attestation-trusting=invalid/TIME_WIDENING@1(agrees=true) negative_control=true
    PASS LC-H-007-d reference=invalid/TIME_WIDENING@1 per-artifact-only=invalid/EXPIRED@0(agrees=false) issuer-attestation-trusting=invalid/TIME_WIDENING@1(agrees=true)
    PASS LC-H-007-e raised=true code=TIME_WIDENING
    PASS LC-H-008-a reference=valid per-artifact-only=valid(agrees=true) issuer-attestation-trusting=valid(agrees=true)
    PASS LC-H-008-b reference=invalid/DEPTH_EXHAUSTED@2 per-artifact-only=valid(agrees=false) issuer-attestation-trusting=invalid/DEPTH_EXHAUSTED@2(agrees=true) negative_control=true
    PASS LC-H-008-c raised=true code=DEPTH_EXHAUSTED
    PASS LC-H-008-d reference=invalid/DEPTH_EXHAUSTED@2 per-artifact-only=invalid/REVOKED@2(agrees=false) issuer-attestation-trusting=invalid/DEPTH_EXHAUSTED@2(agrees=true) negative_control=true
    PASS LC-H-009-a reference=valid per-artifact-only=valid(agrees=true) issuer-attestation-trusting=valid(agrees=true)
    PASS LC-H-009-b reference=invalid/REVOKED@0 per-artifact-only=invalid/REVOKED@0(agrees=true) issuer-attestation-trusting=valid(agrees=false)
    PASS LC-H-009-c reference=invalid/REVOKED@0 per-artifact-only=invalid/REVOKED@0(agrees=true) issuer-attestation-trusting=valid(agrees=false) negative_control=true
    PASS LC-H-009-d earlier=cb9e4007477880df later.prior=cb9e4007477880df
    lifecycle-subdelegation-edges TypeScript: 13/13 passed

    $ node fixtures/lifecycle-subdelegation-edges/sdk-probe.mjs
    # exit code 0

    supported     1. chain verdict for a presented chain under the vector's revocation answers
                     api: verifyAuthorityDelegationChain
    supported     2. a child's declared validity period compared against its parent's at verification time
                     api: verifyAuthorityDelegationChain
    supported     3. a chain's declared maximum subdelegation depth enforced across the whole chain
                     api: verifyAuthorityDelegationChain
    supported     4. issuer refusal to mint a child outside its parent's window or past its declared depth
                     api: issueSubAuthorityDelegation
    not_supported  5. a per-artifact-only verification mode, for the negative control
                     api: none in this SDK
    not_supported  6. taking a member's status from a pinned issuer observation, for the negative control
                     api: none in this SDK
    not_supported  7. a boundary record naming the earlier record it follows by digest
                     api: none in this SDK
    lifecycle-subdelegation-edges npm probe: 4/7 claims have an API

## Python

    $ python3 fixtures/lifecycle-subdelegation-edges/verify.py
    # exit code 0

    PASS LC-H-007-a reference=valid per-artifact-only=valid(agrees=True) issuer-attestation-trusting=valid(agrees=True)
    PASS LC-H-007-b reference=valid per-artifact-only=valid(agrees=True) issuer-attestation-trusting=valid(agrees=True)
    PASS LC-H-007-c reference=invalid/TIME_WIDENING@1 per-artifact-only=valid(agrees=False) issuer-attestation-trusting=invalid/TIME_WIDENING@1(agrees=True) negative_control=True
    PASS LC-H-007-d reference=invalid/TIME_WIDENING@1 per-artifact-only=invalid/EXPIRED@0(agrees=False) issuer-attestation-trusting=invalid/TIME_WIDENING@1(agrees=True)
    PASS LC-H-007-e raised=True code=TIME_WIDENING
    PASS LC-H-008-a reference=valid per-artifact-only=valid(agrees=True) issuer-attestation-trusting=valid(agrees=True)
    PASS LC-H-008-b reference=invalid/DEPTH_EXHAUSTED@2 per-artifact-only=valid(agrees=False) issuer-attestation-trusting=invalid/DEPTH_EXHAUSTED@2(agrees=True) negative_control=True
    PASS LC-H-008-c raised=True code=DEPTH_EXHAUSTED
    PASS LC-H-008-d reference=invalid/DEPTH_EXHAUSTED@2 per-artifact-only=invalid/REVOKED@2(agrees=False) issuer-attestation-trusting=invalid/DEPTH_EXHAUSTED@2(agrees=True) negative_control=True
    PASS LC-H-009-a reference=valid per-artifact-only=valid(agrees=True) issuer-attestation-trusting=valid(agrees=True)
    PASS LC-H-009-b reference=invalid/REVOKED@0 per-artifact-only=invalid/REVOKED@0(agrees=True) issuer-attestation-trusting=valid(agrees=False)
    PASS LC-H-009-c reference=invalid/REVOKED@0 per-artifact-only=invalid/REVOKED@0(agrees=True) issuer-attestation-trusting=valid(agrees=False) negative_control=True
    PASS LC-H-009-d earlier=cb9e4007477880df later.prior=cb9e4007477880df
    lifecycle-subdelegation-edges Python: 13/13 passed

    $ python3 fixtures/lifecycle-subdelegation-edges/sdk_probe.py
    # exit code 0

    supported     1. chain verdict for a presented chain under the vector's revocation answers
                     api: verify_authority_delegation_chain
    supported     2. a child's declared validity period compared against its parent's at verification time
                     api: verify_authority_delegation_chain
    supported     3. a chain's declared maximum subdelegation depth enforced across the whole chain
                     api: verify_authority_delegation_chain
    supported     4. issuer refusal to mint a child outside its parent's window or past its declared depth
                     api: issue_sub_authority_delegation
    not_supported  5. a per-artifact-only verification mode, for the negative control
                     api: none in this SDK
    not_supported  6. taking a member's status from a pinned issuer observation, for the negative control
                     api: none in this SDK
    not_supported  7. a boundary record naming the earlier record it follows by digest
                     api: none in this SDK
    lifecycle-subdelegation-edges PyPI probe: 4/7 claims have an API
