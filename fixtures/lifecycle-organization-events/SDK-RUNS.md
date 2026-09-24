# SDK runs for lifecycle-organization-events

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
| 1. chain verdict for a presented chain under the vector's revocation answers | supported, 34/34 vectors | supported, 34/34 vectors |
| 2. issuer refusal to mint a successor grant outside the successor's own scope | not exercised, the refusal was minted with the PyPI SDK | supported, SCOPE_WIDENING raised at issuance |
| 3. detached Ed25519 verification of an external record's canonical bytes | supported, 6/6 external records | supported, 6/6 external records |
| 4. principal binding reported separately from chain validity | not_supported, no API in this SDK. Built in harness.ts | not_supported, no API in this SDK. Built in verify.py |
| 5. attestor standing evaluated against a verifier trust policy | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 6. an external restriction that narrows scope without revoking, reported as restricted | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 7. a third-party consent gate keyed to an exact target and operation | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 8. an in-flight acceptance boundary for a submitted order | not_supported, no API in this SDK | not_supported, no API in this SDK |

## Cross-language agreement on the external records

The six external records are signed over their own RFC 8785 canonical bytes by
the PyPI SDK at mint time and verified by both SDKs at run time. Both runners
accepted all six and rejected none, so the vendored TypeScript canonicalizer
and the Python mirror in `verify.py` produce the same bytes for every record in
`chains.json`. A divergence there would have surfaced as an
`attestation_signature_invalid` on one side only.

## TypeScript

    $ npm ci --include=dev
    $ npx tsx fixtures/lifecycle-organization-events/verify.ts
    # exit code 0

    PASS LC-B-004-a reference=admitted/admitted
    PASS LC-B-004-b reference=not_admitted/chain_not_valid
    PASS LC-B-004-c reference=not_admitted/chain_not_valid successor-exists-in-role=admitted/admitted(outcome_differs=true,record_differs=true) negative_control=true
    PASS LC-B-004-d reference=not_admitted/chain_not_valid successor-exists-in-role=admitted/admitted(outcome_differs=true,record_differs=true)
    PASS LC-B-004-e raised=true code=SCOPE_WIDENING
    PASS LC-B-012-a reference=admitted/admitted
    PASS LC-B-012-b reference=not_admitted/corporate_record_is_not_a_delegation_event corporate-record-as-delegation-event=admitted/admitted(outcome_differs=true,record_differs=true)
    PASS LC-B-012-c reference=admitted/admitted
    PASS LC-B-013-a reference=not_admitted/corporate_record_is_not_a_delegation_event corporate-record-as-delegation-event=admitted/admitted(outcome_differs=true,record_differs=true) negative_control=true
    PASS LC-B-013-b reference=not_admitted/attestation_attestor_without_standing
    PASS LC-B-016-a reference=admitted/admitted
    PASS LC-B-016-b reference=not_admitted/external_restriction_excludes_operation restriction-blind=admitted/admitted(outcome_differs=true,record_differs=true) negative_control=true
    PASS LC-B-016-c reference=admitted/admitted_within_remaining_scope restriction-blind=admitted/admitted(outcome_differs=false,record_differs=true)
    PASS LC-B-016-d reference=admitted/admitted
    PASS LC-B-030-a reference=admitted/admitted
    PASS LC-B-030-b reference=not_admitted/third_party_consent_absent internal-chain-only=admitted/admitted(outcome_differs=true,record_differs=true) negative_control=true
    PASS LC-B-030-c reference=not_admitted/consent_attestor_without_standing internal-chain-only=admitted/admitted(outcome_differs=true,record_differs=true)
    PASS LC-B-030-d reference=not_admitted/consent_target_mismatch internal-chain-only=admitted/admitted(outcome_differs=true,record_differs=true)
    PASS LC-B-028-a reference=admitted/order_submitted
    PASS LC-B-028-b reference=stop_effective/stop_received_before_acceptance approval-time-check-only=stop_not_effective/authorization_settled_at_submission(outcome_differs=true,record_differs=true) negative_control=true
    PASS LC-B-028-c reference=not_accepted/stopped_before_acceptance approval-time-check-only=accepted/accepted_by_receiving_institution(outcome_differs=true,record_differs=true)
    PASS LC-B-028-d reference=not_settled/stopped_before_acceptance approval-time-check-only=settled/accepted_order_proceeds(outcome_differs=true,record_differs=true)
    PASS LC-B-028-e reference=admitted/order_submitted
    PASS LC-B-028-f reference=accepted/accepted_by_receiving_institution
    PASS LC-B-028-g reference=stop_not_effective/stop_received_after_acceptance approval-time-check-only=stop_not_effective/authorization_settled_at_submission(outcome_differs=false,record_differs=true)
    PASS LC-B-028-h reference=settled/accepted_order_proceeds
    PASS LC-B-029-a reference=admitted/order_submitted
    PASS LC-B-029-b reference=recorded/revocation_recorded
    PASS LC-B-029-c reference=not_accepted/authority_ended_before_acceptance
    PASS LC-B-029-d reference=not_settled/never_accepted
    PASS LC-B-029-e reference=admitted/order_submitted
    PASS LC-B-029-f reference=accepted/accepted_by_receiving_institution
    PASS LC-B-029-g reference=recorded/revocation_recorded
    PASS LC-B-029-h reference=settled/accepted_order_proceeds revocation-halts-everything=not_settled/revocation_halts_submitted_orders(outcome_differs=true,record_differs=true) negative_control=true
    PASS LC-B-029-i reference=not_admitted/chain_not_valid
    lifecycle-organization-events TypeScript: 35/35 passed

    $ node fixtures/lifecycle-organization-events/sdk-probe.mjs
    # exit code 0

    supported     1. chain verdict for a presented chain under the vector's revocation answers
                     api: verifyAuthorityDelegationChain
    supported     2. issuer refusal to mint a successor grant outside the successor's own scope
                     api: issueSubAuthorityDelegation
    supported     3. detached Ed25519 verification of an external record's canonical bytes
                     api: verify
    not_supported  4. principal binding reported separately from chain validity
                     api: none in this SDK
    not_supported  5. attestor standing evaluated against a verifier trust policy
                     api: none in this SDK
    not_supported  6. an external restriction that narrows scope without revoking, reported as restricted
                     api: none in this SDK
    not_supported  7. a third-party consent gate keyed to an exact target and operation
                     api: none in this SDK
    not_supported  8. an in-flight acceptance boundary for a submitted order
                     api: none in this SDK
    lifecycle-organization-events npm probe: 3/8 claims have an API

## Python

    $ python3 fixtures/lifecycle-organization-events/verify.py
    # exit code 0

    PASS LC-B-004-a reference=admitted/admitted
    PASS LC-B-004-b reference=not_admitted/chain_not_valid
    PASS LC-B-004-c reference=not_admitted/chain_not_valid successor-exists-in-role=admitted/admitted(outcome_differs=True,record_differs=True) negative_control=True
    PASS LC-B-004-d reference=not_admitted/chain_not_valid successor-exists-in-role=admitted/admitted(outcome_differs=True,record_differs=True)
    PASS LC-B-004-e raised=True code=SCOPE_WIDENING
    PASS LC-B-012-a reference=admitted/admitted
    PASS LC-B-012-b reference=not_admitted/corporate_record_is_not_a_delegation_event corporate-record-as-delegation-event=admitted/admitted(outcome_differs=True,record_differs=True)
    PASS LC-B-012-c reference=admitted/admitted
    PASS LC-B-013-a reference=not_admitted/corporate_record_is_not_a_delegation_event corporate-record-as-delegation-event=admitted/admitted(outcome_differs=True,record_differs=True) negative_control=True
    PASS LC-B-013-b reference=not_admitted/attestation_attestor_without_standing
    PASS LC-B-016-a reference=admitted/admitted
    PASS LC-B-016-b reference=not_admitted/external_restriction_excludes_operation restriction-blind=admitted/admitted(outcome_differs=True,record_differs=True) negative_control=True
    PASS LC-B-016-c reference=admitted/admitted_within_remaining_scope restriction-blind=admitted/admitted(outcome_differs=False,record_differs=True)
    PASS LC-B-016-d reference=admitted/admitted
    PASS LC-B-030-a reference=admitted/admitted
    PASS LC-B-030-b reference=not_admitted/third_party_consent_absent internal-chain-only=admitted/admitted(outcome_differs=True,record_differs=True) negative_control=True
    PASS LC-B-030-c reference=not_admitted/consent_attestor_without_standing internal-chain-only=admitted/admitted(outcome_differs=True,record_differs=True)
    PASS LC-B-030-d reference=not_admitted/consent_target_mismatch internal-chain-only=admitted/admitted(outcome_differs=True,record_differs=True)
    PASS LC-B-028-a reference=admitted/order_submitted
    PASS LC-B-028-b reference=stop_effective/stop_received_before_acceptance approval-time-check-only=stop_not_effective/authorization_settled_at_submission(outcome_differs=True,record_differs=True) negative_control=True
    PASS LC-B-028-c reference=not_accepted/stopped_before_acceptance approval-time-check-only=accepted/accepted_by_receiving_institution(outcome_differs=True,record_differs=True)
    PASS LC-B-028-d reference=not_settled/stopped_before_acceptance approval-time-check-only=settled/accepted_order_proceeds(outcome_differs=True,record_differs=True)
    PASS LC-B-028-e reference=admitted/order_submitted
    PASS LC-B-028-f reference=accepted/accepted_by_receiving_institution
    PASS LC-B-028-g reference=stop_not_effective/stop_received_after_acceptance approval-time-check-only=stop_not_effective/authorization_settled_at_submission(outcome_differs=False,record_differs=True)
    PASS LC-B-028-h reference=settled/accepted_order_proceeds
    PASS LC-B-029-a reference=admitted/order_submitted
    PASS LC-B-029-b reference=recorded/revocation_recorded
    PASS LC-B-029-c reference=not_accepted/authority_ended_before_acceptance
    PASS LC-B-029-d reference=not_settled/never_accepted
    PASS LC-B-029-e reference=admitted/order_submitted
    PASS LC-B-029-f reference=accepted/accepted_by_receiving_institution
    PASS LC-B-029-g reference=recorded/revocation_recorded
    PASS LC-B-029-h reference=settled/accepted_order_proceeds revocation-halts-everything=not_settled/revocation_halts_submitted_orders(outcome_differs=True,record_differs=True) negative_control=True
    PASS LC-B-029-i reference=not_admitted/chain_not_valid
    lifecycle-organization-events Python: 35/35 passed

    $ python3 fixtures/lifecycle-organization-events/sdk_probe.py
    # exit code 0

    supported     1. chain verdict for a presented chain under the vector's revocation answers
                     api: verify_authority_delegation_chain
    supported     2. issuer refusal to mint a successor grant outside the successor's own scope
                     api: issue_sub_authority_delegation
    supported     3. detached Ed25519 verification of an external record's canonical bytes
                     api: verify
    not_supported  4. principal binding reported separately from chain validity
                     api: none in this SDK
    not_supported  5. attestor standing evaluated against a verifier trust policy
                     api: none in this SDK
    not_supported  6. an external restriction that narrows scope without revoking, reported as restricted
                     api: none in this SDK
    not_supported  7. a third-party consent gate keyed to an exact target and operation
                     api: none in this SDK
    not_supported  8. an in-flight acceptance boundary for a submitted order
                     api: none in this SDK
    lifecycle-organization-events PyPI probe: 3/8 claims have an API
