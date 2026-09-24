# SDK runs for lifecycle-purpose-exhaustion

Both reference SDKs were run against this family on 2026-09-24, after the two earlier
builds of this directory were reconciled into one. This file records the exact commands,
exit codes and verbatim output. It is a record of four runs, not a conformance verdict on
either implementation.

All four runs are **author-produced**: the vectors, both harness classes, both runners and
both probes were written in this lab, and neither SDK was reviewed by anyone outside it.
The two SDKs also share an author, so agreement between them is weaker evidence than
agreement between two independently authored implementations would be.

| field | value |
|---|---|
| date | 2026-09-24 |
| corpus commit | the commit this file is committed in, on branch `lifecycle-pr/purpose-exhaustion` |
| npm implementation | `agent-passport-system` 7.1.0, installed by `npm ci --include=dev` from the pinned `package-lock.json` |
| PyPI implementation | `agent-passport-system` 4.1.0, installed into a local venv |
| node | v24.11.1 |
| python | 3.14.6 |
| operating system | darwin 25.5.0 |
| network during the runs | none after install |

## Claim table

Eleven claims, produced by the two probes rather than typed. Claims 1 to 5 are the
single-use track's, 6 to 11 the bounds track's. Every `not_supported` row names the API
that is missing. Nothing was simulated to fill one in.

| claim | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|
| 1. chain verdict for a presented chain at the event's instant | supported, `verifyAuthorityDelegationChain` | supported, `verify_authority_delegation_chain` |
| 2. an exhaustion ledger keyed to a grant, carried across an ordered event list | not_supported, no API in this SDK. Built in `harness.ts` | not_supported, no API in this SDK. Built in `verify.py` |
| 3. a second presentation of a single-use grant reaching artifacts issued out of it | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 4. an exhaustion state distinguishable from revoked and from expired in a recorded result | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 5. a refusal to undo an exhaustion, and standing checked separately from reversibility | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 6. purpose membership for a requested purpose against a grant's allowed purposes | supported, `isPurposePermitted` | **not_supported**, no `is_purpose_permitted` in any module of `agent_passport` 4.1.0 |
| 7. a completion record's signature and stage validity | supported, `verifyReceiptV1` | supported, `receipt_core.verify_receipt_v1` |
| 8. cumulative spend across a delegation subtree, reserved then settled | supported, `InMemoryAuthorityBudgetLedger` | supported, `InMemoryAuthorityBudgetLedger` |
| 9. a detached signature over canonical JCS bytes, for a principal-signed bound | supported, `canonicalizeJCS` with `verify` | supported, `canonicalize_jcs` with `verify` |
| 10. a purpose bound reached, established from a fulfillment record | not_supported, no API in this SDK | not_supported, no API in this SDK |
| 11. a use-count bound reached, established from the boundary's own admissions | not_supported, no API in this SDK | not_supported, no API in this SDK |

npm answers 5 of 11. PyPI answers 4 of 11, the one difference being purpose membership.

## What the not_supported rows mean here

Every exhaustion claim this family makes has no API in either SDK, which is the expected
shape for a family testing proposed text that no published specification states. Nothing
was simulated to fill a row in. Chain state, receipt verification, budget accounting and
the detached-signature primitives are the claims either SDK decides, and both decide them
the same way on the same bytes.

## TypeScript

    $ npm ci --include=dev
    $ npx tsx fixtures/lifecycle-purpose-exhaustion/verify.ts
    # exit code 0

    lifecycle-purpose-exhaustion: 21 events across 2 tracks, status label candidate_against_proposed
      bounds 12, single-use 9

    === track: bounds (records-bounds.json, AuthorityBoundary) ===

    boundary: reference-boundary
      MATCH PXE-01-accept-first-purchase-tuesday  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-02-observe-authenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=null
      MATCH PXE-03-reject-second-purchase-wednesday  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-04-accept-first-use-under-use-count-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-05-reject-use-count-consumed  outcome=not_admitted reason=use_count_exhausted bound_state=exhausted basis="the admission itself" chain_state=valid
      MATCH PXE-06-accept-first-purchase-under-budget-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-07-reject-budget-exhausted  outcome=not_admitted reason=budget_exhausted bound_state=exhausted basis="the SDK budget ledger" chain_state=valid detail=CUMULATIVE_EXCEEDED
      MATCH PXE-08-reject-unauthenticated-completion  outcome=completion_rejected reason=completion_signature_invalid bound_state=not_established basis=null chain_state=null detail=invalid/["signature_invalid"]
      MATCH PXE-09-reject-completion-from-party-without-standing  outcome=completion_rejected reason=completion_attestor_without_standing bound_state=not_established basis=null chain_state=null detail=sdk_boundary_identity=mismatch
      MATCH PXE-10-reject-purchase-after-unauthenticated-completion  outcome=not_admitted reason=bound_state_not_established bound_state=not_established basis=null chain_state=valid
      MATCH PXE-11-reject-purchase-after-completion-without-standing  outcome=not_admitted reason=bound_state_not_established bound_state=not_established basis=null chain_state=valid
      MATCH PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist  outcome=not_admitted reason=grant_chain_not_valid bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=invalid detail=invalid/EXPIRED

    boundary: defective-boundary-chain-validity-only
      MATCH PXE-01-accept-first-purchase-tuesday  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-02-observe-authenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=null
      DECLARED FAIL PXE-03-reject-second-purchase-wednesday  outcome=admitted reason=dispatch_admitted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-04-accept-first-use-under-use-count-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      DECLARED FAIL PXE-05-reject-use-count-consumed  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-06-accept-first-purchase-under-budget-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      DECLARED FAIL PXE-07-reject-budget-exhausted  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-08-reject-unauthenticated-completion  outcome=completion_rejected reason=completion_signature_invalid bound_state=not_established basis=null chain_state=null detail=invalid/["signature_invalid"]
      MATCH PXE-09-reject-completion-from-party-without-standing  outcome=completion_rejected reason=completion_attestor_without_standing bound_state=not_established basis=null chain_state=null detail=sdk_boundary_identity=mismatch
      DECLARED FAIL PXE-10-reject-purchase-after-unauthenticated-completion  outcome=admitted reason=dispatch_admitted bound_state=not_established basis=null chain_state=valid
      DECLARED FAIL PXE-11-reject-purchase-after-completion-without-standing  outcome=admitted reason=dispatch_admitted bound_state=not_established basis=null chain_state=valid
      MATCH PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist  outcome=not_admitted reason=grant_chain_not_valid bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=invalid detail=invalid/EXPIRED
      defective-boundary-chain-validity-only diverged on exactly its declared set: true

    boundary: defective-boundary-trusts-unauthenticated-completion
      MATCH PXE-01-accept-first-purchase-tuesday  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-02-observe-authenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=null
      MATCH PXE-03-reject-second-purchase-wednesday  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-04-accept-first-use-under-use-count-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-05-reject-use-count-consumed  outcome=not_admitted reason=use_count_exhausted bound_state=exhausted basis="the admission itself" chain_state=valid
      MATCH PXE-06-accept-first-purchase-under-budget-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-07-reject-budget-exhausted  outcome=not_admitted reason=budget_exhausted bound_state=exhausted basis="the SDK budget ledger" chain_state=valid detail=CUMULATIVE_EXCEEDED
      DECLARED FAIL PXE-08-reject-unauthenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=null
      DECLARED FAIL PXE-09-reject-completion-from-party-without-standing  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=null
      DECLARED FAIL PXE-10-reject-purchase-after-unauthenticated-completion  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      DECLARED FAIL PXE-11-reject-purchase-after-completion-without-standing  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist  outcome=not_admitted reason=grant_chain_not_valid bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=invalid detail=invalid/EXPIRED
      defective-boundary-trusts-unauthenticated-completion diverged on exactly its declared set: true

    === track: single-use (records-single-use.json, ExhaustionBoundary) ===

      PASS LC-I-013-a reference=admitted/admitted_and_exhausted/bound=exhausted reuse-rejecting-only=admitted/admitted_and_exhausted(outcome_differs=false,record_differs=false) validity-window-only=admitted/within_validity_window(outcome_differs=false,record_differs=true)
      PASS LC-I-013-b reference=not_admitted/single_use_reuse_detected/bound=invalid reuse-rejecting-only=not_admitted/single_use_reuse_detected(outcome_differs=false,record_differs=false) validity-window-only=admitted/within_validity_window(outcome_differs=true,record_differs=true)
      PASS LC-I-013-c reference=not_admitted/ancestor_invalidated_by_reuse/bound=invalid reuse-rejecting-only=admitted/derived_artifact_chain_valid(outcome_differs=true,record_differs=true) validity-window-only=admitted/within_validity_window(outcome_differs=true,record_differs=true) negative_control=true
      PASS LC-I-013-d reference=admitted/derived_artifact_chain_valid/bound=not_reached reuse-rejecting-only=admitted/derived_artifact_chain_valid(outcome_differs=false,record_differs=false) validity-window-only=admitted/within_validity_window(outcome_differs=false,record_differs=true)
      PASS LC-I-014-a reference=admitted/admitted_and_exhausted/bound=exhausted reuse-rejecting-only=admitted/admitted_and_exhausted(outcome_differs=false,record_differs=false) validity-window-only=admitted/within_validity_window(outcome_differs=false,record_differs=true)
      PASS LC-I-014-b reference=not_admitted/purpose_exhausted/bound=exhausted reuse-rejecting-only=not_admitted/purpose_exhausted(outcome_differs=false,record_differs=false) validity-window-only=admitted/within_validity_window(outcome_differs=true,record_differs=true) negative_control=true
      PASS LC-I-014-c reference=void_refused/exhaustion_is_not_reversible/bound=exhausted reuse-rejecting-only=void_refused/exhaustion_is_not_reversible(outcome_differs=false,record_differs=false) validity-window-only=void_refused/exhaustion_is_not_reversible(outcome_differs=false,record_differs=true)
      PASS LC-I-014-d reference=void_refused/void_attestor_without_standing/bound=exhausted reuse-rejecting-only=void_refused/void_attestor_without_standing(outcome_differs=false,record_differs=false) validity-window-only=void_refused/void_attestor_without_standing(outcome_differs=false,record_differs=true)
      PASS LC-I-014-e reference=not_admitted/purpose_exhausted/bound=exhausted reuse-rejecting-only=not_admitted/purpose_exhausted(outcome_differs=false,record_differs=false) validity-window-only=admitted/within_validity_window(outcome_differs=true,record_differs=true)

    cross-track overlap check, PXE-03 against LC-I-014-b:
      same outcome, reason and bound_state: true (not_admitted/purpose_exhausted/exhausted)
      different exhaustion_basis:           true
        PXE-03    basis: "an authenticated fulfillment record from a party with standing"
        LC-I-014-b basis: "the admission itself"

    TypeScript SDK support, agent-passport-system 7.1.0:
      supported      chain state, including time and revocation  (verifyAuthorityDelegationChain, both tracks)
      supported      purpose membership  (isPurposePermitted)
      supported      completion record authenticity  (verifyReceiptV1)
      supported      completion attestor standing  (verifyReceiptV1 boundary_identity axis)
      supported      budget exhaustion  (InMemoryAuthorityBudgetLedger reserve/markDispatched/commit)
      supported      purpose bound signature  (verify over canonicalizeJCS)
      not_supported  purpose exhaustion  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  use_count exhaustion  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  single-use reuse detection and cascade  (no export in agent-passport-system 7.1.0, supplied by harness.ts)
      not_supported  irreversibility of an exhaustion  (no export in agent-passport-system 7.1.0, supplied by harness.ts)

    bounds     reference-boundary matched: 12/12
    bounds     both defective boundaries diverged on exactly their declared sets: true
    single-use reference policy matched:   9/9
    cross-track overlap check:             true
    PASSED: 21/21 vectors, both reference boundaries matched every event in their track, every defective policy diverged on exactly its declared set

## Python

    $ python3 -m venv /tmp/aac-work/pyenv
    $ /tmp/aac-work/pyenv/bin/pip install agent-passport-system==4.1.0
    $ /tmp/aac-work/pyenv/bin/python fixtures/lifecycle-purpose-exhaustion/verify.py
    # exit code 0

    lifecycle-purpose-exhaustion (python SDK runner): 21 events across 2 tracks, status label candidate_against_proposed
      agent-passport-system (PyPI) version reported by the package: 4.1.0
      bounds 12, single-use 9

    === track: bounds (records-bounds.json) ===

    boundary: reference-boundary
      MATCH PXE-01-accept-first-purchase-tuesday  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-02-observe-authenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=None
      MATCH PXE-03-reject-second-purchase-wednesday  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-04-accept-first-use-under-use-count-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-05-reject-use-count-consumed  outcome=not_admitted reason=use_count_exhausted bound_state=exhausted basis="the admission itself" chain_state=valid
      MATCH PXE-06-accept-first-purchase-under-budget-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-07-reject-budget-exhausted  outcome=not_admitted reason=budget_exhausted bound_state=exhausted basis="the SDK budget ledger" chain_state=valid detail=CUMULATIVE_EXCEEDED
      MATCH PXE-08-reject-unauthenticated-completion  outcome=completion_rejected reason=completion_signature_invalid bound_state=not_established basis=null chain_state=None detail=invalid/["signature_invalid"]
      MATCH PXE-09-reject-completion-from-party-without-standing  outcome=completion_rejected reason=completion_attestor_without_standing bound_state=not_established basis=null chain_state=None detail=sdk_boundary_identity=mismatch
      MATCH PXE-10-reject-purchase-after-unauthenticated-completion  outcome=not_admitted reason=bound_state_not_established bound_state=not_established basis=null chain_state=valid
      MATCH PXE-11-reject-purchase-after-completion-without-standing  outcome=not_admitted reason=bound_state_not_established bound_state=not_established basis=null chain_state=valid
      MATCH PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist  outcome=not_admitted reason=grant_chain_not_valid bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=invalid detail=invalid/EXPIRED

    boundary: defective-boundary-chain-validity-only
      MATCH PXE-01-accept-first-purchase-tuesday  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-02-observe-authenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=None
      DECLARED FAIL PXE-03-reject-second-purchase-wednesday  outcome=admitted reason=dispatch_admitted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-04-accept-first-use-under-use-count-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      DECLARED FAIL PXE-05-reject-use-count-consumed  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-06-accept-first-purchase-under-budget-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      DECLARED FAIL PXE-07-reject-budget-exhausted  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-08-reject-unauthenticated-completion  outcome=completion_rejected reason=completion_signature_invalid bound_state=not_established basis=null chain_state=None detail=invalid/["signature_invalid"]
      MATCH PXE-09-reject-completion-from-party-without-standing  outcome=completion_rejected reason=completion_attestor_without_standing bound_state=not_established basis=null chain_state=None detail=sdk_boundary_identity=mismatch
      DECLARED FAIL PXE-10-reject-purchase-after-unauthenticated-completion  outcome=admitted reason=dispatch_admitted bound_state=not_established basis=null chain_state=valid
      DECLARED FAIL PXE-11-reject-purchase-after-completion-without-standing  outcome=admitted reason=dispatch_admitted bound_state=not_established basis=null chain_state=valid
      MATCH PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist  outcome=not_admitted reason=grant_chain_not_valid bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=invalid detail=invalid/EXPIRED
      defective-boundary-chain-validity-only diverged on exactly its declared set: True

    boundary: defective-boundary-trusts-unauthenticated-completion
      MATCH PXE-01-accept-first-purchase-tuesday  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-02-observe-authenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=None
      MATCH PXE-03-reject-second-purchase-wednesday  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-04-accept-first-use-under-use-count-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-05-reject-use-count-consumed  outcome=not_admitted reason=use_count_exhausted bound_state=exhausted basis="the admission itself" chain_state=valid
      MATCH PXE-06-accept-first-purchase-under-budget-grant  outcome=admitted reason=dispatch_admitted bound_state=not_reached basis=null chain_state=valid
      MATCH PXE-07-reject-budget-exhausted  outcome=not_admitted reason=budget_exhausted bound_state=exhausted basis="the SDK budget ledger" chain_state=valid detail=CUMULATIVE_EXCEEDED
      DECLARED FAIL PXE-08-reject-unauthenticated-completion  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=None
      DECLARED FAIL PXE-09-reject-completion-from-party-without-standing  outcome=completion_accepted reason=fulfillment_recorded bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=None
      DECLARED FAIL PXE-10-reject-purchase-after-unauthenticated-completion  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      DECLARED FAIL PXE-11-reject-purchase-after-completion-without-standing  outcome=not_admitted reason=purpose_exhausted bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=valid
      MATCH PXE-12-reject-after-grant-not_after-expiry-and-exhaustion-coexist  outcome=not_admitted reason=grant_chain_not_valid bound_state=exhausted basis="an authenticated fulfillment record from a party with standing" chain_state=invalid detail=invalid/EXPIRED
      defective-boundary-trusts-unauthenticated-completion diverged on exactly its declared set: True

    === track: single-use (records-single-use.json) ===

      PASS LC-I-013-a reference=admitted/admitted_and_exhausted/bound=exhausted reuse-rejecting-only=admitted/admitted_and_exhausted(outcome_differs=False,record_differs=False) validity-window-only=admitted/within_validity_window(outcome_differs=False,record_differs=True)
      PASS LC-I-013-b reference=not_admitted/single_use_reuse_detected/bound=invalid reuse-rejecting-only=not_admitted/single_use_reuse_detected(outcome_differs=False,record_differs=False) validity-window-only=admitted/within_validity_window(outcome_differs=True,record_differs=True)
      PASS LC-I-013-c reference=not_admitted/ancestor_invalidated_by_reuse/bound=invalid reuse-rejecting-only=admitted/derived_artifact_chain_valid(outcome_differs=True,record_differs=True) validity-window-only=admitted/within_validity_window(outcome_differs=True,record_differs=True) negative_control=True
      PASS LC-I-013-d reference=admitted/derived_artifact_chain_valid/bound=not_reached reuse-rejecting-only=admitted/derived_artifact_chain_valid(outcome_differs=False,record_differs=False) validity-window-only=admitted/within_validity_window(outcome_differs=False,record_differs=True)
      PASS LC-I-014-a reference=admitted/admitted_and_exhausted/bound=exhausted reuse-rejecting-only=admitted/admitted_and_exhausted(outcome_differs=False,record_differs=False) validity-window-only=admitted/within_validity_window(outcome_differs=False,record_differs=True)
      PASS LC-I-014-b reference=not_admitted/purpose_exhausted/bound=exhausted reuse-rejecting-only=not_admitted/purpose_exhausted(outcome_differs=False,record_differs=False) validity-window-only=admitted/within_validity_window(outcome_differs=True,record_differs=True) negative_control=True
      PASS LC-I-014-c reference=void_refused/exhaustion_is_not_reversible/bound=exhausted reuse-rejecting-only=void_refused/exhaustion_is_not_reversible(outcome_differs=False,record_differs=False) validity-window-only=void_refused/exhaustion_is_not_reversible(outcome_differs=False,record_differs=True)
      PASS LC-I-014-d reference=void_refused/void_attestor_without_standing/bound=exhausted reuse-rejecting-only=void_refused/void_attestor_without_standing(outcome_differs=False,record_differs=False) validity-window-only=void_refused/void_attestor_without_standing(outcome_differs=False,record_differs=True)
      PASS LC-I-014-e reference=not_admitted/purpose_exhausted/bound=exhausted reuse-rejecting-only=not_admitted/purpose_exhausted(outcome_differs=False,record_differs=False) validity-window-only=admitted/within_validity_window(outcome_differs=True,record_differs=True)

    cross-track overlap check, PXE-03 against LC-I-014-b:
      same outcome, reason and bound_state: True (not_admitted/purpose_exhausted/exhausted)
      different exhaustion_basis:           True
        PXE-03     basis: "an authenticated fulfillment record from a party with standing"
        LC-I-014-b basis: "the admission itself"

    Python SDK support, recorded by this run:
      supported      budget exhaustion (InMemoryAuthorityBudgetLedger)
      supported      chain state (verify_authority_delegation_chain)
      supported      completion attestor standing (receipt_core.verify_receipt_v1 boundary_identity axis)
      supported      completion record authenticity (receipt_core.verify_receipt_v1)
      not_supported  irreversibility of an exhaustion (no SDK API, supplied by this runner)
      not_supported  notch exhaustion (no SDK API, supplied by this runner)
      supported      purpose bound signature (agent_passport.verify, canonicalize_jcs)
      not_supported  purpose exhaustion (no SDK API, supplied by this runner)
      not_supported  purpose membership (no Python SDK API)
      not_supported  single-use reuse cascade (no SDK API, supplied by this runner)
      not_supported  single-use reuse detection (no SDK API, supplied by this runner)
      not_supported  use_count exhaustion (no SDK API, supplied by this runner)

    bounds     reference-boundary matched: 12/12
    bounds     both defective boundaries diverged on exactly their declared sets: True
    single-use reference policy matched:   9/9
    cross-track overlap check:             True
    PASSED: 21/21 vectors, both reference boundaries matched every event in their track, every defective policy diverged on exactly its declared set (python SDK)

## npm probe

    $ node fixtures/lifecycle-purpose-exhaustion/sdk-probe.mjs
    # exit code 0

    supported     1. chain verdict for a presented chain at the event's instant
                     api: verifyAuthorityDelegationChain
    not_supported  2. an exhaustion ledger keyed to a grant, carried across an ordered event list
                     api: none in this SDK
    not_supported  3. a second presentation of a single-use grant reaching artifacts issued out of it
                     api: none in this SDK
    not_supported  4. an exhaustion state distinguishable from revoked and from expired in a recorded result
                     api: none in this SDK
    not_supported  5. a refusal to undo an exhaustion, and standing checked separately from reversibility
                     api: none in this SDK
    supported     6. purpose membership for a requested purpose against a grant's allowed purposes
                     api: isPurposePermitted
    supported     7. a completion record's signature and stage validity
                     api: verifyReceiptV1
    supported     8. cumulative spend across a delegation subtree, reserved then settled
                     api: InMemoryAuthorityBudgetLedger
    supported     9. a detached signature over canonical JCS bytes, for a principal-signed bound
                     api: canonicalizeJCS
    not_supported  10. a purpose bound reached, established from a fulfillment record
                     api: none in this SDK
    not_supported  11. a use-count bound reached, established from the boundary's own admissions
                     api: none in this SDK
    lifecycle-purpose-exhaustion npm probe: 5/11 claims have an API

## PyPI probe

    $ /tmp/aac-work/pyenv/bin/python fixtures/lifecycle-purpose-exhaustion/sdk_probe.py
    # exit code 0

    supported     1. chain verdict for a presented chain at the event's instant
                     api: verify_authority_delegation_chain
    not_supported  2. an exhaustion ledger keyed to a grant, carried across an ordered event list
                     api: none in this SDK
    not_supported  3. a second presentation of a single-use grant reaching artifacts issued out of it
                     api: none in this SDK
    not_supported  4. an exhaustion state distinguishable from revoked and from expired in a recorded result
                     api: none in this SDK
    not_supported  5. a refusal to undo an exhaustion, and standing checked separately from reversibility
                     api: none in this SDK
    not_supported  6. purpose membership for a requested purpose against a grant's allowed purposes
                     api: is_purpose_permitted
    supported     7. a completion record's signature and stage validity
                     api: verify_receipt_v1
    supported     8. cumulative spend across a delegation subtree, reserved then settled
                     api: InMemoryAuthorityBudgetLedger
    supported     9. a detached signature over canonical JCS bytes, for a principal-signed bound
                     api: canonicalize_jcs
    not_supported  10. a purpose bound reached, established from a fulfillment record
                     api: none in this SDK
    not_supported  11. a use-count bound reached, established from the boundary's own admissions
                     api: none in this SDK
    lifecycle-purpose-exhaustion PyPI probe: 4/11 claims have an API

## Repository gate

    $ npm ci --include=dev            # exit 0
    $ npx tsc --noEmit                # exit 0
    $ npm test                        # exit 0, with this family as its last step

Determinism, both record sets re-minted from their own generator:

    $ npm run generate:lifecycle-purpose-exhaustion-bounds       # exit 0
    $ npm run generate:lifecycle-purpose-exhaustion-single-use   # exit 0
    $ git diff --exit-code                                       # exit 0
