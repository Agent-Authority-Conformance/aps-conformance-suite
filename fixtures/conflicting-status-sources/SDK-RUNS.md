# SDK runs for conflicting-status-sources

Both reference SDKs were run against this family's vectors on 2026-09-23. This
file records the exact commands, exit codes and verbatim output. It is a record
of two runs, not a conformance verdict on either implementation.

Both runs are **author-produced**: the vectors, the harness, both runners and
both bridges were written in this lab, and neither SDK was reviewed by anyone
outside it.

| field | value |
|---|---|
| date | 2026-09-23 |
| corpus commit | the commit this file is committed in, on branch `candidate/lifecycle-conflicting-status-sources` |
| npm implementation | `agent-passport-system` 7.1.0, installed by `npm ci --include=dev` from the pinned `package-lock.json` |
| PyPI implementation | `agent-passport-system` 4.1.0, installed into a local venv |
| node | v24.11.1 |
| python | 3.14.6 |
| operating system | darwin 25.5.0 |
| network during the runs | none after install |

## Claim table

| claim | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|
| 1. chain verdict under the projected single revocation answer | supported, 15/15 | supported, 15/15 |
| 2. per-source freshness bound, inside or past | supported, 22/22 source lines | not_supported |
| 3. two sources compared for conflict | not_supported | not_supported |
| 4. coverage over a declared required-source set | not_supported | not_supported |
| 5. `not_established` at the observation layer | not_supported | not_supported |
| 6. an offline admission records the snapshot and the age it used | partial | not_supported |

Every `not_supported` row names the API that is missing in the runner output
below. Nothing was simulated to fill one in.

## TypeScript

    $ npm ci --include=dev
    $ npx tsx fixtures/conflicting-status-sources/sdk-bridge.ts
    # exit code 0

```
implementation: agent-passport-system 7.1.0 (npm)
node: v24.11.1

claim 1  chain verdict under the projected single revocation answer: SUPPORTED
         api: verifyAuthorityDelegationChain({ resolveRevocation })
         CSS-01.b1    admit           -> resolveRevocation 'active' -> valid
         CSS-02.b1    admit           -> resolveRevocation 'active' -> valid
         CSS-03.b1    deny            -> resolveRevocation 'revoked' -> invalid/REVOKED
         CSS-04.b1    deny            -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-05.b1    deny            -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-06.b1    not_established -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-07.b1    not_established -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-08.b1    not_established -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-09.b1    admit           -> resolveRevocation 'active' -> valid
         CSS-10.b1    not_established -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-11.b1    deny            -> resolveRevocation 'revoked' -> invalid/REVOKED
         CSS-13.b1    admit           -> resolveRevocation 'active' -> valid
         CSS-14.b1    not_established -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-12.b1    admit           -> resolveRevocation 'active' -> valid
         CSS-12.b2    deny            -> resolveRevocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         15/15 boundaries matched

claim 2  per-source freshness bound, answer inside or past it: SUPPORTED
         api: enforceFreshnessPolicy, mode bounded_staleness
         note: recordRevocationFreshness, which builds the underlying record, is not
         exported from the package root; the composition is.
         22/22 source lines matched the harness freshness boundary

claim 3  two status sources compared for conflict about one delegation: NOT_SUPPORTED
         reason: a RevocationObservation carries exactly one status_source, and
         decideFreshness takes exactly one RevocationFreshnessRecord. No exported
         function takes two answers about one authority_ref and returns a conflict.
         Nothing was simulated in its place.

claim 4  coverage over a declared required-source set: NOT_SUPPORTED
         reason: no exported API takes a list of sources a verifier requires, so
         "every required source answered" is not expressible. The suite's
         status_coverage_incomplete reason has no SDK counterpart.

claim 5  not_established as an observation-layer outcome: NOT_SUPPORTED
         reason: FreshnessDecision.effect is allow | deny, and the SDK types say of
         RevocationObservationDecision that "No third verdict value exists". The
         chain layer does carry indeterminate, which claim 1 exercises; the two
         layers do not share a vocabulary.

claim 6  an offline admission records the snapshot and the age it used: PARTIAL
         boundary: CSS-09.b1
         decideFreshness effect=allow
         decideFreshness reason="revocation source fresh within tolerance"
         RevocationFreshnessRecord carries: source=snapshot-c, freshness.validAt=2026-09-20T11:30:00Z, maxStalenessMs=3600000
         SignedRevocationObservation fields: authority_ref, decision, maximum_staleness_ms, observed_at, observer_key, observer_key_id, signature, status_source
         verifyRevocationObservation: valid=true
         supported: the source identity and the tolerated staleness are structured
         fields on the signed observation, and the snapshot's own as_of is a
         structured field on the unsigned freshness record.
         not supported: the signed observation carries neither the snapshot as_of
         nor the age it admitted on, so a reader of the signed record alone cannot
         recompute either. On this path the decision short-circuits on result
         'fresh' and its reason carries no age at all; an age appears in the
         reason string only on the bounded-staleness branch, which is reached only
         after the source's own maxAge has already expired, and even there it is
         prose rather than a field.

PASSED: conflicting-status-sources SDK bridge (TypeScript), agent-passport-system 7.1.0. 2 claims supported and matched, 1 partial, 3 recorded not_supported.
```

## Python

    $ python3 -m venv /tmp/aac-fx-conflicting-status-sources-venv
    $ /tmp/aac-fx-conflicting-status-sources-venv/bin/pip install "agent-passport-system==4.1.0"
    $ /tmp/aac-fx-conflicting-status-sources-venv/bin/python fixtures/conflicting-status-sources/sdk_bridge.py
    # exit code 0

```
implementation: agent-passport-system 4.1.0 (PyPI)
python: 3.14.6

claim 1  chain verdict under the projected single revocation answer: SUPPORTED
         api: verify_authority_delegation_chain(resolve_revocation=...)
         CSS-01.b1    admit           -> resolve_revocation 'active' -> valid
         CSS-02.b1    admit           -> resolve_revocation 'active' -> valid
         CSS-03.b1    deny            -> resolve_revocation 'revoked' -> invalid/REVOKED
         CSS-04.b1    deny            -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-05.b1    deny            -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-06.b1    not_established -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-07.b1    not_established -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-08.b1    not_established -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-09.b1    admit           -> resolve_revocation 'active' -> valid
         CSS-10.b1    not_established -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-11.b1    deny            -> resolve_revocation 'revoked' -> invalid/REVOKED
         CSS-13.b1    admit           -> resolve_revocation 'active' -> valid
         CSS-14.b1    not_established -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         CSS-12.b1    admit           -> resolve_revocation 'active' -> valid
         CSS-12.b2    deny            -> resolve_revocation 'unknown' -> indeterminate/REVOCATION_UNKNOWN
         15/15 boundaries matched

claim 2  per-source freshness bound, answer inside or past it: NOT_SUPPORTED
         checked absent: decide_freshness, enforce_freshness_policy, create_snapshot_freshness, compute_evidence_age, is_evidence_fresh
         reason: this SDK exposes no freshness-policy or evidence-age surface, so a per-source
         bound cannot be expressed. The TypeScript SDK at 7.1.0 does have one,
         so the two reference implementations do not cover the same ground here.

claim 3  two status sources compared for conflict about one delegation: NOT_SUPPORTED
         checked absent: RevocationObservation, build_revocation_observation
         reason: resolve_revocation returns one answer for one delegation and no API takes two
         answers about one delegation. Nothing was simulated in its place.

claim 4  coverage over a declared required-source set: NOT_SUPPORTED
         checked absent: required_sources, coverage
         reason: no API takes a list of sources a verifier requires.

claim 5  not_established as an observation-layer outcome: NOT_SUPPORTED
         checked absent: FreshnessDecision, RevocationObservationDecision
         reason: there is no observation layer in this SDK. The chain layer does return
         indeterminate, which claim 1 exercises.

claim 6  an offline admission records the snapshot and the age it used: NOT_SUPPORTED
         checked absent: build_revocation_observation, verify_revocation_observation
         reason: no observation record exists to carry a snapshot identity, its as_of or its
         age, so there is nothing to record into.

PASSED: conflicting-status-sources SDK bridge (Python), agent-passport-system 4.1.0. 1 claim supported and matched, 5 recorded not_supported.
```
