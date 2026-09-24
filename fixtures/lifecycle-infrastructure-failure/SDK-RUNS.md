# SDK runs: lifecycle-infrastructure-failure

Every vector in this family was run against the published npm
`agent-passport-system` 7.1.0 and the published PyPI `agent-passport-system`
4.1.0. Neither is a local source checkout.

Two kinds of result are recorded, and they are not the same kind of claim.

- **Canonicalization, every vector, both SDKs.** `verify.ts` recomputes each
  case's pinned RFC 8785 (JCS) input digest through npm `canonicalizeJCS`, and
  `verify.py` recomputes the same pins through PyPI `canonicalize_jcs`. All 30
  vectors pass in both. That is a real, per-vector SDK result, and it is a
  result about bytes, not about any verdict in this family.
- **Behaviour, per group.** Only one of the six groups has a behavioural SDK
  surface at all: `status_artifact`, through npm `enforceFreshnessPolicy` and
  `isEvidenceFresh`. The other five are `not_supported` in both packages, with
  the reason recorded below. Nothing in draft-pidlisnyi-aps-03 asks either SDK
  for these behaviours, so `not_supported` here is an absence of a named
  surface, not a defect report and not a conformance verdict.

No result in this file was written by hand. Both blocks below are the verbatim
stdout of the two probe scripts, which anyone can rerun.

## Reproducing

    npm ci --include=dev
    node fixtures/lifecycle-infrastructure-failure/sdk-probe.mjs

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
    /path/to/venv/bin/python fixtures/lifecycle-infrastructure-failure/sdk_probe.py

## npm agent-passport-system 7.1.0

```
agent-passport-system (npm) 7.1.0, 1179 exports

group status_artifact: enforceFreshnessPolicy + isEvidenceFresh
  mapping: AttestationFreshness {type: rotating, validAt: this_update,
           ttl: next_update - this_update}, maxStalenessMs: the verifier bound.
  The artifact's own declared refresh window becomes the evidence ttl and the
  verifier's bound stays the verifier's bound, so both windows reach the SDK.

  LC-F-006-a  fixture expects valid
    isEvidenceFresh(own window)   : true
    fail_closed                   : result=fresh effect=allow reason="revocation source fresh within tolerance"
    bounded_staleness(bound=verifier): result=fresh effect=allow reason="revocation source fresh within tolerance"
  LC-F-006-b  fixture expects not_established
    isEvidenceFresh(own window)   : false
    fail_closed                   : result=stale effect=deny reason="fail_closed: revocation result 'stale' is not fresh"
    bounded_staleness(bound=verifier): result=stale effect=allow reason="bounded_staleness: age 300000ms within bound 600000ms"
  LC-F-006-c  fixture expects invalid
    isEvidenceFresh(own window)   : false
    fail_closed                   : result=stale effect=deny reason="fail_closed: revocation result 'stale' is not fresh"
    bounded_staleness(bound=verifier): result=stale effect=allow reason="bounded_staleness: age 300000ms within bound 600000ms"
  LC-F-006-d-inverse-check  fixture expects not_established
    isEvidenceFresh(own window)   : true
    fail_closed                   : result=stale effect=deny reason="fail_closed: revocation result 'stale' is not fresh"
    bounded_staleness(bound=verifier): result=stale effect=deny reason="bounded_staleness: age 1200000ms exceeds bound 600000ms → deny"
  LC-F-015-a  fixture expects not_established
    isEvidenceFresh(own window)   : true
    fail_closed                   : result=fresh effect=allow reason="revocation source fresh within tolerance"
    bounded_staleness(bound=verifier): result=fresh effect=allow reason="revocation source fresh within tolerance"
  LC-F-015-b  fixture expects valid
    isEvidenceFresh(own window)   : true
    fail_closed                   : result=fresh effect=allow reason="revocation source fresh within tolerance"
    bounded_staleness(bound=verifier): result=fresh effect=allow reason="revocation source fresh within tolerance"

group status_correction: not_supported
  needed: retraction of an erroneous status publication, distinct from a revocation withdrawal
  reason: no export names a publication-error retraction, and no export takes a list version range. The correction/withdrawal names the package does export (withdrawProvisional, withdrawalPayload) belong to the provisional-decision surface, not to a status publisher retracting its own published entry.
group issuer_time_evidence: not_supported
  needed: independent time evidence covering an issuer-claimed issued_at
  reason: the package canonicalizes and asserts timestamps (assertCanonicalTimestamp, compareCanonicalTimestamps) but has no surface that takes evidence about a timestamp from a party other than the issuer, and none that takes a declared time-source-disagreement window.
group history_reconciliation: not_supported
  needed: merging two divergent authority write histories with a reconciliation record
  reason: the revocation store is a single in-memory set (InMemoryAuthorityRevocationStore) with no notion of two histories, no merge entry point and no record of what a merge kept or discarded. reconcileBilateralPair is about a bilateral delegation pair, not about a partitioned authority store.
group causal_read: not_supported
  needed: a required-observation token binding a read to a specific prior write
  reason: the resolveRevocation callback the chain verifier accepts takes the delegation and nothing else, so there is no argument through which a request could name a write the answer must reflect.
group evidence_coverage: not_supported
  needed: coverage of an evidence interval against a declared delivery lag and a consumer set
  reason: capabilityCoverage is scope coverage, not interval coverage. Nothing takes a query interval, a declared delivery-lag bound, or a set of consumers with delivery positions.
```

## PyPI agent-passport-system 4.1.0

```
agent-passport-system (PyPI) 4.1.0, 744 public names across 124 modules

group status_artifact: not_supported
  needed: a freshness record carrying both a source's own declared validity window and the verifier's own bound
  reason: the Python package has no freshness, staleness or evidence-age surface at all. The npm package's enforceFreshnessPolicy / isEvidenceFresh / createRotatingFreshness have no Python counterpart at 4.1.0, so this group has no Python path and the npm run is the only SDK result this family has for it.
group status_correction: present: withdraw_provisional, withdrawal_payload
  needed: retraction of an erroneous status publication, distinct from a revocation withdrawal
  reason: no name in the package retracts a published status entry, and none takes a list version range.
group issuer_time_evidence: not_supported
  needed: independent time evidence covering an issuer-claimed issued_at
  reason: the package canonicalizes and compares timestamps (is_canonical_timestamp, compare_canonical_timestamps) but takes no evidence about a timestamp from a party other than the issuer, and no declared time-source-disagreement window.
group history_reconciliation: not_supported
  needed: merging two divergent authority write histories with a reconciliation record
  reason: InMemoryAuthorityRevocationStore is a single set with no notion of two histories, no merge entry point and no record of what a merge kept or discarded.
group causal_read: not_supported
  needed: a required-observation token binding a read to a specific prior write
  reason: create_authority_revocation_resolver returns a callable over the delegation alone, so a request has no argument through which to name a write the answer must reflect.
group evidence_coverage: present: RequiredRoleCoverage
  needed: coverage of an evidence interval against a declared delivery lag and a consumer set
  reason: nothing takes a query interval, a declared delivery-lag bound, or a set of consumers with delivery positions.

canonicalization: supported. agent_passport.canonical.canonicalize_jcs is what verify.py uses to recompute every case's pinned RFC 8785 input digest, so every vector in this family does have one PyPI SDK result.
```

## Reading the npm status_artifact block

The mapping is stated in the probe's own output: the artifact's own declared
refresh window becomes the evidence `ttl` and the verifier's bound stays
`maxStalenessMs`, so both of this family's two windows reach the SDK.

Three things the run shows, and one it does not.

1. **The SDK does represent the artifact's own window.** On `LC-F-006-b` the
   list is past its own `next_update`, and the SDK's `result` field is `stale`,
   not `fresh`. `isEvidenceFresh` against the artifact's own window is `false`.
   The two-window distinction this group is about is representable in the
   published shape, and it is not something the SDK is blind to.
2. **Which mode is configured decides what happens next.** On the same vector,
   `fail_closed` denies and `bounded_staleness` with the verifier's own bound
   allows, with the reason `bounded_staleness: age 300000ms within bound
   600000ms`. That is the documented behaviour of that mode, not a bug: the
   mode is defined against the relying party's own window. It is also exactly
   the shape `LC-F-006-b` says a naive implementation gets wrong, observed in a
   published package under one of its own supported configurations.
3. **A future-dated answer reads as fresh under every mode.** On `LC-F-015-a`
   the artifact's `this_update` is five minutes ahead of the evaluation
   instant, and `isEvidenceFresh` returns `true`, `fail_closed` returns
   `result=fresh effect=allow`. The SDK's own documentation states the rule
   that produces this. `node_modules/agent-passport-system/dist/src/core/freshness.d.ts`,
   on `computeEvidenceAge`: "Returns 0 if validAt is in the future (clock skew);
   never negative." An age floored at zero is the freshest
   possible age. This fixture's `LC-F-015-a` says such an answer establishes
   nothing.

What it does not show: the SDK's `effect` is `allow` or `deny`, a two-valued
enforcement outcome. This family's verdicts are drawn from the six-value
lifecycle vocabulary, in which `not_established` is a third thing that is
neither. `deny` on `LC-F-006-b` is not the same answer as `not_established`,
and this file does not record it as agreement. It records that the SDK does not
admit there under `fail_closed`, which is a weaker and true statement.

## Near-names reported by the probes

Two probe patterns matched an export that is not the surface being looked for.
They are left in rather than tuned away, because a reader checking this file
should see what the nearest thing in each package is.

| package | probe group | matched | what it actually is |
|---|---|---|---|
| npm | issuer_time_evidence | (none, after the pattern was narrowed) | `verifyRuntimeAttestation` contains the substring `timeAttestation` inside `runTimeAttestation` and is about runtime attestation, not time. The probe's pattern is narrowed and comments say why. |
| PyPI | status_correction | `withdraw_provisional`, `withdrawal_payload` | the provisional-decision surface. Neither retracts a published status entry and neither takes a list version range. |
| PyPI | evidence_coverage | `RequiredRoleCoverage` | coverage of a required role set, not coverage of a time interval. |

## Per-group summary

| group | vectors | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|---|
| status_artifact | 6 | run, `enforceFreshnessPolicy` + `isEvidenceFresh`, output above | not_supported, no freshness surface exists in the package |
| status_correction | 5 | not_supported | not_supported |
| issuer_time_evidence | 5 | not_supported | not_supported |
| history_reconciliation | 6 | not_supported | not_supported |
| causal_read | 4 | not_supported | not_supported |
| evidence_coverage | 4 | not_supported | not_supported |
| all 30, canonicalization only | 30 | pass, `canonicalizeJCS` | pass, `canonicalize_jcs` |

This is an author-produced record, not an independent one, under
`CONTRIBUTING.md`'s admission rules: the same author wrote the vectors, the
probes and this file.
