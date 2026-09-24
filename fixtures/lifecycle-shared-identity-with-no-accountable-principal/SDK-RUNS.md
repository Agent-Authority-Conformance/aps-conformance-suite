# SDK runs: lifecycle-shared-identity-with-no-accountable-principal

Every vector in this family was run against the published npm
`agent-passport-system` 7.1.0 and the published PyPI `agent-passport-system`
4.1.0. Neither is a local source checkout.

- **Canonicalization, every vector, both SDKs.** `verify.ts` recomputes each
  case's pinned RFC 8785 (JCS) input digest through npm `canonicalizeJCS`, and
  `verify.py` recomputes the same pins through PyPI `canonicalize_jcs`. All 12
  vectors pass in both.
- **Behaviour.** `not_supported` in both packages, for all four surfaces this
  family needs. Both packages have an accountability surface and neither one is
  about which person acted, which is worth seeing rather than being told, so the
  npm probe constructs one of the package's own accountability records and
  prints its fields.

Nothing in draft-pidlisnyi-aps-03 asks either SDK for this. A fetch of the
published draft this session confirmed it contains neither "accountable" nor
"shared identity" anywhere. `not_supported` here is an absence of a named
surface, not a defect report and not a conformance verdict.

Both blocks below are the verbatim stdout of the two probe scripts.

## Reproducing

    npm ci --include=dev
    node fixtures/lifecycle-shared-identity-with-no-accountable-principal/sdk-probe.mjs

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
    /path/to/venv/bin/python fixtures/lifecycle-shared-identity-with-no-accountable-principal/sdk_probe.py

## npm agent-passport-system 7.1.0

```
agent-passport-system (npm) 7.1.0, 1179 exports

accountability surface present in the package:
  ATTRIBUTION_AXIS_TAGS
  ATTRIBUTION_ROLES
  aggregateAttributionPrimitives
  attributionCanonicalHashHex
  attributionCanonicalTimestamp
  bridgeScopeOfClaim
  buildRemoteSignerScopeOfClaim
  buildRevocationEnforcementScopeOfClaim
  computeAttributionActionRef
  computeDataSourceAttribution
  constructAttributionPrimitive
  createAttributionReceipt
  projectAttribution
  resignAttributionPrimitive
  signAttributionConsent
  verifyAttributionConsent
  verifyAttributionPrimitive
  verifyAttributionProjection
  verifyAttributionReport
  verifyDataSourceAttribution

ATTRIBUTION_ROLES: ["primary_source","supporting_evidence","context_only","background_retrieval"]
ATTRIBUTION_AXIS_TAGS: ["D","P","G","C"]

not_supported
  needed: a declared distinction between an identity one individual holds and an identity several can drive
  note:   nothing in the package marks a credential as shared. An identity is an identity, and a record naming it says which credential authenticated, which is the fact LC-I-010 says is not the same fact as who is accountable.
not_supported
  needed: a checkout or broker record binding one individual to a shared identity for an interval
  note:   the package exports createCheckout, updateCheckout, completeCheckout and cancelCheckout, which are the ACP commerce checkout, a purchase flow. They are not credential checkout and they bind no individual to a shared identity.
not_supported
  needed: a later attribution record that references an earlier decision record and names the individual established to have acted
  note:   the attribution surface the package does have (aggregateAttributionPrimitives, ATTRIBUTION_ROLES, ATTRIBUTION_AXIS_TAGS) attributes contribution across compute, data and protocol axes between systems. It is a different sense of the word from which person was at the keyboard.
not_supported
  needed: an anomaly flag for an unscoped all-powerful identity used off its own enumerated required-list
  note:   nothing in the package has a notion of an identity that is exceptional by construction, or of a list of tasks only it may perform.

What the package's own accountability record carries, constructed and printed:
  buildRevocationEnforcementScopeOfClaim() -> {"asserts":"The verifier applied the configured freshness policy to the recorded revocation-freshness result, reissued a delegation only when the original was not revoked and the trace_id matched, and emitted a conformant Security Event Token on a revocation.","does_not_assert":["That the revocation source was globally current beyond the recorded staleness.","That no revocation occurred between the source snapshot and verification time.","That an emitted Security Event Token was delivered, ordered, or acknowledged."],"capture_mode":"gateway_observed","completeness":"best_effort","self_attested":false}
  Read the field names: this is a scope of claim over what a check covered.
  No field on it names an accountable individual, and none says the acting
  identity was shared, so a consumer of this record cannot tell LC-I-010-a
  from LC-I-010-b.
```

## PyPI agent-passport-system 4.1.0

```
agent-passport-system (PyPI) 4.1.0, 744 public names across 124 modules

shared identity: not_supported
  needed: a declared distinction between an identity one individual holds and an identity several can drive
  reason: nothing in the package marks a credential as shared, so a record naming an identity says which credential authenticated and nothing about who is accountable.
checkout or broker binding: not_supported
  needed: a record binding one individual to a shared identity for an interval
  reason: the package has no credential-checkout surface. Unlike the npm package it does not even carry the ACP commerce checkout names, so there is not even a near-name here.
later attribution record: not_supported
  needed: a later record referencing an earlier decision record and naming the individual established to have acted
  reason: the package's accountability module builds and verifies accountability bundles over what a check covered. No field names an accountable individual and none marks the acting identity as shared.
privileged-identity anomaly flag: not_supported
  needed: an anomaly flag for an unscoped all-powerful identity used off its own enumerated required-list
  reason: nothing has a notion of an identity that is exceptional by construction, or of a list of tasks only it may perform.

canonicalization: supported. agent_passport.canonical.canonicalize_jcs is what verify.py uses to recompute every case's pinned RFC 8785 input digest, so every vector in this family does have one PyPI SDK result.
```

## Two different words spelled the same

Both packages have a substantial attribution surface and it is not this one.
`ATTRIBUTION_ROLES` is `["primary_source","supporting_evidence","context_only",
"background_retrieval"]` and `ATTRIBUTION_AXIS_TAGS` is `["D","P","G","C"]`.
That is attribution of contribution between systems, across data, protocol and
compute axes. This family's question is which individual was driving a shared
credential. The two senses of "attribution" share a word and nothing else, and
the probe prints both constants so a reader can check that for themselves rather
than take it on assertion.

The same holds for "checkout". The npm package exports `createCheckout`,
`updateCheckout`, `completeCheckout` and `cancelCheckout`, which are the ACP
commerce checkout, a purchase flow. `LC-I-010-c`'s checkout is a credential
checkout that binds an individual to a shared identity for an interval. Nothing
in either package does that.

## What the package's own accountability record does not carry

The npm probe constructs `buildRevocationEnforcementScopeOfClaim()` and prints
it. It is a well-built record: it states what it asserts, enumerates what it
does not assert, and declares `capture_mode` and `completeness`. What it has no
field for is an accountable individual, and it has no field saying the acting
identity was one several people can drive. A consumer of that record cannot
tell `LC-I-010-a` from `LC-I-010-b`, which is the entire distinction this family
is about.

That is a gap in a record shape, not a bug. The package is not claiming to carry
this and nothing asks it to.

## Summary

| surface needed | vectors that need it | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|---|
| shared versus individually bound identity | all 12 | not_supported | not_supported |
| credential checkout binding an individual for an interval | LC-I-010-c, -d, -e | not_supported | not_supported |
| later attribution record referencing an earlier record | LC-I-011-b, -c, -d | not_supported | not_supported |
| anomaly flag for an unscoped all-powerful identity | LC-I-012-a, -b, -c | not_supported | not_supported |
| canonicalization | all 12 | pass, `canonicalizeJCS` | pass, `canonicalize_jcs` |

This is an author-produced record, not an independent one, under
`CONTRIBUTING.md`'s admission rules: the same author wrote the vectors, the
probes and this file.
