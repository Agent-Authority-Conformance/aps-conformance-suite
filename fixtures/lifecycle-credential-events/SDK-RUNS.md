# SDK runs for lifecycle-credential-events

Every claim this family makes against a reference SDK, the exact command, the
exit code and the verbatim output. A `NOT_SUPPORTED` row means the SDK has no
API for the behaviour and nothing was simulated in its place. Both bridges
assert those absences against the installed package, so a later release that
adds the surface turns the run into a failure rather than leaving a stale note.

Run on 2026-09-23 from the suite root, offline, with no network access from any
runner.

| claim | `agent-passport-system` 7.1.0 (npm) | `agent-passport-system` 4.1.0 (PyPI) |
|---|---|---|
| 1. chain verdict under the projected single revocation answer | supported, 43/43 boundaries | supported, 43/43 boundaries |
| 2. a declared recipient scope checked as its own facet | supported, 2/3 outcomes projected exactly, 1 divergence recorded | not_supported |
| 3. scope containment arithmetic for the enforced-scope check | supported, 2/2 vectors | supported, 2/2 vectors |
| 4. per-check results in a fixed enum, and attestor independence corroborated from trust context | supported, 43/43 boundaries | supported, 43/43 boundaries |
| 5. a signing key checked for the purpose it was authorized for | supported, narrower vocabulary | not_supported |
| 6. clock disagreement as an outcome distinct from expiry | partial | not_supported |
| 7. compromise reach over a declared authority graph | not_supported | not_supported |
| 8. revocation effectiveness as a property of the credential class | not_supported | not_supported |
| 9. an issuance-window integrity finding, or trust in an issuer population | not_supported | not_supported |
| 10. a coverage basis for what was exercised under a credential | not_supported | not_supported |

One pinned cross-language constant sits inside claim 4. Both bridges build the
same composition-check receipt from `vectors.json`, sign it with the same
derived key, and check the signature against the same hard-coded hex. It matched
in both, so the composition-check tag and the RFC 8785 canonicalization agree
byte for byte between the two packages.

## Exit codes

| command | exit code |
|---|---|
| `npx tsx fixtures/lifecycle-credential-events/verify.ts` | 0 |
| `python3 fixtures/lifecycle-credential-events/validate.py` | 0 |
| `npx tsx fixtures/lifecycle-credential-events/sdk-bridge.ts` | 0 |
| `python3 fixtures/lifecycle-credential-events/sdk_bridge.py` | 0 |
| `npm ci --include=dev` | 0 |
| `npm test` | 0 |

## `npx tsx fixtures/lifecycle-credential-events/sdk-bridge.ts`

Exit code 0.

```
implementation: agent-passport-system 7.1.0 (npm)
node: v24.11.1

claim 1  chain verdict under the projected single revocation answer: SUPPORTED
         api: verifyAuthorityDelegationChain({ resolveRevocation })
         43/43 boundaries matched the projection

claim 2  a declared recipient scope checked as its own facet, separately from the signature: SUPPORTED, with one projection divergence recorded
         api: checkAudience(proof, policy), four-valued AudienceCheckResult
         LC-G-004-a-key-scope-does-not-cover-the-claimed-audience   family established_invalid  SDK fail/audience_mismatch
         LC-G-004-b-no-key-scope-declared                           family not_established      SDK fail/audience_required_absent
         LC-G-004-c-key-scope-covers-the-claimed-audience           family established_valid    SDK pass/audience_match
         2/3 key-scope outcomes projected exactly
         divergence recorded, not a failure: LC-G-004-b-no-key-scope-declared: family not_established, SDK fail/audience_required_absent
         reason for the divergence: AudienceCheckResult reserves `unknown` for a policy
         carrying no recipientId, and maps "binding required and absent" to `fail`. This
         family returns not established there. The SDK has a four-valued lattice and uses
         its fourth value for a different condition, so the two are not interchangeable.

claim 3  scope containment arithmetic for the enforced-scope check: SUPPORTED
         api: scopeCovers(granted, required)
         LC-D-009-a-enforced-scope-exceeds-declared-scope           SDK contained=false family established_invalid
         LC-D-009-c-enforced-scope-contained                        SDK contained=true  family established_valid
         2/2 attested-scope vectors matched

claim 4  per-check results in a fixed enum with a separate indeterminate, and attestor
         independence corroborated from trust context rather than self-declaration: SUPPORTED
         api: CompositionCheckV0.verifyCompositionCheck, compositionCheckSigningPayload, COMPOSITION_CHECK_RESULTS
         COMPOSITION_CHECK_RESULTS = ["pass","fail","indeterminate","not_checked"]
         ATTESTOR_INDEPENDENCE_CLASSES = ["gateway_self","independent_registered"]
         43/43 boundaries: the SDK verified the anchor, echoed the
         per-check results in order, and returned no aggregate verdict of its own
         self-declared independent, context says registered_by_operator=true  -> independence_is_second_anchor=false
         self-declared independent, context says registered_by_operator=false -> independence_is_second_anchor=true
         this is the same property LC-D-029-b turns on: an attestation that restates the
         signer's own claim is not a second anchor. The SDK downgrades, never upgrades.
         cross-language signature over CE-00.b1: fc2acb57697994cc1edbf39f...

claim 5  a signing key checked for the purpose it was authorized for: SUPPORTED
         api: assertKeyPurpose(keyId, didDoc, requiredPurpose)
         key authorized for assertionMethod: accepted
         same key for capabilityDelegation: rejected, reason=key_purpose_violation
         scope: the SDK's purposes are DID verification relationships, not issuer-defined
         populations. It establishes that a key scope is checked as its own step, which is
         LC-G-004's shape. It does not carry the population vocabulary the case needs.

claim 6  clock disagreement as an outcome distinct from expiry: PARTIAL
         boundary: LC-F-013-a.b1
         declared tolerance 300s, observed skew 46800s
         compareTimestamps(gatewayReading, referenceReading) = definitely_after
         the same comparison one second apart              = incomparable
         supported: HybridTimestamp carries an explicit wall-clock uncertainty band and
         compareTimestamps returns a non-definite ordering while the bands overlap, so
         "these two readings cannot be definitely ordered" is expressible.
         not supported: no API returns a denial category for a clock disagreement.
         validateTemporalRights answers validity and expiry; a skew rejection would be
         recorded as the same expiry LC-F-013-b records, which is what the case says
         must not happen. Nothing was simulated in its place.

claim 7  compromise reach computed over a declared authority graph: NOT_SUPPORTED
         reason: No exported function takes a set of authority edges and a compromised subject and
         returns the reachable set. The nearest surface is evaluateRevocationImpact,
         which walks DerivationReceipt records in a receipt store: an impact set over
         what was recorded, which is the `enumerated-reach-basis` control in this
         family, not the reference basis. cascadeRevoke walks delegation descendants
         and has no notion of a "could mint credentials for" edge.

claim 8  revocation effectiveness as a property of the credential class: NOT_SUPPORTED
         reason: A revocation record and a revocation observation both name one delegation. No
         exported API takes a credential class and returns when a recorded revocation
         becomes effective for it, so LC-F-035's "not yet effective" has no SDK
         counterpart and the two boundaries in that case are indistinguishable.

claim 9  an issuance-window integrity finding, or trust in an issuer population: NOT_SUPPORTED
         reason: buildTrustRootPolicy and verifyTrustRootPolicy carry accepted roots. Nothing takes
         a finding about an issuer's own issuance records over a window, and nothing
         expresses "this issuer's whole population is in question" as distinct from
         revoking named artifacts.

claim 10  a coverage basis for what was exercised under a credential: NOT_SUPPORTED
         reason: The suite's accountability and attribution surfaces record individual actions.
         No exported API states or checks a completeness claim over an interval, which
         is the separate second claim LC-D-025 turns on.

PASSED: lifecycle-credential-events SDK bridge (TypeScript), agent-passport-system 7.1.0. 4 claims supported and matched, 1 supported with a recorded projection divergence, 1 partial, 4 recorded not_supported.
```

## `python3 fixtures/lifecycle-credential-events/sdk_bridge.py`

Exit code 0.

```
implementation: agent-passport-system 4.1.0 (PyPI)
python: 3.14.6

claim 1  chain verdict under the projected single revocation answer: SUPPORTED
         api: verify_authority_delegation_chain(resolve_revocation=...)
         43/43 boundaries matched the projection

claim 2  a declared recipient scope checked as its own facet: NOT_SUPPORTED
         reason: the audience-binding module of the npm SDK (checkAudience, bindAudience,
         AudienceCheckResult) has no counterpart in this package. Nothing here takes a
         proof and a relying-party policy and returns a four-valued audience status, so
         LC-G-004's three key-scope outcomes cannot be projected. Nothing was simulated.

claim 3  scope containment arithmetic for the enforced-scope check: SUPPORTED
         api: scope_covers(granted, required)
         LC-D-009-a-enforced-scope-exceeds-declared-scope           SDK contained=False family established_invalid
         LC-D-009-c-enforced-scope-contained                        SDK contained=True  family established_valid
         2/2 attested-scope vectors matched

claim 4  per-check results in a fixed enum with a separate indeterminate, and attestor
         independence corroborated from trust context rather than self-declaration: SUPPORTED
         api: verify_composition_check, composition_check_signing_payload
         COMPOSITION_CHECK_RESULTS = ['pass', 'fail', 'indeterminate', 'not_checked']
         ATTESTOR_INDEPENDENCE_CLASSES = ['gateway_self', 'independent_registered']
         43/43 boundaries: the SDK verified the anchor, echoed the
         per-check results in order, and returned no aggregate verdict of its own
         self-declared independent, context says registered_by_operator=True  -> independence_is_second_anchor=False
         self-declared independent, context says registered_by_operator=False -> independence_is_second_anchor=True
         cross-language signature over CE-00.b1: fc2acb57697994cc1edbf39f...
         matches the constant the TypeScript bridge checks, so the tag and the RFC 8785
         canonicalization agree byte for byte across the two packages.

claim 5  a signing key checked for the purpose it was authorized for: NOT_SUPPORTED
         reason: assertKeyPurpose and IdentityCompositionError, which the npm SDK exports,
         have no counterpart in this package. is_purpose_permitted is a data-purpose
         matcher, not a key-purpose check on a resolved DID document. Nothing was simulated.

claim 6  clock disagreement as an outcome distinct from expiry: NOT_SUPPORTED
         reason: this package's time surface is RFC 3339 parsing and formatting
         (parse_rfc3339, format_rfc3339, now_ms). There is no HybridTimestamp carrying a
         wall-clock uncertainty band and no compare_timestamps, so the partial support the
         npm bridge records for this claim is absent here. Nothing was simulated.

claim 7  compromise reach computed over a declared authority graph: NOT_SUPPORTED
         reason: No function takes authority edges and a compromised subject and returns the
         reachable set. cascade_revoke walks recorded delegation descendants and has no
         notion of a "could mint credentials for" edge.

claim 8  revocation effectiveness as a property of the credential class: NOT_SUPPORTED
         reason: AuthorityRevocation records name one delegation. Nothing takes a credential class
         and returns when a recorded revocation becomes effective for it.

claim 9  an issuance-window integrity finding, or trust in an issuer population: NOT_SUPPORTED
         reason: Nothing takes a finding about an issuer's own issuance records over a window, and
         nothing expresses trust in an issuer's whole population as distinct from
         revoking named artifacts.

claim 10  a coverage basis for what was exercised under a credential: NOT_SUPPORTED
         reason: Nothing states or checks a completeness claim over an interval, which is the
         separate second claim LC-D-025 turns on.

PASSED: lifecycle-credential-events SDK bridge (Python), agent-passport-system 4.1.0. 3 claims supported and matched, 6 recorded not_supported.
```

## `npx tsx fixtures/lifecycle-credential-events/verify.ts`

Exit code 0.

```
PASS CE-00-positive-control-every-check-established
PASS LC-D-001-a-third-party-disclosure-is-a-trigger
PASS LC-D-001-b-reattested-after-disclosure
PASS LC-D-001-c-unattributed-compromise-claim-is-not-a-trigger
PASS LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record
PASS LC-D-003-a-reach-over-the-graph-not-the-believed-list
PASS LC-D-003-b-both-bases-agree-so-agreement-establishes-nothing
PASS LC-D-004-a-operator-identity-reaches-an-independent-tree
PASS LC-D-004-b-operator-identity-with-no-edge-to-this-tree
PASS LC-D-009-a-enforced-scope-exceeds-declared-scope
PASS LC-D-009-b-no-reachable-scope-attestation
PASS LC-D-009-c-enforced-scope-contained
PASS LC-D-011-a-inherited-root-past-its-reattestation-deadline
PASS LC-D-011-b-inherited-root-inside-its-deadline
PASS LC-D-011-c-inherited-root-reestablished
PASS LC-D-014-a-issuance-log-integrity-unestablished-for-the-window
PASS LC-D-014-b-issued-outside-the-covered-window
PASS LC-D-014-c-reestablished-from-a-reverified-root
PASS LC-D-025-a-revoked-and-accounting-not-established
PASS LC-D-025-b-revoked-and-accounting-established
PASS LC-D-029-a-no-provenance-attestation
PASS LC-D-029-b-provenance-attestor-is-the-signing-key-holder
PASS LC-D-029-c-independent-provenance-attestation
PASS LC-D-033-a-authorizer-with-no-addition-record
PASS LC-D-033-b-addition-attestor-standing-not-declared
PASS LC-D-033-c-every-authorizer-attested
PASS LC-F-013-a-clock-disagreement-is-its-own-outcome
PASS LC-F-013-b-expiry-with-clocks-agreeing
PASS LC-F-013-c-clocks-agree-inside-the-window
PASS LC-F-033-a-issuer-population-trust-not-established
PASS LC-F-033-b-issuer-population-reattested
PASS LC-F-035-a-revocation-not-yet-effective-for-this-credential-class
PASS LC-F-035-b-revocation-effective-where-status-is-looked-up
PASS LC-G-001-a-planned-rotation-opens-no-suspect-window
PASS LC-G-002-a-window-starts-at-exposure-not-discovery
PASS LC-G-002-b-issued-before-the-exposure-start
PASS LC-G-003-a-independently-dated-before-the-compromise-point
PASS LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact
PASS LC-G-003-c-independently-dated-inside-the-window
PASS LC-G-004-a-key-scope-does-not-cover-the-claimed-audience
PASS LC-G-004-b-no-key-scope-declared
PASS LC-G-004-c-key-scope-covers-the-claimed-audience
controls:
  self-initiated-triggers-only (whether a compromise disclosure from another party is ingested as a trigger at all): ran 6, record diverged on 4, verdict changed on 2
  enumerated-reach-basis (what reachability from a compromised subject is computed over): ran 4, record diverged on 4, verdict changed on 2
  signature-satisfies-other-checks (whether a valid signature stands in for a separately declared check): ran 9, record diverged on 9, verdict changed on 6
  grandfather-inherited-root (whether a root that entered the policy by inheritance needs its own re-establishment record): ran 3, record diverged on 3, verdict changed on 1
  per-artifact-revocation-settles-log-integrity (what settles a finding about the issuer's own issuance-log integrity): ran 3, record diverged on 2, verdict changed on 1
  issuer-population-from-caught-chains (whether a systemic issuer finding is answered chain by chain): ran 2, record diverged on 2, verdict changed on 1
  revocation-closes-accounting (whether the accounting of what was done is inferred from the current authority status): ran 2, record diverged on 2, verdict changed on 0
  presence-implies-authorized-addition (whether presence on the authorizer list establishes that the addition was authorized): ran 3, record diverged on 3, verdict changed on 2
  skew-is-expiry (how a clock disagreement beyond tolerance is categorized): ran 3, record diverged on 1, verdict changed on 1
  revocation-is-universal (whether revocation effectiveness is a property of the credential class): ran 2, record diverged on 2, verdict changed on 1
  every-rotation-is-a-trigger (whether a planned rotation at a declared cryptoperiod end opens a suspect window): ran 4, record diverged on 1, verdict changed on 1
  discovery-dated-window (where a suspect window starts when exposure and discovery differ): ran 2, record diverged on 2, verdict changed on 1
  trust-claimed-issued-at (which timestamp partitions artifacts around a compromise point): ran 3, record diverged on 3, verdict changed on 1
  skip-unestablished-checks (what a declared check with no input record resolves to): ran 42, record diverged on 18, verdict changed on 17

PASSED: lifecycle-credential-events TypeScript, 42 vectors, 43 boundaries, reference verifier matched every pinned record, each of 14 controls diverged on exactly its declared set
```

## `python3 fixtures/lifecycle-credential-events/validate.py`

Exit code 0.

```
PASS CE-00-positive-control-every-check-established
PASS LC-D-001-a-third-party-disclosure-is-a-trigger
PASS LC-D-001-b-reattested-after-disclosure
PASS LC-D-001-c-unattributed-compromise-claim-is-not-a-trigger
PASS LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record
PASS LC-D-003-a-reach-over-the-graph-not-the-believed-list
PASS LC-D-003-b-both-bases-agree-so-agreement-establishes-nothing
PASS LC-D-004-a-operator-identity-reaches-an-independent-tree
PASS LC-D-004-b-operator-identity-with-no-edge-to-this-tree
PASS LC-D-009-a-enforced-scope-exceeds-declared-scope
PASS LC-D-009-b-no-reachable-scope-attestation
PASS LC-D-009-c-enforced-scope-contained
PASS LC-D-011-a-inherited-root-past-its-reattestation-deadline
PASS LC-D-011-b-inherited-root-inside-its-deadline
PASS LC-D-011-c-inherited-root-reestablished
PASS LC-D-014-a-issuance-log-integrity-unestablished-for-the-window
PASS LC-D-014-b-issued-outside-the-covered-window
PASS LC-D-014-c-reestablished-from-a-reverified-root
PASS LC-D-025-a-revoked-and-accounting-not-established
PASS LC-D-025-b-revoked-and-accounting-established
PASS LC-D-029-a-no-provenance-attestation
PASS LC-D-029-b-provenance-attestor-is-the-signing-key-holder
PASS LC-D-029-c-independent-provenance-attestation
PASS LC-D-033-a-authorizer-with-no-addition-record
PASS LC-D-033-b-addition-attestor-standing-not-declared
PASS LC-D-033-c-every-authorizer-attested
PASS LC-F-013-a-clock-disagreement-is-its-own-outcome
PASS LC-F-013-b-expiry-with-clocks-agreeing
PASS LC-F-013-c-clocks-agree-inside-the-window
PASS LC-F-033-a-issuer-population-trust-not-established
PASS LC-F-033-b-issuer-population-reattested
PASS LC-F-035-a-revocation-not-yet-effective-for-this-credential-class
PASS LC-F-035-b-revocation-effective-where-status-is-looked-up
PASS LC-G-001-a-planned-rotation-opens-no-suspect-window
PASS LC-G-002-a-window-starts-at-exposure-not-discovery
PASS LC-G-002-b-issued-before-the-exposure-start
PASS LC-G-003-a-independently-dated-before-the-compromise-point
PASS LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact
PASS LC-G-003-c-independently-dated-inside-the-window
PASS LC-G-004-a-key-scope-does-not-cover-the-claimed-audience
PASS LC-G-004-b-no-key-scope-declared
PASS LC-G-004-c-key-scope-covers-the-claimed-audience
controls:
  self-initiated-triggers-only: ran 6, record diverged on 4, verdict changed on 2
  enumerated-reach-basis: ran 4, record diverged on 4, verdict changed on 2
  signature-satisfies-other-checks: ran 9, record diverged on 9, verdict changed on 6
  grandfather-inherited-root: ran 3, record diverged on 3, verdict changed on 1
  per-artifact-revocation-settles-log-integrity: ran 3, record diverged on 2, verdict changed on 1
  issuer-population-from-caught-chains: ran 2, record diverged on 2, verdict changed on 1
  revocation-closes-accounting: ran 2, record diverged on 2, verdict changed on 0
  presence-implies-authorized-addition: ran 3, record diverged on 3, verdict changed on 2
  skew-is-expiry: ran 3, record diverged on 1, verdict changed on 1
  revocation-is-universal: ran 2, record diverged on 2, verdict changed on 1
  every-rotation-is-a-trigger: ran 4, record diverged on 1, verdict changed on 1
  discovery-dated-window: ran 2, record diverged on 2, verdict changed on 1
  trust-claimed-issued-at: ran 3, record diverged on 3, verdict changed on 1
  skip-unestablished-checks: ran 42, record diverged on 18, verdict changed on 17

PASSED: lifecycle-credential-events Python, 42 vectors, 43 boundaries, second implementation matched every pinned record including its RFC 8785 digest, each of 14 controls diverged on exactly its declared set
```
