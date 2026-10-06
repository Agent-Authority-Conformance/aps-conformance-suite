# principal-authority-association

**Status: candidate material. Not conformance.** This family is not in
`fixtures/manifest.json`, is not counted there, and is not run by `npm test` or
by any other conformance run. `vectors.json` carries `"status": "candidate"` and
`"conformance": false`, and the runner refuses a file without both.

## What it tests

A verifier can accept a principal binding and accept a root authority basis
independently and still not know whether the two belong to one authority
context. draft-pidlisnyi-aps-04 names this in Section 19.2.10 (lines 11287 to
11343) and defines no artifact for it. AIN-WRP reaches the same point from the
relying party side. A signed assertion counts only when its source is competent
for that principal, scope and domain (draft-tanase-ain-authoritative-resolution-00,
Section 7.3, and Appendix B.7, which is non-normative).

The family keeps two outcomes apart. One is an association that cannot be
established from the evidence. The other is an association a competent source
shows to be wrong.

In all six cases the PrincipalBindingV1 verifies and the root delegation verifies
under the case's trust anchors. Only the association evidence changes, plus the
evaluation instant in case 3.

## The fixture-local artifact

-04 defines nothing to carry the association, so this family defines two things
of its own. Both are labeled fixture local and are not a proposal for either
draft.

An association statement:

```
{ type: "x-fixture/principal-authority-association/v0",
  principal_ref, root_ref,
  relation: "same_authority_context" | "different_authority_context",
  source_id, issued_at, expires_at, signature }
```

An association profile, listing which source keys are competent for which
principal, scope and domain. Registries A and B are competent for the principal,
scope `payments:refund` and domain `payments.example`. The HR registry is
competent for the same principal and scope but only for domain `hr.example`.

The checker takes each statement through six checks in order. The first one that
fails is that statement's reason, and a statement that fails any check is not
evidence either way. This follows the pattern -04 uses for activation
attestations at lines 4459 to 4507. The order is written out in
`vectors.json` under `statement_check_order`.

## Cases

Every case expects binding `accepted` (SDK state `valid`, code `OK`) and root
basis `accepted` (SDK state `valid`, no failures).

| case | evidence | association | boundary |
|---|---|---|---|
| PAA-1 missing | none | not established, limb source, `X_FIXTURE_ASSOCIATION_NOT_PRESENTED` | not established, `X_FIXTURE_BOUNDARY_PRINCIPAL_AUTHORITY_NOT_ESTABLISHED`, not authorized for the named principal |
| PAA-2 wrong source | registry HR says same, but it is competent for another domain | not established, limb source, `X_FIXTURE_ASSOCIATION_SOURCE_NOT_COMPETENT` | as PAA-1 |
| PAA-3 stale | registry A says same, evaluated after its `expires_at` | not established, limb freshness, `X_FIXTURE_ASSOCIATION_EXPIRED` | as PAA-1 |
| PAA-4 conflict | registry A says same, registry B says different | not established, limb source, `X_FIXTURE_ASSOCIATION_SOURCES_CONFLICT` | as PAA-1 |
| PAA-5 shown wrong | registry A says different, nothing conflicts | `inconsistent`, `aps_04_defined_shape: false`, `X_FIXTURE_ASSOCIATION_DIFFERENT_AUTHORITY_CONTEXT` | denied, `X_FIXTURE_PRINCIPAL_AUTHORITY_INCONSISTENT` |
| PAA-6 positive control | registry A says same | `established` under the fixture profile, `X_FIXTURE_ASSOCIATION_ESTABLISHED` | authorized, `X_FIXTURE_BOUNDARY_AUTHORIZED_ASSOCIATION_ESTABLISHED`, subject to every check the case does not exercise |

For cases 1 to 4 the boundary follows the last sentence of the 19.2.10
requirement (lines 11322 to 11324). A verifier that cannot establish the
association does not report the action as taken for the principal the chain
names.

**PAA-5 is the seam between the two drafts.** Under AIN-WRP 7.3 and B.7 a source
competent for this principal, scope and domain settles the question, and here it
settles it in the negative. The verifier has reached a conclusion, so -04 forbids
reporting not established for it (lines 677 to 678 and 3731 to 3733). -04 gives
a shape to three negatives only (lines 679 to 686) and defines no artifact for
the association (lines 11300 to 11307), so it gives this negative no shape. The
value `inconsistent` and its boundary code are this fixture's stopgap and nothing
more.

## Pairs

Each pair differs in one element. The generator and the runner both compute the
JSON paths at which the two inputs differ and fail unless they match the
declared paths.

| pair | element | differing paths |
|---|---|---|
| PAA-1 and PAA-6 | statement added | `/association_evidence/0` |
| PAA-5 and PAA-6 | relation flipped | `/association_evidence/0/relation` and its `signature` |
| PAA-2 and PAA-6 | signer changed | `/association_evidence/0/source_id` and its `signature` |
| PAA-3 and PAA-6 | clock moved past expiry | `/evaluation_instant` |

The signature changes with the relation and with the signer because it signs
them. A statement whose signature did not change would fail as unverified.

## What -04 defines and what is fixture local

Defined by -04, used as written:

- the verdict name not established and its evidential meaning, a source that is
  missing, not accepted for that state, stale past its bound, or in unresolved
  conflict (lines 645 to 647, 717 to 724, 3726 to 3731)
- the rule that not established names at least one limb from source, freshness
  and coverage (lines 3737 to 3738)
- the rule that a reached negative is never reported as not established (lines
  677 to 678, 3731 to 3733)
- the requirement in 19.2.10 that an association which cannot be made is not
  established and the action is not reported as taken for the named principal
  (lines 11317 to 11324)

So the association outcome of cases 1 to 4 has a shape -04 defines.

Fixture local:

- the statement format, the profile format and the competence rule
- the association values `inconsistent` (PAA-5) and `established` (PAA-6)
- every reason code. All carry the `X_FIXTURE_` prefix.

The boundary axis uses the three boundary outcome names of -04 (lines 692 to 698
and 3704 to 3707). -04 states those names as informative vocabulary and places no
requirement on them, so the boundary column is not a -04 requirement either.

### Why every reason code is X_FIXTURE_

-04 has no single reason code list. Each subsection defines codes for its own
subject, for example "The reason codes for this subsection are" at line 5394.
None of them has the principal to authority association as its subject. Lines
664 to 668 require two findings that share a verdict name and differ in substance
to carry different reason codes, so reusing a code from another subject would
merge two different findings. The nearest -04 codes, not reused:

| fixture code | nearest -04 code | line | its subject |
|---|---|---|---|
| `X_FIXTURE_ASSOCIATION_NOT_PRESENTED` | `NO_ATTESTATION_PRESENTED` | 4524 | activation conditions |
| `X_FIXTURE_ASSOCIATION_SIGNATURE_UNVERIFIED` | `ATTESTATION_SIGNATURE_UNVERIFIED` | 4468 | activation attestations |
| `X_FIXTURE_ASSOCIATION_SOURCE_NOT_COMPETENT` | `ATTESTATION_ATTESTOR_ROLE_MISMATCH` | 4489 | activation attestor roles |
| `X_FIXTURE_ASSOCIATION_EXPIRED` | `STATUS_STALE_BEYOND_BOUND` | 5397 | revocation and status resolution |
| `X_FIXTURE_ASSOCIATION_SOURCES_CONFLICT` | `STATUS_SOURCES_CONFLICT`, `CONDITION_EVIDENCE_CONFLICT`, `IDENTIFIER_BINDING_CONFLICT` | 5397, 4514, 4835 | status, activation, identifier binding |
| `X_FIXTURE_PRINCIPAL_AUTHORITY_INCONSISTENT` | `COMPOSITION_NOT_SATISFIED`, `PINNED_REFERENT_MISMATCH` | 681 to 686 | the only boundary denials -04 shapes, neither about the association |

Codes the checker can emit but no case exercises: `X_FIXTURE_ASSOCIATION_MALFORMED`,
`X_FIXTURE_ASSOCIATION_SOURCE_UNRECOGNIZED`, `X_FIXTURE_ASSOCIATION_SIGNATURE_UNVERIFIED`,
`X_FIXTURE_ASSOCIATION_REFS_NOT_COVERED` (limb coverage),
`X_FIXTURE_ASSOCIATION_DATED_AFTER_EVALUATION` and
`X_FIXTURE_BOUNDARY_BINDING_OR_ROOT_NOT_ACCEPTED`. A statement signed by the
agent itself would stop at the unrecognized source check. No case presents one.

## SDK

`agent-passport-system` 7.1.0, the version the suite pins in `package.json`.

- The root is issued with `issueAuthorityDelegation` and verified with
  `verifyAuthorityDelegationChain`, both from the package root. Revocation state
  is fixture supplied and every delegation is active. Revocation is not what this
  family tests.
- The binding is issued with `issuePrincipalBindingV1` and verified with
  `verifyPrincipalBindingV1`. In 7.1.0 these are compiled into
  `dist/src/v2/identity-binding/principal-binding.js` but exported from neither
  the package root nor `./core`. `sdk.ts` loads that compiled module by file URL.
  This runs the published code unchanged but is not the package's public API.
- The checker also requires that the binding's `agent_id` equals the root's
  `subject` and that the binding's audiences include the case audience.
- Statements are signed and verified with the SDK `sign` and `verify` over the
  string `X-FIXTURE-PRINCIPAL-AUTHORITY-ASSOCIATION-SIG-V0`, one U+0000, then the
  RFC 8785 JCS of the statement without its signature.

Test keys are SHA-256 over `aps-conformance-suite:principal-authority-association:<label>`
for the labels in `generate.ts`. They are published test keys.

## Files and commands

Run from the suite root.

| file | command | what it does |
|---|---|---|
| `generate.ts` | `npx tsx fixtures/principal-authority-association/generate.ts` | writes `vectors.json`, byte for byte the same on every run. Fails if the binding or root does not verify or a pair differs in more than its declared paths |
| `run.ts` | `npx tsx fixtures/principal-authority-association/run.ts [--report <path>]` | compares every case on all four axes and every pair. Exits 1 on any mismatch, writes no report and prints no PASS line |
| `negative-runner-check.ts` | `npx tsx fixtures/principal-authority-association/negative-runner-check.ts` | in fresh temporary directories, runs an unchanged copy (expects exit 0, a report, PASS) and a copy whose checker throws (expects nonzero exit, no report, no PASS) |
| `mutation-check.ts` | `npx tsx fixtures/principal-authority-association/mutation-check.ts` | four checker mutations, each in a fresh copy: conflict treated as established, expiry ignored, any signer accepted, the negative mapped to not established. Each must fail at least one case |

`check.ts` is the reference checker, `pairs.ts` computes pair differences,
`sdk.ts` gathers the SDK surface and `fresh-copy.ts` builds the temporary copies.

## Authorship

Author produced. The vectors, the expected results and the checker are by the
same author, and the expected blocks are written by hand in `generate.ts` rather
than computed by the checker. Agreement between them shows the checker does what
its author meant. It does not show anyone else would read the drafts the same way.

## What this does not establish

- No APS conformance. -04 defines no artifact or family for the association, and
  this family does not supply one.
- No AIN-WRP conformance. The profile is this fixture's reading of 7.3 and B.7,
  not AIN-WRP's.
- No claim about how either draft will define the association, its negative, or
  its reason codes.
- Nothing about revocation, scope, spend or any check other than the
  association. A positive boundary in PAA-6 is conditional on those.
- Nothing about the Python SDK, which this family does not use.
