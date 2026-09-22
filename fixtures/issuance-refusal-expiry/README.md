# Issuer refuses a bad parent, expiry is distinct from revocation

This fixture exercises two properties of `AuthorityDelegationV1`. The first is
issuer-side: draft-03 section 3.6 requires an issuer minting a child
delegation to verify the parent's signature and temporal validity first, and
to refuse to issue under an expired, not-yet-valid, or revoked parent, at
issuance time, not leaving that invalidity for a verifier to discover later.
The second is verifier-side: draft-03 section 3.3's chain verification
reports a stable failure code, and this fixture shows the code for an
expired chain member differs from the code for a revoked one.

This is plain draft-03 conformance, not a proposal. It makes existing
required behavior executable and reviewable, the same way
[C19](../revocation-resolution-forward-compat/README.md) and
[AAC](../ancestor-revocation-chain/README.md) did for their own sections. It
does not propose new wording.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/).

Section 3.6, "Core Invariants", lines 695-704 of the plain-text rendering:

    695    INV-2, INV-3, and INV-8 are enforced at issuance, not only at
    696    verification.  An issuer minting a child delegation MUST verify the
    697    parent delegation's signature and temporal validity before signing
    698    the child, and MUST refuse to issue under an expired, not-yet-valid,
    699    or revoked parent.  Issuance from an expired parent MUST fail at the
    700    issuer; it MUST NOT produce a delegation whose invalidity is left for
    701    a later verifier to discover.  Verification-time checking remains
    702    required (Section 3.3), but a conforming issuer does not rely on it
    703    as the sole enforcement point: a delegation that was invalid at
    704    issuance never becomes valid later.

Section 3.3, "Chain Verification", lines 578-592:

    578 3.3.  Chain Verification
    579
    580    A verifier processes a root-to-leaf chain in this order: closed
    581    schema and canonical values; delegation_id; historical signing-key
    582    resolution and signature; duplicate identifiers; root trust;
    583    parent_delegation_id; issuer-to-subject continuity; child issuance
    584    time; the seven facet comparisons in Section 3.2; current validity;
    585    and revocation state for every member.  A cycle, repeated identifier,
    586    broken parent link, or issuer discontinuity invalidates the chain.
    587
    588    Verification returns one of valid, invalid, indeterminate, or
    589    unsupported with a stable failure code.  An unavailable or stale
    590    revocation result is indeterminate.  An unsupported facet profile is
    591    unsupported.  Cryptographic or attenuation failure is invalid.  A
    592    caller MUST NOT collapse indeterminate or unsupported into valid.

Section 3.2, "Facet Comparisons", lines 535-539, on the half-open validity
interval:

    535    Time  The half-open child interval [not_before, not_after) MUST be
    536    contained in the parent interval.  A child's not_before MUST NOT
    537    predate its issued_at, and a child MUST be issued while the parent
    538    is valid.  Relative durations are converted to absolute instants
    539    before signing and do not appear in the wire record.

The load-bearing phrases are "MUST refuse to issue under an expired,
not-yet-valid, or revoked parent" and "Issuance from an expired parent MUST
fail at the issuer" (section 3.6), and "a stable failure code" together with
"Cryptographic or attenuation failure is invalid" (section 3.3). Section 3.6
does not name a failure code for issuance refusal. It states only that
issuance MUST fail. This fixture records whatever code or message each SDK's
issuance function actually surfaces, without treating any particular string
as normative, and separately checks that section 3.3's verification-time
codes for EXPIRED and REVOKED differ from each other and are stable across
both SDKs.

## Case

**Part A, issuance.** A fixed root `AuthorityDelegationV1` (`parent`, issuer
`irx-principal`, subject `irx-agent-a`, valid `[2026-09-20T10:00:00.000Z,
2026-09-20T20:00:00.000Z)`) and a fixed, unsigned child body
(`child_body`, issuer `irx-agent-a`, subject `irx-agent-l`, requested window
`[2026-09-20T12:00:00.000Z, 2026-09-20T14:00:00.000Z)`, inside the parent's
window and narrower on every facet). Both runners call the SDK's own
child-delegation issuance function (`issueSubAuthorityDelegation` /
`issue_sub_authority_delegation`) directly, live, once per vector. Every
reject vector changes exactly one input from IRX-01's accepted baseline:

| vector | changed from IRX-01 | input | expected |
|---|---|---|---|
| IRX-01-accept-parent-valid-active | (baseline) | `now` inside parent window, resolver `active`, real parent signature | issuance succeeds |
| IRX-02-reject-parent-expired | `now` | `now` at or after parent's `not_after` | refused, `EXPIRED` |
| IRX-03-reject-parent-not-yet-valid | `now` | `now` before parent's `not_before` | refused, `NOT_YET_VALID` |
| IRX-04-reject-parent-revoked | resolver | revocation resolver answers `revoked` | refused, `REVOKED` |
| IRX-05-reject-parent-signature-invalid | parent | one hex character of the parent's signature flipped | refused, `SIGNATURE_INVALID` |

No reject vector ever reaches a returned child artifact: a pass requires the
issuance call to throw (TypeScript) or raise (Python) before producing one.
An SDK that returned a signed child for any reject vector would fail that
vector outright, per the common rule that a reject vector must not be worked
around.

**Part B, verification codes.** The same fixed two-record chain
(`parent`, then `leaf`, the child actually issued under IRX-01's accepted
inputs) is run through `verifyAuthorityDelegationChain` /
`verify_authority_delegation_chain` three times, changing only the verifier's
clock or the leaf's revocation answer from a positive control:

| vector | changed from control | input | expected |
|---|---|---|---|
| IRX-06-control-chain-valid | (baseline) | `now` inside leaf's window, resolver `active` for both members | `valid` |
| IRX-07-verify-leaf-expired | `now` | `now` at or after the leaf's `not_after`, resolver still `active` | `invalid`, `EXPIRED`, index 1 |
| IRX-08-verify-leaf-revoked-chain-not-expired | resolver | `now` unchanged (leaf not expired), leaf's resolver answer `revoked` | `invalid`, `REVOKED`, index 1 |

IRX-07 and IRX-08 both fail at index 1, the leaf, but under different codes,
for different reasons: one is a clock check against the leaf's own signed
window, the other is an external resolver answer. Neither vector touches the
other's input.

## Controls

IRX-01 is Part A's positive control: parent valid and active, and the
identical inputs used to accept a child are what mint the `leaf` record that
Part B verifies. IRX-06 is Part B's positive control: the same two-record
chain verifies `valid` before either failure code is introduced. Every reject
or non-valid vector in both parts is one stated change away from its
control, per the table above.

## Failure stage

Part A vectors exercise the issuer, not a verifier: IRX-02 through IRX-05 are
expected to fail inside the issuance call itself, before any child record is
constructed or signed. Part B vectors exercise chain verification, not
issuance: IRX-07 and IRX-08 verify an already-issued, already-signed
`leaf` record, using the verifier's own clock and revocation resolver.

## Ruling out the fixture as the cause

Both SDKs matched every vector's expected outcome and code, so this fixture
records no SDK gap. Before treating a divergent result as an SDK gap, this
fixture's own resolvers and inputs were checked as follows. The revocation
resolver is a plain constant or index-keyed function with no branching on
anything but the vector's declared answer, mirroring
`fixtures/ancestor-revocation-chain`'s `resolverFor`. The "expired" and
"not-yet-valid" `now` values are computed directly from the same
`parent.authority.time` window minted into `fixture.json`, not from an
independently guessed timestamp. `parent_signature_tampered` is the exact
byte-identical parent with one hex character of its signature flipped, so
every other check (shape, delegation_id, key resolution, temporal window,
revocation) is unchanged from the accepted baseline and only the signature
check is exercised. A vector that failed under an unexpected code would
therefore isolate to the SDK's own issuance or verification logic, not to
this fixture's harness.

## Does not claim

A pass does **not** establish:

- anything about cascade evidence, cascade completion records, or
  suspension. No case here mints, checks, or requires a cascade-completion
  record, and no case models suspension.
- anything about whether a replacement grant is expected after expiry, or
  any wider lifecycle claim about what happens after a delegation expires or
  is revoked. This fixture tests issuer refusal at issuance and the
  verification-time code distinction only, nothing about what a principal or
  agent is expected to do afterward.
- that `EXPIRED`, `NOT_YET_VALID`, `REVOKED`, and `SIGNATURE_INVALID` are the
  only strings either SDK could report, or that a third SDK would use the
  same strings. Section 3.6 does not name a failure code for issuance
  refusal. This fixture records what each pinned SDK revision actually
  returns, per the reproduction commands below, and asserts only that the
  codes for expiry and revocation differ from each other and are stable
  across the two runs in this fixture, not that they are the only
  conforming vocabulary.
- anything about depth, spend, scope, or the other five facets' narrowing
  checks. The child body here narrows on every facet by construction, and
  no vector here targets a facet-widening rejection.
- that this behavior is unique to the SDKs run here, or that every
  independent draft-03 implementation has been checked.

## fixture.json

Generated by `mint.py` from published seed labels, so it carries no secret
material and regenerates byte for byte:

    python3 fixtures/issuance-refusal-expiry/mint.py

After regeneration `git diff` on `fixture.json` should be empty. It holds the
signed `parent` record, `parent_signature_tampered` (parent with one hex
character of the signature flipped), the unsigned `child_body` template, the
two-record `chain` (`parent` then the actually-issued `leaf`), the
`verification_keys` map, and the two Ed25519 private key seeds
(`principal_priv`, `agent_a_priv`). The seeds are SHA-256 digests of
published ASCII labels, the same construction
`fixtures/ancestor-revocation-chain/mint.py` uses, so storing them commits no
secret: anyone can recompute them from the label strings in `mint.py`. Both
runners call the issuance function live at run time using these same seeds,
because Part A tests the issuance call itself, not a pre-baked artifact.

## TypeScript

The repository root currently pins the published `agent-passport-system`
package, version 7.1.0, which exports `issueAuthorityDelegation`,
`issueSubAuthorityDelegation`, `verifyAuthorityDelegation`, and
`verifyAuthorityDelegationChain` from its package root (`agent-passport-system`,
not a deep import). From the conformance-suite root:

    npm ci --include=dev
    npm run verify:issuance-refusal-expiry

It also runs as part of `npm test`.

Expected final line:

    issuance-refusal-expiry TypeScript: 8/8 passed

## Python

Run against agent-passport-system 4.0.0, the published wheel, in a clean
virtual environment, importing only names public in
`agent_passport.v2.authority_delegation` (all of `issue_sub_authority_delegation`,
`verify_authority_delegation_chain`, and `AuthorityDelegationError` are
listed in that module's `__all__`):

    python3 -m venv /tmp/aps-py400
    /tmp/aps-py400/bin/pip install agent-passport-system==4.0.0
    /tmp/aps-py400/bin/python fixtures/issuance-refusal-expiry/mint.py
    /tmp/aps-py400/bin/python fixtures/issuance-refusal-expiry/validate.py

Expected final line:

    issuance-refusal-expiry Python: 8/8 passed

This is a manual run, not part of `npm test`. The rest of this suite's
`npm test` stays Node only, the same convention
`fixtures/runtime-authority-denial-continuity/README.md` documents for its
own Python runner.

## Results

| vector | TypeScript | Python |
|---|---|---|
| IRX-01-accept-parent-valid-active | issued | issued |
| IRX-02-reject-parent-expired | refused, `EXPIRED` | refused, `EXPIRED` |
| IRX-03-reject-parent-not-yet-valid | refused, `NOT_YET_VALID` | refused, `NOT_YET_VALID` |
| IRX-04-reject-parent-revoked | refused, `REVOKED` | refused, `REVOKED` |
| IRX-05-reject-parent-signature-invalid | refused, `SIGNATURE_INVALID` | refused, `SIGNATURE_INVALID` |
| IRX-06-control-chain-valid | valid | valid |
| IRX-07-verify-leaf-expired | invalid, `EXPIRED`, index 1 | invalid, `EXPIRED`, index 1 |
| IRX-08-verify-leaf-revoked-chain-not-expired | invalid, `REVOKED`, index 1 | invalid, `REVOKED`, index 1 |

Both runners agree on every code, for every vector. `EXPIRED` and `REVOKED`
are distinct strings in both SDKs, at both the issuance layer (Part A, as
message-embedded codes on a thrown error) and the verification layer (Part
B, as `AuthorityFailure.code`).

## Provenance

Vectors, `fixture.json`, `mint.py`, `verify.ts`, and `validate.py` are
authored for this suite, adapting the minting, key-resolution, and resolver
pattern already established by
[`fixtures/ancestor-revocation-chain/`](../ancestor-revocation-chain/) to
issuance calls rather than a fixed pre-minted chain. Both runners were
executed locally against the pinned TypeScript SDK
(`agent-passport-system` 7.1.0, `package.json`) and the published Python
wheel (`agent-passport-system` 4.0.0) in a clean virtual environment on this
machine. This is an author-produced record, not an independent one, per
`CONTRIBUTING.md`'s admission rules for run records.

## Boundary

A run of this family does not establish:

- anything about a real issuer implementation outside these two SDK
  revisions, or that every conforming implementation reports the same codes.
- anything about the wider delegation lifecycle after expiry or revocation,
  including whether, when, or how a replacement grant is expected. See "Does
  not claim" above.
- anything about cascade revocation, cascade-completion records, or
  execution-time re-checking (Section 3.5). This fixture calls the chain
  verifier and the issuance functions directly, at fixed instants. It makes
  no enforcement-gateway call and checks no re-check-at-execution behavior.
- that `SIGNATURE_INVALID`, `EXPIRED`, `NOT_YET_VALID`, and `REVOKED` are an
  exhaustive list of issuance-refusal or verification-failure codes. They
  are the five inputs this fixture varies from its two controls, not a
  catalog of every way an issuer or verifier can refuse.
