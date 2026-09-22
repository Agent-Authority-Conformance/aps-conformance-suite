# Key rotation and historical key selection

This fixture exercises `AuthorityDelegationV1` key resolution across a
signing-key rotation: a resolver must select the key version authorized at a
delegation's `issued_at`, not the key that is current when verification
runs.

This is plain draft-03 conformance, not a proposal. draft-pidlisnyi-aps-03
already requires this behavior; this fixture makes it executable and
reviewable, the same way
[C19](../revocation-resolution-forward-compat/README.md) did for the
unrecognized-resolver-answer boundary and
[ancestor-revocation-chain](../ancestor-revocation-chain/README.md) did for
per-member revocation. It does not propose new wording.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/), Section 2.4,
"Key Rotation and Historical Verification", lines 309-323 of the plain-text
rendering:

    309 2.4.  Key Rotation and Historical Verification
    310
    311    An update-capable identifier MAY rotate its signing key.  A retired
    312    key is eligible only for artifacts whose signing time falls within
    313    the key's method-defined validity interval.  A resolver MUST select
    314    the key version authorized at the artifact's issued_at; selecting the
    315    key that is current at verification time is insufficient.
    316
    317    The artifact timestamp is an issuer claim.  This document does not
    318    define a trusted timestamping service.  When key retirement makes the
    319    result depend on whether an artifact was signed before a boundary, a
    320    profile MUST identify an acceptable timestamp, transparency-log, or
    321    equivalent evidence source.  Without that evidence the key-authority
    322    result is indeterminate, even when the artifact signature is
    323    cryptographically valid.

The prompt that produced this fixture also asked for the Section 3.3
requirement that a verifier resolves `verification_method` at `issued_at`,
citing a line number near 492. That sentence exists, but it is in **Section
3.1**, "Faceted Authority Attenuation", not Section 3.3. Quoted here with the
correct section, since it is the sentence that ties Section 2.4's rule
directly to `AuthorityDelegationV1`:

    488    signature = Ed25519-Sign(issuer_private_key,
    489        ASCII("APS-AUTHORITY-DELEGATION-SIGNATURE-V1") || 0x00 ||
    490        UTF8(JCS(delegation without signature)))
    491
    492    A verifier resolves verification_method for issuer at issued_at.  A
    493    valid self-issued root is not trusted automatically; acceptance of a
    494    root is verifier policy.

Section 2.5, "Key Resolution for External and Evidence Signers", also states
the same principle in its own terms, lines 353-357, and both reference SDKs'
`verify.ts` and `verify.py` cite these same line numbers in the comment on
their key-resolution phase:

    353    Published key material MAY carry per-key validity windows.  Key
    354    selection is gated on the artifact's own signed issuance time,
    355    evaluated against each key's window; a verifier MUST NOT select
    356    whichever key is current at verification time.  A key set in which a

The load-bearing phrase is "the key version authorized at the artifact's
issued_at": key selection is keyed to the record's own claimed signing time,
not to whatever the verifier's clock reads. Nothing in Section 2.4 scopes
this to a first verification, or exempts it once enough time has passed
since rotation.

## Case

**Setup.** One issuer identity, `did:aps:example:krh-principal`, with a
single stable `verification_method`,
`did:aps:example:krh-principal#key-1`, held across a key rotation from K1 to
K2 at `rotation_boundary` (`2026-09-20T12:00:00.000Z`). K1 is the key
authorized for `issued_at` before `rotation_boundary`; K2 is authorized for
`issued_at` at or after it. This models Section 2.2's "one stable agent
identifier across key rotation... resolve the verification method at the
artifact's signing time": the identifier does not change at rotation, only
which key material a resolver returns for a given `issued_at` does. Every
vector is an independent root `AuthorityDelegationV1` (`parent_delegation_id:
null`), verified at `now` = `2026-09-20T14:00:00.000Z`, which is after
`rotation_boundary` in every case, so every vector resolves a key across the
rotation rather than before it happened.

**Vectors 1-4, from `mint.py` / `delegations.json`:**

1. **KRH-01-accept-before-rotation-signed-k1.** `issued_at` before
   `rotation_boundary`, signed with K1. Expected: `valid`. A resolver that
   returns whichever key is current at verification time (K2, since
   verification always happens after rotation here) fails this vector.
2. **KRH-02-accept-after-rotation-signed-k2.** `issued_at` after
   `rotation_boundary`, signed with K2. Expected: `valid`.
3. **KRH-03-reject-after-rotation-signed-k1.** `issued_at` after
   `rotation_boundary`, but the signature was produced with K1, the retired
   key. Expected: `invalid`, `SIGNATURE_INVALID`. A correct resolver picks
   K2 for this `issued_at`; K2's public key does not verify a signature K1
   produced.
4. **KRH-04-reject-before-rotation-signed-k2.** `issued_at` before
   `rotation_boundary`, but the signature was produced with K2, a key not
   yet authorized then. Expected: `invalid`, `SIGNATURE_INVALID`. A correct
   resolver picks K1 for this `issued_at`; K1's public key does not verify a
   signature K2 produced.

Every reject vector differs from an accept vector by exactly one change:
KRH-03 is KRH-02's `issued_at` with KRH-01's signing key; KRH-04 is KRH-01's
`issued_at` with KRH-02's signing key.

**Vector 5, boundary evidence:**

5. **KRH-05-indeterminate-boundary-no-evidence.** `issued_at` one second
   before `rotation_boundary`, signed with K1: the same key/time
   relationship as KRH-01, adjacent to the boundary instead of an hour away
   from it. The vector's `boundary_evidence` field is `null`: no timestamp
   or transparency-log evidence anchors this `issued_at` claim. Per Section
   2.4's second paragraph, this is exactly the case where "key retirement
   makes the result depend on whether an artifact was signed before a
   boundary" without "an acceptable timestamp, transparency-log, or
   equivalent evidence source": the required result is `indeterminate`, not
   `valid`, even though the signature is cryptographically valid. See
   "Known SDK gap" below.

## Two policies, checked in both directions

`verify.ts` and `validate.py` each run two resolver policies against vectors
1-4, matching the pattern
[runtime-authority-denial-continuity](../runtime-authority-denial-continuity/README.md)
uses for its N1 and N2 negative controls:

- **historical-key-resolution.** The positive control. Resolves
  `verification_method` against `rotation_boundary` and the record's own
  `issued_at`: K1 before the boundary, K2 at or after it. Must match every
  vector.
- **current-key-only.** A deliberately wrong resolver. Ignores `issued_at`
  entirely and always returns K2, the key current at verification time.
  This is exactly Section 2.4's named insufficient behavior. Declared to
  fail exactly `KRH-01-accept-before-rotation-signed-k1` and
  `KRH-04-reject-before-rotation-signed-k2`, and to pass
  `KRH-02-accept-after-rotation-signed-k2` and
  `KRH-03-reject-after-rotation-signed-k1`.

`current-key-only` passes KRH-02 and KRH-03 not because it is doing
historical resolution, but because both of those vectors' correct key
happens to equal the key current at verification time (K2). The two
vectors it fails are exactly the two whose correct key is K1, the retired
one. Both runners check the observed fail set against the declared one, not
only that the declared failures fail: an undeclared failure or a declared
failure that quietly starts passing would be visible in either runner's
output.

KRH-05 is run once, against `historical-key-resolution` only, and its
result is recorded rather than scored pass or fail against either policy.
See below.

## Known SDK gap

`resolveVerificationKey` (TypeScript) and `resolve_verification_key`
(Python) are called as `(issuer, verification_method, issued_at)` and return
key material or one of a fixed set of resolution-failure outcomes (`not
found`, `ambiguous`, `malformed`, `unreachable`, `unsupported scheme`; see
`node_modules/agent-passport-system/dist/src/v2/authority-delegation/types.d.ts`
lines 96-108, and
`agent_passport/v2/authority_delegation/types.py`'s
`KEY_RESOLUTION_OUTCOME_CODES`). Nothing in that surface carries a
timestamp, transparency-log reference, or any other evidence source, and
neither SDK's chain verifier treats a boundary-adjacent `issued_at`
differently from one with a wide safety margin: both resolve
`KRH-05-indeterminate-boundary-no-evidence` exactly as they resolve
`KRH-01-accept-before-rotation-signed-k1`, and return `valid`.

`fixtures/key-rotation-historical/vectors.json` records this vector with
`known_sdk_gap: true`, the exact reason, a `draft_required` field
(`indeterminate`) and an `observed` field (`valid`) that both runners check
their live result against. This is not a bug report against either SDK: a
resolver taking no evidence input has no way to distinguish this vector from
KRH-01 in the first place. It is a gap between what Section 2.4 requires a
profile to identify (an evidence source for boundary-dependent results) and
what either SDK's current resolver interface can express, recorded as the
batch-1 common instructions ask.

## mint.py and delegations.json

`delegations.json` holds five independent root `AuthorityDelegationV1`
records under one issuer, subject and `verification_method`. It is generated
by `mint.py` from published seed labels, so it carries no secret material
and regenerates byte for byte:

    python3 fixtures/key-rotation-historical/mint.py

After regeneration `git diff` on `delegations.json` should be empty.

## TypeScript

The repository root currently pins the published `agent-passport-system`
package.

From the conformance-suite root:

    npm ci --include=dev
    npm run verify:key-rotation-historical

It also runs as part of `npm test`.

Expected final line:

    PASSED: historical-key-resolution matched every vector, current-key-only failed exactly the declared set

## Python

Run against the actual Python SDK under test, for example:

    PYTHONPATH=/path/to/agent-passport-python/src \
      python3 fixtures/key-rotation-historical/validate.py

Expected final line: the same as the TypeScript runner's.

## SDK historical key resolution used by this fixture

Both SDKs implement historical key resolution the same way: the chain
verifier calls the caller-supplied resolver with the record's own
`issued_at`, not with the verification clock, and neither SDK maintains any
key-version table of its own. Selecting the correct key for a rotated
identifier is entirely the resolver's responsibility, which is why this
fixture's `historical-key-resolution` and `current-key-only` policies live in
`verify.ts` and `validate.py`, not in the SDKs.

- TypeScript:
  `node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.js`,
  Phase 3, lines 153-172 (published package; only `dist/` ships, there is no
  `src/` in the npm package). The resolver call is at line 161:
  `resolveVerificationKey(delegation.issuer, delegation.verification_method,
  delegation.issued_at)`. The comment above it (lines 153-156) cites draft
  lines 313-315.
- Python: `agent_passport/v2/authority_delegation/verify.py`, Phase 3, lines
  234-254 (checkout at `agent-passport-python/src` on this machine). The
  resolver call is at lines 241-243. The docstring above it (lines 234-237)
  cites the same draft lines, 313-315, plus 353-357.

## What a pass establishes

For the exact SDK revision that was run, a pass establishes that:

- both reference SDKs call the caller-supplied key resolver with the
  record's own `issued_at`, and check the signature against whatever key
  material that call returns
- a resolver that implements Section 2.4's historical-selection rule
  produces `valid` for a delegation signed with the key authorized at its
  own `issued_at`, on both sides of a rotation
- a resolver that implements the rule produces `invalid` /
  `SIGNATURE_INVALID` for a delegation whose signature was produced with the
  key authorized at a different time than its claimed `issued_at`
- a resolver that instead always answers with the key current at
  verification time reproduces exactly the failure pattern Section 2.4
  names: it wrongly rejects a still-valid pre-rotation delegation, and it
  wrongly accepts a delegation signed with a not-yet-authorized key, in both
  cases only for the vectors whose correct key is not the current one
- neither SDK's resolver interface can express "boundary-dependent, no
  timestamp or log evidence" as anything other than ordinary key resolution,
  for the one vector this fixture uses to probe that

## Does not claim

A pass does **not** establish:

- that any trusted timestamping service, transparency log, or other
  evidence source is defined or implemented anywhere in this fixture. None
  is. Section 2.4 says a profile MUST identify one when the result is
  boundary-dependent; this fixture does not define that profile
- anything about delegation revocation. Rotating a key does not revoke what
  the key signed, and this family does not test revocation: every vector's
  `resolveRevocation` / `resolve_revocation` callback always returns
  `active`
- that `KRH-05`'s `valid` result from either SDK is wrong for that SDK's own
  documented resolver contract. It is right for that contract; the gap is
  that the contract has no evidence input at all, not that the SDK misused
  the input it has
- that Section 2.4's evidentiary requirement applies uniformly to every
  boundary-adjacent case in the same way, or what "acceptable" timestamp or
  log evidence looks like. The draft leaves that to a profile
- that this behavior is unique to the SDKs run here, or that every
  independent draft-03 implementation resolves keys this way
- anything about Section 2.5's resolution-outcome taxonomy for external or
  evidence signers beyond the two line ranges quoted above; this fixture's
  identifier is the issuer's own signing key, not an external or evidence
  signer

This fixture is evidence about the key-resolution phase of chain
verification across one rotation, not a conformance verdict about key
management, DID method behavior, or timestamping as a protocol feature.
