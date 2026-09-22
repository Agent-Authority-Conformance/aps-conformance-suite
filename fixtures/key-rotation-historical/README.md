# Key rotation and historical key selection

This fixture exercises `AuthorityDelegationV1` key resolution across a
signing-key rotation: a resolver must select the key version authorized at a
delegation's `issued_at`, not the key that is current when verification
runs.

This is plain draft-03 conformance, not a proposal. draft-pidlisnyi-aps-03
already requires this behavior. This fixture makes it executable and
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
authorized for `issued_at` before `rotation_boundary`, and only when
`boundary_evidence` corroborates that claim. K2 is authorized for
`issued_at` at or after it, unconditionally. This models Section 2.2's "one
stable agent identifier across key rotation... resolve the verification
method at the artifact's signing time": the identifier does not change at
rotation, only which key material a resolver returns for a given `issued_at`
does. Every vector is an independent root `AuthorityDelegationV1`
(`parent_delegation_id: null`), verified at `now` = `2026-09-20T14:00:00.000Z`,
which is after `rotation_boundary` in every case, so every vector resolves a
key across the rotation rather than before it happened.

**boundary_evidence.** Section 2.4's second paragraph (lines 317-323) says
`issued_at` is an issuer claim, that the draft defines no trusted
timestamping service, and that when key retirement makes a result depend on
whether an artifact was signed before a boundary, a profile MUST identify an
acceptable timestamp, transparency-log, or equivalent evidence source.
Without it the result is indeterminate. `delegations.json` carries a `boundary_evidence` map, keyed by `issued_at`, holding one
record: `{"source": "aps-conformance-suite-test-timestamp-v0", "attests_before_boundary": true}`.
For this fixture, the test profile treats this record as acceptable signing-time evidence.
Draft-03 requires acceptable timestamp or log evidence but does not define this record
format. The record is not an APS object and not a proposal for one, and no claim is made
that it would be acceptable evidence in any real deployment. K2's window needs no entry: K2 does not retire, so
no claim about its `issued_at` relative to a closing window needs
corroborating.

**Vectors 1-4, from `mint.py` / `delegations.json`:**

1. **KRH-01-accept-before-rotation-signed-k1.** `issued_at` before
   `rotation_boundary`, signed with K1, `boundary_evidence` present. K1 is
   the key authorized at `issued_at`, and evidence corroborates the claim,
   so this is valid. A resolver that returns whichever key is current at
   verification time (K2, since verification always happens after rotation
   here) fails this vector.
2. **KRH-02-accept-after-rotation-signed-k2.** `issued_at` after
   `rotation_boundary`, signed with K2. Expected: `valid`. K2's window is
   unconditional, so `boundary_evidence` does not apply.
3. **KRH-03-reject-after-rotation-signed-k1.** `issued_at` after
   `rotation_boundary`, but the signature was produced with K1, the retired
   key. Expected: `invalid`, `SIGNATURE_INVALID`. A correct resolver picks
   K2 for this `issued_at` (no evidence needed). K2's public key does not
   verify a signature K1 produced.
4. **KRH-04-reject-before-rotation-signed-k2.** `issued_at` before
   `rotation_boundary`, `boundary_evidence` present (the same claimed
   `issued_at` as KRH-01, corroborated the same way), but the signature was
   produced with K2, a key not yet authorized then. Expected: `invalid`,
   `SIGNATURE_INVALID`. A correct resolver picks K1 for this `issued_at`,
   and K1's public key does not verify a signature K2 produced. The only stated
   change from KRH-01 is the signing key, not the evidence, which isolates
   this reject on the signature check alone.

Every reject vector differs from an accept vector by exactly one change:
KRH-03 is KRH-02's `issued_at` with KRH-01's signing key. KRH-04 is KRH-01's
`issued_at` and evidence with KRH-02's signing key.

**Vector 5, no evidence:**

5. **KRH-05-indeterminate-boundary-no-evidence.** `issued_at` before
   `rotation_boundary`, signed with K1: the same key/time relationship as
   KRH-01. `boundary_evidence` is absent. Expected: `indeterminate`,
   `KEY_AMBIGUOUS`. Per Section 2.4's second paragraph, this is exactly the
   case where "key retirement makes the result depend on whether an artifact
   was signed before a boundary" without "an acceptable timestamp,
   transparency-log, or equivalent evidence source": the required result is
   `indeterminate`, not `valid`, even though the signature is
   cryptographically valid.

   KRH-05's `issued_at` is not identical to KRH-01's: both reference SDKs'
   `resolveVerificationKey` / `resolve_verification_key` are called as
   `(issuer, verification_method, issued_at)` only, so a resolver has no way
   to tell apart two records that share all three. Giving them different
   results requires a different `issued_at`. That value is thirty minutes
   before `rotation_boundary`, exactly as far from it as KRH-01's own
   `issued_at`, so nothing about its distance from the boundary is doing any
   work. An earlier version of this fixture used an `issued_at` one second
   before `rotation_boundary` and described KRH-05 as testing boundary
   adjacency specifically. That framing had no basis in Section 2.4: the
   draft conditions the indeterminate result on the presence or absence of
   evidence, not on how close the claimed signing time sits to the boundary.
   KRH-01 and KRH-05 are the same input class, before-rotation-boundary and
   signed-with-K1. The only substantive difference between them is
   `boundary_evidence`.

## Three policies, checked in both directions

`verify.ts` and `validate.py` each run three resolver policies against all
five vectors, matching the pattern
[runtime-authority-denial-continuity](../runtime-authority-denial-continuity/README.md)
uses for its N1 and N2 negative controls:

- **historical-key-resolution.** The positive control. Resolves
  `verification_method` against `rotation_boundary` and the record's own
  `issued_at`: K2 at or after the boundary unconditionally. K1 before it,
  but only when `boundary_evidence` corroborates the claim, otherwise an
  `ambiguous` resolution outcome. Must match every vector.
- **current-key-only.** A deliberately wrong resolver. Ignores `issued_at`
  and `boundary_evidence` entirely and always returns K2, the key current at
  verification time. This is exactly Section 2.4's named insufficient
  behavior. Declared to fail exactly `KRH-01-accept-before-rotation-signed-k1`,
  `KRH-04-reject-before-rotation-signed-k2`, and
  `KRH-05-indeterminate-boundary-no-evidence`, and to pass
  `KRH-02-accept-after-rotation-signed-k2` and
  `KRH-03-reject-after-rotation-signed-k1`.
- **claim-trusting.** A second deliberately wrong resolver. Performs the
  same before/after split on `issued_at` that `historical-key-resolution`
  does, but never consults `boundary_evidence`: this is what this fixture's
  own resolver did before this correction. It is exactly the gap Section
  2.4's second paragraph identifies, an issuer's unverified `issued_at`
  claim treated as sufficient on its own to authorize the retired key.
  Declared to fail exactly `KRH-05-indeterminate-boundary-no-evidence`: it
  matches `historical-key-resolution` on every other vector, and diverges
  only where the correct result depends on evidence it never looks at.

`current-key-only` passes KRH-02 and KRH-03 not because it is doing
historical resolution, but because both of those vectors' correct key
happens to equal the key current at verification time (K2). It fails
KRH-01 and KRH-04 for the reason Section 2.4 names, and it fails KRH-05
because resolving K2 against a K1 signature reports `invalid` /
`SIGNATURE_INVALID`, not the `indeterminate` this vector requires, for an
unrelated reason. Both runners check the observed fail set against the
declared one, not only that the declared failures fail: an undeclared
failure or a declared failure that quietly starts passing would be visible
in either runner's output.

## Findings

Both reference SDKs leave Section 2.4's evidence handling entirely to the
caller's resolver. `verifyAuthorityDelegationChain` /
`verify_authority_delegation_chain` never inspect `issued_at` against a
boundary or against any evidence source themselves. They call the
caller-supplied `resolveVerificationKey` / `resolve_verification_key` with
`(issuer, verification_method, issued_at)` and check the signature against
whatever key material that call returns, or report the state the call's
`KeyResolutionFailure` outcome maps to. Neither SDK ships a Section
2.4-aware resolver for authority delegations. `historicalResolver` /
`historical_resolver` in this fixture's own `verify.ts` and `validate.py`
are this fixture's resolvers, not SDK code.

That resolver call's outcome vocabulary is fixed by Section 2.5, lines
360-364:

    360    Resolution outcomes preserve failure structure.  At minimum a
    361    resolver distinguishes: resolved; subject or key not found; ambiguous
    362    (including duplicate key identifiers); structurally malformed key
    363    material; transport unreachability; and an unsupported identifier
    364    scheme.

Both SDKs implement exactly these five non-resolved outcomes plus the
unspecified case a raw `null` (or a `KeyResolutionFailure` object with an
unrecognized `outcome`) produces:
`node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.js`
lines 23-46 (`keyResolutionFailure`), and
`agent_passport/v2/authority_delegation/verify.py` lines 74-97
(`_key_resolution_failure`) together with
`agent_passport/v2/authority_delegation/types.py` lines 30-35
(`KEY_RESOLUTION_OUTCOME_CODES`). None of the five outcomes means "the
claimed signing time could not be established against a key-validity
boundary." This fixture's corrected `historicalResolver` /
`historical_resolver` reports `ambiguous` (`KEY_AMBIGUOUS`) for
`KRH-05-indeterminate-boundary-no-evidence`, chosen as the least-bad
existing fit: which key epoch governs is exactly what is unresolved without
evidence. `not_found`, `malformed`, `unreachable`, and `unsupported_scheme`
each name a more specific and less applicable failure. This is a finding
about the resolver contract, not a bug: the contract has no outcome for
"signing time not established," so a resolver implementing Section 2.4's
evidentiary requirement has no way to report that specific reason. It
reports one of the five fixed Section 2.5 codes instead, none of them
written with this reason in mind, and the specific reason a caller might
want to see collapses into whichever of those five generic, borrowed codes
fits least badly.

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

    PASSED: historical-key-resolution matched every vector, both negative controls failed exactly their declared sets

## Python

The recorded run used a clean virtual environment with the published
`agent-passport-system` 4.0.0 wheel, nothing inherited from a local checkout:

    python3 -m venv /tmp/aps-py400
    /tmp/aps-py400/bin/pip install agent-passport-system==4.0.0
    /tmp/aps-py400/bin/python fixtures/key-rotation-historical/validate.py

Expected final line: the same as the TypeScript runner's. To test another Python
implementation, run `validate.py` with that implementation importable as `agent_passport`
and record which one ran.

## SDK historical key resolution used by this fixture

Both SDKs implement historical key resolution the same way: the chain
verifier calls the caller-supplied resolver with the record's own
`issued_at`, not with the verification clock, and neither SDK maintains any
key-version table of its own. Selecting the correct key for a rotated
identifier, and deciding whether `boundary_evidence` corroborates a
before-boundary claim, is entirely the resolver's responsibility, which is
why this fixture's `historical-key-resolution`, `current-key-only`, and
`claim-trusting` policies live in `verify.ts` and `validate.py`, not in the
SDKs. See "Findings" above.

- TypeScript:
  `node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.js`,
  Phase 3, lines 153-172 (published package. Only `dist/` ships, there is no
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
- a resolver that trusts the `issued_at` claim alone, with no evidence
  check, produces exactly the same result as one that implements Section
  2.4's evidentiary requirement, for every vector except the one whose
  correct result depends on evidence being absent
- for `KRH-01-accept-before-rotation-signed-k1` and
  `KRH-05-indeterminate-boundary-no-evidence`, two records of the same input
  class (before `rotation_boundary`, signed with K1, differing only in the
  specific `issued_at` value a resolver needs to tell them apart), a
  resolver that checks `boundary_evidence` produces `valid` for the one
  evidence corroborates and `indeterminate` for the one it does not, which
  is the whole of what distinguishes them

## Does not claim

A pass does **not** establish:

- that `aps-conformance-suite-test-timestamp-v0` is an acceptable timestamp,
  transparency-log, or equivalent evidence source under Section 2.4 for any
  real deployment. It is this fixture's own minimal, deterministic stand-in,
  built only to make Section 2.4's evidence requirement executable here
- that Section 2.4's evidentiary requirement applies uniformly to every
  boundary-dependent case in the same way, or what "acceptable" timestamp or
  log evidence looks like in general. The draft leaves that to a profile.
  This fixture's profile is a test fixture, not a proposal
- anything about delegation revocation. Rotating a key does not revoke what
  the key signed, and this family does not test revocation: every vector's
  `resolveRevocation` / `resolve_revocation` callback always returns
  `active`
- that `KEY_AMBIGUOUS` is the only defensible code for "boundary-dependent,
  no evidence." It is this fixture's own choice among Section 2.5's five
  fixed outcomes, recorded as a finding, not a claim that the taxonomy
  itself settles the question
- that this behavior is unique to the SDKs run here, or that every
  independent draft-03 implementation resolves keys, or reports resolution
  failures, this way
- anything about Section 2.5's resolution-outcome taxonomy for external or
  evidence signers beyond the line ranges quoted above. This fixture's
  identifier is the issuer's own signing key, not an external or evidence
  signer

This fixture is evidence about the key-resolution phase of chain
verification across one rotation, not a conformance verdict about key
management, DID method behavior, or timestamping as a protocol feature.
