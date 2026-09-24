# One revocation record format, checked against its own bytes

Section 3.5.1 names what a revocation record carries and fixes no encoding,
no identifier construction, no signature construction and no signer rule for
it. `aps:authority-revocation:v1` is one format that carries those members.
This fixture runs that format's own construction: the three domain-separated
preimages, the identifier hashed over the body, the signature over the record
including that identifier, the revocation time as a signed member, the closed
`record_type`, the cascade transaction identity bound to the record's own
originating content, and the store slot that a second record for the same
delegation does not take.

The positive vector is not authored here. It is the TypeScript SDK's own
committed `aps:authority-revocation:v1` vector, re-minted from the published
inputs and checked against the identifiers and signature that vector carries.
The six rejects are minted here, one defect each.

## Source

draft-pidlisnyi-aps-03 as published
(https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/), sha256
`59b9547a20c6d514eceb97d169b92b2f9c70a231f5b914e8fc1b478c7f359fca`.

Section 3.5.1, "Revocation Evidence", lines 653-660 of the plain-text
rendering:

    653    A revocation MUST produce a signed revocation record carrying, at
    654    minimum: the revoked delegation's identity; the revocation time,
    655    inside the signed content; a reference to the revoking authority; and
    656    a machine-readable reason code, with optional free-text detail.  A
    657    revocation derived from a cascade MUST additionally carry a reference
    658    to the originating revocation, so that a verifier can reconstruct
    659    from the records why a descendant delegation died.  A cascade carries
    660    a transaction identity shared by every record it produces.

Section 3.5, "Cascade Revocation", line 635, on who may revoke:

    635    Any delegation MAY be revoked by its issuer.

The load-bearing phrases for this fixture are "the revocation time, inside
the signed content" and "a transaction identity shared by every record it
produces" (section 3.5.1), and "by its issuer" (section 3.5). The section
names no encoding, no identifier construction, no signature construction, no
reason-code vocabulary and no signer rule, so none of those is treated here
as a requirement of the draft. They are properties of the one format under
test.

The format itself is `src/v2/authority-revocation/` in
`aeoess/agent-passport-system`, ported to
`agent_passport/v2/authority_revocation/` in the Python SDK. The member list
is that module's closed schema. The three domain tags are its `canonical.ts`
constants.

## Case

One `AuthorityDelegationV1` (issuer `did:example:aps-root-authority`, subject
`did:example:aps-agent-alpha`, valid `[2026-03-01T00:00:00.000Z,
2026-04-01T00:00:00.000Z)`) and one revocation of it by its issuer at
`2026-03-15T12:00:00.000Z`, reason code `issuer-key-compromise`, signed by
`did:example:aps-root-authority#key-1`.

**Part A, record verification.** Each vector hands one candidate record and
that delegation to `verifyAuthorityRevocation` / `verify_authority_revocation`
with the fixture's key-resolver table. Every reject vector changes exactly one
thing from ARR-01 and re-mints both identifiers and the signature wherever the
defect does not forbid it, so one thing is wrong per vector and everything
else recomputes.

| vector | changed from ARR-01 | expected |
|---|---|---|
| ARR-01-control-valid-record | (baseline) | `valid`, no failures |
| ARR-02-reject-revocation-id-wrong-domain | `revocation_id` domain tag | `invalid`, `ID_MISMATCH` |
| ARR-03-reject-signature-wrong-domain | signature domain tag | `invalid`, `SIGNATURE_INVALID` |
| ARR-04-reject-revocation-time-outside-signed-content | `revoked_at` is not a member | `invalid`, `SCHEMA_INVALID` then `NONCANONICAL_VALUE` |
| ARR-05-reject-unknown-record-type | `record_type` | `unsupported`, `UNSUPPORTED_RECORD_TYPE` |
| ARR-06-reject-cascade-transaction-id-not-bound | `cascade_transaction_id` | `invalid`, `CASCADE_TRANSACTION_MISMATCH` |

ARR-02 and ARR-03 are the domain-separation cases. Neither uses an invented
tag. ARR-02 hashes `revocation_id` under
`APS-AUTHORITY-DELEGATION-ID-V1` and one NUL byte, the tag a real
`AuthorityDelegationV1` identifier uses, and ARR-03 signs under
`APS-AUTHORITY-REVOCATION-ID-V1` and one NUL byte, this record's own
identifier tag. Bytes minted for one construction reading as bytes minted for
another is the thing the tags exist to stop, so a tag from a different live
construction is what tests them.

ARR-04 carries no revocation time at all. The schema is closed, so there is
no member a time could ride in outside the signed content: a record under this
format either signs its revocation time or does not carry one. The time the
record would have carried is kept beside it in `fixture.json` under
`out_of_band.revoked_at`.

ARR-06's `cascade_transaction_id` is a well-formed `sha256:` content address
derived from a different origin, this record's own content with a different
nonce. `revocation_id` is recomputed over the body carrying it and the record
is re-signed, so the cascade binding is the only thing that does not hold.

**Part B, store first-wins.** One store, two offers of ARR-01's record in
order, through `recordAuthorityRevocation` / `record_authority_revocation`,
the verifying path that is the only supported way a record enters a store.

| vector | changed from ARR-07 | expected |
|---|---|---|
| ARR-07-control-first-record-inserted | (baseline) | `recorded` true, `inserted` true, the store holds ARR-01's `revocation_id` |
| ARR-08-reject-duplicate-record-id | the same record id offered a second time | `recorded` true, `inserted` **false**, the store still holds the first record |

## Controls

ARR-01 is Part A's positive control: a record the verifier returns `valid`
for, with an empty failure list. Every Part A reject is one stated change away
from it, per the table above. ARR-07 is Part B's positive control: the same
record taking an empty slot. ARR-08 changes nothing about the record and only
offers it again.

## Failure stage

Part A vectors fail inside record verification, against the target delegation,
before any store is touched. Part A runs no store at all. Part B vectors
reach the store only because their record verifies: the mutation path returns
`recorded: false` and touches the store not at all on anything but `valid`, so
ARR-08's `inserted: false` is a first-wins outcome and not a rejected record.

## Ruling out the fixture as the cause

Both SDKs matched every vector's state, its `valid` flag, and its full failure
list including messages, so this fixture records no SDK gap. Before treating a
divergent result as an SDK gap, the fixture's own inputs were checked as
follows.

`mint.py` refuses to write `fixture.json` unless the re-minted target
delegation and control revocation reproduce, byte for byte, the
`delegation_id`, `cascade_transaction_id`, `revocation_id` and both
signatures that the TypeScript SDK's committed vector carries. A drift in the
positive case is therefore a mint failure, not a silently re-baselined vector.
`mint.py` also asserts that its own `mint()` helper reproduces the record the
SDK's `issue_authority_revocation` produces before it mints any negative from
that helper, so a negative cannot be built by a construction that differs from
the shipped one in some second way.

The key-resolver table is a plain list lookup with no branching beyond the
declared `(controller, verification_method)` match and the `key_valid_from`
comparison, mirroring `fixtures/issuance-refusal-expiry`'s resolver pattern.
Both runners rebuild it from the same committed table.

Every reject record differs from ARR-01 in exactly one construction input, and
every one of them recomputes its own identifiers and signature under that
input, so a vector that failed under an unexpected code would isolate to the
SDK's own schema, identifier, cascade or signature logic rather than to a
second unintended defect in the record.

## Does not claim

A pass does **not** establish:

- that `aps:authority-revocation:v1` is the format section 3.5.1 requires.
  The section fixes no encoding, no identifier construction, no signature
  construction, no reason-code vocabulary and no signer rule. This fixture
  runs one format that carries the members the section names.
- anything about the reason-code value space. `issuer-key-compromise` is the
  string the SDK vector carries. The schema requires a non-empty string and
  nothing more, no vector varies the value, and no vector would fail if an
  implementation used a different vocabulary.
- anything about cascade-derived records for descendants of the revoked
  delegation. No vector here mints one, and neither SDK produces one.
- anything about cascade-completion records or INV-4 cascade completeness.
  Section 3.5.1 makes completion depend on the last descendant's revocation
  being persistent, no store interface in either SDK establishes persistence,
  and no vector here reaches the question.
- anything about the authority result of a chain. Part A runs the record
  verifier, not the chain verifier. No vector here reports whether a chain
  containing the revoked delegation is valid, and the record outcomes are not
  inputs to that question.
- that `ID_MISMATCH`, `SIGNATURE_INVALID`, `SCHEMA_INVALID`,
  `NONCANONICAL_VALUE`, `UNSUPPORTED_RECORD_TYPE` and
  `CASCADE_TRANSACTION_MISMATCH` are the only codes either SDK could report,
  or that a third implementation would use the same strings. They are what the
  two pinned revisions returned for the six defects this fixture mints.
- that a durable store would report ARR-08 the way the in-memory reference
  does. Both SDKs document that the in-memory store meets the indivisible
  check-and-write contract only because its read and write are one synchronous
  statement sequence. No vector here runs two concurrent callers.
- anything about the enforcement boundary. No vector makes a gateway call and
  none checks revocation status at the point an approval is consumed.

## fixture.json

Generated by `mint.py` from published seed labels, so it carries no secret
material and regenerates byte for byte:

    python3 fixtures/authority-revocation-record/mint.py

After regeneration `git diff` on `fixture.json` should be empty. Its sha256 at
the run recorded below is
`255b07e9f8f732317f95475af2d6454ddcf66b7368c19987ba5d69a740d36d7e`.

It holds the signed `target_delegation`, the six candidate records under
`records`, the key-resolver table, the three Ed25519 private key seeds, the
three domain tags this format uses plus the foreign tag ARR-02 mints against,
ARR-04's out-of-band revocation time, and ARR-06's foreign cascade origin.

The seeds are
`sha256(utf8("agent-passport-system:authority-revocation-vector:<label>"))`
for the labels `issuer-key`, `issuer-rotated-key` and `impostor-key`, the same
published derivation the SDK's own vector file documents. The 32 bytes are the
Ed25519 seed. Storing them commits no secret: anyone recomputes them from the
label strings in `mint.py`. They are test keys in a public repository and
control nothing.

## TypeScript

The repository root pins the published `agent-passport-system` package,
version 7.1.0, which exports `verifyAuthorityRevocation`,
`recordAuthorityRevocation` and `InMemoryAuthorityRevocationStore` from its
package root. The run recorded below is against 7.2.0, installed clean from
the registry over that pin without changing it. From the suite root:

    npm ci --include=dev
    npm install --include=dev --no-save agent-passport-system@7.2.0
    npm run verify:authority-revocation-record

Expected final line:

    authority-revocation-record TypeScript: 8/8 passed

It also runs as part of `npm test`, there against the root pin.

## Python

Run against agent-passport-system 4.2.0, the published wheel, in a clean
virtual environment, importing only names public in
`agent_passport.v2.authority_revocation`:

    python3 -m venv /tmp/aps-py420
    /tmp/aps-py420/bin/pip install agent-passport-system==4.2.0
    /tmp/aps-py420/bin/python fixtures/authority-revocation-record/mint.py
    /tmp/aps-py420/bin/python fixtures/authority-revocation-record/validate.py

Expected final line:

    authority-revocation-record Python: 8/8 passed

This is a manual run, not part of `npm test`, the same convention
`fixtures/issuance-refusal-expiry/README.md` documents for its own Python
runner.

## Results

Run 2026-09-24 against `agent-passport-system` 7.2.0 (npm) and
`agent-passport-system` 4.2.0 (PyPI), both installed clean from their
registries.

| vector | TypeScript 7.2.0 | Python 4.2.0 |
|---|---|---|
| ARR-01-control-valid-record | pass, `valid` | pass, `valid` |
| ARR-02-reject-revocation-id-wrong-domain | pass, `invalid` / `ID_MISMATCH` | pass, `invalid` / `ID_MISMATCH` |
| ARR-03-reject-signature-wrong-domain | pass, `invalid` / `SIGNATURE_INVALID` | pass, `invalid` / `SIGNATURE_INVALID` |
| ARR-04-reject-revocation-time-outside-signed-content | pass, `invalid` / `SCHEMA_INVALID`, `NONCANONICAL_VALUE` | pass, `invalid` / `SCHEMA_INVALID`, `NONCANONICAL_VALUE` |
| ARR-05-reject-unknown-record-type | pass, `unsupported` / `UNSUPPORTED_RECORD_TYPE` | pass, `unsupported` / `UNSUPPORTED_RECORD_TYPE` |
| ARR-06-reject-cascade-transaction-id-not-bound | pass, `invalid` / `CASCADE_TRANSACTION_MISMATCH` | pass, `invalid` / `CASCADE_TRANSACTION_MISMATCH` |
| ARR-07-control-first-record-inserted | pass, inserted | pass, inserted |
| ARR-08-reject-duplicate-record-id | pass, not inserted, first record stands | pass, not inserted, first record stands |

No vector is `not_supported` in either language. Both runners assert state,
the `valid` flag, and the full failure list including messages, so the two
SDKs agreeing on the codes here is also agreement on the message strings.

TypeScript, verbatim:

    $ npm run verify:authority-revocation-record

    authority-revocation-record Part A: record verification
    PASS ARR-01-control-valid-record state=valid failures=-
    PASS ARR-02-reject-revocation-id-wrong-domain state=invalid failures=ID_MISMATCH
    PASS ARR-03-reject-signature-wrong-domain state=invalid failures=SIGNATURE_INVALID
    PASS ARR-04-reject-revocation-time-outside-signed-content state=invalid failures=SCHEMA_INVALID,NONCANONICAL_VALUE
    PASS ARR-05-reject-unknown-record-type state=unsupported failures=UNSUPPORTED_RECORD_TYPE
    PASS ARR-06-reject-cascade-transaction-id-not-bound state=invalid failures=CASCADE_TRANSACTION_MISMATCH

    authority-revocation-record Part B: store first-wins
    PASS ARR-07-control-first-record-inserted recorded=true inserted=true stored=sha256:2e4a42ace216ca9041e15a5207804af7ad3e213d44563644ba5db721a34b23dc
    PASS ARR-08-reject-duplicate-record-id recorded=true inserted=false stored=sha256:2e4a42ace216ca9041e15a5207804af7ad3e213d44563644ba5db721a34b23dc

    authority-revocation-record TypeScript: 8/8 passed

Python, verbatim:

    $ /tmp/aps-py420/bin/python fixtures/authority-revocation-record/validate.py

    authority-revocation-record Part A: record verification
    PASS ARR-01-control-valid-record state=valid failures=-
    PASS ARR-02-reject-revocation-id-wrong-domain state=invalid failures=ID_MISMATCH
    PASS ARR-03-reject-signature-wrong-domain state=invalid failures=SIGNATURE_INVALID
    PASS ARR-04-reject-revocation-time-outside-signed-content state=invalid failures=SCHEMA_INVALID,NONCANONICAL_VALUE
    PASS ARR-05-reject-unknown-record-type state=unsupported failures=UNSUPPORTED_RECORD_TYPE
    PASS ARR-06-reject-cascade-transaction-id-not-bound state=invalid failures=CASCADE_TRANSACTION_MISMATCH

    authority-revocation-record Part B: store first-wins
    PASS ARR-07-control-first-record-inserted recorded=True inserted=True stored=sha256:2e4a42ace216ca9041e15a5207804af7ad3e213d44563644ba5db721a34b23dc
    PASS ARR-08-reject-duplicate-record-id recorded=True inserted=False stored=sha256:2e4a42ace216ca9041e15a5207804af7ad3e213d44563644ba5db721a34b23dc

    authority-revocation-record Python: 8/8 passed

The same TypeScript runner also exits 0 under the repository's own pin,
`agent-passport-system` 7.1.0, with byte-identical output, which is why it is
wired into `npm test`.

Both clean-install runs re-minted `fixture.json` first and produced the same
sha256, `255b07e9f8f732317f95475af2d6454ddcf66b7368c19987ba5d69a740d36d7e`.

## Provenance

ARR-01's target delegation and revocation record are the `valid_case` of
`fixtures/authority-revocation/authority-revocation-vectors-v1.json` in
`aeoess/agent-passport-system`, file sha256
`43dbe7fed137269405be38bf829681bc18525a1eccb8e8236e37f03720147ee2`, whose
recorded outcomes were produced by the TypeScript reference at commit
`f6792af732f2102b239cca6b18840f6fa7d8fe87`. `mint.py` re-mints that record
from the published inputs rather than copying it, and refuses to write
`fixture.json` unless the result reproduces the vector's identifiers and
signatures byte for byte.

ARR-02 through ARR-08, `vectors.json`, `mint.py`, `verify.ts` and
`validate.py` are authored for this suite, adapting the minting and
key-resolution pattern already established by
[`fixtures/issuance-refusal-expiry/`](../issuance-refusal-expiry/) to record
verification and to the store's mutation path rather than to issuance.

Both runners were executed locally against the published npm package
(`agent-passport-system` 7.2.0) and the published wheel
(`agent-passport-system` 4.2.0), each installed clean from its registry on
this machine. This is an author-produced record, not an independent one, per
`CONTRIBUTING.md`'s admission rules for run records: the same author wrote the
vectors, the harness and the SDK the harness calls.

## Boundary

A run of this family does not establish:

- anything about an implementation outside these two SDK revisions, or that
  every implementation of this format reports the same codes.
- anything about whether a chain containing the revoked delegation is valid.
  That is the chain verifier's result and no vector here reaches it. See
  [`fixtures/ancestor-revocation-chain/`](../ancestor-revocation-chain/) for
  the chain question.
- anything about cascade-derived records, cascade-completion records, or
  cascade completeness.
- anything about revocation freshness, staleness, or a verifier that has not
  yet established the revocation.
- anything about a durable store under concurrency. Both SDKs' in-memory
  store meets the indivisible check-and-write contract because of its runtime,
  and no vector here runs two callers at once.
- that the six defects minted here are a catalog of every way a record under
  this format can be wrong. They are the six this fixture varies from its two
  controls.
