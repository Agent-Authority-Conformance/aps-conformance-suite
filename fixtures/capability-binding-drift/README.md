# capability-binding-drift: a tool keeps its name while what it does changes

**Status: candidate against proposed text. This is not a draft-03 conformance case.**
Every vector in `vectors.json` carries `status: "candidate_against_proposed"` and names
the proposed text it tests. `verify.ts` and `verify.py` both refuse to run if any vector
loses that label or names proposed text the file does not define.

A grant pins a tool by name and by implementation digest. The tool keeps its name. Its
implementation digest, or its declared schema and permissions, changes and gains a
destructive capability. The question this family makes executable is whether an action
through the changed tool is established under the pinned grant, and what a verifier
records when the grant carries no pin at all.

## What this tests, and against which text

The proposed text is the **Action or capability binding** concept in
[`AUTHORITY-LIFECYCLE.md`](https://github.com/aeoess/agent-authority-lifecycle), version
0.1.2-draft, at commit `5c1bf09ee29d517f2f19c9bb9212543a7c44b227`, section **Lifecycle
concepts are separate > Authority and dependencies**:

> Action or capability binding. Which operation, implementation or schema a grant refers
> to, where that distinction matters. A tool can keep its name while what it does
> changes, which widens effective authority without any change to the grant.

Three vectors also test the neighbouring **Target binding** concept in the same section
of the same commit:

> Target binding. Which resource, counterparty or object the authority applies to.
> Continuity of a name does not by itself establish continuity of the thing named.

That document states the status of both entries itself:

> The grouping and every other entry are **proposed**, added in 0.1.1-draft or
> 0.1.2-draft. No public case tests them yet.

### Why this is not a draft-03 case

[draft-pidlisnyi-aps-03](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/03/) states
no rule about pinning a tool to an implementation digest or a schema, and defines no
syntax for such a pin. The closest text is section 4.1, on the `target` field of an
action reference:

> target is the exact resource, tool, or endpoint against which the action will be
> dispatched; a profile MUST define its target string construction.

`target` names a resource, tool or endpoint. It carries no implementation digest and no
schema digest, so it cannot tell apart two revisions of one tool that keep the same
endpoint, which is exactly the case CBD-03 presents. Nothing in draft-03 section 3.2
(scope component order), section 3.3 (chain verification) or section 5.3 (core receipt
types) supplies the missing distinction either.

One piece of draft-03 the family does lean on is the scope grammar, section 3.2:

> Scope grants use ASCII colon-separated segments. "\*" covers all grants; a wildcard is
> otherwise permitted only as the terminal segment ":\*".

A pin is expressed here as further colon-separated segments under the tool grant, so the
pin stays inside the grammar draft-03 already defines rather than inventing a new facet
or record field. draft-03 does not define this encoding or any other pin encoding.

## What this family defines itself

The proposed text names the distinction and stops. It does not say how a grant carries a
pin, what a verifier returns when the pin does not match, whether "implementation" and
"schema" are pinned separately, or what happens when a grant carries no pin. This family
supplies all four, because a runnable case cannot exist without them, and none of them is
a reading the proposed text compels:

1. **Pin encoding.** `tool:<name>` is the tool grant. `tool:<name>:impl:sha256:<64 hex>`
   pins the implementation digest. `tool:<name>:meta:sha256:<64 hex>` pins the declared
   metadata digest.
2. **Verdict vocabulary.** `admitted`, `not_established`, `invalid`. A digest that does
   not match the pin gives `not_established`, not `invalid`: the grant is a fine grant
   and the chain is valid, and what has not been established is that this tool is the
   tool the grant was written against.
3. **Metadata digest.** `sha256:` over `"APS-CBD-TOOL-METADATA-V0" || 0x00 ||
   JCS(metadata)`, following the domain-separated digest style draft-03 uses for
   `payload_ref` and `action_ref`. No SDK computes this digest. See "SDK findings".
4. **The unpinned rule.** A grant that names a tool and carries no pin gives
   `not_established`, recorded with reason `no_capability_pin_in_grant`, rather than
   admitting. CBD-04 and CBD-05 pin that down and are the variant the family exists to
   make visible.

Read 1 to 4 as this family's proposal for how the concept would be tested, not as the
concept's meaning. See "Where the proposed text was too vague to test".

## What exists

Neither reference SDK exposes an API that decides whether an action through a tool is
established under a grant that pins that tool. The reference boundary is therefore this
family's own code, in `harness.ts`, following the precedent set by
[`fixtures/runtime-authority-denial-continuity/`](../runtime-authority-denial-continuity/)
and [`fixtures/approval-single-use/`](../approval-single-use/). **The capability-binding
boundary is implemented by this fixture, not by either APS SDK. The SDKs are used only
for the things they actually decide.**

`harness.ts` calls the TypeScript SDK for three of them:

- `verifyAuthorityDelegationChain` for the grant's structural, temporal, signature and
  revocation state
- `verifyToolIntegrity` for the tool registry entry's attestor signature and for whether
  the signed entry still describes the implementation reachable right now
- `canonicalizeJCS` for the RFC 8785 canonical bytes the metadata digest is taken over

Everything else, the pin parsing, the pin comparisons, the unpinned rule and the verdict
vocabulary, is the family's own.

### SDK findings

Three findings surfaced while building this family. They are recorded here because they
changed how the family is built, not as vectors: no vector tests an SDK's export list.

**1. The TypeScript SDK's tool-manifest layer is compiled but not reachable.**
`agent-passport-system` 7.1.0 ships `createToolManifest`, `verifyToolManifest`,
`reviseToolManifest`, `reapproveToolManifest`, `createNamespaceClaim` and
`verifyNamespaceClaim` in `dist/src/core/tool-integrity.js`, with type declarations in
the matching `.d.ts`. None of them is exported from the package root or from the `./core`
subpath, so none is callable by a consumer of the published package.
`fixtures/capability-binding-drift/sdk-probe.mjs` records this. That layer is where a
`metadataHash` lives, described in the SDK's own declaration as

    "`sha256:` of the canonicalized metadata block — DISTINCT from implementationHash so
    a description/schema/permissions change is detectable even when the implementation is
    byte-identical"

which is precisely CBD-03. Because it is unreachable, this family computes its own
metadata digest instead. Only the older `createToolRegistryEntry` and
`verifyToolIntegrity` pair, which digests an implementation and nothing else, is
reachable.

**2. `createToolRegistryEntry` cannot produce reproducible bytes.** It stamps
`verifiedAt` from `new Date().toISOString()` and offers no override, so calling it twice
gives two different records and two different signatures. The unreachable
`createToolManifest` does take a `verifiedAt` override, documented in the SDK as "Override
timestamp — for deterministic conformance fixtures". `mint.ts` works around this the
narrow way: it mints through the SDK, re-stamps `verifiedAt` at the pinned instant, and
re-signs the same body with the SDK's own `sign` over the SDK's own `canonicalize`. It
then asserts the re-signed record satisfies the SDK's own `verifyToolIntegrity`, so
nothing about the signature is taken on trust.

**3. The Python SDK ships no tool-integrity module at all.**
`agent-passport-system` 4.1.0 on PyPI has no `create_tool_registry_entry`, no
`verify_tool_integrity` and no `ToolRegistryEntry` anywhere in the installed package.
`fixtures/capability-binding-drift/sdk-probe.py` records this. The whole tool layer is
therefore `not_supported` on the Python side, and `verify.py` writes the registry-entry
signature check and the implementation-digest comparison out from the SDK's own
`agent_passport.crypto.verify` and `agent_passport.canonicalize`. That is a recorded gap,
not a claim that the Python SDK decided any of it.

## What the family does

`mint.ts` mints, with `agent-passport-system` 7.1.0:

- three one-hop `AuthorityDelegationV1` grants, principal to acting agent, identical
  except for their nonce and their scope: `pinned` carries both pins, `impl_pin_only`
  carries the implementation pin and no metadata pin, `unpinned` carries neither
- two revisions of one tool named `ledger.export`, both behind the same endpoint. The
  implementation is an endpoint descriptor, one of the three kinds of content the SDK
  documents as hashable. Revision 2 changes the build string, so its implementation
  digest changes. The declared metadata is the tool's schema, description and
  permissions. Metadata revision 2 adds a `purge` boolean to the schema and adds
  `ledger:delete` to the declared permissions.
- three `ToolRegistryEntry` records: one over each implementation signed by the tool
  attestor, and one over implementation 1 signed by a different attestor
- one `aps-action-ref-v2` action reference with `scope_required: ["ledger:read"]`,
  computed with `createActionReferenceInputV2`, `computeActionRefV2` and
  `computePayloadRefV1`

`mint.ts` asserts at mint time, and exits without writing `chain.json` if any assertion
fails, that: all three grants verify `valid` at the pinned instant with an active
resolver, the re-signed registry entries satisfy the SDK's own `verifyToolIntegrity`, the
entry for implementation 1 reports `implementationVerified: false` against implementation
2, the entry signed by the other attestor reports `attestorSignatureValid: false` against
the tool attestor's key, and the two implementation digests and the two metadata digests
are pairwise distinct.

`harness.ts` implements `CapabilityBindingBoundary` in five ordered steps: the grant
chain, the grant's scope, the tool attestation, the implementation pin, the metadata pin.
Two configurations are built from it, described under "Negative control".

`verify.ts` runs both configurations over the eight presentations and checks each against
its expected outcome. `verify.py` is a second implementation of the same five steps,
written against the Python SDK's primitives. Both run with no network access.

Each presentation is an independent evaluation against a fresh boundary. Unlike
`fixtures/approval-single-use/`, no state is carried between presentations and
presentation order does not matter.

## Vectors

| id | covers | differs from CBD-01 by | expected |
|---|---|---|---|
| CBD-01-admit-unchanged-under-pin | control | nothing, this is the control | `admitted`, `capability_continuity_established` |
| CBD-02-not-established-implementation-digest-drift | implementation pin | the build changes, the attestor re-attests it, and the declared permissions gain `ledger:delete` | `not_established`, `pinned_implementation_digest_mismatch` |
| CBD-03-not-established-schema-drift-same-implementation-digest | metadata pin | the endpoint descriptor is byte-identical while the schema gains a `purge` parameter and the permissions gain `ledger:delete` | `not_established`, `pinned_metadata_digest_mismatch` |
| CBD-04-not-established-unpinned-grant-tool-changed | the unpinned variant | the grant names the tool and carries no pin, and the tool changed | `not_established`, `no_capability_pin_in_grant` |
| CBD-05-not-established-unpinned-grant-tool-unchanged | the unpinned variant | the grant carries no pin and nothing about the tool changed | `not_established`, `no_capability_pin_in_grant` |
| CBD-06-not-established-registry-entry-stale-against-running-implementation | attestation currency | the signed entry still names the pinned digest while the implementation reachable now is revision 2 | `not_established`, `registry_entry_implementation_mismatch` |
| CBD-07-not-established-attestation-by-unrecognized-attestor | attestation authenticity | the entry names the pinned digest but is signed by a different attestor | `not_established`, `tool_attestation_signature_invalid` |
| CBD-08-not-established-implementation-pinned-metadata-unpinned | partial pin | the grant pins the implementation digest and says nothing about schema or permissions, and the schema drifted | `not_established`, `metadata_not_pinned_in_grant` |

CBD-01 is the prompt's control: digest unchanged, action admitted. CBD-05 is the vector
most likely to be argued with, and it is deliberate. An unpinned grant gives a verifier
no basis to establish capability continuity either way, so the absence of change is not
something the grant establishes, and the verdict does not depend on a fact the verifier
cannot check from the records in front of it.

## Negative control

`defective-boundary-trusts-registry-entry-digest` is an implementation that pins a tool by
the digest its signed registry entry declares and stops there. It runs the identical
grant-chain check, the identical scope check and the identical attestor-signature check,
and it compares the grant's implementation pin to the entry's declared
`implementationHash`. It removes exactly three steps:

- it never compares the metadata pin
- it treats an absent pin as satisfied
- it ignores whether the signed entry still describes the implementation reachable now

Those three removals account for exactly five vectors. The declared failing set:

    CBD-03-not-established-schema-drift-same-implementation-digest
    CBD-04-not-established-unpinned-grant-tool-changed
    CBD-05-not-established-unpinned-grant-tool-unchanged
    CBD-06-not-established-registry-entry-stale-against-running-implementation
    CBD-08-not-established-implementation-pinned-metadata-unpinned

This is the negative control a naive implementation passes wrongly, and it is not a straw
man. Comparing a grant's pin to a signed registry entry is the obvious reading of "pin the
tool by digest", it involves real signature verification, and on CBD-03 and CBD-06 it
admits an action through a tool that has gained `ledger:delete` while reporting a clean
digest match. Both `verify.ts` and `verify.py` check the control in both directions: every
declared id must actually diverge from its expected outcome, and every other id must still
match, so an undeclared failure or a declared failure that quietly starts passing is loud
in either runner's output.

## Running

TypeScript, wired into `npm test` as its last step:

    npm ci --include=dev
    npm run verify:capability-binding-drift

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set

Regenerating `chain.json` gives the same bytes, and `git diff` is empty after a second run:

    npx tsx fixtures/capability-binding-drift/mint.ts

Python, a manual run and not part of `npm test`, the same convention
`fixtures/approval-single-use/verify.py` and
`fixtures/ancestor-revocation-chain/validate.py` already follow for a Python side kept out
of the hermetic Node-only CI gate. Needs `agent-passport-system` 4.x installed:

    python3 fixtures/capability-binding-drift/verify.py

Expected final line:

    PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set (python)

The two SDK support probes, which print a per-API `supported` or `not_supported` line and
assert nothing:

    node fixtures/capability-binding-drift/sdk-probe.mjs
    python3 fixtures/capability-binding-drift/sdk-probe.py

## Determinism

Every Ed25519 key is the SHA-256 of a published label under the seed prefix
`aps-conformance-suite:capability-binding-drift`, recorded in `chain.json` as
`seed_prefix`. Every delegation nonce and the action nonce are derived the same way. Every
timestamp is pinned: `now` is `2026-09-23T12:00:00.000Z`, delegations are issued at
`09:00:00.000Z`, registry entries are attested at `10:00:00.000Z`, the action reference is
issued at `11:00:00.000Z`. The metadata digest is taken over RFC 8785 JCS canonical bytes
produced by the SDK's own `canonicalizeJCS`, and `verify.py` reproduces the same bytes
with the Python SDK's `canonicalize_jcs`. No secret material is in the file: every public
key is published and every private key is reproducible from its published label, which is
exactly why these keys are for test vectors and nothing else.

SHA-256 over the exact bytes of this family's files, at the commit that introduced it:

    06b2021ba4b19740415c37d4701438387d31e21d8e7adfc97229a52e9c479bbb  chain.json
    3fd1fd57c8bb0885a481bed1866d1c9bd4c1bbca6fe87b12ce3306c1f226d9b3  harness.ts
    7e572fba1cf00bde9d25a29cf22aa3d06a9c3349f20e08145746bbd2024ae22a  mint.ts
    039834c8f0266eba8bf0fe5c3bddb20cc1651cd3158bc12fbf42a31e032ac7f0  sdk-probe.mjs
    b73dba427ab65ff708cb24a72ab7c66dfac7b3f4f6682479f77670f09739144f  sdk-probe.py
    5d76af92b5b52bcde058bb1a62830f3faa7462ba1283f5b7fa0bb2e5bf650943  vectors.json
    69acc7a3680daa17203e0e6adab85239389d640073054e5c2f90b4ac7dd4266b  verify.py
    0dddf2d26a4a81784a85fc94f84592df3399f8dd1aa2dbbbb84521f78a524b54  verify.ts

These are listed here rather than in a `CHECKSUMS.sha256` file on purpose. Under
`CONTRIBUTING.md`, files covered by a record's published digest set are immutable and a
later correction goes to a `CLARIFICATIONS.md` rather than to the file. A candidate family
against proposed text should stay editable while the text it tests is still being argued
about, so it does not publish a digest set.

## Verification split

This family is lab-authored and APS-native, not an ingestion from an external system, so
`CONTRIBUTING.md` does not require this section of it. It is recorded anyway, in the same
format and with the same two label axes, because the family's verdicts come from its own
boundary rather than from either SDK and a reader deserves to see that split stated rather
than inferred. Nothing here asks for the family to be classified as an external-system
family, and it is not listed in `fixtures/cross-stack/index.json`.

- grant chain state for all three grants at the pinned instant (`valid`, active resolver); runner aeoess; Mode A; author-produced, because this lab authored the vectors, `mint.ts` and the implementation under test is this lab's own `agent-passport-system`; recomputed by `agent_passport.v2.authority_delegation.verify_authority_delegation_chain` in `verify.py` under the same relationship.
- tool registry entry Ed25519 signatures and implementation-digest matches; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `verifyToolIntegrity` on one side and the Python SDK's `agent_passport.crypto.verify` plus `hashlib` on the other.
- metadata digests over RFC 8785 JCS canonical bytes; runner aeoess; Mode B; author-produced, same relationship, with the TypeScript SDK's `canonicalizeJCS` on one side and the Python SDK's `canonicalize_jcs` on the other.
- the eight capability-binding verdicts and the declared defective failing set; runner aeoess; Mode A; author-produced, because the boundary that decides each verdict is this family's own `harness.ts` and its Python counterpart in `verify.py`, both written in this lab.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Results

Both runners were executed locally against `agent-passport-system` 7.1.0 (npm) and
`agent-passport-system` 4.1.0 (PyPI, in a temporary virtual environment). The
`reference-boundary` matched 8/8 presentations under both runners.
`defective-boundary-trusts-registry-entry-digest` failed exactly the declared set of 5
under both runners and matched the remaining 3 under both. `npm ci --include=dev` and
`npm test` both exited 0 with this family wired in. These are author-produced records,
not independent ones, per `CONTRIBUTING.md`.

## Where the proposed text was too vague to test

This is a finding, and it matters at least as much as the fixture. The **Action or
capability binding** entry names a real distinction in two sentences and leaves four
things undetermined. Each one had to be decided before a single vector could exist, and a
different decision gives different expected verdicts for the same records:

1. **No pin representation.** The proposed text does not say where a pin lives: a scope
   grant, a new authority facet, a field on the action reference, or an out-of-band
   registry the grant points at. Each choice changes what narrowing means for a pin, and
   the scope-grant encoding this family chose means a child delegation's pin is checked
   by draft-03's ordinary scope covering rule, which was not a decision the proposed text
   asked for.
2. **No verdict.** The proposed text says a tool that changes "widens effective authority
   without any change to the grant". It does not say what a verifier returns. `invalid`,
   `not_established`, `indeterminate` and "valid but re-approval required" are all
   readings of that sentence. This family chose `not_established`, which is the reading
   that keeps the grant and the chain intact and says only that continuity of the thing
   named was not shown. Nothing in the text compels it.
3. **No rule for the unpinned grant.** The text says the distinction matters "where that
   distinction matters", which leaves the default open. A grant that names a tool and
   pins nothing could reasonably be read as admitting, as admitting with a recorded
   caveat, or as not established. CBD-04 and CBD-05 make the third reading executable and
   would have to change wholesale under either of the other two.
4. **No decomposition.** The text lists "operation, implementation or schema" in one
   breath. It does not say whether those are one pin or three, whether pinning one of
   them says anything about the others, or what a partial pin means. CBD-08 is that gap
   made executable, and its expected verdict is the most arguable one in the family.

A fifth thing is under-determined rather than undetermined. The text says a tool "can keep
its name while what it does changes". It does not distinguish a change in the
implementation from a change in what the tool *declares* it does, which are different
evidence problems: CBD-06 shows an implementation that drifted away from its own signed
attestation, and CBD-03 shows an attestation that is perfectly current about an
implementation whose declared capability grew underneath it. A boundary that only checks
one of the two admits the other.

Until at least 1 to 4 are settled in the proposed text, no case in this family can move
from `candidate` to `tested` against it, because there is nothing yet to be conformant
with. That is the finding.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that, for this family's own reference
boundary and its own pin encoding:

- an action through a tool whose implementation digest and declared metadata digest both
  match the grant's pins is admitted
- an action through a tool that kept its name while its implementation digest changed is
  not established under the pinned grant, even when the new build is properly attested
- an action through a tool that kept both its name and its implementation digest, while
  its declared schema and permissions changed and gained a destructive permission, is not
  established under the pinned grant
- a grant that names a tool and carries no pin records that capability continuity was not
  established, whether or not the tool in fact changed, rather than admitting
- a grant that pins the implementation and not the declared metadata records that the
  metadata was not pinned, rather than treating the implementation pin as covering it
- a signed tool attestation that no longer describes the implementation reachable now
  does not establish continuity, and neither does one signed by an attestor the boundary
  does not resolve for that tool
- an implementation that pins a tool by its registry entry's declared digest and stops
  there predictably fails exactly those five vectors, and none of the other three

## Does not claim

A pass does **not** establish:

- anything about draft-pidlisnyi-aps-03 conformance. draft-03 states no capability pin
  rule. Every vector is `candidate_against_proposed`, and a maintainer who disagrees with
  any of the four decisions under "What this family defines itself" should expect
  different expected verdicts, not a bug report.
- that this family's pin encoding, verdict vocabulary, metadata digest or unpinned rule
  is the right one, or the only defensible one. See "Where the proposed text was too
  vague to test".
- anything about a deployed enforcement gateway, MCP server, tool registry or agent
  runtime. No network call is made and no protocol is spoken. `harness.ts` is this
  family's own in-process reference model.
- anything about MCP tool descriptions, OpenAI function definitions or any other concrete
  tool-description format. The metadata block here is a generic description, schema and
  permission triple authored for this family.
- that either reference SDK implements capability binding. Neither does. The TypeScript
  SDK decides a tool registry entry's signature and implementation-hash match and nothing
  further, and the Python SDK ships no tool-integrity surface at all. See "SDK
  findings".
- anything about how a capability pin should narrow across a delegation chain. Every
  grant here is a one-hop root delegation, so no parent-to-child scope comparison of a
  pin is exercised.
- that a destructive capability was actually reachable. `ledger:delete` appears in a
  declared permission list and a `purge` parameter appears in a declared schema. Nothing
  here executes anything.

## Provenance

`README.md`, `vectors.json`, `chain.json`, `mint.ts`, `harness.ts`, `verify.ts`,
`verify.py`, `sdk-probe.mjs` and `sdk-probe.py` are authored for this suite. The minting,
key-derivation and seed-label pattern follows `fixtures/approval-single-use/mint.ts` and
`fixtures/ancestor-revocation-chain/mint.py`. The reference-boundary-plus-declared-defective-control
pattern follows `fixtures/runtime-authority-denial-continuity/harness.ts` and
`fixtures/approval-single-use/harness.ts`. All code was written in this lab. Neither
runner was reviewed by anyone outside it, and no independent third party has run either of
them.
