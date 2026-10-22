# Open independent runs

This is a work queue for verification layers that have an author-produced record but no
qualifying independent record yet. Rows may come from merged external-system families,
lab-authored fixtures or pinned interop runs.

Independence is defined per layer in `CONTRIBUTING.md`. An independent result for one layer
does not close another. For example, independently recomputing a package's expected verdicts
does not establish what that package itself returned.

When an independent run closes a listed layer, its record is added under `interop/` or
appended to the relevant `SOURCE.md`, and the matching row is removed here in the same
commit. Earlier records remain unchanged.

This queue tracks follow-up work, not admission decisions. Claims that require independent
evidence before admission cannot use this queue to defer that requirement.


| family / record | layer / claim | what an independent run recomputes | command |
|---|---|---|---|
| `fixtures/lease-revocation-axes` | three-axis candidate model and eight defective variants | recompute the frozen timelines and observe each declared mutation under an independently authored implementation; runner here authored vectors and model | `npm run verify:lease-revocation-axes` |
| `fixtures/lease-revocation-axes` | SDK original-evidence expiry and chain checks under supplied revocation answers | reproduce the primitive observations with pinned SDK and corpus; no complete mode or downstream enforcement is claimed | `npm run verify:lease-revocation-axes:sdk` |
| `fixtures/cross-stack/nobulex-bilateral-v0` | two-profile comparison: nobulex integer-epoch digests against the APS string-timestamp profile via `computeExternalActionRefV1` | render each vector's instant in the string profile and recompute the digest under an implementation other than the APS SDK; report per-vector match or diverge | `node fixtures/cross-stack/nobulex-bilateral-v0/run.mjs` |
| `fixtures/cross-stack/action-ref-v1-negatives` | every layer: the vectors were authored by this lab's maintainer (upstreamed as argentum-core PR #12), so no run by the vector author or by the Argentum implementation author is independent | recompute the five positive `action_ref` digests and the nine drifted `claimed_action_ref` digests from the stated byte forms under any third implementation; confirm each negative fails at its declared stage | `node fixtures/cross-stack/action-ref-v1-negatives/run.mjs` |
| `fixtures/cross-stack/aat-amdal` | window bounds evaluated against each vector's `verification_time`; the comparison is hand written in `runners/aat_runner.py`, so the layer is author-produced | evaluate each vector's window against its `verification_time` under an implementation the runner did not write; report per-vector match or diverge | `python3 runners/aat_runner.py fixtures/cross-stack/aat-amdal/aat-amdal-2026-08-26.json` |
| `fixtures/cross-stack/nobulex-bilateral-v0` | the canonical preimage of each vector under the integer-epoch profile, produced by the hand-written `jcsFlat` in `run.mjs`, so the layer is author-produced | recompute each vector's canonical preimage under an RFC 8785 implementation the runner did not write and compare it byte for byte | `node fixtures/cross-stack/nobulex-bilateral-v0/run.mjs` |
| `fixtures/cross-stack/receipts-amdal` | did:key resolution of the receipt signer, decided by the hand-written base58 and multicodec decoder in `runners/receipt_runner.py`, so the layer is author-produced | resolve each signer's did:key under a third-party resolver and compare the recovered public key | `python3 runners/receipt_runner.py fixtures/cross-stack/receipts-amdal/receipts-amdal-2026-07-29.json` |
| `fixtures/cross-stack/ctef-v0.3.1` | JWS header-policy enforcement (`alg=EdDSA`, key `kty=OKP`/`crv=Ed25519`, unique `kid`), decided by the author-written `plugins/jws.py`, so the layer is author-produced | decode each fixture's JWS header and resolve its key under an implementation the runner did not write; confirm the five fixtures pass and that `alg`/`kty`/`crv`/`kid` violations are refused | `python3 fixtures/cross-stack/ctef-v0.3.1/validate.py` |
| `fixtures/cross-stack/ctef-v0.3.1` | tamper rejection: a mutated signing input is refused at the signature check, decided by the author-written `plugins/jws.py` + `plugins/ed25519_pure.py`, so the layer is author-produced | flip a byte of a fixture's signed payload and confirm the signature check refuses it (not a header rejection) under an implementation the runner did not write | `python3 fixtures/cross-stack/ctef-v0.3.1/validate.py` |
| `fixtures/cross-stack/token-exchange-attenuation-v0` | scope and chain axis over the 12 attenuation cases | the 12 vector-validity findings and the 15 per-request decisions under the oauth-rfc8693 bridge of agent-passport-system 6.0.0 | `npx tsx runners/ts/token-exchange-attenuation.test.ts` |
| `fixtures/cross-stack/token-exchange-attenuation-v0` | clean-room recompute of the same 12 cases | the same findings and decisions under a runner-authored Python stdlib implementation of the published rules | `python3 fixtures/cross-stack/token-exchange-attenuation-v0/recompute.py` |
| `interop/attenu-guard-0.8.0` | package canonicalization over the corpus canonical-bytes cases at 0.8.0 | the ten canonical byte outputs under attenu-guard 0.8.0, compared byte for byte with fixtures/canonical-bytes | `v/bin/python interop/attenu-guard-0.6.1/jcs-byte-diff.py` with attenu-guard==0.8.0 installed |
| `interop/attenu-guard-0.8.0` | draft-semantics recomputation over the 19 package vectors at 0.8.0 | the nineteen accept and reject verdicts under an independently authored verifier of the draft rules | `v/bin/python interop/attenu-guard-0.6.1/cleanroom/verify_asor00.py` with attenu-guard==0.8.0 installed |
| `interop/attenu-guard-0.11.0-bundles` | bundle verification by a README-derived verifier over the same eight vectors | the eight accept and reject verdicts and their failure sets under an independently authored verifier of the published rules | `cr/bin/python interop/attenu-guard-0.11.0-bundles/cleanroom/verify_bundle_v1.py <bundle_vectors_v1.json>` with rfc8785==0.1.4 |
| `interop/cleanroom-oracle-safety-check-6e8b05b2` | JCS bytes, SHA-256 and Ed25519 outer witness over the same 13 vectors | the 13 outer-primitive reproductions under rfc8785 and cryptography, no suite or SDK code | `python cleanroom_osc.py <corpus dir>` in that directory, per its SOURCE.md |

Layers with an independent record and therefore not listed: `aat-amdal` (issuer signature,
runner aeoess, `cryptography` library, vectors and implementation by AgentLair);
`receipts-amdal` (JCS bytes, Ed25519 signature, `receipt_id` recomputation, runner aeoess,
Python stdlib for canonicalization and hashing and `cryptography` for Ed25519, vectors and
implementation by AgentLair); `nobulex-bilateral-v0` SHA-256 over each vector's own
`expected_canonical_preimage` (runner aeoess, node:crypto, vectors and implementation by
Nobulex).

Families still under admission review carry their verification split in the admission record
and are not listed here.

Interop entries refer to specific pinned observations, not entire families. Each interop row
is listed as its record labels the layer. Where a record's label is reclassified under the
current `CONTRIBUTING.md` definition, the reclassification is appended to that record as a
dated clarification and the row is removed in the same commit. Closing one layer does not
change the attribution or status of any other layer.
