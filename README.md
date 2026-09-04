# aps-conformance-suite

This is the Agent Passport System corpus hosted by Agent Authority Conformance, an LF Decentralized Trust lab: byte-level test vectors, verifier adapters and reproducible run reports for identity, delegated authority and signed decision receipts. It is one corpus in the lab; the lab itself is at https://github.com/Agent-Authority-Conformance.

Run it: `npm ci --include=dev && npm test`. After dependencies are installed, the run makes no network calls. Exit 0 means every APS-native vector passed. External-system families under `fixtures/cross-stack/` are not executed by `npm test`; each carries its own reproduction command in its README.

Report your run: copy the verbatim output into a Run report issue, or commit it under `interop/` and open a PR. Ran the vectors with your own implementation instead? docs/RUN-REPORT.md describes the independent-run report. Both passes and divergences are useful. Every published report records who ran it and which revision was tested.

> **Status:** the corpus carries APS-native vectors, cross-stack fixtures from outside parties, and interop records from independently authored implementations, each labelled by who ran what (Mode A, the author's runner; Mode B, an independent runner) and by whether it was author-produced or independent. The inventory below is generated from the tree; nothing here is a conformance verdict about any implementation.

## What this suite is

A packaged corpus of test vectors that any APS-compatible implementation can run to verify it agrees, byte-for-byte, with the canonical APS reference. The fixture categories below cover the major spec surfaces:

- **bilateral-delegation**: JCS canonicalization (RFC 8785) vectors used in bilateral delegation receipts. 10 vectors, deterministic seed `aps-canonicalize-fixture-v1`.
- **inference-session**: CTEF v0.3.1 cryptographic agent identity vectors (validity windows, sequence bounds). 7 vectors, deterministic seed `ctef-synthetic-fixture-v1`.
- **instruction-provenance**: InstructionProvenanceReceipt v0.2 envelope, path canonicalization, exhaustiveness, action-time recompute. 10 vectors (6 positive + 4 negative), deterministic seed `aps-instruction-provenance-fixture-v1`.
- **aivss-scenarios**: AIVSS §3.6 worked scenarios (OWASP AAI001 through AAI010) with CVSS+AIVSS scoring and APS-primitive mappings. 10 scenarios, structural fixtures.
- **canonical-bytes**: RFC 8785 JCS byte-contract vectors (UTF-16 key ordering, ECMAScript number serialization, NFC, string escaping), TS-reference-derived and runner-verified, plus a production-derived string-concatenation preimage failure-class fixture (qntm v0.3.2). 9 fixtures (8 JCS vectors verified, 1 production-diff).
- **accountability-record**: signed enforcement-boundary decision records (allow/deny/halt plus execution status) with a detached-payload action digest. 12 vectors.
- **read-fidelity-receipt**: sampled readback fidelity receipts with word-digest handles. 8 vectors.
- **actionref-canonical**: native action_ref scopeRequired canonicalization: NFC per scope string plus Unicode code-point sort (draft-pidlisnyi-aps-03 section 4.1). 4 vectors, TS-generated and Go-verified.
- **bilateral-pair**: bilateral pair reconciliation verdicts across the five mismatch classes. 6 vectors, co-signed.
- **bilateral-golden**: BilateralReceipt canonical signable bytes carrying aud and action_ref; independently derived and cross-verified (TypeScript reference plus from-scratch Python RFC 8785). 2 vectors, runner-checked signatures.

A `.well-known/aps-test-vectors.json` mirrors the agentgraph.co `.well-known` shape for the canonical reference subset.

## What this suite isn't

- **Not a normative spec.** The spec lives in the nine APS papers (Zenodo) and the IETF Internet-Draft `draft-pidlisnyi-aps`. This suite is the conformance corpus that says "does your implementation match the canonical reference at the byte level."
- **Not the live test suite.** For full APS adversarial testing, run `agent-passport-system` `npm test` upstream. This suite extracts the byte-canonical reference set; it does not replace dynamic test execution.
- **Not a validator.** The runner verifies your canonicalizer against the corpus. It does not validate that your implementation's API surface matches APS; that is an integration question, not a canonicalization one.

## Running the TS runner

```bash
cd runners/ts
npm install
npm run verify
```

Or from the repo root:

```bash
npm ci --include=dev && npm test
```

There are two commands and they answer different questions. `npm test` runs the
repository-wide integrity and verification gate at this commit. `npm run verify` is the
generic APS-native corpus verifier alone. External-system families under
`fixtures/cross-stack/` may use dedicated verifiers, documented with the family.

### Families decided by more than one layer

Some families are not decided by a single check. `accountability-record` has
negatives rejected by cryptography (a signature that does not verify, a payload
that does not bind to its digest) and negatives rejected only by JSON Schema (a
`decision` outside the boundary enum, a non-canonical `sig_alg`), whose records
are cryptographically coherent and correctly accepted by the crypto layer.

The layers stay orthogonal (no layer is taught another layer's job), and none
of them emits an overall verdict. Which layers decide a family is declared in
one place, `fixtures/manifest.json`: the required layers, which `rejection_kind`
each layer owns, the concrete error each `expected_error_code` must produce,
and, for a schema layer, the dialect, the pinned validator, the schema path and
the schema's SHA-256. `runners/ts/layered-gate.ts` runs every required layer and
computes the per-vector verdict from their results.

A negative passes only when the layer that owns its `rejection_kind` actually
rejected it with the error it declares. A positive must be accepted by every
required layer. A required layer that produced no result (schema absent,
unparseable, not a valid Draft 2020-12 schema, bytes not matching the pin,
validator not installed) fails every vector in the family rather than skipping
it. `npm run test:layered-gate-mutation` proves this by mutating a copy of the
repository eight ways and asserting `npm test` fails each time, for the stated
reason.

Every JSON Schema under `fixtures/` is inventoried in `fixtures/manifest.json`
with its digest and a statement of what enforces it, compared against the files
on disk in both directions. That makes a schema change explicit; it is not
tamper-proofing, since a change to a schema can update its digest in the same
commit.

The runner ships a vendored RFC 8785 JCS canonicalizer in `runners/ts/canonicalize.ts` so external implementations can run it standalone, with **no dependency on `agent-passport-system` at runtime**. Implementations under test bring their own canonicalizer; this runner verifies the corpus against the reference.

Output: pass/fail per vector + per-category summary. Exit code 0 on full pass, 1 on any failure.

Runners exist for TypeScript (`runners/ts`), Go (`runners/go`) and Python (`runners/python` plus the receipt and AAT runners under `runners/`).

## Repository layout

```
aps-conformance-suite/
├── README.md                          (this file)
├── LICENSE                            (Apache-2.0)
├── package.json
├── tsconfig.json
├── fixtures/
│   ├── manifest.json                  (index of the APS-native fixtures with sha256; cross-stack families are outside it)
│   ├── bilateral-delegation/          (10 vectors)
│   ├── inference-session/             (7 vectors)
│   ├── instruction-provenance/        (10 vectors)
│   └── aivss-scenarios/               (10 scenario files + manifest)
├── runners/
│   ├── ts/                            (TypeScript reference runner)
│   └── python/                        (Python runner)
├── docs/
│   ├── fixture-format.md
│   ├── canonicalization.md
│   └── adding-vectors.md
└── well-known/
    └── aps-test-vectors.json          (canonical reference subset)
```

### Inventory

<!-- BEGIN GENERATED INVENTORY -->
### APS-native corpus

| family | target surface | vectors |
|---|---|---|
| `bilateral-delegation/canonicalize-fixture-v1.json` | JCS canonicalization (RFC 8785) for delegation receipts; bilateral receipt envelope §4 / §6 | 10 |
| `inference-session/inference-session-fixtures.json` | CTEF v0.3.1 cryptographic agent identity; inference-session validity windows + sequence bounds | 7 |
| `instruction-provenance/canonicalize-fixture-v1.json` | InstructionProvenanceReceipt v0.2 §4 envelope, §5 canonicalization, §6 verification | 10 |
| `aivss-scenarios/manifest.json` | AIVSS §3.6 worked scenarios: OWASP Agentic AI Core risks AAI001 to AAI010 | 10 |
| `canonical-bytes/canonical-bytes-diff-v032.json` | String-concatenation preimage failure class. Mirrored from corpollc/qntm#15. Deep verification in runners/ts/canonical-bytes-qntm-v0.3.2.test.ts. | 1 |
| `accountability-record/accountability-record-fixture-v1.json` | Accountability record v0.1: boundary decision (allow/deny/halt) plus execution status; shape derived from decisionReceipt/execution-envelope and action_ref; detached-payload digest; Ed25519 over JCS. Includes tampered-payload and wrong-key negatives. | 12 |
| `read-fidelity-receipt/read-fidelity-receipt-fixture-v1.json` | read_fidelity_receipt v0.1: sampled readback challenge over perceived content; Ed25519 over JCS; seed = sha256(JCS of content_digest, presentation_digest, nonce, version); word_digest_handle checksum. Deep verification in fixtures/read-fidelity-receipt/verify.ts, which decides every vector inside npm test; fixtures/read-fidelity-receipt/validate.py is an independent Python reimplementation run by the schema-parity CI job, not by npm test. Includes replayed-nonce, presentation-mismatch, tampered-digest, out-of-lexicon, and transposition negatives. | 8 |
| `actionref-canonical/actionref-canonical-fixture-v1.json` | Native action_ref scopeRequired canonicalization: NFC + Unicode code-point sort (draft-pidlisnyi-aps-03 section 4.1) | 6 |
| `bilateral-pair/bilateral-pair-fixture-v1.json` | Bilateral pair reconciliation verdicts: one reconciled pair plus one vector per mismatch class | 6 |
| `bilateral-golden/bilateral-golden-fixture-v1.json` | BilateralReceipt canonical signable bytes with aud and action_ref; independently derived and cross-verified (TypeScript reference plus from-scratch Python RFC 8785) | 2 |
| `canonical-bytes/canonical-bytes-jcs-v1.json` | RFC 8785 JCS byte-contract vectors: ECMAScript number formatting (float, 1e21 boundary, negative zero, integer above 2^53, exponent-vs-decimal), UTF-16 key ordering, NFD keys used as given, nested objects. Verified via the runner vendored canonicalizer. | 8 |
| `canonical-bytes/canonical-bytes-jcs-v2.json` | RFC 8785 JCS byte-contract vectors, v2: the eight v1 vectors byte-identical (v1 stays frozen) plus two integer-domain vectors, 2^60 inside signed int64 and 2^68 above it (RFC 8785 section 3.2.2.3 and appendix B). The pair exercises different integer paths in consumers that parse numbers as int64 before serializing. Verified against the TypeScript and Python reference canonicalizers. | 10 |
| `merkle-root-parity/vectors.json` | Attribution Merkle root, domain-separated construction (receipt format v1.2, Day-145 audit): cross-language root byte-parity for TS, Go, Python | 6 |

13 files, 96 vectors.

### External-system families

Artifacts produced by another party, admitted per family. Open the evidence
document for provenance, pins and the verification split.

| path | evidence document |
|---|---|
| `fixtures/cross-stack/aat-amdal` | [`SOURCE.md`](fixtures/cross-stack/aat-amdal/SOURCE.md) |
| `fixtures/cross-stack/action-ref-v1-negatives` | [`SOURCE.md`](fixtures/cross-stack/action-ref-v1-negatives/SOURCE.md) |
| `fixtures/cross-stack/argentum-action-ref-v1v2` | [`SOURCE.md`](fixtures/cross-stack/argentum-action-ref-v1v2/SOURCE.md) |
| `fixtures/cross-stack/nobulex-bilateral-v0` | [`SOURCE.md`](fixtures/cross-stack/nobulex-bilateral-v0/SOURCE.md) |
| `fixtures/cross-stack/oracle-safety-check` | [`SOURCE.md`](fixtures/cross-stack/oracle-safety-check/SOURCE.md) |
| `fixtures/cross-stack/receipts-aeoess` | [`SOURCE.md`](fixtures/cross-stack/receipts-aeoess/SOURCE.md) |
| `fixtures/cross-stack/receipts-amdal` | [`SOURCE.md`](fixtures/cross-stack/receipts-amdal/SOURCE.md) |

### Lab-authored regression fixtures

Generated by this repository, not ingested from an external system. Listed
separately because they are not external-system families and are not admitted
under that rule.

| path | evidence document |
|---|---|
| `fixtures/cross-stack/synthetic` | [`SOURCE.md`](fixtures/cross-stack/synthetic/SOURCE.md) |

### Interop run records

Observations of an implementation at an exact revision. Each record states its
own mode, authorship and pins; open it to read them.

| record | evidence document |
|---|---|
| `interop/a2a-go-368-jcs` | [`RUN.md`](interop/a2a-go-368-jcs/RUN.md) |
| `interop/a2a-go-368-jcs-ea003f9` | [`RUN.md`](interop/a2a-go-368-jcs-ea003f9/RUN.md) |
| `interop/aae-envelope` | [`README.md`](interop/aae-envelope/README.md) |
| `interop/arpa-v0.9.5-1ec3008` | [`RUN.md`](interop/arpa-v0.9.5-1ec3008/RUN.md) |
| `interop/attenu-guard-0.11.0-bundles` | [`SOURCE.md`](interop/attenu-guard-0.11.0-bundles/SOURCE.md) |
| `interop/attenu-guard-0.13.0-envelopes` | [`SOURCE.md`](interop/attenu-guard-0.13.0-envelopes/SOURCE.md) |
| `interop/attenu-guard-0.6.0` | [`SOURCE.md`](interop/attenu-guard-0.6.0/SOURCE.md) |
| `interop/attenu-guard-0.6.1` | [`SOURCE.md`](interop/attenu-guard-0.6.1/SOURCE.md) |
| `interop/attenu-guard-0.8.0` | [`SOURCE.md`](interop/attenu-guard-0.8.0/SOURCE.md) |
| `interop/ca2a-validity-window-d3db81c` | [`RUN.md`](interop/ca2a-validity-window-d3db81c/RUN.md) |
| `interop/cleanroom-oracle-safety-check-6e8b05b2` | [`SOURCE.md`](interop/cleanroom-oracle-safety-check-6e8b05b2/SOURCE.md) |
| `interop/ethers-oracle-safety-check-6e8b05b2` | [`SOURCE.md`](interop/ethers-oracle-safety-check-6e8b05b2/SOURCE.md) |
| `interop/ethers-oracle-safety-check-9b4ffee` | [`run-report.md`](interop/ethers-oracle-safety-check-9b4ffee/run-report.md) |
| `interop/hjs-bb6be62` | [`SOURCE.md`](interop/hjs-bb6be62/SOURCE.md) |
| `interop/insight-oracle-safety-check-13bd3ed` | [`run-report.md`](interop/insight-oracle-safety-check-13bd3ed/run-report.md) |
| `interop/mih-sato-composition-00` | [`README.md`](interop/mih-sato-composition-00/README.md) |
| `interop/remora-edd8a4e` | [`SOURCE.md`](interop/remora-edd8a4e/SOURCE.md) |
| `interop/scitt-cose-vectors-ietf126` | [`README.md`](interop/scitt-cose-vectors-ietf126/README.md) |
| `interop/x402-receipts-debc94f` | [`RUN.md`](interop/x402-receipts-debc94f/RUN.md) |

Generated by `scripts/readme-inventory.mjs`. Do not edit between the markers.
<!-- END GENERATED INVENTORY -->

## Cross-validation triangle (CTEF v0.3.2 §A-aligned)

Three independent implementations (ArkForge / APS / AgentGraph) anchor the cross-validation triangle. CTEF v0.3.2 §A names two reader-runnable verifier scripts (`verify-aps-byte-match.mjs` and `verify-ctef-byte-match.mjs`) as the canonical reproduction references, mirrored byte-exact in this repo's [`cross-impl-receipts/`](./cross-impl-receipts/) with daily-poll synchronization. Any third party resolving any one of the three repos arrives at byte-identical canonical envelopes. The conformance bar is reproducibility-without-maintainer-rerun, not the count of byte-matches.

| Implementation | Repo | Fixture path / harness URL | Verifier |
|---|---|---|---|
| **APS** | [`Agent-Authority-Conformance/aps-conformance-suite`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite) | `cross-impl-receipts/` (this repo) + `fixtures/bilateral-delegation/canonicalize-fixture-v1.json` (upstream) | `runners/ts/verify.ts` (this repo) + Nobulex `scripts/verify-aps-byte-match.mjs` mirrored byte-exact at [`cross-impl-receipts/`](./cross-impl-receipts/) |
| **ArkForge** | [`corpollc/qntm`](https://github.com/corpollc/qntm) | `specs/test-vectors/` + production-derived `canonical-bytes-diff-v032.json` (qntm#15) | TODO, finalize when CTEF v0.3.2 §A draft names ArkForge's verifier code path |
| **AgentGraph** | [`agentgraph-co/agentgraph`](https://github.com/agentgraph-co/agentgraph) (frozen at `69ad94d`) | [`https://agentgraph.co/.well-known/interop-harness.json`](https://agentgraph.co/.well-known/interop-harness.json) `cross_validation_receipts` block | Nobulex `scripts/verify-ctef-byte-match.mjs` against CTEF v0.3.1 inline vectors (4/4 incl. negative-path `INVALID_CLAIM_SCOPE` + `INVALID_COMPOSITION`), named normatively in CTEF v0.3.2 §A draft as one of the two reader-runnable verifier scripts |

### Three SHA-256 commitments

The byte-faithful mirrored receipts in [`cross-impl-receipts/`](./cross-impl-receipts/) carry the following SHA-256 hashes (frozen at `arian-gogani/nobulex@d68fcee`, fetched 2026-05-02T00:18:49Z):

| File | SHA-256 |
|---|---|
| `cross-impl-receipts/aps-byte-match-receipt.json`  | `a4d63359574a7408cac8dd3c132586cff611535c4c8f074ed3556a61cf165443` |
| `cross-impl-receipts/ctef-byte-match-receipt.json` | `2e8afc85080ed64fe539c913410f2343d10cba8c5b17f61cc8a7d19e4fa11216` |
| `cross-impl-receipts/ctef-vectors.json`            | `b655d1b3e7aeccb8b75517c1efc46d2dbf6759dea07581a1b39d4ab59baa7046` |

### Reciprocal pointer: AgentGraph harness aggregator

The same three SHA-256s are surfaced by AgentGraph at [`https://agentgraph.co/.well-known/interop-harness.json`](https://agentgraph.co/.well-known/interop-harness.json) under the `cross_validation_receipts.receipt_sources.mirror.files_pinned_2026_05_02` block, with `source_commit` pinned to `arian-gogani/nobulex@d68fcee`. Reviewers can pull receipt artifacts from either [`arian-gogani/nobulex`](https://github.com/arian-gogani/nobulex) (originating) or this mirror and reproduce the byte-match independently, so the maintainer-rerun-dependency gap is closed.

### Cross-stack corpora (`fixtures/cross-stack/`)

- [`action-ref-v1-negatives/`](./fixtures/cross-stack/action-ref-v1-negatives/): recomputation-property vectors for `action-ref-v1` (field-order, timestamp-form, casing, and payload drift), mirrored from the fixture set contributed upstream to `giskard09/argentum-core` (PR #12). Five positives double-derived, nine negatives with real drifted-form digests.
- [`aat-amdal/`](./fixtures/cross-stack/aat-amdal/): weekly AgentLair AAT pairs (one live-window, one pre-expired) verified against the issuer JWKS, beginning 2026-06-17. Boundary semantics for the two layers are documented at [agent-passport.org/aat-aps-boundary.html](https://agent-passport.org/aat-aps-boundary.html). Vectors carry `verification_time`; runners evaluate windows against that instant so the corpus stays replayable.
- [`oracle-safety-check/`](./fixtures/cross-stack/oracle-safety-check/): `insight.oracle-safety-check:v2` evidence inside ReceiptV1 (draft-pidlisnyi-aps §5.5) — EIP-712 26-field attestation with four ABI-keccak commitments and an inner-layer secp256k1 signature, fail-closed composite gate. Generated by the upstream generator (`agent-passport-system` #119); consumed with the **published** SDK package. Coverage is enumerated in the family README: `verify.ts` (13/13) enforces `expected` (`allowed | halt`), `expectReasons`, `verdict`, `revocation`, `oracle_input` and each vector's `expected_sub_results`, and `verify-consistency.ts` (56/56) is a same-implementation comparison.


### Forward pointer

CTEF v0.3.2 §A "Conformance Appendix" was drafted by [@kenneives](https://github.com/kenneives) on 2026-05-04 in [A2A#1786 comment](https://github.com/a2aproject/A2A/issues/1786#issuecomment-4373904351). The §A normative text adopts:

> Implementations claiming CTEF v0.3.2 conformance MUST demonstrate byte-match reproduction against the inline-vector set. Two reader-runnable verifier scripts are published under stable URLs as the canonical reproduction reference: `scripts/verify-aps-byte-match.mjs` (10/10 against the APS bilateral-delegation fixture) and `scripts/verify-ctef-byte-match.mjs` (4/4 against the CTEF inline vectors INCLUDING both negative-path vectors). The two scripts are maintained at `arian-gogani/nobulex` (originating verifier) and mirrored byte-exact at `Agent-Authority-Conformance/aps-conformance-suite/cross-impl-receipts/` with daily-poll synchronization. The harness aggregator at `https://agentgraph.co/.well-known/interop-harness.json` `cross_validation_receipts` block surfaces both source URLs with SHA-256 pins of the receipt artifacts. Reviewers verifying conformance MUST be able to reproduce byte-match without contacting the implementation maintainer.

Target publish for the v0.3.2 spec (which will normative-cite this section): mid-May 2026, post-launch. The ArkForge row TODO will firm up if the v0.3.2 spec text or a follow-up §A revision normatively enumerates an ArkForge-specific verifier code path; until then ArkForge's role is captured in the May 4 18:41 components plan ("cross-validated against APS depth-walker code path") rather than in the §A normative draft itself.

---

## Adoption

This suite is the **reference test corpus for the Agent Passport System protocol**. External implementations of APS-compatible delegation chains, decision receipts, instruction-provenance receipts, and adversarial scenarios are encouraged to validate against these fixtures.

Cross-implementation byte-parity is the contract: an implementation passes when every fixture vector's recomputed `canonical_bytes_hex` and `canonical_sha256` match the published values, and every Ed25519 signature verifies against the deterministic keypair.

## Adding new vectors

See `docs/adding-vectors.md`. Vectors are added upstream first, then copied here.

## Citation

This suite is the conformance reference for the protocol described in:

- *The Agent Social Contract*: https://doi.org/10.5281/zenodo.18749779
- *Monotonic Narrowing*: https://doi.org/10.5281/zenodo.18932404
- *Faceted Authority Attenuation*: https://doi.org/10.5281/zenodo.19260073
- *Behavioral Derivation Rights*: https://doi.org/10.5281/zenodo.19476002
- *Physics-Enforced Delegation*: https://doi.org/10.5281/zenodo.19478584
- *Governance in the Medium*: https://doi.org/10.5281/zenodo.19582550
- *Cognitive Attestation*: https://doi.org/10.5281/zenodo.19646276
- *The Evidence-Safety Gap*: https://doi.org/10.5281/zenodo.19914628
- IETF Internet-Draft: `draft-pidlisnyi-aps-03`

AIVSS scenario fixtures cite: *AIVSS Scoring System For OWASP Agentic AI Core Security Risks v0.8* (OWASP, accessed 2026-04-26).

## Related

- **Agent Passport System SDK**: https://github.com/aeoess/agent-passport-system
- **Agent Governance Vocabulary**: https://github.com/aeoess/agent-governance-vocabulary
- **Agent Passport System org**: https://agent-passport.org
- **InstructionProvenanceReceipt v0.2 spec**: `agent-passport-system/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md`

Verify bundles in the browser at https://agent-passport.org/verify.html

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi.
