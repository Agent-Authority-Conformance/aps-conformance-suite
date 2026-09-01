# mcp-audit-gateway-v0.6: external-system vector family

Two vector files from `elang2/mcp-audit-gateway` v0.6.0, mirrored here at commit `a0f14a0418c2abe6135436f037f6b171735d1e73`. Contributed following the invitation on [docker/mcp-gateway#557 (issuecomment-5388392662)](https://github.com/docker/mcp-gateway/issues/557#issuecomment-5388392662) and after the naming, layering, and directory-shape decisions in [aps-conformance-suite#52 (issuecomment-5482476173)](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/52#issuecomment-5482476173).

## Contents

The family carries two concerns, each in its own subdirectory beneath the family root. `canonicalization/` holds the tuple-array canonical form for signed audit records and the vector sets that exercise it across scenarios (record-level canonicalization, three-record chain hash relations, the dual-hash demonstration showing why attestation-included and attestation-excluded digests differ, party-attribution and scope-order-significance vectors, ai-invocation signing, and the extensionsDigest base suite). The tuple-array form is deliberately not RFC 8785 JCS; the reason is spelled out at [test/vectors/SDK-AUDIT.md at v0.6.0](https://github.com/elang2/mcp-audit-gateway/blob/v0.6.0/test/vectors/SDK-AUDIT.md), which documents 26 wire-level serialization divergences across the ten official MCP SDKs.

`checkpoint/` holds the vectors that exercise checkpoint chain integrity: record-level canonicalization for checkpoint records, three-record chain hash relations, log rotation continuity, chain_break successor semantics, sequence-regression detection for rotation laundering, and truncation-detection scenarios. The same file also carries an inline `canonicalize_value` block (nested-value canonicalization with M/L type tags, UTF-16 key sort, lone-surrogate reject, float reject) and an `extensions_digest` block (per-record `extensionsDigest` field, canonical form with and without the field), which the runner exercises alongside the checkpoint-specific sections. Following aeoess's taxonomy on aps-conformance-suite#52, the suite-level failure class `chain_continuity_violation` covers the three source-native failure codes `head_missing`, `count_mismatch`, and `sequence_regression`. Two of the three are exercised by executable vectors in this file. `count_mismatch` is documented but not executable; see Boundaries. A `chain_break` record is a source-native record type in this design, not a failure mode. It is a valid chain start whose successor chains from the break record's own hash, converting a gap in evidence into signed evidence of a gap.

## Recompute without a checkout of mcp-audit-gateway

Each concern subdirectory ships a `run.mjs` adapted from mcp-audit-gateway's own `test/vectors/verify.mjs` at v0.6.0. The adapter inlines the canonicalization logic and uses only Node's stdlib (`node:crypto`, `node:fs`), so no `npm install` is needed to reproduce and the runner has no runtime dependency on the source package. Every recompute here is Mode A per CONTRIBUTING.md: reproduction of the documented verifier, transplanted, not an alternate implementation.

```bash
cd fixtures/cross-stack/mcp-audit-gateway-v0.6
node canonicalization/run.mjs
node checkpoint/run.mjs
```

Stdlib-only, no network, no third-party packages. Tested against Node 20 LTS.

## Verbatim recompute run

Cold run against `node:20-alpine` on 2026-08-31, `docker run --rm -v $PWD:/w -w /w node:20-alpine node <concern>/run.mjs` from the family root.

```
$ node canonicalization/run.mjs
Format version: 1.1.0
Encoding: utf-8
Hash: sha256 (hex-lowercase)

=== Canonicalization Vectors ===

  PASS: canonicalization/genesis_all_fields
  PASS: canonicalization/genesis_null_optionals
  PASS: canonicalization/error_with_code
  PASS: canonicalization/zero_duration
  PASS: canonicalization/invalid_params_error
  PASS: canonicalization/unicode_in_fields
  PASS: canonicalization/max_safe_integer_duration
  PASS: canonicalization/empty_string_tool_name

=== Chain Vectors ===

  PASS: chain[0]/canonical (search)
  PASS: chain[0]/record_hash (search)
  PASS: chain[0]/native_stringify_match (search)
  PASS: chain[0]/linkage (search)
  PASS: chain[1]/canonical (summarize)
  PASS: chain[1]/record_hash (summarize)
  PASS: chain[1]/native_stringify_match (summarize)
  PASS: chain[1]/linkage (summarize)
  PASS: chain[2]/canonical (store_result)
  PASS: chain[2]/record_hash (store_result)
  PASS: chain[2]/native_stringify_match (store_result)
  PASS: chain[2]/linkage (store_result)

=== Dual-Hash Demonstration ===

  PASS: dual_hash/canonical_hashes_match (attestation excluded)
  PASS: dual_hash/chain_hashes_differ (attestation included)
  PASS: dual_hash/assertions.canonical_hashes_match
  PASS: dual_hash/assertions.chain_hashes_differ

=== Party Attribution Vectors ===

  PASS: party_attribution/parties_gateway_only
  PASS: party_attribution/parties_dual_attribution
  PASS: party_attribution/no_parties_backward_compat
  PASS: party_attribution/parties_empty_array
  PASS: party_attribution/scope_order_original
  PASS: party_attribution/scope_order_sorted

=== Chain with Parties ===

  PASS: chain_with_parties[0]/canonical (fetch_data)
  PASS: chain_with_parties[0]/record_hash (fetch_data)
  PASS: chain_with_parties[0]/linkage (fetch_data)
  PASS: chain_with_parties[1]/canonical (transform_data)
  PASS: chain_with_parties[1]/record_hash (transform_data)
  PASS: chain_with_parties[1]/linkage (transform_data)

=== Scope Order Significance ===

  PASS: scope_order/different_order_different_hash

=== aiInvocation Signing ===

  PASS: ai_invocation_signing/ai_invocation_full/canonical
  PASS: ai_invocation_signing/ai_invocation_full/digest
  PASS: ai_invocation_signing/ai_invocation_partial_turnid_only/canonical
  PASS: ai_invocation_signing/ai_invocation_partial_turnid_only/digest
  PASS: ai_invocation_signing/ai_invocation_with_all_optionals/canonical
  PASS: ai_invocation_signing/ai_invocation_with_all_optionals/digest
  PASS: ai_invocation_signing/mutation_pair_digests_reproduce
  PASS: ai_invocation_signing/mutation_changes_digest

=== extensionsDigest (base suite) ===

  PASS: extensions_digest_base/extensions_digest_with_parties/canonical
  PASS: extensions_digest_base/extensions_digest_with_parties/digest

=== Results: 47 passed, 0 failed ===

$ node checkpoint/run.mjs

=== Checkpoint Canonicalization ===
  PASS: checkpoint_canonicalization/checkpoint_basic/canonical
  PASS: checkpoint_canonicalization/checkpoint_basic/sha256
  PASS: checkpoint_canonicalization/checkpoint_with_parties/canonical
  PASS: checkpoint_canonicalization/checkpoint_with_parties/sha256

=== Checkpoint Chain ===
  PASS: checkpoint_chain/record[0]/hash
  PASS: checkpoint_chain/record[1]/hash
  PASS: checkpoint_chain/record[1]/previousHash_links_to_record[0]
  PASS: checkpoint_chain/record[2]/hash
  PASS: checkpoint_chain/record[2]/previousHash_links_to_record[1]

=== Truncation Detection ===
  PASS: truncation_detection/full_chain_contains_externalized_checkpoint
  PASS: truncation_detection/truncated_chain_missing_checkpoint (head_missing detected)

=== canonicalizeValue ===
  PASS: canonicalize_value/nested_same_content_different_order/canonical_form
  PASS: canonicalize_value/nested_same_content_different_order/digest
  PASS: canonicalize_value/nested_same_content_different_order/both_inputs_same_digest
  PASS: canonicalize_value/array_order_matters/canonical_a
  PASS: canonicalize_value/array_order_matters/digest_a
  PASS: canonicalize_value/array_order_matters/canonical_b
  PASS: canonicalize_value/array_order_matters/digest_b
  PASS: canonicalize_value/array_order_matters/digests_differ
  PASS: canonicalize_value/unicode_keys_sorted/canonical_form
  PASS: canonicalize_value/unicode_keys_sorted/digest
  PASS: canonicalize_value/astral_plane_keys_utf16_order/canonical_form
  PASS: canonicalize_value/astral_plane_keys_utf16_order/digest
  PASS: canonicalize_value/lone_surrogate_throws/throws_on_invalid_input
  PASS: canonicalize_value/float_throws/throws_on_invalid_input

=== Extensions Digest ===
  PASS: extensions_digest/simple_integer_map/canonical_form
  PASS: extensions_digest/simple_integer_map/digest
  PASS: extensions_digest/empty_extension_map/canonical_form
  PASS: extensions_digest/empty_extension_map/digest
  PASS: extensions_digest/nested_recursive_sort/canonical_form
  PASS: extensions_digest/nested_recursive_sort/digest
  PASS: extensions_digest/float_as_string/canonical_form
  PASS: extensions_digest/float_as_string/digest
  PASS: extensions_digest/record_with_extensionsDigest/canonical
  PASS: extensions_digest/record_with_extensionsDigest/sha256
  PASS: extensions_digest/record_without_extensionsDigest/canonical (backward_compat)
  PASS: extensions_digest/record_without_extensionsDigest/sha256

=== Rotation Boundary ===
  PASS: rotation_boundary/file1/record[0]/hash
  PASS: rotation_boundary/file1/record[1]/hash
  PASS: rotation_boundary/file2_first_chains_to_file1_last_hash
  PASS: rotation_boundary/file2/record[0]/hash

=== Sequence Regression ===
  PASS: sequence_regression/detected_in_chain
  PASS: sequence_regression/failure_code_is_sequence_regression

=== Chain Break ===
  PASS: chain_break/record[0]/hash
  PASS: chain_break/record[1]/hash
  PASS: chain_break/successor_chains_from_break_record_hash

=== Results: 46 passed, 0 failed (46 total) ===
```

93 checks total across the two runners, 0 failures. Machine-readable per-check outcomes land in `canonicalization/results.json` and `checkpoint/results.json`.

## Verification split

One entry per verification claim: layer / claim; runner; Mode A | Mode B; author-produced | independent; implementation.

- canonicalization/ tuple-array canonical form for signed audit records, 8 record-level vectors (`genesis_all_fields`, `genesis_null_optionals`, `error_with_code`, `zero_duration`, `invalid_params_error`, `unicode_in_fields`, `max_safe_integer_duration`, `empty_string_tool_name`) exercising field order, null rule, error paths, unicode handling, boundary durations, and the empty-tool-name case (`canonicalization` block); elang2; Mode A; author-produced (author of the vectors and of `mcp-audit-gateway`); `canonicalization/run.mjs` at commit a0f14a0…, 8/8
- canonicalization/ three-record chain with previousHash linkage, per-record canonical form, per-record record_hash, and native-JSON.stringify-matches-reference at each record (`chain` block); elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 12/12
- canonicalization/ dual-hash demonstration, attestation-excluded canonical hashes match while attestation-included chain hashes differ, with the two assertion flags in the vector file (`dual_hash_demo` block); elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 4/4
- canonicalization/ party-attribution vectors, 6 sub-vectors covering gateway-only, dual-attribution, no-parties backward-compat, empty array, scope-order original, and scope-order sorted (`party_attribution.vectors` block); elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 6/6
- canonicalization/ chain with parties, 2 records × 3 checks each covering canonical form, record_hash, and linkage (`party_attribution.chain_with_parties` block); elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 6/6
- canonicalization/ scope-order significance, different scope order produces a different digest for the same otherwise-identical record; elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 1/1
- canonicalization/ ai-invocation signing, 3 sub-vectors (full, partial-turnid-only, all-optionals) × 2 checks each plus mutation-pair reproduction and mutation-changes-digest (`ai_invocation_signing` block); elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 8/8
- canonicalization/ extensionsDigest base suite, 1 record-level vector covering `extensions_digest_with_parties` (`extensions_digest_base` block); elang2; Mode A; author-produced (author of the vectors and of the canonicalization implementation under test); same runner, 2/2
- checkpoint/ checkpoint record canonical form, 2 sub-vectors (basic, with-parties) × 2 checks each for canonical form and sha256 (`checkpoint_canonicalization` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); `checkpoint/run.mjs` at commit a0f14a0…, 4/4
- checkpoint/ three-record checkpoint chain with the checkpoint in the middle, per-record hash and previousHash linkage across the sequence (`checkpoint_chain` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 5/5
- checkpoint/ truncation-detection scenario for `head_missing`, asserts the fixture's full chain contains the externalized checkpoint and its truncated chain is missing that checkpoint with no descendant checkpoint present (`truncation_detection` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 2/2
- checkpoint/ injective type-tagged nested-value canonicalization (M/L tags, UTF-16 key sort, lone-surrogate reject, float reject), 6 sub-vectors covering nested-same-content-different-order, array-order-matters, unicode-keys-sorted, astral-plane-keys, lone-surrogate-throws, float-throws (`canonicalize_value` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 14/14
- checkpoint/ extensionsDigest across 4 nested-value sub-vectors plus record-level canonicalization with and without an `extensionsDigest` field (`extensions_digest` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 12/12
- checkpoint/ rotation-boundary chain continuity, `lastHash` vs `rotationBoundaryHash` split, file-2 first record chains to file-1 last hash across a log rotation (`rotation_boundary` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 4/4
- checkpoint/ sequence-regression detection, non-monotonic checkpoint sequence numbers indicating rotation laundering with `failureCode: sequence_regression` (`sequence_regression` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 2/2
- checkpoint/ chain_break record semantics, per-record hash on 2 records plus the invariant that the successor chains from the break-record's hash rather than genesis (`chain_break` block); elang2; Mode A; author-produced (author of the vectors and of the checkpoint implementation under test); same runner, 3/3

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Boundaries

Recomputation agreement only. Passing every vector in this family establishes that a verifier agrees with mcp-audit-gateway v0.6.0 on the byte-level canonical form, the hash-chain relations, and the completeness outcomes for the three failure codes above. It does not establish that any policy was applied, that any external checkpoint was actually externalized to a consumer, or that any operator ever anchored a chain head to an external transparency log.

The `checkpoint_field_order`, `conditional_fields`, `design_notes`, and `verification_modes` blocks inside `checkpoint.json` describe the format's design intent (strict versus relative verification semantics for `verification_modes`, field ordering rules for the others) and are not themselves recomputable claims. They are documentation, not vectors, and the runner does not exercise them.

No signatures in this family. The tuple-array form is the pre-signing canonical payload, not the attestation itself. Ed25519 and HMAC-SHA256 signature verification are tested inside `elang2/mcp-audit-gateway` at `src/attestation/signer.test.ts` and are out of scope here.

`count_mismatch` is one of the three failure codes under the `chain_continuity_violation` class, but it does not have an executable vector in this file. The code is described in the `failure_codes` block (line 446) and illustrated inside `verification_modes.adjacent_delta_check` (line 432), so reviewers scanning for a `count_mismatch/` sub-vector or a raw `failureCode: "count_mismatch"` value will not find one. Only `head_missing` (line 147) and `sequence_regression` (lines 340 and 386) appear as executable `failureCode` values.

The `ran_at` timestamp inside each `results.json` is frozen at the recompute that produced this commit. A reviewer re-running the runner will see a different `ran_at` in the emitted file, and that difference alone is not a follow-up commit unless the per-check pass/fail outcomes change.

Per the lab charter, this submission does not ask to be listed, endorsed, or described as APS-validated. It is a record offered for independent verification, as CONTRIBUTING.md requires for an external-system vector family.
