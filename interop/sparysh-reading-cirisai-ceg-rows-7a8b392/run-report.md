# Run report: cirisai-ceg-rows, Mode B

**Who ran it:** Andrii Sparysh (GitHub `andreysparish`), using an AI assistant.

**Date:** 2026-11-25.

**Run mode:** B, alternate recomputation.

**Implementation name, and its repository and version:** the reader in `reader/`, written by the runner for this run; not published in a repository. Identified by the SHA-256 of each source file:
- `reader/cbor_strict.py` `9ca3dbfce8067c317d06bec33fe7df21268550b19b74212b7846294fa2876717`;
- `reader/ceg_reader_pass2.py` (blind) `f17a26ee04f5157e3be23e9d0d1172837103466bad909cf870aca756829be4ef`;
- `reader/ceg_reader_pass3.py` (after the comparison) `26adbc7ca2dfd8357458cb7743605778eb394ceb01ff9b20fedaa19949277ddf`;
- `reader/compare.py` `252e538d275dba250487fd55ee441f52256c6b9cade488ff2315d483b4ba8f8b`.

**Corpus reference:** `aps-conformance-suite` at `7a8b3927e715a92cec447f3ceba84b45d6ac535d` (PR #246), candidate `cirisai-ceg-rows`, as submitted.

**Environment:** Python 3.13.18 (CPython), pyca/cryptography 50.0.2 with OpenSSL 4.0.3; Linux 6.18.44, x86_64.

**Author-produced or independent:** per claim; see "Labels per claim". The runner wrote the reader that decides every answer. The signature primitives are third-party: neither the runner nor the candidate's author wrote them. The runner authored none of the candidate, its vectors, CIRISVerify or the draft. The blind answers were frozen before `expected.json` was opened.

**Suspected defective vectors:** none. Data observations, each a difference between the draft's text and the vectors, not a claim that a vector is wrong:
- unknown_row_type expects a verification refusal for a check that Section 3 and Table 4 place at admission (F01).
- Four expected strings are not in the draft's "complete list" of reasons: `key_record_bad_identity_type`, `key_record_bad_pq_custody`, `waiting:record:` and `waiting:covering_record:` (F07).
- Eleven statement and payload cases need facts of [CC] that the draft does not give (F08). The candidate says this of the `family` level only.
- row_ref_not_a_digest answers `neither` for the value Section 5.3 calls a reference (F09).

## Labels per claim

| claim (CANDIDATE.md) | cases | mode | label | implementation |
|---|---|---|---|---|
| The composite signature verifies, or does not (Section 6.1) | the 2 `bad_signature` cases, and the signature of every statement answered Valid | B | independent for ML-DSA-65 and Ed25519 (pyca/cryptography); author-produced for M' and the Sig_structure | `reader/ceg_reader_pass2.py` (`sig_ok`) |
| The public keys of `inputs/keys.json` come from their seeds | 6 keys | B | independent for key generation (pyca/cryptography); author-produced for the RFC 9679 thumbprint | `reader/ceg_reader_pass2.py` (`key_from_seed`, `thumb`) |
| The row id, statement id, object id, kid and iss of a valid statement (Sections 5, 7.1) | 14 statements, 1 object | B | author-produced | `reader/ceg_reader_pass2.py` |
| Each malformed, mis-encoded or mis-signed statement has its reason (Section 8) | the `statement` and `object` levels | B | author-produced | `reader/ceg_reader_pass2.py`, `reader/cbor_strict.py` |
| The signing key is a key of iss (Section 6.2) | the `statement` cases with key records or a directory | B | author-produced | `reader/ceg_reader_pass2.py` |
| A key record meets its end rule (Section 6.2) | 17 `payload` cases | B | author-produced | `reader/ceg_reader_pass2.py` |
| The form of a reference and its digest | 11 `value` cases | B | author-produced | `reader/ceg_reader_pass2.py` |
| The row id known answer of Appendix B.1 | the draft's own example | B | author-produced | `reader/b1_check.py` |
| The `family` level | 47 cases | not run | — | — |

The ambiguity log, the classification of differences and the findings are this run's own analysis, not claims of the candidate.

## Tallies

| level | cases | match, blind (pass 2) | match, pass 3 | not matched, blind |
|---|---|---|---|---|
| statement | 73 | 43 | 43 | 30 |
| payload | 17 | 12 | 12 | 5 |
| value | 11 | 8 | 8 | 3 |
| object | 6 | 5 | 6 | 1 |
| family | 47 | not run | not run | — |
| **read** | **107** | **68** | **69** | **39** |

By expected answer, statement and object levels, blind:
- Valid: 15 expected, 14 match.
- Invalid: 56 expected; 30 match exactly, and 17 more are refused under another reason.
- Waiting: 8 expected; 4 match exactly, and 3 more are Waiting with something else named as missing (F04).

Every valid answer that matches also matches on each value `expected.json` gives for it.

## Per-case table

"Result" is the blind comparison. "After pass 3" is filled only where pass 3 changed the answer. "Category" and "finding" are from `out/classification.json`. Digests are cut to 12 characters.

| case | source id | level | expected | this run, blind (pass 2) | result | after pass 3 | category | finding |
|---|---|---|---|---|---|---|---|---|
| `c-c61053e0b115` | object_unknown_typ | object | `invalid:malformed:typ` | `invalid:malformed:typ` | match |  |  |  |
| `c-8463a46c5c80` | object_with_cty | object | `invalid:unexpected:protected` | `invalid:unexpected:protected` | match |  |  |  |
| `c-9b4f9f26b4cc` | object_with_family | object | `invalid:unexpected:protected` | `invalid:unexpected:protected` | match |  |  |  |
| `c-6132f8215005` | object_with_row_type | object | `invalid:unexpected:protected` | `invalid:unexpected:protected` | match |  |  |  |
| `c-e362eaa87b67` | revocation_snapshot_header | object | `valid` | `valid` | match |  |  |  |
| `c-48de6f8518f1` | row_typ_as_object | object | `invalid:malformed:typ` | `invalid:malformed:cty` | same answer, other reason | `invalid:malformed:typ` | omission |  |
| `c-c703dc340a1f` | accord_holder_with_end | payload | `key_record_out_of_window` | `key_record_out_of_window` | match |  |  |  |
| `c-897c29f78ddd` | agent_without_end | payload | `key_record_out_of_window` | `key_record_out_of_window` | match |  |  |  |
| `c-8e233744eff5` | attestation_evidence_not_map | payload | `key_record_bad_pq_custody` | `ok` | diverge | `malformed:attestation_evidence` | omission | F07 |
| `c-58e47c6eb5fc` | mixed_user_node | payload | `key_record_mixed_roles` | `key_record_mixed_roles` | match |  |  |  |
| `c-19c274e6ad6b` | node_at_asserted | payload | `ok` | `ok` | match |  |  |  |
| `c-9d0656481226` | node_at_bound | payload | `ok` | `ok` | match |  |  |  |
| `c-f86175a4f133` | node_before_asserted | payload | `key_record_out_of_window` | `key_record_out_of_window` | match |  |  |  |
| `c-2b958707565b` | node_one_ms_over | payload | `key_record_out_of_window` | `ok` | diverge |  | not_in_draft | F08 |
| `c-2e1b43e00f55` | node_one_second_over | payload | `key_record_out_of_window` | `ok` | diverge |  | not_in_draft | F08 |
| `c-1a10f371fa8a` | pq_custody_missing | payload | `ok` | `ok` | match |  |  |  |
| `c-9688405b1b4d` | pq_custody_removable_offline | payload | `ok` | `ok` | match |  |  |  |
| `c-a2207994da64` | pq_custody_unknown | payload | `key_record_bad_pq_custody` | `ok` | diverge | `malformed:attestation_evidence` | omission | F07 |
| `c-1ac663701449` | pseudonym_with_end | payload | `ok` | `ok` | match |  |  |  |
| `c-98f295fffa8c` | roles_unsorted | payload | `key_record_bad_identity_type` | `malformed:identity_type` | same answer, other reason |  | naming | F07 |
| `c-6598a610e39a` | steward_no_end_rule | payload | `ok` | `ok` | match |  |  |  |
| `c-e39af313e474` | user_with_end | payload | `key_record_out_of_window` | `key_record_out_of_window` | match |  |  |  |
| `c-d2275122d150` | user_without_end | payload | `ok` | `ok` | match |  |  |  |
| `c-69ca4e0ce09e` | a_as_a_raw | statement | `valid` | `valid` | match |  |  |  |
| `c-f543da184bb3` | a_as_a_records | statement | `valid` | `valid` | match |  |  |  |
| `c-a37031749c85` | a_iss_b_raw | statement | `invalid:kid_not_of_iss` | `waiting:key-record-of:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463@urn:ietf:params:oauth:ckt:sha-256:TjkwzcxCJYXe8Of_OiKEuHShc9mC2cS0IwRkf5PZnyM` | diverge |  | reading | F04 |
| `c-63f847167c76` | a_iss_b_records | statement | `invalid:kid_not_of_iss` | `invalid:kid_not_of_iss` | match |  |  |  |
| `c-909c00272f2f` | a_not_held_raw | statement | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | match |  |  |  |
| `c-15f3d86f2ade` | a_not_held_records | statement | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | match |  |  |  |
| `c-fe02f57a9d3e` | after_valid_until | statement | `waiting:covering_record:4e3930cdcc422585def0e7ff3a2284b874a173d982d9c4b42304647f93d99f23:1763200001001` | `valid` | diverge |  | not_in_draft | F06 |
| `c-64855174d1d9` | also_unknown_role | statement | `invalid:unexpected:also` | `invalid:unexpected:also` | match |  |  |  |
| `c-2e5d93ca0e7d` | authored_score | statement | `valid` | `valid` | match |  |  |  |
| `c-ad900e0395af` | b_as_b_raw | statement | `valid` | `valid` | match |  |  |  |
| `c-93644e7648f9` | b_as_b_records | statement | `valid` | `valid` | match |  |  |  |
| `c-f6cb3136a273` | bad_signature | statement | `invalid:bad_signature` | `invalid:bad_signature` | match |  |  |  |
| `c-b9b8d14b5ff9` | confidence_negative | statement | `invalid:malformed:confidence` | `invalid:malformed:confidence` | match |  |  |  |
| `c-2236534a442a` | counted_with_refs | statement | `valid` | `valid` | match |  |  |  |
| `c-1c0c7f363cac` | cty_with_parameters | statement | `invalid:malformed:cty` | `invalid:malformed:cty` | match |  |  |  |
| `c-eb5aea86598e` | deep_waiting | statement | `waiting:kid:3b1adf0d6418248db5214e17379d85b8debc51b89a2e55ae0e46792f50d7e10f` | `waiting:kid:3b1adf0d6418248db5214e17379d85b8debc51b89a2e55ae0e46792f50d7e10f` | match |  |  |  |
| `c-48cefe1b9571` | digest_repeated | statement | `invalid:duplicate_digest` | `invalid:set_order:list` | same answer, other reason |  | not_in_draft | F08 |
| `c-8f18ebdef3db` | dimension_less_specific_header | statement | `invalid:dimension_family` | `valid` | diverge |  | not_in_draft | F08 |
| `c-f9e3af56a15e` | dimension_open_vocabulary | statement | `invalid:dimension_unregistered` | `invalid:dimension_family` | same answer, other reason |  | not_in_draft | F08 |
| `c-830683e0e32f` | dimension_other_family | statement | `invalid:dimension_family` | `invalid:dimension_family` | match |  |  |  |
| `c-a3428bcd497d` | dimension_refused_by_matcher | statement | `invalid:dimension_refused:namespace_vocab_value_unregistered` | `valid` | diverge |  | not_in_draft | F08 |
| `c-d39de2b15dbe` | disclosed | statement | `valid` | `invalid:set_order:list` | diverge |  | not_in_draft | F08 |
| `c-2e7b9ee8a2e9` | disclosure_key_present | statement | `invalid:disclosure_unmatched` | `invalid:set_order:list` | same answer, other reason |  | not_in_draft | F08 |
| `c-a5a0c5f996bd` | disclosure_short_salt | statement | `invalid:malformed:sd-disclosure` | `valid` | diverge | `invalid:malformed:sd_claims` | omission |  |
| `c-62a126edf4dc` | disclosure_twice | statement | `invalid:disclosure_unmatched` | `invalid:set_order:list` | same answer, other reason |  | not_in_draft | F08 |
| `c-10e6c7928482` | disclosure_unmatched | statement | `invalid:disclosure_unmatched` | `invalid:set_order:list` | same answer, other reason |  | not_in_draft | F08 |
| `c-66518ba8e00f` | edition_1 | statement | `invalid:malformed:edition` | `invalid:malformed:edition` | match |  |  |  |
| `c-3c5225fa93e4` | exp_missing | statement | `invalid:time:exp` | `invalid:time:exp` | match |  |  |  |
| `c-8fa5ce4804eb` | extra_protected_member | statement | `invalid:unexpected:protected` | `invalid:unexpected:protected` | match |  |  |  |
| `c-a324db596b16` | family_leaf_uppercase | statement | `invalid:malformed:family-id` | `invalid:malformed:family-id` | match |  |  |  |
| `c-91bb6f489dba` | family_unregistered | statement | `invalid:unregistered_family` | `valid` | diverge |  | not_in_draft | F08 |
| `c-5b39a639d6af` | float_member | statement | `invalid:not_deterministic:payload` | `invalid:not_deterministic:payload` | match |  |  |  |
| `c-77582ed206e4` | held_through_chain | statement | `valid` | `valid` | match |  |  |  |
| `c-4e0dafdde8a0` | iat_disagrees | statement | `invalid:time:iat` | `invalid:time:iat` | match |  |  |  |
| `c-09dc7605e788` | iss_bad_last_char | statement | `invalid:malformed:iss` | `invalid:malformed:iss` | match |  |  |  |
| `c-945422b76bd8` | long_array_head | statement | `invalid:not_deterministic:statement` | `invalid:not_deterministic:statement` | match |  |  |  |
| `c-7c6401d61045` | ml_dsa_empty_ctx | statement | `invalid:bad_signature` | `invalid:bad_signature` | match |  |  |  |
| `c-8b862cdecacf` | names_earlier_form | statement | `invalid:malformed:also` | `invalid:malformed:refs` | same answer, other reason |  | naming | F07 |
| `c-8596ef032579` | no_asserted_at | statement | `invalid:malformed:asserted_at` | `invalid:malformed:asserted_at` | match |  |  |  |
| `c-2982161d8cfb` | no_family | statement | `invalid:unexpected:protected` | `invalid:malformed:family-id` | same answer, other reason |  | reading | F02 |
| `c-2fe4a2ee5b39` | no_row_type | statement | `invalid:unexpected:protected` | `invalid:malformed:row-type` | same answer, other reason |  | reading | F02 |
| `c-01ff72f6e1f1` | null_member | statement | `invalid:malformed:ceg-value` | `invalid:malformed:x` | same answer, other reason |  | naming | F07 |
| `c-a1d502a28a89` | payload_keys_unsorted | statement | `invalid:not_deterministic:payload` | `invalid:not_deterministic:payload` | match |  |  |  |
| `c-08624a8a480f` | record_breaks_end_rule | statement | `invalid:key_not_valid` | `invalid:key_not_valid` | match |  |  |  |
| `c-35e612add6a0` | record_by_other_key_only | statement | `invalid:kid_not_of_iss` | `invalid:kid_not_of_iss` | match |  |  |  |
| `c-f08fd3340819` | refs_duplicate | statement | `invalid:set_order:further_heads` | `invalid:set_order:further_heads` | match |  |  |  |
| `c-1bdf94c158c6` | refs_empty | statement | `invalid:malformed:refs` | `invalid:malformed:refs` | match |  |  |  |
| `c-227ae979e0c0` | refs_empty_set | statement | `invalid:malformed:further_heads` | `invalid:malformed:refs` | same answer, other reason |  | naming | F07 |
| `c-3a5c2f7d4258` | refs_unsorted_set | statement | `invalid:set_order:further_heads` | `invalid:set_order:further_heads` | match |  |  |  |
| `c-48762166da25` | room_key_self | statement | `valid` | `valid` | match |  |  |  |
| `c-63523cc66c4c` | rotation_b2_as_b | statement | `valid` | `valid` | match |  |  |  |
| `c-074678d83bd4` | rotation_b2_as_b_reverse_order | statement | `valid` | `valid` | match |  |  |  |
| `c-2229fcafeb5f` | rotation_contested | statement | `invalid:kid_not_of_iss` | `valid` | diverge |  | not_in_draft | F03 |
| `c-1d42ababb975` | rotation_cosigned_by_another_key | statement | `invalid:kid_not_of_iss` | `invalid:key_not_valid` | same answer, other reason |  | reading | F05 |
| `c-c0bf1c2c9a3e` | rotation_genesis_not_held | statement | `waiting:kid:4e3930cdcc422585def0e7ff3a2284b874a173d982d9c4b42304647f93d99f23` | `waiting:row:bd50ac2a1e10da6aaa2c069ecd3008af7fe084d1034e1fa20746d3db4933346f` | same answer, other reason |  | reading | F04 |
| `c-f2fedbf46f9e` | rotation_names_another_record | statement | `invalid:kid_not_of_iss` | `invalid:key_not_valid` | same answer, other reason |  | reading | F05 |
| `c-0e67f9060cdf` | rotation_rival_names_uncovered_record | statement | `valid` | `valid` | match |  |  |  |
| `c-69da10372252` | rotation_target_not_held | statement | `waiting:record:bd50ac2a1e10da6aaa2c069ecd3008af7fe084d1034e1fa20746d3db4933346f` | `waiting:row:bd50ac2a1e10da6aaa2c069ecd3008af7fe084d1034e1fa20746d3db4933346f` | same answer, other reason |  | naming | F04 |
| `c-79486ac657b8` | rotation_two_hops | statement | `valid` | `valid` | match |  |  |  |
| `c-7b56d87cb09c` | rotation_two_hops_middle_missing | statement | `waiting:kid:bd27864d58303131cc36fae29c51457d56a32e2bb999d1d4df50227fe255ac10` | `waiting:row:2a366c87660e6c97addc62974cad1f6d7bc8b445ad5b38c71916429576fb7110` | same answer, other reason |  | reading | F04 |
| `c-5c1ad414d1b8` | rotation_without_own_statement | statement | `invalid:kid_not_of_iss` | `valid` | diverge |  | not_in_draft | F03 |
| `c-2e1360b72546` | rotation_without_predecessor_statement | statement | `invalid:kid_not_of_iss` | `waiting:statement-of:4e3930cdcc422585def0e7ff3a2284b874a173d982d9c4b42304647f93d99f23-over:2a366c87660e6c97addc62974cad1f6d7bc8b445ad5b38c71916429576fb7110` | diverge |  | reading | F04 |
| `c-9141e9ee4a7f` | row_ref_edition_1 | statement | `invalid:malformed:target` | `invalid:malformed:refs` | same answer, other reason |  | naming | F07 |
| `c-52514e44bdf2` | row_ref_other_hash | statement | `invalid:malformed:head` | `invalid:malformed:refs` | same answer, other reason |  | naming | F07 |
| `c-478d7d4dd103` | row_ref_tuple_reversed | statement | `invalid:malformed:head` | `invalid:malformed:refs` | same answer, other reason |  | naming | F07 |
| `c-5ff2dc8476f6` | score_below_range | statement | `invalid:malformed:score` | `invalid:malformed:score` | match |  |  |  |
| `c-84167e2cf683` | score_out_of_range | statement | `invalid:malformed:score` | `invalid:malformed:score` | match |  |  |  |
| `c-dbf7949ddfa8` | second_voice | statement | `valid` | `valid` | match |  |  |  |
| `c-0bdbefb18480` | unknown_row_type | statement | `invalid:malformed:row-type` | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | diverge |  | reading | F01 |
| `c-1ba27c0ac8c8` | unprotected_text_label | statement | `invalid:unexpected:unprotected` | `invalid:unexpected:unprotected` | match |  |  |  |
| `c-4f070977aa40` | unrelated_key_claims_iss | statement | `invalid:kid_not_of_iss` | `invalid:key_not_valid` | same answer, other reason |  | reading | F05 |
| `c-6ad83f7a9a4d` | untagged | statement | `invalid:not_cose_sign1` | `invalid:not_cose_sign1` | match |  |  |  |
| `c-4ae13dc87157` | waiting_on_key | statement | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | `waiting:kid:d6f095b738a1e18fb62fa92478036189cb894203946d4c71a52d9b27b4117463` | match |  |  |  |
| `c-68b79e6a8cc1` | bare_hex | value | `neither` | `neither` | match |  |  |  |
| `c-b33f7b4ff56b` | identity_ref_42_chars | value | `neither` | `neither` | match |  |  |  |
| `c-cd0ddfc85436` | identity_ref_sha512 | value | `neither` | `neither` | match |  |  |  |
| `c-6614ee351325` | identity_ref_trailing_bits | value | `neither` | `neither` | match |  |  |  |
| `c-f200abf82b32` | key_a | value | `key` | `key d6f095b738a1…` | match |  |  |  |
| `c-12b24e140058` | key_b | value | `key` | `key 4e3930cdcc42…` | match |  |  |  |
| `c-6e6391df35bb` | other_hash_alg | value | `neither` | `neither` | match |  |  |  |
| `c-d640ff377753` | row_id | value | `row adc376f3b632…` | `digest adc376f3b632…` | diverge |  | vocabulary | F09 |
| `c-269d9aadb935` | row_id_of_vector | value | `row 4d7193e4b48b…` | `digest 4d7193e4b48b…` | diverge |  | vocabulary | F09 |
| `c-061404c6389e` | row_ref_not_a_digest | value | `neither` | `row adc376f3b632…` | diverge |  | vocabulary | F09 |
| `c-6db888385463` | short_digest | value | `neither` | `neither` | match |  |  |  |
