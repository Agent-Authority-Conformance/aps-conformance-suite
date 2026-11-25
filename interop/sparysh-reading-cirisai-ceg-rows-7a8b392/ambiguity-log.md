# Ambiguity log

Every place where this run's reader had to choose a reading because draft-moore-scitt-ciris-ceg-03 leaves a choice. The identifiers are those `reader/ceg_reader_pass2.py` writes in `READINGS` and attaches to each answer that rests on them. "Cases" counts the blind answers that carry the reading, and names those that differ from `expected.json`.

| id | the choice | where the text is open | cases (differing) |
|---|---|---|---|
| R-DET-ORDER | Step 1 checks determinism of the statement, then the protected header, then the payload. | Table 3 lists the three parts in one row; Section 6.4 names no order. | 3 (none) |
| R-MISSING-MEMBER | A protected-header member that is missing is `malformed:<member>`; one that should not be there is `unexpected:protected`. | Section 2.1 says a verifier refuses a header that lacks the type or the family label, without a reason. Table 3 gives `unexpected:protected` for "holds exactly the members". | 3 (no_family, no_row_type: expected `unexpected:protected`) — F02 |
| R-ALG | A wrong alg is `malformed:alg`. | Table 3 lists cty, typ, row-type, family-id, edition and iss for `malformed:<member>`, not alg. | 0 |
| R-ROWTYPE | A row type outside the five, as text, passes verification and is refused at admission with `attestation_type_unregistered`; a non-text value is `malformed:row-type`. | Section 3 and Table 4 put the five-value check at admission; Table 3 has `malformed:row-type` for "type and value". | unknown_row_type (expected `malformed:row-type`; this run went on to step 6 and waited on the key) — F01 |
| R-REGISTRY | A family the draft names is registered; for any other the answer rests on [CC]. | Registration of families and dimensions is in [CC] (Section 8). | 5 (family_unregistered, dimension_open_vocabulary) — F08 |
| R-DIM-UNKNOWN | The evidence family is authored (B.1 says its signer is the author); whether it requires a dimension is not decided. | B.1 shows a dimension but does not say the family requires one. Pass 1 inferred that it did (`out/changes.md`). | 16; the 5 differing cases differ for other reasons |
| R-MIXED-FIRST | `key_record_mixed_roles` is checked before `key_record_out_of_window`. | Table 3 lists them the other way, but a mixed set always breaks the end rule, so in that order the mixed reason is never given. | 1 (agrees: the vectors check mixed roles first) |
| R-MAXSECS | The upper bound of the key record end rule is not checked. | `key_record_max_secs` appears only in a CDDL comment; its value is in [CC]. | 11 (node_one_ms_over, node_one_second_over) — F08 |
| R-VU-GENERAL | `valid_until_not_after_asserted_at` applies to every row. | Table 3 puts it at step 4 for every row; the CDDL comment states it for accord rows. | 0 |
| R-RAW-WAIT | A verifier holding bare keys only cannot show ways 2 to 4 of Section 6.2; kid other than the thumbprint in iss waits on the key record those ways need. | Section 6.2: "Where none of the four holds and a row one of them needs is not held, the answer is Waiting on that row." | a_iss_b_raw (expected `kid_not_of_iss`) — F04 |
| R-KID-BY-SUB | A held key record is found by the key its sub names; `kid_mismatch` is a record whose key member lacks the thumbprint its sub names. | Section 6.2 and Table 3 do not say how a record is matched to kid. | 13; the 3 differing cases differ for other reasons |
| R-ROTATION | A rotation record names its predecessor's record in `refs.prev` or `refs.target`, and is carried by a statement of the predecessor key over the same payload. | Section 6.2 says a rotation "names the old key's record", not under which member. Table 2 gives `target` to supersedes, withdraws and recants rows and `prev` to "a predecessor". The inputs use `target` on a scores row. Pass 1 read `prev` only. | 7 (rotation_contested, rotation_without_own_statement) — F03 |
| R-STEP9-AUTHOR | Where the draft does not say whether a family is authored, an author member present is read as authored, and iss must equal it. | Authored or counted is stated per family in [CC] (Section 5.4). | 4 (differing for other reasons) |
| R-IDTYPE-SET | An `identity_type` out of order is `malformed:identity_type`. | Table 3 names `set_order` only for sets in refs; Section 4.3 names `federation_set_semantics_unsorted`, which Tables 3 and 4 do not carry. | roles_unsorted (expected `key_record_bad_identity_type`) — F07 |
| R-SET-OUTSIDE-REFS | An array member the draft does not define is a set; one out of order is `set_order:<member>`. | Section 4.3: "Where no definition says, it is a set." The member `list` is not defined in the draft. | 5 (all five disclosure cases answer `set_order:list`) — F08 |

## Waiting answers and how they are spelled

Section 8 fixes one Waiting spelling, `waiting:kid:` and the thumbprint. For the others this run wrote `row:` and the row id, `key-record-of:` and the kid with the iss, and `statement-of:` and the kid with the row id. `expected.json` writes `waiting:record:` and the row id, and `waiting:covering_record:` and the kid with an instant. The comparison treats a spelling difference with the same missing object as the same answer, other reason (rotation_target_not_held).

## Mappings for the comparison

- A blind answer is `valid`, `invalid:` and the reason, or `waiting:` and what is missing, compared as a string with `expect`.
- A payload answer is `ok` or the reason, as `expect` writes it.
- A value answer maps this run's forms to `expected.json`'s: identity-ref to `key`, row-ref to `row`, hash-digest to `digest`, anything else to `neither` (F09).
