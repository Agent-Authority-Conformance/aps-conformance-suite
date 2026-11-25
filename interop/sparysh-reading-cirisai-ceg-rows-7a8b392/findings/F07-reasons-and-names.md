# F07. Reasons outside the complete list, and what <member> names

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Cases:**

| case | expected | this run |
|---|---|---|
| null_member | `malformed:ceg-value` | `malformed:x` |
| refs_empty_set | `malformed:further_heads` | `malformed:refs` |
| row_ref_tuple_reversed, row_ref_other_hash | `malformed:head` | `malformed:refs` |
| row_ref_edition_1 | `malformed:target` | `malformed:refs` |
| names_earlier_form | `malformed:also` | `malformed:refs` |
| disclosure_short_salt | `malformed:sd-disclosure` | `malformed:sd_claims` (pass 3) |
| roles_unsorted | `key_record_bad_identity_type` | `malformed:identity_type` |
| attestation_evidence_not_map, pq_custody_unknown | `key_record_bad_pq_custody` | `malformed:attestation_evidence` (pass 3) |

**Sentences of the draft:**

- Section 8: "A name in angle brackets stands for the part, member, map or claim at fault, as in not_deterministic:payload, malformed:refs, unexpected:also and time:iat."
- Section 8: "The two tables are the complete list for a row statement."
- Section 4.2 names `federation_malformed_row` with `envelope_member_null`; Section 4.3 names `federation_set_semantics_unsorted`. Neither is in Tables 3 or 4.

**What was observed:**

1. **What `<member>` names.** The vectors use three conventions: the innermost member (`head`, `target`, `further_heads`), a CDDL rule name (`ceg-value`, `sd-disclosure`), and the containing member (`also`). This run used the payload member at fault, as the example `malformed:refs` suggests. The outcome is the same; the string is not, and Section 1.3 says reasons are compared byte for byte.
2. **Tokens outside the list.** `key_record_bad_identity_type` and `key_record_bad_pq_custody` are expected on payload cases, and `waiting:record:` and `waiting:covering_record:` on statement cases. None of the four is in the draft. Sections 4.2 and 4.3 name tokens the tables do not carry.
3. **Order.** Table 3 lists `key_record_out_of_window` before `key_record_mixed_roles`. A mixed set always breaks the end rule, so in that order the mixed reason is never given. The vector checks mixed roles first, as this run did.

**Suggested change:** state one rule for `<member>`, for example "the innermost member or CDDL rule that fails". Add the four tokens to Table 3 (or Section 6.2), or move Sections 4.2 and 4.3 to the tables' tokens. Swap the two key record rows of Table 3.
