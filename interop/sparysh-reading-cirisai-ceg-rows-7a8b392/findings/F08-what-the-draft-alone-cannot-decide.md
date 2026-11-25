# F08. Cases the draft alone cannot decide

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Cases:**

| case | expected | needs |
|---|---|---|
| family_unregistered | `unregistered_family` | the family registry of [CC] |
| dimension_open_vocabulary | `dimension_unregistered` | the same |
| dimension_refused_by_matcher | `dimension_refused:namespace_vocab_value_unregistered` | the namespace rules of [CC] |
| dimension_less_specific_header | `dimension_family` | that `accord:lifecycle:.kind` is registered and that resolution takes the most specific family |
| node_one_ms_over, node_one_second_over | `key_record_out_of_window` | the value of `key_record_max_secs` |
| disclosure_unmatched, disclosure_key_present, digest_repeated, disclosure_twice, disclosed | the disclosure reasons, and `valid` for disclosed | that the payload member `list` is a sequence, not a set |

**Sentences of the draft:**

- Section 8: "The namespace rules that decide whether a dimension is registered, and their tokens, are defined in [CC] and are outside the scope of this document."
- Section 4.3: "An array of one element type is a set or a sequence, as its definition states. Where no definition says, it is a set."
- Appendix A, key record comment: "asserted_at <= valid_until <= asserted_at + key_record_max_secs * 1000".

**What was observed:** the candidate's notes say the `family` level needs [CC]. These 11 statement and payload cases need it too, or need one fact of it. For the disclosure cases the default of Section 4.3 decides first: `list` is not defined in the draft, so a reader of the draft treats it as a set and refuses the unsorted elements with `set_order:list` before it reaches the disclosures. Five cases, one of them expected `valid`, turn on that one fact.

**Suggested change:** either restate in the draft the few registry facts the vectors use (the families they name, `key_record_max_secs`, and that `list` is a sequence), or mark these cases in the candidate as needing [CC], so that a reading from the draft alone is scored on the cases it can decide.
