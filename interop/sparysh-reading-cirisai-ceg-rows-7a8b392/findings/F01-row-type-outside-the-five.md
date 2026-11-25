# F01. A row type outside the five: refused at verification or at admission?

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Case:** unknown_row_type (`c-0bdbefb18480`). Expected `invalid:malformed:row-type`.

**Sentences of the draft:**

- Section 3: "The row type label (-70001) takes exactly one of five values. A Substrate MUST refuse any other value, compared byte for byte, with attestation_type_unregistered."
- Section 8, Table 3, step 2: "Each header member has its type and value: cty, typ, row-type, family-id, edition, iss", reason `malformed:<member>`.
- Section 8, before Table 4: "A Substrate then applies the checks of Table 4 to a statement that verified." Table 4: "Type is one of the five", token `attestation_type_unregistered`.

**What was observed:** this run read Section 3 and Table 4 as placing the five-value check at admission, after verification, and Table 3's "type and value" as a check that the label is a text string. Under that reading the statement passes step 2 and, holding no key, waits at step 6. The vector refuses it at step 2 with `malformed:row-type`. If that is the rule, `attestation_type_unregistered` cannot be reached by a statement that verified, since every type outside the five has already failed Table 3.

**Suggested change:** say in Section 3 which check comes first, for example: "A verifier refuses any other value at step 2 with malformed:row-type; a Substrate applies attestation_type_unregistered to rows it emits." Or remove the token from Table 4.
