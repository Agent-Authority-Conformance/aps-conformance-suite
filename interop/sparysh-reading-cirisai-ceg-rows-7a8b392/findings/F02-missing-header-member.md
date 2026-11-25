# F02. A protected header that lacks a member

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Cases:** no_family (`c-2982161d8cfb`), no_row_type (`c-2fe4a2ee5b39`). Expected `invalid:unexpected:protected`; this run answered `malformed:family-id` and `malformed:row-type`.

**Sentences of the draft:**

- Section 2.1: "A verifier MUST refuse a row whose cty carries parameters, or whose protected header lacks the type label or the family label. It MUST refuse a protected header with any other member".
- Table 3, step 2: "The protected header holds exactly the members of Section 2", reason `unexpected:protected`; "Each header member has its type and value", reason `malformed:<member>`.

**What was observed:** Section 2.1 states the refusal of a missing label but not its reason. "unexpected" reads naturally as a member that should not be there, and "has its type and value" as a member that is absent or wrong, so this run chose `malformed:<member>`. The vectors read "holds exactly" as covering absence too.

**Suggested change:** one sentence in Section 2.1 or under Table 3: "A missing member is refused unexpected:protected, as an extra one is."
