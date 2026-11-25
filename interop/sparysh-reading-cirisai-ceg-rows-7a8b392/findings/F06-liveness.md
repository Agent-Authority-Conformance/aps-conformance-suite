# F06. A key's liveness at the statement's instant

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Case:** after_valid_until (`c-fe02f57a9d3e`). Expected `waiting:covering_record:4e3930cd…:1763200001001`; this run answered `valid`.

**Sentences of the draft:**

- Section 6.2: "A key is live at an instant when one of its records covers that instant and its own revocation has not taken effect by then."
- Section 6.2, way 4 asks for an occurrence "covering the statement's instant". Ways 1 to 3 do not mention the instant.

**What was observed:** the statement is asserted after the `valid_until` of the only held record of its key. Section 6.4 has no step that checks the key is live at the statement's instant, and Section 8 has no reason or Waiting spelling for it. The description of the case cites CC 2.4.1.1. A reader of the draft alone accepts the statement.

**Suggested change:** add the check to Section 6.4, at step 8 or as its own step, with its answer: "Check that kid's key is live at the statement's asserted_at, or answer Waiting on a record that covers it: waiting:covering_record:<kid hex>:<instant>."
