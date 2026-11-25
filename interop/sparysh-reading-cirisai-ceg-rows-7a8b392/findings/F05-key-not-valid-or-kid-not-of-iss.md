# F05. A broken rotation chain: key_not_valid or kid_not_of_iss?

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Cases:** rotation_cosigned_by_another_key (`c-1d42ababb975`), unrelated_key_claims_iss (`c-4f070977aa40`), rotation_names_another_record (`c-f2fedbf46f9e`). Expected `invalid:kid_not_of_iss`; this run answered `invalid:key_not_valid` for all three.

**Sentences of the draft:**

- Section 6.4: "A statement whose key record is Invalid is Invalid."
- Table 3, step 6: "The signer's key record is not itself Invalid", reason `key_not_valid`. Step 8: "kid's key is a key of iss", reason `kid_not_of_iss`.

**What was observed:** in each case the signer's key record is itself a statement whose kid is not a key of its iss: the chain from it to the genesis record is broken. This run verified the record with all the steps of Section 6.4, found it Invalid at its own step 8, and so refused the statement at step 6 with `key_not_valid`. The vectors carry the fault to the statement's own step 8. Both answers refuse; they differ in which step owns a broken chain.

**Suggested change:** say in Section 6.4 how much of a key record is verified at step 6, for example: "At step 6 the key record is verified through step 7; whether its key is a key of iss is decided once, at the statement's step 8."
