# F04. Invalid or Waiting, and what a Waiting answer names

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Cases:**

| case | expected | this run |
|---|---|---|
| a_iss_b_raw (`c-a37031749c85`) | `invalid:kid_not_of_iss` | waiting on a key record of A under iss B |
| rotation_without_predecessor_statement (`c-2e1360b72546`) | `invalid:kid_not_of_iss` | waiting on B's statement over B2's record |
| rotation_two_hops_middle_missing (`c-7b56d87cb09c`) | `waiting:kid:` B2 | waiting on B2's record |
| rotation_genesis_not_held (`c-c0bf1c2c9a3e`) | `waiting:kid:` B | waiting on B's record |
| rotation_target_not_held (`c-69da10372252`) | `waiting:record:` and the row id | `row:` and the same row id |

**Sentences of the draft:**

- Section 6.2: "Where none of the four holds and a row one of them needs is not held, the answer is Waiting on that row. Otherwise the statement is Invalid, kid_not_of_iss. A held record of the key under another identity is the plain case. A verifier that holds bare keys and no rows can show only the first way."
- Section 6.4: "A statement whose key record is Waiting is Waiting, naming the deepest missing key."
- Section 8: "step 8 answers Waiting on the row it needs."

**What was observed:**

1. **Bare keys only.** With a raw directory a verifier never holds the rows that ways 2 to 4 need, so the first sentence, read literally, makes every kid other than the thumbprint in iss Waiting. The vector answers Invalid.
2. **A missing voice of a held row.** The rotation record is held, but the old key's statement over it is not. This run read that statement as something not held and waited. The vector answers Invalid. Section 1.3 separates a row from the statements over it, which supports the vector, but Section 6.2 does not say it.
3. **Row or key.** Section 6.2 and step 8 say Waiting names a row; Section 6.4 says the deepest missing key. In the two-hop and genesis cases the vectors name a key, and in rotation_target_not_held a record.

**Suggested change:** add to Section 6.2: "A verifier that holds bare keys only answers Invalid when kid is not the thumbprint in iss. A rotation record held without the old key's statement is Invalid, not Waiting. A Waiting answer names the deepest missing key when a key is missing, and the record otherwise, as waiting:kid:<hex> or waiting:record:<row id hex>."
