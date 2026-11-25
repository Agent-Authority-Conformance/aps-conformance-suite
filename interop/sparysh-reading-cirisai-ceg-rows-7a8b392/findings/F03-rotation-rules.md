# F03. Rotation: three rules the vectors apply that Section 6.2 does not state

Draft note to the author of draft-moore-scitt-ciris-ceg-03. Not filed.

**Cases:** rotation_without_own_statement (`c-5c1ad414d1b8`), rotation_contested (`c-2229fcafeb5f`); and the member naming the predecessor, which every rotation case uses. Expected `invalid:kid_not_of_iss` for the first two; this run answered `valid` for both.

**Sentences of the draft:**

- Section 6.2: "A rotation is a record of another key that names the old key's record and carries the old key's signature."
- Section 6.2, way 2: "The verifier holds a key record of that key whose own iss is the statement's iss, and that record reaches the genesis key's record through rotation records. Each rotation record names its predecessor's record and carries the predecessor key's statement."
- Section 6.2, way 4: "carrying the bound key's own statement as proof of possession."
- Table 2: `prev` is "A predecessor"; `target` is "The row a supersedes, withdraws or recants row names".

**What was observed:**

1. **The new key's own statement.** In rotation_without_own_statement the rotation record is carried by the old key only. Way 2 asks for the predecessor key's statement and says nothing of the new key's, while way 4 asks for proof of possession explicitly. This run accepted the record; the vector refuses it.
2. **Two successors.** In rotation_contested two rotation records name the same predecessor. The draft speaks of forks for genesis bundles (Section 7.2) but not for rotations. This run accepted the statement; the vector refuses it.
3. **Which member names the predecessor.** The rotation records of the inputs are `scores` rows that name the old record in `refs.target`. Table 2 gives `target` to supersedes, withdraws and recants rows and `prev` to "a predecessor", so this run's first pass looked in `prev` only (`out/changes.md`).

**Suggested change:** in Section 6.2, after "carries the old key's signature": "It also carries the new key's own statement, as proof of possession. It names the old key's record in refs.target. Two rotation records that name one record are contested, and neither makes its key a key of iss."
