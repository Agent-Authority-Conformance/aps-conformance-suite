# F09. What the "form" of a value means

Note to the candidate (CANDIDATE.md), and to the author of the draft. Not filed.

**Cases:** row_ref_not_a_digest (`c-061404c6389e`), row_id_of_vector (`c-269d9aadb935`), row_id (`c-d640ff377753`).

**Sentences of the draft:**

- Section 5.3: "A reference is the array [2, digest]: the edition and the row id."
- Section 5.1: "A digest is written as the array [-16, digest], where -16 names SHA-256."
- CANDIDATE.md, level `value`: "the form of a reference, and its digest".

**What was observed:** `[2, [-16, d]]` is a reference in the sense of Section 5.3, and this run answered it as one. `expected.json` answers `neither` for it, and `row` for the bare `[-16, d]`. The digests agree. The two sides name the forms differently: `expected.json`'s `row` is a row id, and a Section 5.3 reference is not one of its forms. The draft does not define the answer `form`.

**Suggested change:** in CANDIDATE.md, list the forms and what each is ("row: a row id written [-16, digest]; key: an identity reference; neither: anything else, including a reference [2, digest]"), or answer `[2, [-16, d]]` as a row reference.
