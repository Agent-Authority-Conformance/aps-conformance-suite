# Changes between passes

## Pass 1 to pass 2 (before `expected.json` was opened)

`reader/ceg_reader_pass1.py` to `reader/ceg_reader_pass2.py`. Made after reading the inputs and the pass-1 answers, and before `expected.json` was opened. Both readers and both answer files are in `logs/frozen.sha256`, recorded at the time in `logs/frozen-at.txt`.

1. **R-ROTATION.** Pass 1 looked for a rotation's predecessor in `refs.prev` only. The rotation records of the inputs name it in `refs.target`, and Section 6.2 names no member. Pass 2 accepts either.
2. **R-DIM-UNKNOWN.** Pass 1 inferred from Appendix B.1 that the evidence family requires a dimension, and refused 11 evidence rows without one with `dimension_missing`. B.1 shows a dimension but does not say the family requires one. Pass 2 does not decide `dimension_missing` for that family.
3. **R-SET-OUTSIDE-REFS.** Pass 1 did not apply Section 4.3's default ("Where no definition says, it is a set") to array members the draft does not define. Pass 2 does.

Pass 2 changed the answer or the reason of 22 cases of pass 1; 25 answer records differ, counting the readings they carry.

## Pass 2 to pass 3 (after `expected.json` was opened)

`reader/ceg_reader_pass2.py` to `reader/ceg_reader_pass3.py`. Three omissions of this reader, each a part of the draft it had not implemented. No reading of `ambiguity-log.md` was changed, and no rule was taken from `expected.json`.

1. Read the disclosures that `sd_claims` (label 17) carries, as Section 4.8 and Table 3 describe them. Before, only the `disclosed_digests_hex` input was read.
2. Check `attestation_evidence` of a key record against Appendix A.
3. For a case of level `object`, require a typ of Section 7.1.

Pass 3 changed 4 answers: row_typ_as_object now matches; disclosure_short_salt, attestation_evidence_not_map and pq_custody_unknown now refuse with this run's spelling of the reason.
