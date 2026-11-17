# F06 — Section 8.2: presence of members, and absent vs null

To: the author of draft-li-rttp-iqa-addressing-02
Cases: GR-G02 (B24), GR-G03 (B14), GR-G04 (B12). Draft only; not filed.

8.2 lists the five members of "a structure with the following members" and marks only `observation_as_of_ms` as nullable. It contains no MUST for the presence of each member, and no statement that an omitted member differs from null.

This run's reading agrees with all three `nonconformant` verdicts. GR-G02's verdict rests on the candidate's own representation rule ("an absent key is not the same as an explicit null"), not on the draft. A JSON binding that serialises null by omission would read GR-G02 as conformant.

Possible clarification: "Every response MUST carry all five members; `observation_as_of_ms` is the only member that may be null, and null is not the same as omission."
