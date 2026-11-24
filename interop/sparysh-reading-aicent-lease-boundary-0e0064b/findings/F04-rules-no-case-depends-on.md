# F04. Rules of this run's checker that no case of the candidate depends on

Draft note to the author of the candidate aicent-lease-boundary and of draft-li-rttp-iqa-addressing-02. Not filed.

**Cases:** all fifteen; the observation is about which variants change no verdict.

**Sentences of the draft:**

- 7.2: "(2) rejects the frame if lease_expiry is earlier than the current time, checked against the receiver's own clock (Section 6.1);"
- 8.1: "A response that reports an outcome without its reason is not conformant: the reason is what makes a refusal auditable."
- 8.1: "The set is closed: implementations MUST NOT emit values outside it, and MUST NOT reinterpret an emitted value to mean something else."
- 8.1: "For a refusal, the reason is exactly one value from the following closed set, and it is the first value in the list whose condition applies (the priority order is part of this definition):"

**What was observed:** in this run's sensitivity table (`out/phase1-sensitivity.json`), these variants change no verdict:

- R03 inverted (expired at equality instead of strictly earlier). The cases that give numeric clock and expiry (LB-E01 to LB-E03, LB-W01, LB-W02) are 100 seconds past or 1 second before the expiry; equality is given only as the boolean `at_boundary`.
- R13 removed (reason member present), R14 removed (closed set), R15 removed (grant_ref present). Every outcome carries `reason` and `grant_ref`, and every reason is null or in the closed set.
- R11 removed (any applicable refusal accepted instead of the first). Only LB-M05 has two applicable conditions, and its outcome gives the first.

These are statements about this run's checker against these fifteen cases. They do not say that the candidate's own checker has untested rules; its `mutate.py` was not read. The candidate's known limitations note that the never-assent mapping is tested by another candidate.

**Suggested change:** add one case with numeric `now_ms` equal to `lease_expiry_ms` and a declared convention, so that the boundary is reached from the clock rather than from `at_boundary`; and one case in which the expired lease is refused with `authority_not_determined` while the organ is unreachable, so that the 8.1 priority is tested in the direction of a wrong second value.
