# F05 — Section 8.1: must a response be a permit when no condition applies?

To: the author of draft-li-rttp-iqa-addressing-02
Cases: GR-P09 (blind B06), GR-C04 (blind B17). Draft only; not filed.

8.1 says "The refusal reason is null when there is no refusal" and gives the value for a refusal. It does not state that a response MUST be a permit when none of the five conditions applies. 6.2 says "Whether an action proceeds on lease-fresh evidence is decided by the calling layer's action policy, not by this document".

GR-P09 is still decided: its input has `operation_permitted: true`, so the emitted `operation_not_permitted` does not meet "the first value in the list whose condition applies". This run's reading agrees with `nonconformant`. The verdict depends on reading `operation_permitted: true` as "no policy forbids the operation", not only "the grant's scope covers it".

Possible clarification: one sentence stating that when no condition applies the reason is null, or that any refusal outside the first four conditions is `operation_not_permitted`.
