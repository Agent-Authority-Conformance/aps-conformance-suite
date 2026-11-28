# F03 — The cases: rules that no single case depends on, under this run's decomposition

To: the author of the candidate aicent-grant-ref (revision 1)
Draft only; not filed.

This run's checker implements 12 rules. Removing each one alone and re-running gave these results; full table in RESULTS.md:

- Closed set (8.1 "MUST NOT emit values outside it") removed: no case changes. GR-C03 (`authority_suspended`) and GR-C01 (`granted`) carry 8.1 input facts, so the priority rule rejects them as well: the required value differs.
- "No affirmative granted value" removed: no case changes. GR-C01 is also caught by the closed set and the priority rule.
- "Refuse when a condition applies" removed: no case changes. GR-N04 (permit on stale-observation facts) also backfills `observation_as_of_ms` with the diagnostic instant 1150, so the 8.2 null rule rejects it independently.
- "Observation equals the relied-on as-of instant when that observation is present and fresh" removed: no case changes. No case has a fresh relied-on observation and a member carrying some other instant.

CANDIDATE.md reports `21/21 mutants killed` against the candidate's own checker. That figure and the above are about different decompositions and do not contradict each other. Pairwise removals were not attempted.

Cases that would isolate each rule (suggestions): an off-set value on a case without 8.1 facts (with 8.1 facts, any value outside the set also differs from the required value, so the priority rule rejects it as well); a GR-N04 variant with `observation_as_of_ms` null; a GR-N01 variant with `observation_as_of_ms` set to a value other than 1100.
