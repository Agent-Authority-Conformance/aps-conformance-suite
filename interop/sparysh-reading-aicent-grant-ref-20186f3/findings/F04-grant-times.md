# F04 — Case data: grant expiry earlier than grant issue

To: the author of the candidate aicent-grant-ref (revision 1)
Draft only; not filed.

GR-P01, P02, P03, P04, P06, GR-C02, GR-N03, GR-N04 and GR-N05 (nine cases; blind B15, B01, B05, B03, B02, B16, B09, B18, B11) carry `issued_at_ms` 1000 with `expires_at_ms` 900. GR-P01, P02, P03, P04, P06, GR-C02 and GR-G03 carry `observation_as_of_ms` 800 with `issued_at_ms` 1000: the observation predates the grant. GR-N05's note calls 900 "the grant's original expiry".

8.2 states no ordering between `issued_at_ms` and `expires_at_ms`, and CANDIDATE.md says "Identifiers and times are illustrative", so this does not change any verdict in either reading. A reader who adds a well-formedness check (expiry after issue) would turn four cases expected conformant (GR-P01, P03, P06, N05) nonconformant for a reason the cases do not intend to test.

Suggestion: use times with expiry after issue, or state in `vectors.json` that member values other than those a rule reads are unconstrained.
