# F02 — Section 8.2: race boundary, and the observation instant on a revocation refusal

To: the author of draft-li-rttp-iqa-addressing-02
Cases: GR-A02 (blind B19). Draft only; not filed.

Facts: authority revoked, `revoked_at_ms` 1101. Outcome: `authority_revoked` with `observation_as_of_ms` 1100.

This run's reading scored the case `ambiguous`, with the value part conformant, as the candidate does. Its alternative reading differs from the candidate's note:

- The candidate's note asks which value the boundary owes (revoked, not determined, or a permit).
- This run's reading asks whether the record is self-consistent. 8.2 defines `observation_as_of_ms` as "the as-of instant of the standing observation the answer relied on", and 8.1 requires the reason to be "computed over the authority facts the response carries". An observation as of 1100 cannot establish a revocation effective at 1101, unless revocation knowledge reaches the answer by some route other than a standing observation, which the text does not describe.

Possible clarification: say whether a revocation refusal must cite an observation no earlier than the revocation, or whether revocation may be learned outside the standing observation the member records.
