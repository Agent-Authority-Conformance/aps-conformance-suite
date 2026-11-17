# F04. PK-11: the basis omits the item that decides it

To: Tymofii Pidlisnyi, author of `aeoess-presenter-key-possession`
Status: draft, not filed.

**Case.** PK-11 (blind B08): the token has no `cnf`; the proof is valid and signed with the agent's key; the answer is accept with all axes true. Expected: nonconformant. Basis: `7.1`, `6.1`. This run agrees with the expected result.

**Text.** 7.1 begins "For such an access token, a resource server MUST check ...", which refers to a DPoP-bound token; a token with no `cnf` can be read as not DPoP-bound, and 7.1 would then not apply. 4.3 item 12 applies whenever the proof is presented "in conjunction with an access token": "confirm that the public key to which the access token is bound matches the public key from the DPoP proof." With no bound key this cannot be confirmed.

**Observed.** The expected result follows from 4.3 item 12 (second bullet) without depending on whether 7.1 applies. Under the reading that 7.1 alone governs and does not apply to an unbound token, the case would not be decided by the cited sections. This run did not evaluate that reading both ways (ambiguity log A5).

**Suggested change.** Add `4.3 item 12` to PK-11's `basis`.
