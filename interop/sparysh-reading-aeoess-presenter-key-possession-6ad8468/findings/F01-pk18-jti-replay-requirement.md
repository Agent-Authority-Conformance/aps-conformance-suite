# F01. PK-18: the expected result rests on a requirement RFC 9449 does not state

To: Tymofii Pidlisnyi, author of `aeoess-presenter-key-possession`
Status: draft, not filed.

**Case.** PK-18 (blind B27): the server tracks `jti` (`policy.tracks_jti: true`), the request's `seen_jti` holds `["https://api.example.test/orders", "p-0001"]`, the proof carries `jti` `p-0001` for that URI, every other condition holds, and the answer is accept with all axes true. Expected: nonconformant.

**Text.** RFC 9449 11.1: "In the context of the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof." and "HTTP requests to the same URI for which the jti value has been seen before would be declined." Section 4.3, whose checks 7.1 requires before access is granted ("The resource server MUST NOT grant access to the resource unless all checks are successful."), has no item for `jti`.

**Observed.** This run recomputed the replay (the seen pair matches the request URI with query and fragment dropped, and the proof's `jti`). Whether accepting it is contrary to the text depends on the reading: if a server that declares it tracks `jti` must decline a seen value, the answer is nonconformant; if 11.1's "can" and "would" carry no requirement, the answer is not contrary to the text. This run reports PK-18 `ambiguous`; the candidate expects `nonconformant`. `CANDIDATE.md`, Known limitations, says the same about the text: "Section 11.1 says a server can do this and does not require it."

**Suggested change.** Either mark PK-18 `ambiguous`, as PK-17 is, or state in `vectors.json` `readings` that a server declaring `tracks_jti` is held to decline a seen (URI, `jti`), and say in the case's `basis` that the expected result rests on that representation rather than on RFC 9449 text.
