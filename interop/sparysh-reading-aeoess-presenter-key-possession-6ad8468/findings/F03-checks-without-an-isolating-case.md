# F03. Four conditions have no case whose verdict depends on them alone (under this run's checker)

To: Tymofii Pidlisnyi, author of `aeoess-presenter-key-possession`
Status: draft, not filed.

**What was run.** For each condition, this run's checker was re-run with that condition removed (always holding), under the candidate's axis map (`out/final.json`, `sensitivity_removed_under_final_readings`) and in phase 1 with all readings (`out/phase1-sensitivity.json`). A condition whose removal changes no verdict is not isolated by any case. This is a statement about this checker; the candidate's `mutate.py` was not obtained, and its mutants may be defined differently.

**Observed.**
- 4.3 item 1 (one DPoP header field): no case has more than one. `CANDIDATE.md` already lists this.
- 4.3 item 2 (well-formed JWT): PK-25 has two segments; with no signature segment, item 6 also fails, and both are in `proof_signature`. Removing the item-2 check changes no verdict.
- 4.3 item 3 for `jti`, `htm`, `htu`, `iat`: no case omits one of these claims.
- 4.3 item 3 for `nonce`: PK-24 and PK-28 omit `nonce`; both also fail item 10 (no claim equals the server nonce). In PK-28, `request_binding: true` fails on item 10 whatever item 3 gives, so removing the nonce-presence check changes no verdict. `CANDIDATE.md` says PK-26 to PK-28 kill the mutants for "the required claims check, the missing `ath` and the missing nonce"; under this checker that holds for the missing `ath` (PK-26) and not for the missing `nonce`.
- 4.3 item 5 (`alg`): PK-08 has `alg: none` and an empty signature segment, so item 6 fails as well. In this checker an `alg` other than EdDSA also makes item 6 fail, so the claim is limited to that coupling; an implementation that verified the empty segment as Ed25519 would also fail item 6.

**Suggested change.** Add cases that fail one of these conditions while every other condition holds, for example: a proof with a valid EdDSA signature and a `policy.accepted_algs` that does not list EdDSA (item 5 alone); a three-segment proof with a valid signature whose header repeats a parameter name (item 2 alone, via RFC 7515 section 5.2 step 4); a proof with a valid signature that omits `jti` while `tracks_jti` is false (item 3 alone); and, for PK-24's input, an answer that reports `proof_signature: true`, `request_binding: false` and rejects at `request_binding`, so that only the nonce-presence check (item 3, which the candidate places in `proof_signature`) decides the verdict.
