# Ambiguity log

Places where RFC 9449, or the candidate's representation read beside it, admits more than one reading. For each: where, the readings, the one chosen and why. Entries A1 to A4 are choice points the checker evaluates both ways (`CHOICES` in `reader/checker.py`); where the two readings give different verdicts the case is reported `ambiguous`. The other entries are fixed choices; for each, whether any case's verdict depends on it is stated.

Status: entries A1 to A19 were written in phase 1, before `inputs/sealed/` was opened. Entries added in phase 2, if any, are marked "(phase 2)".

## Choice points evaluated both ways

### A1. Which outcome field reports RFC 9449 4.3 item 3 (required claims)

- Text: 4.3 item 3, "All required claims per Section 4.2 are contained in the JWT." Section 4.2 makes `ath` required when the proof accompanies an access token, and `nonce` required when the server provided a nonce.
- Reading A: a missing claim is charged to the axis whose later check uses the claim: `ath` to `key_binding` (item 12), `nonce` to the axis that reports item 10, `jti`/`htm`/`htu`/`iat` to `request_binding`.
- Reading B: a missing claim makes the proof JWT itself incomplete, so it is also charged to `proof_signature`.
- Chosen as primary: A, because the outcome field names refer to what each check binds, and RFC 9449 does not assign item 3 to any reporting axis. Both are evaluated.
- Verdict depends on it: B26 (missing `ath`, outcome `proof_signature: true`, `key_binding: false`).

### A2. Which outcome field reports freshness (items 10, 11, and the jti replay of 11.1)

- Text: 4.3 items 10 and 11; 11.1.
- Reading A: `request_binding`.
- Reading B: `proof_signature`.
- Chosen as primary: A. RFC 9449 does not group these with either; neither name describes them. Both are evaluated.
- Verdict depends on it: B28 (server nonce provided, no `nonce` claim; outcome `proof_signature: false`, `request_binding: true`, `reject_axis: proof_signature`).

### A3. An `iat` ahead of `now` when the policy's `future_skew_s` is null

- Text: 4.3 item 11, "is within an acceptable window (see Section 11.1)"; 11.1, "the server MAY accept DPoP proofs that carry an iat time in the reasonably near future".
- Reading A: null means the server allows no future skew; an `iat` 20 s ahead is outside the window.
- Reading B: null means the policy says nothing; under the MAY, accepting a near-future `iat` is permitted, so it is not a failed check.
- Chosen as primary: A (a policy field present with no value is read as no allowance). Both are evaluated.
- Verdict depends on it: B17 (`iat` = now + 20, outcome accept).

### A4. A replayed `jti` when the policy says `tracks_jti: true`

- Text: 11.1, "servers can store the jti value ... to prevent multiple uses of the same DPoP proof." and "HTTP requests to the same URI for which the jti value has been seen before would be declined." Section 4.3 has no item for `jti`.
- Reading A: a server that tracks `jti` declines a seen (URI, `jti`), so accepting it fails a check.
- Reading B: 11.1 states this with "can" and "would", not MUST; 4.3 lists no `jti` check; accepting is not contrary to a requirement of the text.
- Chosen as primary: A, because the policy states that the server tracks `jti`. Both are evaluated.
- Verdict depends on it: B27 (seen `["https://api.example.test/orders","p-0001"]`, outcome accept).

## Fixed choices

### A5. An access token with no `cnf.jkt`

- Text: 4.3 item 12, "confirm that the public key to which the access token is bound matches the public key from the DPoP proof." 7.1 begins "For such an access token" (a DPoP-bound one).
- Reading A: the proof was presented with an access token, so item 12 applies; with no bound key nothing can be confirmed, so the check is not successful.
- Reading B: a token without `cnf` is not DPoP-bound, so the second bullet of item 12 and 7.1 do not apply.
- Chosen: A. Item 12 applies whenever a proof is "presented to a protected resource in conjunction with an access token", which is what the input describes. Not evaluated both ways. Case: B08. Under B, B08's `key_binding` would hold and its verdict would change from nonconformant to conformant.

### A6. What `proof_signature` covers

- Readings: only item 6 (the signature verifies with the `jwk`), or items 1, 2, 4, 5, 6 and 7 (the proof as a signed, typed JWT).
- Chosen: items 1, 2, 4, 5, 6, 7. No verdict depends on it: the cases where only the wider set fails (B06, B11, B14, B25) all report `decision: accept`, which fails on its own.

### A7. `key_binding` covers both bullets of item 12

- Chosen: `ath` equals the token hash and the token's bound key matches the proof key; plus the presence of `ath` (A1 reading A). The field name could be read as the key comparison only. With that narrow reading the `key_binding` part of B03, B19 and B26 changes: B03 stays nonconformant (its accept fails); B26 becomes nonconformant; B19 becomes conformant if A1 reading B is also taken (then its `proof_signature: false` holds) and stays nonconformant under A1 reading A. Not evaluated both ways; recorded here.

### A8. What makes a reported rejection conformant

- RFC 9449 does not require a server to grant access, and does not split a rejection into reporting axes.
- Chosen: `decision: reject` is never contrary to the text by itself. `reject_axis` holds when it names one of the four axes, that axis's conditions fail on the facts, and the outcome reports that axis as false. Any failing axis may be named, resting on 4.3 "These checks may be performed in any order."

### A9. What makes a reported accept conformant

- Text: 7.1, "The resource server MUST NOT grant access to the resource unless all checks are successful."
- Chosen: `decision: accept` holds only if every RFC condition holds and, by the candidate's representation, the token scope contains `required_scope`. An accept must have `reject_axis: null`.

### A10. "Each axis is read on its own"

- The candidate's `readings` statement. Chosen: each reported axis value is compared with the facts of that axis's conditions alone, whatever the decision or the other axes say. A false axis with a correct decision is still a failed part.

### A11. A proof that is not a well-formed JWT (B06, two parts)

- Chosen: the header and payload that do decode are still used to compute the other axes' facts (A10). With no signature part, item 6 fails as well as item 2.

### A12. The `iat` window bound

- Chosen: `now - iat <= iat_window_s` holds (inclusive); `now` is `input.request.now`, equal to the top-level `now` in every case. No case lies on the bound (differences seen: 5, 600, -20).

### A13. `htm` comparison

- Chosen: exact, case-sensitive string equality with `request.method`. RFC 9110 is not supplied (see PROVENANCE, "Used without a supplied text").

### A14. `htu` comparison

- Chosen: drop query and fragment from both sides, then apply RFC 3986 6.2.2 and 6.2.3 normalisation (the SHOULD in 4.3), then compare. Only B09 (query on the request URI) and B22 (different path) exercise it; no case depends on normalisation itself.

### A15. "registered asymmetric digital signature algorithm" and "supported by the application"

- The IANA JOSE registry is not supplied. Chosen: a fixed list of asymmetric JWS algorithms; "supported by the application" is the set this checker can verify (EdDSA with Ed25519); "acceptable per local policy" is `policy.accepted_algs`.
- Consequence: an `alg` other than EdDSA also makes item 6 fail (no verification applies). B14 (`alg: none`) fails items 5 and 6.

### A16. "does not contain a private key" (item 7)

- Chosen: the `jwk` has none of the members `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`. For OKP, RFC 8037 section 2 names `d` as the private key. Only B11 exercises it (`d` present).

### A17. Scope containment

- The candidate's representation, not RFC 9449. Chosen: `scope` split on single spaces; `required_scope` must equal one element. RFC 6749 section 3.3 is not supplied.

### A18. jti replay context

- Chosen: `seen_jti` is a list of `[URI, jti]` pairs; a match needs the URI (query and fragment dropped, normalised as A14) to equal the request URI and the `jti` to be equal; checked only when `tracks_jti` is true.

### A19. Form of the DPoP field in the input

- Chosen: a string stands for one DPoP header field; a list would stand for several (item 1). No case uses a list.

## Added in phase 2

### A20 (phase 2). The candidate's stated axis map resolves A1 and A2

- `CANDIDATE.md` states that `proof_signature` covers RFC 9449 4.3 items 2 to 7 (so item 3 is reported by `proof_signature`, A1 reading B) and that `request_binding` covers items 8 to 11 and 11.1 (A2 reading A). This is the candidate's representation; RFC 9449 does not decide it. `out/final.json` fixes A1 and A2 accordingly (`out/changes.md`). A3 and A4 are not resolved by anything read in phase 2.
