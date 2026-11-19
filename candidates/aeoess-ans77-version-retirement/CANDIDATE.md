# Candidate: aeoess-ans77-version-retirement

Cases for what the two ANS-6 caller verification tiers decide when an agent version is retired, under the current ANS text, under the change proposed in agentnameservice/ans-spec#77, and under the revocation sequence proposed in reply. This is a candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's schema, failure classes or verifier behavior.

## Submitter

Tymofii Pidlisnyi (Agent Passport System).

## Normative target

The ANS text is used as written at one commit. The #77 proposal and its replies are proposed text, not agreed text, and the cases are candidate cases against them.

- `ans6`: [agentnameservice/ans-spec](https://github.com/agentnameservice/ans-spec) at `9284c7edd622e80d50eca092339f33e3918bded5`, `spec/ans-6-agent-authentication.md`, sections 4.1, 4.4, 6.2, 6.3, 8.1, 9.4 and 11.1.
- `ans1`: same commit, `spec/ans-1-registration.md`, section 6.3 (`AGENT_DEPRECATED` reserved and not emitted) and the revocation reasons, including `SUPERSEDED`.
- `i77`: [ans-spec#77](https://github.com/agentnameservice/ans-spec/issues/77), body as of 2026-10-17T19:07:48Z, sha256 `c032c5f4fbef3611dac1a193e85b6c50ce9d588db79d6e4ff21a2df01c68401c`.
- `i77c1`: [comment 6178618043](https://github.com/agentnameservice/ans-spec/issues/77#issuecomment-6178618043), 2026-10-14, proposing revocation with `SUPERSEDED` followed by DNS cleanup instead of a deprecation transition.
- `i77c2`: [comment 6239228769](https://github.com/agentnameservice/ans-spec/issues/77#issuecomment-6239228769), 2026-10-17, saying `AGENT_DEPRECATED` must repeat the previous event's certificate arrays.

## What the cases test

Each case gives the DNS records present, the TL entry for each version, the last status token the caller holds, the verification instant and the verifier's policy. It states what the badge tier and the SCITT tier decide and whether they agree.

| Case | Reading | Badge tier | SCITT tier | Agree |
|---|---|---|---|---|
| A77-01 | current, control | accept | accept | yes |
| A77-02 | current, `_ans-badge` record deleted, TL still ACTIVE | reject, `no_badge_match` | accept | no |
| A77-03 | proposed, `AGENT_DEPRECATED` with certificate arrays | accept with warning | accept with warning | yes |
| A77-04 | proposed, `AGENT_DEPRECATED` without certificate arrays, caller presents the newly issued token | reject, `fingerprint_not_listed` | reject, `fingerprint_not_listed` | yes |
| A77-05 | proposed, record deleted before revocation | not accepted, reason open | accept with warning | no |
| A77-06 | alternative, revoked `SUPERSEDED` 5 minutes earlier | reject | accept on the old token | no |
| A77-07 | alternative, past token exp plus skew, no grace | reject | reject, `token_expired` | yes |
| A77-08 | alternative, same instant, 9.4 grace at 1x TTL | reject | accept | no |
| A77-09 | alternative, past the old token's exp plus 10 min skew and 1 h grace | reject | reject, `token_expired` | yes |
| A77-10 | proposed, verifier rejects DEPRECATED as local policy | reject | reject | yes |
| A77-11 | proposed, caller still presents an ACTIVE token issued before deprecation | accept with warning | accept, no warning | no |

A77-05 carries an open point. ANS-6 8.1 says to reject when no badge matches, while the proposal says a verifier MUST NOT conclude a version is retired from a missing record while its TL status is not terminal. Neither reading accepts, so the case fixes the decision and leaves the reason open.

A77-04 only shows what happens when the caller presents the token derived from the new event. A caller still holding an older token gets the A77-11 result instead.

A77-11 is the case the proposal leaves open. After `AGENT_DEPRECATED`, the badge tier sees the new status on its next uncached read, while the SCITT tier decides on whatever token the caller presents. Both admit the caller, but they report different status until the old token is no longer accepted.

The revocation cases measure from the old token's `exp`. The SCITT tier accepts it until `exp` plus the verifier's skew allowance (10 minutes in these cases), plus any 9.4 grace (none in A77-06 and A77-07, one hour in A77-08 and A77-09). How much of that window is left after a revocation depends on the token's age when the revocation happens. The 2 hours 10 minutes in ANS-6 11.1 is that window measured from issuance for a one hour token at the maximum skew and one hour of grace.

A77-10 is not conformant to the current text, which says to accept DEPRECATED with a migration signal. It shows the outcome of the local policy the issue's open question asks about.

## How to run

```
python3 check.py
python3 check.py --mutants
```

Standard library only, Python 3.9 or later. The first command prints one line per case and exits 0 if every case matches. There are eleven cases. The second also runs five single-rule changes to the model and reports the cases that catch each one.

| Change to the model | Caught by |
|---|---|
| Badge tier reads the TL entry when the `_ans-badge` record is missing | A77-02, A77-05 |
| SCITT tier ignores the status token `exp` | A77-07, A77-09 |
| SCITT tier applies no skew or grace allowance | A77-08 |
| DEPRECATED treated as ACTIVE, with no migration signal | A77-03, A77-05, A77-10, A77-11 |
| Identity certificate fingerprint not checked | A77-04 |

## Evidence

Author-produced only. `check.py` was written by the submitter and run on 2026-11-19 (UTC). No ANS implementation has been run against these cases.

## Limitations

- The model is synthetic. It reads the decision rules from the ANS text and does not construct or verify badges, receipts, status tokens, certificates or DNS records. Fingerprints are placeholder strings.
- The badge tier is modelled as reading the latest TL event's status and certificate arrays, as `i77c2` says GoDaddy's production TL does. A TL that derives them differently could decide A77-04 differently.
- Badge caching (ANS-6 6.4) and the badge-tier staleness threshold (9.2) are not modelled, so the badge tier is treated as reading the TL live.
- Times are fixed integers from `t0`. No clock is read.

## License

Apache-2.0. The cases quote section numbers and short phrases from the ANS specification, which is Apache-2.0.
