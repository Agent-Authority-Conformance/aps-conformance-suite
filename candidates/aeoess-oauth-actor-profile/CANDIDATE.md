# Candidate: aeoess-oauth-actor-profile

Cases for how an authorization server issues the `act` claim in JWT access tokens outside Token
Exchange, as specified in draft-mcguinness-oauth-actor-profile. Each case gives what the server
knows and one outcome it produced, and states whether that outcome satisfies the draft and which
rule decides. This is a candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and
adds nothing to the lab's schema, failure classes or verifier behavior.

## Submitter

Tymofii Pidlisnyi (Agent Passport System).

## Normative target

draft-mcguinness-oauth-actor-profile, read at two text bases, because one open change affects one
case:

- `-01`: repository https://github.com/mcguinness/draft-mcguinness-oauth-actor-profile, file
  `draft-mcguinness-oauth-actor-profile.md` at commit
  `d76465c86c061e066860307dbd3e21650ae57953`, which is the -01 text.
- `-01+pr32`: the same commit with pull request #32 applied (head
  `5c5bb3c8eb7b5ae0400cf90b06f4ce9aa7768b83`, open when this candidate was written). It changes
  one sentence of Delegated Token Issuance. Where a delegation basis exists, -01 says the server
  MAY include `act`, and #32 says the token carries `act` as Delegation Chains requires,
  regardless of the requested scope.

Under `-01+pr32` the cases describe proposed text, not published text. Section names follow the
draft. The numbers in rule ids (3.4, 3.5, 5.2) are the section numbers the draft's editors use
for -01.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`, `mutate.py`. No files are
copied from the draft repository. Rule references quote single sentences of the draft.

## License

Apache 2.0, the license of this repository.

## What the cases test

Fifteen cases, all JWT access tokens issued outside Token Exchange. Identifiers are illustrative.

| ids | grant | rule tested |
|---|---|---|
| AC-01, AC-02 | authorization code | a basis covering this subject and actor means `act` is present, whether or not an agent scope was requested |
| AC-03 | authorization code | basis present, `act` missing. Under `-01` this is `ambiguous`, because Delegation Chains says `act` MUST be present and Delegated Token Issuance says the server MAY include it. Under `-01+pr32` it is nonconformant |
| AC-04 | authorization code | no basis, so `act` must be absent, even though `sub` and `client_id` differ |
| AC-05 | authorization code | a registration shared by several actors is no basis |
| AC-06 | authorization code | an `act` object without `iss` conforms to RFC 8693 but not to this profile |
| AC-07 | authorization code | the actor identity must derive from the basis, here a key thumbprint is used instead |
| AC-08 | authorization code | the issuer places `client_profile` inside `act`, which the draft says MUST NOT appear there. Only the issuer is tested. A consumer's choice to reject or ignore that member is not |
| AC-09 | authorization code | the basis covers a different user than the token subject |
| RT-01 to RT-04 | refresh token | the recorded chain is carried into the refreshed token unchanged, including extension members, or the request is rejected |
| CC-01, CC-02 | client credentials | when the client acts on its own behalf there is no actor separate from `sub`, so no `act` |

Each case states its assumptions in `as_state`: which user the basis covers, that it is the only
basis, and that no trusted mapping links the registered actor to any key thumbprint. A different
assumption can change the verdict, AC-05 and AC-07 in particular.

## How to run

```
python3 -I check.py vectors.json -01
python3 -I check.py vectors.json -01+pr32
python3 -I mutate.py
```

`check.py` judges each case's `outcome` and compares the verdict and the deciding rule with the
case's `expect` and `expect_rule` for the chosen text. To test a server, give it each case's
inputs, replace `outcome` with what it returned, and run `check.py`. `mutate.py` disables one rule
of `check.py` at a time and fails unless some case catches every change.

At the revision submitted, the submitter's own runs on Python 3 printed
`text -01: 15/15 cases matched expectation`, `text -01+pr32: 15/15 cases matched expectation` and
`12/12 mutants killed`, each with exit 0. These show that the checker agrees with the expected
results and that every rule has a case depending on it. They say nothing about any
authorization server.

## Evidence

No authorization server has been run against these cases.

The expected results were reviewed before submission. A separate model session, given only
the draft text, PR #32 and the case inputs without the expected results, judged every case under
both texts. Its verdicts matched the expected results for thirteen of the fourteen cases it was
given. For AC-03 it found the `-01` text ambiguous, and the `-01` expectation for AC-03 was
changed to `ambiguous` after that review. AC-09 was added afterwards to cover a rule that review
found untested, and the assumptions in `as_state` were added where it found inputs
underspecified. The same session then judged AC-09 alone, again without the expected result, and
found it nonconformant under both texts, which matches. That review is a reading of the draft by
a session working for the submitter. It is author-produced and is not a run.

## Known limitations

- Only the issuing server is judged. Token Exchange, Transaction Tokens, resource server
  processing, depth limits, `cnf`, `azp` and top-level `sub_profile` are not covered.
- RT-03 accepts any rejection. The draft maps no error code for rejecting a refresh token grant,
  so the code is not checked.
- No case has a recorded chain that itself fails the actor object rules. There, "carry unchanged"
  and "MUST conform" would conflict, and the draft does not say which wins.
- No case covers the first refresh rule, that a server issuing a refresh token together with a
  token carrying `act` MUST record that chain.
- `-01+pr32` follows an open pull request and will need a new revision if #32 changes or the
  draft moves to -02.
- The checker encodes one reading of the draft. A correction from the draft's editors overrides
  it.
