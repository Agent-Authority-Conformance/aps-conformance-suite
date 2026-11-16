# Run report: bacs-oauth-server against candidates/aeoess-oauth-actor-profile

> Transcribed into the lab by Tymofii Pidlisnyi (aeoess) from the report Ilja Radusch posted on
> [mcguinness/draft-mcguinness-oauth-actor-profile#31](https://github.com/mcguinness/draft-mcguinness-oauth-actor-profile/issues/31#issuecomment-6910398658)
> on 2026-11-16. The text below is his, unchanged. The same comment also reports a partial run of the
> draft-mishra-oauth-agent-grants-03 vectors, which belongs to that corpus and is not part of this record.


## Required fields

| field | value |
|---|---|
| who ran it | Ilja Radusch (bacs-oauth-server maintainer) |
| date | 2026-11-15 (UTC) |
| run mode | Mode A, reproduction: the documented verifier (check.py) run on outcomes this implementation issued |
| implementation name | bacs-oauth-server |
| implementation repo and commit | private repository; commit 8c61947c72606dae06b3db173807d295c11c3349 |
| corpus reference | https://github.com/Agent-Authority-Conformance/aps-conformance-suite @ 20186f3ebc78de2f34e79a0b4bfe5f828599653b (candidates/aeoess-oauth-actor-profile) |
| per-vector result | below: live-captured, code-derived and not-applicable kept apart |
| verbatim command and output | below |
| environment | Node v26.13.1; OS Darwin 27.2.0 arm64; PostgreSQL 18; Python: see the check.py command (python3) |
| author-produced or independent | author-produced: run by the maintainers of the implementation under test, against their own server. Not independent. |
| suspected defective vectors | none |

Issuer under test: `http://127.0.0.1:3901` (local test server, throwaway database). User and service identifiers (`sub`, the client_credentials `client_id`) are pseudonyms; agent client ids are server-minted `dcr_` ids.

## Per-vector results

### Live-captured (outcome issued by this server in this run)

| case | source | check.py -01 | check.py -01+pr32 |
|---|---|---|---|
| AC-01 | first token of the agent-lane grant | ok (expect conformant, got conformant; R-5.2-basis) | ok (expect conformant, got conformant; R-5.2-basis) |
| AC-02 | floor client, agent scope not requested | ok (expect conformant, got conformant; R-5.2-basis) | ok (expect conformant, got conformant; R-5.2-basis) |
| RT-01 | token after one refresh | ok (expect conformant, got conformant; R-5.2-refresh (carried unchanged)) | ok (expect conformant, got conformant; R-5.2-refresh (carried unchanged)) |
| AC-03-live | floor client | ok (expect conformant, got conformant; R-5.2-basis) | ok (expect conformant, got conformant; R-5.2-basis) |
| AC-05-live | shared registration | ok (expect conformant, got conformant; R-5.2-shared (no act without basis)) | ok (expect conformant, got conformant; R-5.2-shared (no act without basis)) |

### Code-derived (candidate outcomes, not issued by this server)

These outcomes are the candidate author's illustrative values. An `ok` here says the checker reads the fixture as its author expected; it is not a property of this server.

| case | source | check.py -01 | check.py -01+pr32 |
|---|---|---|---|
| AC-03 | candidate outcome | ok (expect ambiguous, got ambiguous; R-3.5-iff MUST vs -01 R-5.2 MAY (basis present, act missing)) | ok (expect nonconformant, got nonconformant; R-5.2-basis / R-3.5-iff (basis present, act missing)) |
| AC-04 | candidate outcome | ok (expect nonconformant, got nonconformant; R-3.5-iff (act without a basis covering this sub)) | ok (expect nonconformant, got nonconformant; R-3.5-iff (act without a basis covering this sub)) |
| AC-05 | candidate outcome | ok (expect nonconformant, got nonconformant; R-5.2-shared (shared registration is no basis)) | ok (expect nonconformant, got nonconformant; R-5.2-shared (shared registration is no basis)) |
| AC-06 | candidate outcome | ok (expect nonconformant, got nonconformant; R-3.4-iss (act object missing sub or iss)) | ok (expect nonconformant, got nonconformant; R-3.4-iss (act object missing sub or iss)) |
| AC-07 | candidate outcome | ok (expect nonconformant, got nonconformant; R-5.2-derive (actor not from basis)) | ok (expect nonconformant, got nonconformant; R-5.2-derive (actor not from basis)) |
| AC-08 | candidate outcome | ok (expect nonconformant, got nonconformant; R-3.4-iss (client_profile inside act)) | ok (expect nonconformant, got nonconformant; R-3.4-iss (client_profile inside act)) |
| RT-02 | candidate outcome | ok (expect nonconformant, got nonconformant; R-5.2-refresh (chain dropped)) | ok (expect nonconformant, got nonconformant; R-5.2-refresh (chain dropped)) |
| RT-03 | candidate outcome | ok (expect conformant, got conformant; R-5.2-refresh (reject branch)) | ok (expect conformant, got conformant; R-5.2-refresh (reject branch)) |
| RT-04 | candidate outcome | ok (expect nonconformant, got nonconformant; R-5.2-refresh (chain changed)) | ok (expect nonconformant, got nonconformant; R-5.2-refresh (chain changed)) |
| CC-01 | candidate outcome | ok (expect conformant, got conformant; R-3.5-iff) | ok (expect conformant, got conformant; R-3.5-iff) |
| CC-02 | candidate outcome | ok (expect nonconformant, got nonconformant; R-3.5-iff (client acts on own behalf, no actor separate from sub)) | ok (expect nonconformant, got nonconformant; R-3.5-iff (client acts on own behalf, no actor separate from sub)) |

### Not applicable

- **AC-09**: Not applicable (maintainer ruling, draft-mcguinness-oauth-actor-profile#31, 2026-10-31): this issuance path binds every token to the user who completed authorization, so a delegation granted by one user cannot be used to mint a token for another. Not a pass.

### Unit-derived (not part of this run)

`tests/unit/token-pipeline-act-floor.test.ts` runs AC-01..03, AC-05 and CC-01 against the token-issuance pipeline in CI (stubbed store, mocked floor config). Those are unit-derived, not part of this run, and are not counted below.

## Verbatim command and output

### Capture (secrets redacted; credentials come from the environment)

```text
pnpm run test:manual:aps-capture -- --base-url http://127.0.0.1:3901 --database-url postgres://***@127.0.0.1:5432/aps_throwaway --overlay --dpop --server-checkout /tmp/aps-server --aps-vectors /tmp/aps-live/suite/candidates/aeoess-oauth-actor-profile/vectors.json --daap-vectors /tmp/aps-live/grantex/docs/ietf-draft/test-vectors/oauth-agent-grants-03.json --out /tmp/aps-live/out3
```

### check.py -01

```text
cd /tmp/aps-live/suite/candidates/aeoess-oauth-actor-profile && python3 check.py /tmp/aps-live/out3/vectors.json -01
```

```text
ok   AC-01  expect=conformant     got=conformant     R-5.2-basis
ok   AC-02  expect=conformant     got=conformant     R-5.2-basis
ok   AC-03  expect=ambiguous      got=ambiguous      R-3.5-iff MUST vs -01 R-5.2 MAY (basis present, act missing)
ok   AC-04  expect=nonconformant  got=nonconformant  R-3.5-iff (act without a basis covering this sub)
ok   AC-05  expect=nonconformant  got=nonconformant  R-5.2-shared (shared registration is no basis)
ok   AC-06  expect=nonconformant  got=nonconformant  R-3.4-iss (act object missing sub or iss)
ok   AC-07  expect=nonconformant  got=nonconformant  R-5.2-derive (actor not from basis)
ok   AC-08  expect=nonconformant  got=nonconformant  R-3.4-iss (client_profile inside act)
ok   AC-09  expect=nonconformant  got=nonconformant  R-3.5-iff (act without a basis covering this sub)
ok   RT-01  expect=conformant     got=conformant     R-5.2-refresh (carried unchanged)
ok   RT-02  expect=nonconformant  got=nonconformant  R-5.2-refresh (chain dropped)
ok   RT-03  expect=conformant     got=conformant     R-5.2-refresh (reject branch)
ok   RT-04  expect=nonconformant  got=nonconformant  R-5.2-refresh (chain changed)
ok   CC-01  expect=conformant     got=conformant     R-3.5-iff
ok   CC-02  expect=nonconformant  got=nonconformant  R-3.5-iff (client acts on own behalf, no actor separate from sub)
ok   AC-03-live expect=conformant     got=conformant     R-5.2-basis
ok   AC-05-live expect=conformant     got=conformant     R-5.2-shared (no act without basis)
text -01: 17/17 cases matched expectation
```

### check.py -01+pr32

```text
cd /tmp/aps-live/suite/candidates/aeoess-oauth-actor-profile && python3 check.py /tmp/aps-live/out3/vectors.json -01+pr32
```

```text
ok   AC-01  expect=conformant     got=conformant     R-5.2-basis
ok   AC-02  expect=conformant     got=conformant     R-5.2-basis
ok   AC-03  expect=nonconformant  got=nonconformant  R-5.2-basis / R-3.5-iff (basis present, act missing)
ok   AC-04  expect=nonconformant  got=nonconformant  R-3.5-iff (act without a basis covering this sub)
ok   AC-05  expect=nonconformant  got=nonconformant  R-5.2-shared (shared registration is no basis)
ok   AC-06  expect=nonconformant  got=nonconformant  R-3.4-iss (act object missing sub or iss)
ok   AC-07  expect=nonconformant  got=nonconformant  R-5.2-derive (actor not from basis)
ok   AC-08  expect=nonconformant  got=nonconformant  R-3.4-iss (client_profile inside act)
ok   AC-09  expect=nonconformant  got=nonconformant  R-3.5-iff (act without a basis covering this sub)
ok   RT-01  expect=conformant     got=conformant     R-5.2-refresh (carried unchanged)
ok   RT-02  expect=nonconformant  got=nonconformant  R-5.2-refresh (chain dropped)
ok   RT-03  expect=conformant     got=conformant     R-5.2-refresh (reject branch)
ok   RT-04  expect=nonconformant  got=nonconformant  R-5.2-refresh (chain changed)
ok   CC-01  expect=conformant     got=conformant     R-3.5-iff
ok   CC-02  expect=nonconformant  got=nonconformant  R-3.5-iff (client acts on own behalf, no actor separate from sub)
ok   AC-03-live expect=conformant     got=conformant     R-5.2-basis
ok   AC-05-live expect=conformant     got=conformant     R-5.2-shared (no act without basis)
text -01+pr32: 17/17 cases matched expectation
```

## Notes

- Divergences are recorded, not verdicts; the corpus may be the party at fault.
- This report certifies nothing and is not an endorsement.
