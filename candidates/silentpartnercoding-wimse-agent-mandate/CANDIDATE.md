# Candidate: silentpartnercoding-wimse-agent-mandate

Signed test vectors for draft-hulea-wimse-agent-mandate, the Agent Mandate Internet-Draft
discussed on the IETF WIMSE working group list. The vectors are in the draft's own format and
terms. This is a candidate under `docs/CANDIDATES.md`, and it adds nothing to the lab's schema,
failure classes or verifier behavior.

## Submitter

Silent Partner (GitHub: Silentpartnercoding).

## Normative target

[draft-hulea-wimse-agent-mandate-00](https://datatracker.ietf.org/doc/html/draft-hulea-wimse-agent-mandate-00),
Section 9 (validation and the Validation Result) and Appendix A (the worked example). Cases 00
to 03 follow revision -00 only.

## Source

- Repository: https://github.com/Silentpartnercoding/wimse-agent-mandate-vectors
- Commit: `52653c2d1f3622baa4d3c3c5ddebd9f5b12557ca`
- The 36 files listed in `CHECKSUMS.sha256` are byte copies of the source at that commit, each
  at the same path. `run.sh` compares each one with a fresh clone before it runs anything.
- Written for this candidate: `CANDIDATE.md`, `CHECKSUMS.sha256`, `run.sh`.

The source repository stays the canonical copy. A later revision there is a new candidate
revision here.

Not copied: the checker (`check.py`), the generator (`generate.py`), the tests (`tests/`),
`requirements.txt`, the test keys (`keys/chei.json`) and the Validation Profile (`profile/`).
`run.sh` uses them from the clone at the pin. `keys/chei.json` holds private Ed25519 test keys,
so this directory holds no private key material. `keys/chei.json`, `profile/profil.json` and
`profile/profil.digest` are the draft author's published test inputs for Appendix B, kept
unchanged in the source repository. The profile bytes are still pinned here: every
`inputs.json` carries the profile digest, and `check.py` refuses a profile whose bytes do not
match it. `trust-anchors.json` holds public keys only.

## License

Apache License 2.0, the license of the source repository, which covers every file in this
directory.

## What the vectors test

Each case is one presentation (`presentation.json`: subject token, actor token,
`mandate_evidence` and `authorization_details`), the inputs a Validator is configured with
(`inputs.json`: time T, RP identifier, profile reference, PoP outcome; `trust-anchors.json`),
and the expected Validation Result of Section 9.6 (`expected-result.json`). The artifacts are
compact JWS signed with Ed25519. `decoded.json` shows headers and payloads for reading only.

| case | what it tests | expected outcome | authority | errors |
|---|---|---|---|---|
| 00-baseline | the Appendix A presentation validates end to end | valid | established | none |
| 01-root-broader-than-powers | root `max` on `/instructedAmount/amount` is 200000.00, above the 100000.00 the Authority Assertion powers allow | invalid | refuted | authority_insufficient |
| 02-authority-not-presented | the root references an Authority Assertion the presentation leaves out | invalid | refuted | authority_missing |
| 03-authority-expired | Authority Assertion `exp` is 1792886400, before T minus `max_clock_skew` | invalid | refuted | authority_insufficient, expired |

Each negative case makes one change from the baseline. All four use T = 1792972800 and RP
`https://bank.example`. Results are compared as JSON values under Section 4.6.

## How to run

```
sh run.sh
```

Needs git, Python 3.10 or later with `venv`, and `shasum` or `sha256sum`. The clone and the
install of the pinned `requirements.txt` (including `cryptography` 43.0.0) are the network
steps. `run.sh` then runs `check.py`, regenerates every case file with `generate.py` and
compares the bytes, and runs the source's unit tests. Expected lines:

```
ok: 36 files
all cases agree with expected results
ok: rebuild is byte-identical
OK
```

## Evidence

- 2026-10-30, Silent Partner, revision `52653c2`, cases 00 to 03, Mode A with `check.py`
  (Python 3.13.5, `cryptography` 43.0.0) through `run.sh`: all four cases agree with their
  expected results, regeneration is byte-identical, and the 6 unit tests pass.
  Author-produced: the submitter wrote the vectors, `generate.py` and `check.py`.

## Known limitations

- Four cases. The three negative cases are all about the Authority Assertion. No case covers
  status, a broken delegation chain, or the enforcement side
  (Sections 9.5, 10.1 and 10.2).
- Revision -00 only. Revision -01 is expected to name the Validation Profile shape and the
  `max_lifetime` artifact types, which may change these bytes.
- The draft leaves several points open, and these vectors make one choice for each. The source
  README lists 13 such points. The ones that change expected results: which artifact an
  authority_* error carries (these vectors attach the root mandate reference), the role value
  for the sub-mandate signer (`agent_instance`), Artifact References that carry `dig` only, and
  `alternatives` listed even when the outcome is invalid.
- The PoP outcome is a Validator input (Section 9.1 item 8). No request signature or PoP proof
  is included or checked.
- One implementation. `check.py` shares no code with `generate.py`, but both have the same
  author.
- These vectors check records. They do not test a running relying party.
