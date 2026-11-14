# Candidate: aicent-ae128-fail-closed

Byte-level fail-closed cases for the attestation envelope of section 7.2: the
parse-time rejection rules a receiver MUST apply before any cryptographic work,
the canonical HMAC rule whose coverage makes rewrites of the organ tag, the
nonce and the standing byte detectable, and the published test vector that any
implementation MUST reproduce byte for byte. Every case is a concrete
128-octet frame, and the checker re-derives the parse and verification
decisions from the frame bytes alone, using only the rules the source text
states and the test key the source text itself publishes. This is a candidate
under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to
the lab's schema, failure classes or verifier behavior.

The source is a published Internet-Draft rather than a proposal under
discussion: the frame layout, the standing closed set, the canonical HMAC rule
and the four-step verification procedure are defined by
draft-li-rttp-iqa-addressing-02, section 7.2; the published positive frame and
its parameters by section 7.2.1. The expected values are anchored in the
published text itself and were checked against it sentence by sentence.

## Submitter

ShaoBao Li (Lee), author of the draft. RTTP & IQA Organization.

## Normative target

- `spec`: draft-li-rttp-iqa-addressing-02, posted 2026-11-01
  (https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02), sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` of the retrieved TXT copy.
  Sections 7.2 (The Attestation Envelope) and 7.2.1 (Test Vector AE128-VECTOR-1)
  are used. The draft is Informational and published for the public record; it
  is not the agreed text of any working group, and a later revision can change
  it.

Rule descriptions quote single sentences. Each case lists the sections it
rests on in `basis`.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`,
`mutate.py`. The frame bytes are computed from the documented parameters of
section 7.2.1 and documented, deterministic mutations of the published
positive frame (the same mutation definitions the submitter's package
generator uses); nothing is hand-typed. No files are copied from the sources,
and no code from any implementation is used: `check.py` derives the parse and
HMAC rules from the pinned text, not from any library.

## License

Apache 2.0, the license of this repository. The draft is an IETF
Internet-Draft contribution; this candidate reuses no text from it beyond
short quoted sentences for identification and rule description, names the
document and the sha256 of the retrieved copy, and adds no code from any
implementation.

## What the cases test

Twenty-one cases: 1 positive, 13 parse-negative and 7 tamper-negative. The
positive case is the frame published in section 7.2.1; the build step asserts
it byte for byte against that published frame.

| ids | rule | what is tested | basis |
|---|---|---|---|
| AE-P01 | R-REPRODUCE | the published vector AE128-VECTOR-1: parse accepts it and verification passes under the draft-published test key | sect-7.2.1 |
| AE-N01 to AE-N06, AE-N08 to AE-N10 | R-PARSE-FAIL-CLOSED | the step (1) rejection list of section 7.2: wrong length, wrong magic, wrong version, wrong or undefined algorithm, standing byte outside the closed set, nonzero reserved or extension fields | sect-7.2 |
| AE-N07, AE-N11 | R-PARSE-FAIL-CLOSED | two fail-closed checks the step (1) list does not name: the unassigned flags bits and the US-ASCII charset of the organ tag; end-to-end cases — the same mutation also breaks the attestation, so a receiver that reports only a final rejection passes them without attributing the cause; proposed behavior, see the disclosure below | sect-7.2 |
| AE-N12, AE-N13 | R-PARSE-FAIL-CLOSED | the same two checks with the attestation recomputed and valid under the canonical rule, so a rejection can come only from the parser check, whatever order an implementation checks in: the parser-isolated variants of AE-N07 and AE-N11 | sect-7.2 |
| AE-T01 to AE-T07 | R-HMAC-COVERS-FRAME | the canonical rule: the attestation field covers the entire frame with the attestation field itself zeroed, so a flipped attestation bit, an altered organ tag, nonce, standing or lease, a swapped intent_shard and an attestation produced under a different key all fail verification | sect-7.2 |

Case statuses in `vectors.json`:

- `normative` — the expected rejection or verification failure follows from
  the step (1) list or the canonical rule as written.
- `authoritative-tightening` — AE-N07 and AE-N12 (flags 0x0100) and AE-N11
  and AE-N13 (organ tag 0xFF) rest on the field rows ("unassigned; sent as 0x0000" / "exactly 8
  octets of US-ASCII") rather than the step (1) list, which does not name
  them. The draft author has decided (2026-11-09) that the -03 revision adds
  both to the MUST-reject list; until that revision is posted these two cases
  test the tightened reading, and a strict reading of -02 alone would score
  them unsettled.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` re-derives each case's parse decision from the frame bytes (the
step (1) list plus the two disclosed field-row checks) and, for parseable
frames, the verification decision under the draft-published test key, and
compares both with the declared expectations. To test an implementation, feed
it each case's frame and record the parse and verification decisions it
produces. `mutate.py` weakens or distorts one rule of `check.py` at a time —
each step (1) check dropped, both disclosed checks dropped, always-accept and
always-reject in both stages, and three distortions of the HMAC coverage
(omitted zeroing, truncated coverage, always-pass, always-fail) — and fails
unless some case catches each change. Parse mutants are scored against all
cases; verify mutants only against the cases that reach verification, so a
kill is never borrowed across stages.

At the revision submitted, the submitter's runs on Python 3 printed `21/21
agree` and `15/15 mutants killed`, each with exit 0. These show that the
checker agrees with the expected results and that every rule has a case
depending on it, in both directions. They say nothing about any
implementation, and they do not show that the expected results are the right
reading of the source.

## Evidence

No implementation has been run against these cases. The frames were reviewed
by the author against the source text section by section during construction;
the reviews are author-produced and are not runs.

## Recorded run and live report

A recorded run of this family ships with this repository: [`family_runner.py`](https://github.com/Aicent-Stack/conformance/blob/590b26b/family-runner/family_runner.py) replays every case and the full mutation battery into a single deterministic output — no timestamps, no paths, byte-replayable. The run is author-produced and is presented as such. Recorded totals for this family: 21/21 cases agree, 15/15 mutants killed, exit 0.

The full recorded-run report — per-case results, the mutation battery, run metadata, and the verbatim console output — lives on the family page at [iqa.org/conformance/aicent-ae128-fail-closed/](https://iqa.org/conformance/aicent-ae128-fail-closed/), sealed as a single-file site freeze ([aicent-ae128-fail-closed-site-20261114a.tar.gz](https://iqa.org/seal/aicent-ae128-fail-closed-site-20261114a.tar.gz)).

## Known limitations

- The source is one document at one revision. A revised draft needs a new
  revision of this candidate.
- Verification step (2) of section 7.2 (lease_expiry against the receiver's
  clock) is time-dependent and is not exercised here; the lease boundary is
  tested by the aicent-lease-boundary candidate.
- Step (4) (interpreting the standing byte) is semantics, not wire encoding,
  and is out of scope here; the four values of the closed set are exercised
  only as parse-level accept/reject boundaries.
- AE-N07, AE-N11, AE-N12 and AE-N13 are `authoritative-tightening` cases
  (see above); a reader applying only the step (1) list of -02 would not
  derive their expectations. These cases remain proposed behavior,
  clearly distinguished from the requirements of -02; they will be
  reassessed when the -03 revision is published.
- AE-N07 and AE-N11, as frozen, cannot attribute their rejection: the same
  mutation breaks the attestation, so the case passes for an implementation
  that reports only a final rejection. AE-N12 and AE-N13 carry the
  parser-isolated form; the end-to-end form is kept for the fail-closed
  discipline itself and overlaps the mutation battery by construction.
- The HMAC coverage distortions are caught by the positive frame itself (any
  coverage change alters the canonical frame's MAC), so the tamper cases are
  not their only witnesses.
- The checker encodes one reading of the source. A correction in a later
  revision of the draft overrides it.
