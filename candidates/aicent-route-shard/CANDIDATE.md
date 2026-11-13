# Candidate: aicent-route-shard

Cases for the ROUTE_SHARD derivation of section 4.4: the derivation function
itself (SHA-256 over the ASCII of the canonical authority, first 16 octets),
the authority-only boundary (scheme, "//" and action excluded), the canonical
form boundary (uppercase is invalid input and MUST NOT be normalised, non-ASCII
is refused), the full-authority shape, and the display-form red line of
section 9.1 (the 8-hex display form MUST NOT be the sole identifier of a
subject). Derivation cases give an authority and the expected 16-octet address;
property cases give a derivation input or a pair and an outcome. This is a
candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds
nothing to the lab's schema, failure classes or verifier behavior.

The source is a published Internet-Draft rather than a proposal under
discussion: the derivation and its four properties are defined by
draft-li-rttp-iqa-addressing-02, section 4.4; the canonical-form boundary by
section 4.2; the display-form red line and the honest truncation account by
section 9.1. The expected values are anchored in the published text itself and
were checked against it sentence by sentence.

## Submitter

ShaoBao Li (Lee), author of the draft. RTTP & IQA Organization.

## Normative target

- `spec`: draft-li-rttp-iqa-addressing-02, posted 2026-11-01
  (https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02), sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` of the retrieved TXT copy.
  Sections 4.4 (The Address: ROUTE_SHARD Derivation), 4.2 (Reserved Characters
  and Exclusions) and 9.1 (The rttp scheme) are used. The draft is
  Informational and published for the public record; it is not the agreed text
  of any working group, and a later revision can change it.

Rule descriptions quote single sentences. Each case lists the sections it
rests on in `basis`.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`,
`mutate.py`. The expected addresses are computed with the standard library's
SHA-256 and asserted against the ROUTE_SHARD the source itself publishes for
the section 4.1 example authority (section 7.2.1 pins
`557c8154d3780cb78cc5fa1bd72b331c` for `f3b2a1c4.pillar.example`). No files
are copied from the sources, and no code from any implementation is used: the
checker derives the rules from the pinned text, not from any library.

## License

Apache 2.0, the license of this repository. The draft is an IETF
Internet-Draft contribution; this candidate reuses no text from it beyond
short quoted sentences for identification and rule description, names the
document and the sha256 of the retrieved copy, and adds no code from any
implementation.

## What the cases test

Sixteen cases: 3 derivation and 13 property.

| ids | rule | what is tested | basis |
|---|---|---|---|
| RS-D01 to RS-D03 | R-SHARD | the derivation: the draft example authority yields the address published in section 7.2.1; a name-intent authority and a digits-and-hyphens authority derive deterministically | sect-4.4, sect-7.2.1 |
| RS-B01, RS-B02 | R-ACTION-INDEPENDENT | different actions on one authority yield the same address; including the action would split one subject into several | sect-4.4 |
| RS-B03, RS-B04 | R-AUTHORITY-ONLY | the derivation takes the authority alone: the scheme name, // and any action are excluded | sect-4.4 |
| RS-B05 to RS-B08 | R-CANONICAL-FORM | uppercase is invalid input and MUST NOT be normalised (normalising would map two distinct strings onto one address); non-ASCII input is refused | sect-4.2, sect-4.4 |
| RS-B09, RS-B10 | R-FULL-AUTHORITY | the derivation input is the full authority intent.pillar.root; the intent segment alone is not the derivation input | sect-4.4 |
| RS-B11 to RS-B13 | R-DISTINCT-AUTHORITIES | two distinct authorities yield distinct addresses (a spot check, not a collision search); the 8-hex display form MUST NOT be used as the sole identifier of a subject — routing by it alone is nonconformant | sect-4.4, sect-9.1 |

Case statuses in `vectors.json`: all cases are `normative`. The substitution
and birthday figures of section 9.1 (approximately 2^128 and 2^64) are design
accounts, not conformance targets, and appear only in case notes.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` recomputes each derivation case's address from the authority and
scores each property case's outcome against the rule it tests, comparing both
with the declared expectations. To test an implementation, give it each case's
input, record the address it derives or the decision it produced, and run
`check.py`. `mutate.py` weakens or distorts one rule of `check.py` at a time —
wrong truncation length in both directions, uppercase lowercased before
hashing, action or scheme participating in the derivation, intent-only input,
display-form routing accepted, and always-conformant / always-nonconformant
for the property rules — and fails unless some case catches each change.

At the revision submitted, the submitter's runs on Python 3 printed `16/16
agree` and `9/9 mutants killed`, each with exit 0. These show that the checker
agrees with the expected results and that every rule has a case depending on
it, in both directions. They say nothing about any implementation, and they do
not show that the expected results are the right reading of the source.

## Evidence

No implementation has been run against these cases. The cases were reviewed by
the author against the source text section by section during construction; the
reviews are author-produced and are not runs.

## Recorded run and live report

A recorded run of this family ships with this repository: [`family_runner.py`](https://github.com/Aicent-Stack/conformance/blob/590b26b/family-runner/family_runner.py) replays every case and the full mutation battery into a single deterministic output — no timestamps, no paths, byte-replayable. The run is author-produced and is presented as such. Recorded totals for this family: 16/16 cases agree, 9/9 mutants killed, exit 0.

The full recorded-run report — per-case results, the mutation battery, run metadata, and the verbatim console output — lives on the family page at [iqa.org/conformance/aicent-route-shard/](https://iqa.org/conformance/aicent-route-shard/), sealed as a single-file site freeze ([aicent-route-shard-site-20261114a.tar.gz](https://iqa.org/seal/aicent-route-shard-site-20261114a.tar.gz)).

## Known limitations

- The source is one document at one revision. A revised draft needs a new
  revision of this candidate.
- The collision bounds of section 9.1 are properties of the construction, not
  testable behavior; RS-B11 is a distinctness spot check and does not search
  for collisions.
- The derivation cases exercise the wire-level function only; determinism
  across hosts is assumed of SHA-256 itself and is not re-measured here.
- The checker encodes one reading of the source. A correction in a later
  revision of the draft overrides it.
