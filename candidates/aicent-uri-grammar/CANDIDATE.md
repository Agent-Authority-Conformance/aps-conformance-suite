# Candidate: aicent-uri-grammar

String-level cases for the rttp URI grammar: the ABNF of section 4.1 (three
dot-separated segments, hash-intent versus name-intent, single-segment action)
and the exclusions of section 4.2 (lowercase canonical form, no userinfo, port,
query or fragment, no percent-encoded octets in a canonical URI, no "rttps"
fallback). Each case is a URI and an expected grammar decision; the checker
re-derives the decision from the pinned text. This is a candidate under
`docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the
lab's schema, failure classes or verifier behavior.

The source is a published Internet-Draft rather than a proposal under
discussion: the ABNF and the segment rules are defined by
draft-li-rttp-iqa-addressing-02, section 4.1; the exclusions by section 4.2.
The expected values are anchored in the published text itself and were checked
against it sentence by sentence.

## Submitter

ShaoBao Li (Lee), author of the draft. RTTP & IQA Organization.

## Normative target

- `spec`: draft-li-rttp-iqa-addressing-02, posted 2026-11-01
  (https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02), sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` of the retrieved TXT copy.
  Sections 4.1 (Syntax) and 4.2 (Reserved Characters and Exclusions) are used.
  The draft is Informational and published for the public record; it is not the
  agreed text of any working group, and a later revision can change it.

Rule descriptions quote single sentences. Each case lists the sections it
rests on in `basis`.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`,
`mutate.py`. No files are copied from the sources, and no code from any
implementation is used: the checker derives the grammar from the pinned text,
not from any library.

## License

Apache 2.0, the license of this repository. The draft is an IETF
Internet-Draft contribution; this candidate reuses no text from it beyond
short quoted sentences for identification and rule description, names the
document and the sha256 of the retrieved copy, and adds no code from any
implementation.

## What the cases test

Twenty-six cases: 8 positive, 17 negative and 1 `ambiguous`.

| ids | rule | what is tested | basis |
|---|---|---|---|
| UG-P01 to UG-P03 | R-GRAMMAR | the three examples of section 4.1 (with and without action, hash-intent and name-intent forms) | sect-4.1 |
| UG-P04 to UG-P07 | R-GRAMMAR | the intent branches: exactly 8 lowhex digits take the hash-intent branch, other label-shaped strings (8 non-lowhex letters, 7 hex-shaped characters, digits and hyphens) take the name-intent branch; both forms are opaque to a client | sect-4.1 |
| UG-P08 | R-GRAMMAR | a hyphen in any segment position including last, which the ABNF literal admits | sect-4.1 |
| UG-N01 to UG-N03 | R-GRAMMAR | uppercase anywhere (intent, action, scheme prefix) is invalid input, not a formatting difference: a parser MUST NOT normalise it | sect-4.2 |
| UG-N04 | R-GRAMMAR | there is no "rttps" scheme and no fallback | sect-4.2 |
| UG-N05 to UG-N08 | R-GRAMMAR | userinfo, port, query and fragment are not defined; a URI carrying any of them is not valid | sect-4.2 |
| UG-N09 to UG-N14, UG-N17 | R-GRAMMAR | the ABNF shape: exactly three non-empty dot-separated segments, characters restricted to the segment set, the action is a single non-empty path segment, and whitespace is in no allowed set in any position | sect-4.1 |
| UG-N15, UG-N16 | R-GRAMMAR | a leading hyphen in the intent or pillar segment — see the disclosure below | sect-4.1 |
| UG-A01 | R-GRAMMAR | a percent-encoded octet: a parser MAY reject such input rather than normalising it, so both licensed decisions conform and the case cannot be settled either way | sect-4.2 |

Case statuses in `vectors.json`:

- `normative` — the expected decision follows from the ABNF and exclusions as
  written in -02.
- `authoritative-tightening` — UG-N15 and UG-N16. The section 4.1 ABNF literal
  `1*( %x61-7A / DIGIT / "-" )` admits a leading hyphen, but the published
  conformance vectors reject it, and the draft author has decided
  (2026-11-09) that the -03 revision tightens the grammar accordingly. Until
  -03 is posted these two cases test the tightened reading, and a strict
  reading of -02 alone would score them unsettled. UG-P08 records the
  complementary boundary: trailing hyphens remain ABNF-literal accepts.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` re-derives each case's grammar decision from the URI string (the
section 4.1 ABNF plus the section 4.2 exclusions and the disclosed tightening)
and compares it with the declared expectation, including the reject reason
named by the case. To test an implementation, feed it each case's URI and
record the decision it produced. `mutate.py` weakens or distorts one rule of
`check.py` at a time — uppercase normalised away, any scheme accepted, the
component exclusions lifted, segment count and emptiness relaxed, the charset
widened, the path rules relaxed, the tightening dropped, whitespace stripped
silently, percent-encoding forced to either licensed decision, and
always-accept / always-reject — and fails unless some case catches each
change.

At the revision submitted, the submitter's runs on Python 3 printed `26/26
agree` and `13/13 mutants killed`, each with exit 0. These show that the
checker agrees with the expected results and that every rule has a case
depending on it, in both directions. They say nothing about any
implementation, and they do not show that the expected results are the right
reading of the source.

## Evidence

No implementation has been run against these cases. The cases were reviewed by
the author against the source text section by section during construction; the
reviews are author-produced and are not runs.

## Recorded run and live report

A recorded run of this family ships with this repository: [`family_runner.py`](https://github.com/Aicent-Stack/conformance/blob/590b26b/family-runner/family_runner.py) replays every case and the full mutation battery into a single deterministic output — no timestamps, no paths, byte-replayable. The run is author-produced and is presented as such. Recorded totals for this family: 26/26 cases agree, 13/13 mutants killed, exit 0.

The full recorded-run report — per-case results, the mutation battery, run metadata, and the verbatim console output — lives on the family page at [iqa.org/conformance/aicent-uri-grammar/](https://iqa.org/conformance/aicent-uri-grammar/), sealed as a single-file site freeze ([aicent-uri-grammar-site-20261114a.tar.gz](https://iqa.org/seal/aicent-uri-grammar-site-20261114a.tar.gz)).

## Known limitations

- The source is one document at one revision. A revised revision (-03) needs a
  new revision of this candidate; UG-N15, UG-N16 and UG-P08 in particular
  mark the boundary the tightening text will settle.
- The iqa URI syntax (sections 5.1 and 5.2) is out of scope here; this
  candidate tests the rttp scheme only.
- The ambiguous case (UG-A01) records parser discretion the source licenses;
  it constrains neither decision and exists to keep the checker from scoring
  either choice as a violation.
- Address derivation (ROUTE_SHARD) is out of scope here; it is tested by the
  aicent-route-shard candidate.
- The checker encodes one reading of the source. A correction in a later
  revision of the draft overrides it.
