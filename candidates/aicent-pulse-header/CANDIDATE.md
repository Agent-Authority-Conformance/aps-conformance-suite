# Candidate: aicent-pulse-header

Cases for the pulse header of section 7.1: the fixed 128-octet frame layout
validated with fixed comparisons, the extension-block rules of section 7.1.1
(SPEC_REV set, FLAGS bits, ACTION grammar, length and padding, RESERVED), and
the time-and-order semantics of section 7.1.2 (TTL forwarding, TIMESTAMP age
and its boundary against standing). Frame cases are concrete 128-octet headers;
behavior cases give a frame, a role and an outcome, and state whether that
outcome satisfies the source text. This is a candidate under
`docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the
lab's schema, failure classes or verifier behavior.

The source is a published Internet-Draft rather than a proposal under
discussion: the field table and the fixed-comparison reading are defined by
draft-li-rttp-iqa-addressing-02, section 7.1; the extension-block rules and
the fail-closed rejection list by section 7.1.1; the time-field rules by
section 7.1.2; the action character set by section 4.1; the default operation
by section 4.3. The expected values are anchored in the published text itself
and were checked against it sentence by sentence.

## Submitter

ShaoBao Li (Lee), author of the draft. RTTP & IQA Organization.

## Normative target

- `spec`: draft-li-rttp-iqa-addressing-02, posted 2026-11-01
  (https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02), sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` of the retrieved TXT copy.
  Sections 7.1 (The Pulse Header), 7.1.1 (The Extension Block), 7.1.2 (Time
  Fields of the Pulse), 4.1 (Syntax) and 4.3 (Default Operation) are used. The
  draft is Informational and published for the public record; it is not the
  agreed text of any working group, and a later revision can change it.

Rule descriptions quote single sentences. Frame cases list their sections in
`basis`; behavior cases likewise.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`,
`mutate.py`. The frame bytes are computed from the documented field layout
with the submitter's V1.3.2 encoder used as a computation tool and documented,
deterministic field mutations of the positive frames; the ROUTE_SHARD is the
section 4.4 derivation of the section 4.1 example authority, tying the frame
cases to the published example. No files are copied from the sources, and no
code from any implementation is used: `check.py` derives the validation rules
from the pinned text, not from any library.

## License

Apache 2.0, the license of this repository. The draft is an IETF
Internet-Draft contribution; this candidate reuses no text from it beyond
short quoted sentences for identification and rule description, names the
document and the sha256 of the retrieved copy, and adds no code from any
implementation.

## What the cases test

Twenty-four cases: 3 positive frames, 9 negative frames and 12 behavior cases.

| ids | rule | what is tested | basis |
|---|---|---|---|
| PH-P01 to PH-P03 | R-FRAME | frames that MUST validate: URI-anchored with an action, actionless and unanchored (either, both or neither), and a pre-extension frame (SPEC_REV 0, block all zero) | sect-7.1, sect-7.1.1 |
| PH-N01 to PH-N09 | R-FRAME | the fail-closed rejection list of section 7.1.1 and the field rows of section 7.1: ACTION_LEN greater than 16, ACTION characters outside the section 4.1 set, non-zero ACTION padding, SPEC_REV outside the known set, SPEC_REV 0 with a non-zero block, SPEC_REV 1 with non-zero RESERVED, unknown FLAGS bits, VERSION_ID other than 130, wrong magic | sect-7.1, sect-7.1.1 |
| PH-B01, PH-B02 | R-ANCHORED-ROUTING | routing between nodes MUST require URI_ANCHORED to be set; a clear bit confines the ROUTE_SHARD to local dispatch | sect-7.1.1 |
| PH-B03 to PH-B05, PH-B12 | R-UNKNOWN-VERB | an unrecognised action verb MUST NOT be scored as safe via the default operation; it MUST either require explicit authorisation or be rejected — silent admission is neither | sect-7.1.1, sect-4.3 |
| PH-B06 to PH-B09 | R-TTL | a receiver MUST NOT forward a pulse received with TTL 0, MUST decrement before forwarding, and consumes-where-received places no trust in the field | sect-7.1.2 |
| PH-B10, PH-B11 | R-TIMESTAMP | the pulse age is derivable offline from the bytes alone, and MUST NOT be treated as a statement about the subject's standing | sect-7.1.2 |

Case statuses in `vectors.json`: all cases are `normative`. The two field-row
cases (PH-N08 VERSION_ID, PH-N09 magic) rest on the field table of section
7.1, which fixes the values a reader validates with fixed comparisons.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` re-derives each frame case's decision from the frame bytes (fixed
comparisons against the section 7.1 field rows plus the section 7.1.1
fail-closed list) and scores each behavior case's outcome against the rule it
tests, comparing both with the declared expectations. To test an
implementation, feed it each case's frame, record the decision or forwarding
behavior it produced, and run `check.py`. `mutate.py` weakens or distorts one
rule of `check.py` at a time — each frame check dropped, always-accept and
always-reject for frames, the anchored-routing requirement inverted, the
unknown-verb rule relaxed in two directions, the TTL rules relaxed in two
directions, the timestamp boundary dropped, and always-conformant /
always-nonconformant for behavior — and fails unless some case catches each
change.

At the revision submitted, the submitter's runs on Python 3 printed `24/24
agree` and `19/19 mutants killed`, each with exit 0. These show that the
checker agrees with the expected results and that every rule has a case
depending on it, in both directions. They say nothing about any
implementation, and they do not show that the expected results are the right
reading of the source.

## Evidence

No implementation has been run against these cases. The frames were reviewed
by the author against the source text section by section during construction;
the reviews are author-produced and are not runs.

## Recorded run and live report

A recorded run of this family ships with this repository: [`family_runner.py`](../../family-runner/family_runner.py) replays every case and the full mutation battery into a single deterministic output — no timestamps, no paths, byte-replayable. The run is author-produced and is presented as such. Recorded totals for this family: 24/24 cases agree, 19/19 mutants killed, exit 0.

The full recorded-run report — per-case results, the mutation battery, run metadata, and the verbatim console output — lives on the family page at [iqa.org/conformance/aicent-pulse-header/](https://iqa.org/conformance/aicent-pulse-header/), sealed as a single-file site freeze ([aicent-pulse-header-site-20261109c.tar.gz](https://iqa.org/seal/aicent-pulse-header-site-20261109c.tar.gz)).

## Known limitations

- The source is one document at one revision. A revised draft needs a new
  revision of this candidate.
- SEQUENCE_ID is governed by SHOULD/MAY clauses (monotonic assignment,
  duplicate detection) and is not exercised here; no case depends on a
  receiver's duplicate handling.
- PRIORITY is an operator-assigned scheduling weight with no normative
  receiver rule in the source, so no case tests it beyond its fixed offset.
- The behavior cases score declared outcomes, not live network behavior; how
  an implementation actually forwards or authorises is outside what a
  candidate can observe.
- The checker encodes one reading of the source. A correction in a later
  revision of the draft overrides it.
