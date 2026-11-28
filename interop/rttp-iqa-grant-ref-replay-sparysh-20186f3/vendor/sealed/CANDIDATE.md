# Candidate: aicent-grant-ref

Cases for the response semantics of an attestation answer: which refusal value the closed
vocabulary owes, when the observation member must be null, and which structure members every
response carries. Each case gives the facts at answer time and one response an implementation could
produce, and states whether that response satisfies the source text and which rule decides. This is
a candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's
schema, failure classes or verifier behavior.

The source is a published Internet-Draft rather than a proposal under discussion: the closed
refusal vocabulary and the priority order are defined by draft-li-rttp-iqa-addressing-02, section
8.1, and the grant reference structure and the null rule for the observation member by section 8.2.
The same five refusal values and their priority order appear in the lab's lease-revocation-axes
revision 3 (#191), based on proposals discussed on the public-agentprotocol list. The lab's
reference model and the submitter's separately written runner (#194) have both been exercised
against revision 3. Both results are author-produced under the lab's run classification. The
expected values are anchored in the published text itself and were checked against it sentence by
sentence.

## Submitter

ShaoBao Li (Lee), author of the draft. RTTP & IQA Organization.

## Normative target

- `spec`: draft-li-rttp-iqa-addressing-02, posted 2026-11-01
  (https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02), sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` of the retrieved TXT copy.
  Section 8.1 (Refusal Reasons) and section 8.2 (Grant Reference) are used. The draft is
  Informational and published for the public record; it is not the agreed text of any working
  group, and a later revision can change it.

Rule descriptions quote single sentences. Each case lists the sections it rests on in `basis`.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`, `mutate.py`. No files are
copied from the sources. Rule descriptions quote single sentences.

## License

Apache 2.0, the license of this repository. The draft is an IETF Internet-Draft contribution; this
candidate reuses no text from it beyond short quoted sentences for identification and rule
description, names the document and the sha256 of the retrieved copy, and adds no code from any
implementation.

## What the cases test

Twenty-five cases: 11 conformant, 12 nonconformant and 2 `ambiguous`. Identifiers and times are
illustrative.

| ids | rule | what is tested | basis |
|---|---|---|---|
| GR-P01 to GR-P06, GR-P08 | R-ORDER | the priority order is part of the definition: the reason is the first value in the list whose condition applies, including mismatch over expiry (P01/P02), expiry over revocation (P03/P04), mismatch over revocation (P05), all three (P06), and operation_not_permitted alone (P08) | sect-8.1 |
| GR-P09 | R-ORDER | no condition applies, so the reason must be null; emitting a refusal value without a condition is not conformant | sect-8.1 |
| GR-P07, GR-N04 | R-NOTDET | an unreachable source, or an observation that predates the request, ends in authority_not_determined and is never read as assent; N04 flips to a permit on a diagnostic read, which does not participate in authorisation | sect-8.1, sect-8.2 |
| GR-N01 to GR-N03, GR-N05, GR-N06 | R-NULLOBS | observation_as_of_ms is null whenever the observation the answer relied on is absent or not fresh, even if a later successful observation exists (N01/N02/N03); a diagnostic read after the relied-on evidence expired neither backfills the member (N03) nor renews evidence (N05/N06) | sect-8.2 |
| GR-C01 to GR-C04 | R-CLOSED | the set is closed: no affirmative "granted" value (C01), a response without its reason is not conformant (C02), no sixth value (C03), and null reason over the set is the only representation of permitted (C04) | sect-8.1 |
| GR-G01 to GR-G04 | R-GRANTREF | every response, permit or refusal, carries the five members: grant, evidence_id, issued_at_ms, expires_at_ms, observation_as_of_ms; each of G02 to G04 drops one | sect-8.2 |
| GR-A01, GR-A02 | R-ORDER, R-NOTDET | open readings, scored in parts: a correct value computed over an operator label (A01), and a revocation one millisecond after the relied-on observation (A02) | sect-8.1, sect-8.2 |

R-NOTDET and R-ORDER score the ambiguous cases in named parts, listed in `expect_parts`, so a case
can show which part of an outcome holds and which does not. A case is ambiguous when no part is
nonconformant and one is ambiguous.

Reading rules, stated in `vectors.json`: an outcome is read as the record it presents; an absent
key is not the same as an explicit null; outcome field names are this candidate's own
representation, since the source names values and structure members, not a JSON binding.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` recomputes each case's verdict from its input and outcome, compares the verdict with
`expect` and the parts with `expect_parts`. To test an implementation, give it each case's input,
replace `outcome` with the response it produced, and run `check.py`. `mutate.py` weakens or
distorts one rule of `check.py` at a time, including a version of every rule that always answers
nonconformant and one that always answers conformant, and fails unless some case catches each
change.

At the revision submitted, the submitter's runs on Python 3 printed `25/25 agree` and `21/21
mutants killed`, each with exit 0. These show that the checker agrees with the expected results and
that every rule has a case depending on it, in both directions. They say nothing about any
implementation, and they do not show that the expected results are the right reading of the source.

## Evidence

No implementation has been run against these cases. The cases were reviewed by the author against
the source text section by section during construction; the reviews are author-produced and are not
runs.

## Known limitations

- The source is one document at one revision. A revised draft needs a new revision of this
  candidate.
- GR-A01: section 8.1 says a refusal computed over labels, opinions, or unrecorded context alone is
  not auditable, and producing one is not a conformance target of the section. It does not state
  what verdict the response itself earns, so the case is scored in parts and the computation source
  is ambiguous.
- GR-A02: section 8.2 says a revocation arriving just before or just after an invocation ends is a
  boundary no protocol erases, and names the record the response owes; which answer that boundary
  requires is settled, if at all, by the evaluation rules the draft references, which this candidate
  does not cover. The case is scored in parts and the boundary call is ambiguous.
- The five members are tested for presence only. Value formats, identifier syntax, and the
  relationship between expires_at_ms and the lease rules of the draft's section 6 are not covered.
- GR-N05 and GR-N06 encode the clause that diagnostic reads "do not renew evidence"
  conservatively: the renewal reading fires only when a diagnostic read is in play and the response
  pushes expires_at_ms past the grant's own recorded expiry. An implementation that re-issues the
  grant out of band is outside these cases.
- The checker encodes one reading of the source. A correction in a later revision of the draft
  overrides it.
