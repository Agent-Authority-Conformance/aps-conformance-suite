# Candidate: aicent-lease-boundary

Cases for the lease of an attestation answer: which boundary convention an implementation may
declare and apply at the lease instant, what an expired lease still owes, how the declared answer
mode shapes the refusal when the organ cannot be reached, and which expiry a verifier checks. Each
case gives the facts at answer time and one response an implementation could produce, and states
whether that response satisfies the source text and which rule decides. This is a candidate under
`docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's schema, failure
classes or verifier behavior.

The source is a published Internet-Draft rather than a proposal under discussion: the lease, its
boundary convention and the prohibition on extending an expired lease are defined by
draft-li-rttp-iqa-addressing-02, section 6.1; the two answer modes and their normative rules by
section 6.2; the evaluation-at-the-moment-of-use rule by section 6.3; and the frame-level
verification procedure by section 7.2. The expected values are anchored in the published text
itself and were checked against it sentence by sentence.

## Submitter

ShaoBao Li (Lee), author of the draft. RTTP & IQA Organization.

## Normative target

- `spec`: draft-li-rttp-iqa-addressing-02, posted 2026-11-01
  (https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02), sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` of the retrieved TXT copy.
  Sections 6.1 (The Lease), 6.2 (Answer Modes), 6.3 (Evaluation at the Moment of Use) and the
  verification procedure of section 7.2 are used. The draft is Informational and published for the
  public record; it is not the agreed text of any working group, and a later revision can change it.

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

Fifteen cases: 9 conformant, 5 nonconformant and 1 `ambiguous`. Identifiers and times are
illustrative.

| ids | rule | what is tested | basis |
|---|---|---|---|
| LB-D01 to LB-D05 | R-DECLARED | the boundary convention of section 6.1: whether the lease instant counts as fresh or as expired is a deployment convention, so a permit under a declared inclusive boundary (D01) and an expired refusal under a declared exclusive boundary (D02) are both conformant; a declaration that contradicts use is not (D03); with no declaration the boundary answer is scored in parts and cannot be settled (D04); and a frame accepted at the instant under the verification procedure of section 7.2 does not decide the reliance convention, because frame validity and reliance are different layers (D05) | sect-6.1, sect-7.2 |
| LB-E01 to LB-E03 | R-NOEXTEND | an expired lease: an answer read past its expiry is answered as expired (E01); replaying the original observation as fresh is not (E02); reinterpreting the lease inside a locally added grace period is not (E03) | sect-6.1, sect-6.3 |
| LB-M01 to LB-M05 | R-MODE | the declared answer mode with an unreachable organ: in live mode the call is refused regardless of the age of any cached answer (M01), and a fresh cache does not rescue it (M02); in cached-lease mode a policy demanding a current observation refuses with authority_not_determined (M03) and a policy accepting lease-fresh evidence may admit the call (M04); an expired cache is refused as evidence_expired, the first applicable value (M05) | sect-6.1, sect-6.2, sect-8.1 |
| LB-W01, LB-W02 | R-WINDOW | the window length is an operator choice: an answer whose stated lease has not expired is not refused (W01), and refusing it by assuming the 120-second deployment default instead of checking the stated expiry is not (W02) | sect-6.1 |

R-DECLARED scores the undeclared case in named parts, listed in `expect_parts`, so the case can
show which part of the outcome holds and which does not. A case is ambiguous when no part is
nonconformant and one is ambiguous.

Reading rules, stated in `vectors.json`: an outcome is read as the record it presents; an absent
key is not the same as an explicit null; outcome field names are this candidate's own
representation, since the source names values and rules, not a JSON binding.

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

At the revision submitted, the submitter's runs on Python 3 printed `15/15 agree` and `17/17
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
- LB-D03 rests on a strict reading: section 6.1 says implementations SHOULD declare which boundary
  they use and does not attach an explicit consequence to a declaration that contradicts use. The
  case treats a contradicting declaration as nonconformant because a declaration that does not
  state the boundary used defeats the function the clause gives declarations.
- LB-D04 is ambiguous by design: the clause licenses both boundary readings and asks (SHOULD) for
  a declaration; with no declaration given, the answer at the instant cannot be settled either way.
- The mode cases take the never-assent mapping of an unreachable source (refused under
  authority_not_determined, never read as assent) as given; that mapping is tested by the
  aicent-grant-ref candidate and is not re-tested here. What these cases test is the
  mode-conditional refusal and the policy split of cached-lease mode.
- Mid-task halting and the calling layer's enforcement are out of scope here; only the answer the
  verification owes is tested (the basis of LB-E01 quotes the mid-task sentence for the expiry
  answer it names).
- LB-D05 reads the verification procedure of section 7.2 as a rejection floor for the envelope
  frame, distinct from the reliance convention of section 6.1; a revision that fuses the two layers
  would need a new case.
- LB-D01 to LB-D05 take `at_boundary` as a given input. They test how an implementation handles
  that boundary, not whether it correctly determines the boundary from the observation time and
  lease expiry.
- The window cases test the stated-expiry check only; the 120-second figure itself is a deployment
  observation in the source, not a conformance target.
- The checker encodes one reading of the source. A correction in a later revision of the draft
  overrides it.
