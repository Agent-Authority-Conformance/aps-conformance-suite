# Candidate: cirisai-ceg-rows

Known-answer cases for the signed row statement of the CIRIS Epistemic Grammar (CEG): a COSE_Sign1
over a deterministically encoded CBOR payload, with one composite ML-DSA-65 and Ed25519 signature,
whose issuer and subject are CWT claims. The cases ask three things of a reader. Does it compute
the row id and the statement id? Does it give each malformed, mis-encoded or mis-signed statement
its reason? Does it bind the signing key to the identity the statement claims as issuer? This is a
candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's
schema, failure classes or verifier behavior.

The scope is delegated authority and the evidence produced under it: a CEG row is the signed
record of a claim, a delegation, a replacement, a withdrawal or a recantation between named keys.

## Submitter

Eric Moore, author of the draft. CIRIS L3C.

## Normative target

- `spec`: draft-moore-scitt-ciris-ceg-03
  (https://datatracker.ietf.org/doc/html/draft-moore-scitt-ciris-ceg-03), sha256
  `9ec525d710fc310f6ac11086465064de9da0350db0cb23df75ae6baaa1c6ae02` of the TXT. Section 2 (the signed statement), Section 4 (encoding), Section 5 (names),
  Section 6 (signatures, keys, the verification order), Section 8 (the checks and their reasons)
  and Appendix A (CDDL) are used. The draft is Informational and individual; it is not the agreed
  text of any working group, and a later revision can change it.
- The draft cites the CIRIS Constitution 1.0-rc21 (CIRISAI/CIRISConstitution, tag `v1.0-rc21`,
  commit `b016df47a7697b6544e34177541be442ff6f24e9`) for the family registry and the rules it
  does not restate.

## Source

The cases are derived from two files of CIRISAI/CIRISVerify at the tag `v23.3.0`, commit
`ffd7af1f1b53`, under `src/ciris-verify-core/tests/vectors/edition2/`:

| file | sha256 |
|---|---|
| `row_statements_v3.json` | `0c072516dea1d89132567e0f343ca47a2183df79697651685aa557d739cdf920` |
| `key_of_iss_v1.json` | `bd584d9b31b7271dc86c05a29eec75044b5fe74aae8dd586701a227f09001333` |

Those files carry each case's expected answer and a description beside its bytes, so they are not
copied here. `split.py` reads them and writes the sealed inputs and, apart from them, the
expected results. Appendix B of the draft gives the same two digests.

The source files were written by a generator that shares no code with the verifier: its own CBOR
encoder, dilithium-py for ML-DSA-65 (FIPS 204, deterministic variant) and pyca/cryptography for
Ed25519. The generators are beside the files in the source repository.

## License

Apache 2.0, the license of this repository, for every file of this directory. CIRISVerify as a
whole is AGPL-3.0. CIRIS L3C holds the copyright in the two source files and licenses the files
derived from them here under Apache 2.0; `NOTICE` says so. No verifier code is copied.

## What the cases test

154 cases in `inputs/cases.json`. Each has an opaque id, a `level` and its bytes. It carries no
expectation, no description and no source id, and the cases are sorted by the opaque id, so
neither a name nor the order tells a reader the answer.

| level | cases | what a reader is given | what it answers |
|---|---|---|---|
| `statement` | 73 | a statement's bytes and the keys held (`held_key_seeds`), or key records and a directory kind | Valid with the row id, the statement id, `kid` and `iss`; Invalid with a reason; or Waiting with what is missing |
| `family` | 47 | a statement, the keys held, and the family model named in `model` | the same, read under the family's authorship rule |
| `payload` | 17 | a key record's payload | whether the record meets its end rule, and the reason if not |
| `value` | 11 | one CBOR value | the form of a reference, and its digest |
| `object` | 6 | a statement of a signed object that is not a row | Valid with the object id, or Invalid with a reason |

The `statement` cases include the four valid statements and 42 refusals of the row statements
file, and the key-of-issuer cases: a key signing under its own identity, a key signing under
another's, a rotated successor, and a chain with a link not held.

A reason is one of the strings of Section 8 of the draft, written `invalid:` and the reason.
`expected.json` maps each opaque id to its source file, section and source id, its expected
answer and the source's one-line description.

`inputs/keys.json` gives the composite public key of each `kid` the cases use. A key seed `n`
is ML-DSA-65 seed `[n]*32` and Ed25519 seed `[n+100]*32`; the private keys are test keys and
are derivable from the seeds by design.

## How to run

To read the cases, use `inputs/` and the draft only. Compare with `expected.json` afterwards.

To reproduce the split from the pinned source:

```
git clone https://github.com/CIRISAI/CIRISVerify && cd CIRISVerify && git checkout ffd7af1f1b53
python3 -I <this directory>/split.py --source src/ciris-verify-core/tests/vectors/edition2 --check
```

`split.py` checks each source file against its SHA-256 first, and with `--check` exits 1 if what
it would write differs from the committed files. At the revision submitted it printed
`split: 154 cases, 6 public keys; compared` with exit 0. That shows the inputs and expected
results here are the source's, nothing more.

## Evidence

Author-produced only. CIRISVerify's own tests replay both source files at v23.3.0
(`tests/edition2_row_vectors_v3.rs`, `tests/edition2_key_of_iss_vectors.rs`), and the verifier
and the generator share an author's organisation. An outside reviewer of the draft, credited in its acknowledgments, ran
eight scenarios of his own and the 24 key-of-issuer cases against v23.3.0 and reported them
passing; that run is not recorded in this lab.

No implementation written from the draft's text alone has been run against these cases.

## Known limitations

- The draft is one document at one revision. A revised draft needs a new revision of this candidate.
- The reason strings are the verifier's, as its vector files carry them. The draft lists them in
  Section 8 and says that the specification it cites names only some of them at 1.0-rc21. A
  reader that reaches the right answer under a differently worded reason has found a naming
  difference, not a behavioural one.
- The `family` cases need the family registry of the cited specification, which the draft does
  not restate. A reading from the draft's text alone covers the `statement`, `payload`,
  `value` and `object` levels.
- The size bound (1 MiB) and the two substrate-level admission tokens of the draft's Table 4 other
  than the row type have no case here.
- The composite algorithm identifier, -70100, is from the private-use range, and the drafts that
  define the composite signature are not yet RFCs.
- The source files predate two rulings of 1.0-rc21 that a later vector file (v4, at CIRISVerify
  v23.3.2) covers. This candidate stays on the files the draft pins.
- The cases cover verification of a statement. They do not cover admission as a whole: rosters,
  counted rows across several holders, withdrawal rules and the halt are outside them.
