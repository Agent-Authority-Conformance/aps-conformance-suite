# Run classification audit, 2026-08-29

Every record under `interop/` and every family under `fixtures/cross-stack/`, classified under
the single definition in CONTRIBUTING.md (policy commit 4ce9421): Mode A / Mode B says how a
claim was checked; author-produced / independent says whether the runner authored the vectors,
the claim inputs, or the implementation whose behavior or output supplied the recomputation. A
thin harness that only invokes independently authored implementations or primitives and
compares their outputs does not make a record author-produced; a harness that itself decides
the claimed semantic result is part of the implementation.

Classification is per claim, not per directory. This document is the current classification.
Historical records are not rewritten; where a record materially misstates its own
classification, a dated clarification is appended, text given below. Where a claim cannot be
classified from the record without reading the harness source, it is marked INDETERMINATE and
the source check is named.

Placement of each clarification follows the record's digest set: where the target file is listed in the record's CHECKSUMS.sha256 or SHA256SUMS.txt, the clarification is recorded in CLARIFICATIONS.md beside the record and the target file is unchanged; where it is not listed, the clarification is appended at the end of the target file. The text of a clarification does not depend on its placement.

Reading used for every row: the record's own text at suite main 3feec34. Pins are quoted as
recorded and are not changed.

## Table

| record | layer / claim | runner | implementation supplying the recomputation | Mode | authorship | basis | action |
|---|---|---|---|---|---|---|---|
| interop/a2a-go-368-jcs | a2a-go PR #368 canonical.go at 411e3e81 reproduces the 10 canonical-bytes v2 vectors | aeoess | a2a-go candidate (kuangmi-bit), not ours | B | author-produced | the runner authored the vectors (claim inputs); the implementation is external | classification absent: append clarification A1; append successor note S1 |
| interop/a2a-go-368-jcs-ea003f9 | same claim at ea003f9, two decode modes reported separately | aeoess | a2a-go candidate at ea003f9 | B | author-produced | same relationship | classification absent: append clarification A1 |
| interop/aae-envelope | the shipped APS verifier decides four MoltyCel AAE chain vectors as declared | aeoess | agent-passport-system (ours) plus verify.ts adapter (ours, maps AAE to APS and decides) | A | author-produced | runner authored the implementation under test and the adapter that decides | classification absent: append clarification A2 |
| interop/arpa-v0.9.5-1ec3008 | ARPA release gate `make release-check-all`, eight targets, reproduces at tag v0.9.5 | aeoess | ARPA's own gate and tests | A | independent | runner authored neither vectors nor implementation; reuse of the documented path | classification absent: append clarification A3 |
| interop/arpa-v0.9.5-1ec3008 | nine authority-evaluation vectors recomputed from specification text by recompute.py | aeoess | recompute.py: `evaluate()` written by the runner from the spec text, stdlib json and datetime only | B | author-produced | source read: the harness decides the evaluation verdict; no third-party implementation supplies it | append clarification A3 (covers both layers) |
| interop/attenu-guard-0.6.0 | attenu-guard `_canonical_json` against canonical-bytes v1+v2 | aeoess | attenu-guard 0.6.0 (theirs) | B | author-produced | runner authored the vectors | Mode labels absent (authorship stated): append clarification A4 |
| interop/attenu-guard-0.6.0 | clean-room verifier for draft-asor-wimse-00 over the seven vectors | aeoess | cleanroom verifier (written by the runner, decides the verdicts) | B | author-produced | harness decides the semantic result | covered by A4 |
| interop/attenu-guard-0.6.1 | both directions | aeoess | as above, eighth vector | B | author-produced | record already carries both labels correctly | none |
| interop/ca2a-validity-window-d3db81c | ca2a conformance profile incl. ACTION-012/013, DELEG-007..009 reproduces at d3db81cd | aeoess | ca2a-runtime 0.2.1 (theirs) via its own pytest | A | independent | runner authored neither vectors nor implementation | no axis stated: append clarification A5 |
| interop/ethers-oracle-safety-check-9b4ffee | EIP-712 layer of oracle-safety-check at PR #32 head 9b4ffee recomputed with ethers 6.17.0 | aeoess | ethers TypedDataEncoder / recoverAddress (third party) | B | independent | record's own statement checks: vectors by imokokok, implementation by ethers, thin harness | labels correct; append erratum E1 withdrawing the pin-replacement sentence |
| interop/mih-sato-composition-00 | 27 composition-pack cases at emilia-protocol PR 521 / 30916c8 reproduce their expectations | aeoess | two from-scratch adapters written by the runner (canonicalizer, digest form, fourteen join checks), Node builtins and Python stdlib only | B | author-produced | the adapters decide the semantic result and were written by the runner; "independent" in the record used the older reading (not run by the pack's authors), which is a true fact but not this label | append erratum E2 |
| interop/scitt-cose-vectors-ietf126 | six SCITT COSE v1 vectors at tag vectors-ietf126 / 529515b reproduce their verdicts; negatives fail at declared stage | aeoess | from-scratch TypeScript verifier written by the runner (CBOR from RFC 8949, COSE_Sign1 from RFC 9052, inclusion proof from RFC 9162) | B | author-produced | same reasoning as mih-sato; the record's "independent verification run" used the older reading | append erratum E3 |
| interop/x402-receipts-debc94f | x402-receipts vitest suite reproduces at debc94f (seven vectors, five negatives) | aeoess | x402-receipts 0.5.1 (theirs) via its own test runner | A | independent | reuse of the documented path, nothing authored by the runner | classification absent: append clarification A6 |
| interop/x402-receipts-debc94f | envelopeDigest values recomputed by recompute.py, Python stdlib | aeoess | recompute.py: hand-written JCS (`utf16_code_units`, `js_number`, `jcs`) by the runner; only SHA-256 is a primitive | B | author-produced | source read: the canonicalizer that produces the preimage is the runner's code | append clarification A6 (covers both layers) |
| fixtures/cross-stack/aat-amdal | issuer Ed25519 signature over each AAT token against the pinned AgentLair JWKS kid | aeoess | Python `cryptography` library (third party), runners/aat_runner.py as harness | B | independent | signature check is a primitive call; vectors and issuer by AgentLair | none; row already correct |
| fixtures/cross-stack/aat-amdal | window bounds evaluated against `verification_time` | aeoess | runners/aat_runner.py: `parse_instant` and hand-written bound comparisons by the runner | B | author-produced | source read: the harness decides the window verdict; the 2026-08-28 row said independent | append clarification A7; add the layer to docs/OPEN-RUNS.md in the same commit |
| fixtures/cross-stack/action-ref-v1-negatives | five positive action_ref digests | aeoess | shipping computeExternalActionRefV1 (ours) plus stdlib recompute | B | author-produced | record already says so; on OPEN-RUNS | none |
| fixtures/cross-stack/action-ref-v1-negatives | nine drifted claimed_action_ref digests and failure stages | aeoess | as above | B | author-produced | as above | none |
| fixtures/cross-stack/nobulex-bilateral-v0 | canonical preimage of each vector under the integer-epoch profile | aeoess | run.mjs `jcsFlat` (Object.keys().sort() plus JSON.stringify), written by the runner | B | author-produced | source read: hand-written canonicalization; it is cross-checked against the vector's own `expected_canonical_preimage` where present, which is a fact to record, not an independence source | append clarification A7; OPEN-RUNS row for this layer |
| fixtures/cross-stack/nobulex-bilateral-v0 | SHA-256 of the vector-supplied preimage against expected_action_ref | aeoess | node:crypto sha256 over `expected_canonical_preimage` | B | independent | primitive over a counterparty-supplied input; the runner authored neither | none; this is the layer the 2026-08-28 row can keep, restated per A7 |
| fixtures/cross-stack/nobulex-bilateral-v0 | two-profile comparison via computeExternalActionRefV1 | aeoess | APS SDK (ours) | B | author-produced | record says so; on OPEN-RUNS | none |
| fixtures/cross-stack/receipts-amdal | did:key resolution of the signer | aeoess | receipt_runner.py `b58decode` and multicodec check, written by the runner | B | author-produced | source read: hand-written decoder decides the resolution result | append clarification A7; OPEN-RUNS row |
| fixtures/cross-stack/receipts-amdal | RFC 8785 canonical bytes with `signature` excluded | aeoess | `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`, a stdlib primitive; the record states why it equals JCS for string-only ASCII-key envelopes | B | independent | thin call to a primitive the runner did not write; the equivalence argument is stated in the record | none |
| fixtures/cross-stack/receipts-amdal | Ed25519 signature over the canonical bytes | aeoess | `cryptography` Ed25519PublicKey.verify (third party) | B | independent | primitive call; the record's "Python stdlib" wording is imprecise (cryptography is a dependency) and A7 states it | append clarification A7 (wording only) |
| fixtures/cross-stack/receipts-amdal | receipt_id recomputation under the issuer's formula | aeoess | hashlib sha256 over the issuer's stated prefix plus the json.dumps primitive | B | independent | primitives only over the issuer's stated formula | none |
| fixtures/cross-stack/receipts-aeoess | Gate B recompute of both preimages, chain root, receipt ids | aeoess | runners/aeoess_receipt_runner.py, written by the runner | B | author-produced | the record itself declines the word independent for the co-signer relationship; vectors are ours | add the two-axis row to the family's Verification split (family is ours; author-produced is the honest row); no erratum needed, the text is already accurate |
| fixtures/cross-stack/synthetic | aat-synthetic-regression.json | aeoess | runners/generate_synthetic_regression.py (ours, seeded) | n/a (generated, not a run) | author-produced | no SOURCE.md or README exists for this directory | add SOURCE.md stating what it is and that it is not an external family (Track B, not an erratum) |

## What the table shows

Every claim is classified; the eight that could not be read from the records alone were
resolved by reading the five harness files (`interop/arpa-v0.9.5-1ec3008/recompute.py`,
`interop/x402-receipts-debc94f/recompute.py`, `fixtures/cross-stack/nobulex-bilateral-v0/run.mjs`,
`runners/aat_runner.py`, `runners/receipt_runner.py`). The line applied, claim by claim: code
the runner did not write (hashlib, node:crypto, `cryptography`, `json.dumps` with parameters,
ethers, rfc8785, a counterparty's own test gate) is a primitive; code the runner wrote that
produces the preimage, decodes the identifier or evaluates the rule is the runner's
implementation. Five layers labeled independent on 2026-08-28 move to author-produced under
that line (aat window bounds, nobulex hand-written preimage, receipts-amdal did:key, plus the
two interop recompute scripts that carried no label); three stay independent because they are
primitive calls over counterparty-supplied inputs.

Two records used "independent" under the older reading (a run by a party other than the
vector authors). That fact remains true and can be stated as a fact. It is not this label.
Both records get an erratum; their observations stand unchanged.

One systemic consequence, stated for the maintainer rather than decided here: under the
single definition, a clean-room implementation written by the runner is the runner's
implementation, so a maintainer-written clean-room run is author-produced however far it is
from the counterparty's code. Independent runs of a counterparty's vectors by this lab's
maintainer are therefore possible only through third-party primitives or third-party
implementations (rfc8785, ethers, `cryptography`, the counterparty's own gate). That is
coherent and it is what #42 established. It also means several rows written on 2026-08-28 under
"independent" may move to OPEN-RUNS after the source read. If that is not the intended reading
of "primitive", the place to say so is CONTRIBUTING.md, once, before any label is applied.

## Proposed appended text (not applied; CC applies verbatim after approval)

A1, both a2a-go records, appended at the end of RUN.md:

    Classification, added 2026-08-29: Mode B (the external candidate implementation
    recomputed this corpus's vectors); author-produced (the runner authored the vectors).
    The run and its results above are unchanged.

S1, interop/a2a-go-368-jcs/RUN.md only, appended:

    Successor record: interop/a2a-go-368-jcs-ea003f9/, the same claim against the later head
    ea003f9. This record stays pinned to 411e3e81.

A2, interop/aae-envelope/README.md, appended:

    Classification, added 2026-08-29: Mode A (the shipped APS verifier decided the vectors
    through an adapter); author-produced (the runner authored the implementation under test
    and the adapter). The vectors are MoltyCel's; the decisions recorded above are unchanged.

A3, interop/arpa-v0.9.5-1ec3008/RUN.md, appended:

    Classification, added 2026-08-29: release-gate reproduction, Mode A, independent (the
    runner authored neither the vectors nor the gate). The recompute.py layer is classified
    separately once its dependency on hand-written evaluation logic is stated; until then it
    carries no label.

A4, interop/attenu-guard-0.6.0/SOURCE.md, appended:

    Classification, added 2026-08-29: both directions Mode B, author-produced, as the 0.6.1
    successor record states; direction 1 because the runner authored the vectors, direction
    2 because the clean-room verifier that decides the verdicts was written by the runner.

A5, interop/ca2a-validity-window-d3db81c/RUN.md, appended:

    Classification, added 2026-08-29: Mode A, independent (the counterparty's own test
    suite, run by a party that authored neither it nor the vectors).

A6, interop/x402-receipts-debc94f/RUN.md, appended:

    Classification, added 2026-08-29: vitest reproduction Mode A, independent. The
    recompute.py digest layer is classified separately once its dependence on hand-written
    canonical form is stated; until then it carries no label.

A7, fixtures/cross-stack/aat-amdal/SOURCE.md, nobulex-bilateral-v0/SOURCE.md and
receipts-amdal/SOURCE.md, appended to the Verification split (one paragraph each, same shape):

    Classification clarification, 2026-08-29: the row(s) above labeled independent on
    2026-08-28 are restated under the single definition. [aat-amdal: window bounds are
    evaluated by hand-written comparisons in runners/aat_runner.py, so that layer is
    author-produced and is listed in docs/OPEN-RUNS.md; the Ed25519 layer stays independent
    (cryptography library).] [nobulex-bilateral-v0: the canonical preimage is produced by a
    hand-written jcsFlat in run.mjs, author-produced, listed in docs/OPEN-RUNS.md; the SHA-256
    over each vector's own expected_canonical_preimage stays independent.] [receipts-amdal:
    did:key resolution is a hand-written decoder, author-produced, listed in docs/OPEN-RUNS.md;
    canonical bytes (json.dumps primitive with the stated equivalence), Ed25519 (the
    cryptography library, not stdlib as written above; the runner uses Python stdlib for
    canonicalization and hashing and cryptography for Ed25519 verification) and receipt_id
    (hashlib) stay independent.] Results and pins are unchanged.

E1, interop/ethers-oracle-safety-check-9b4ffee/run-report.md, appended:

    Historical-pin clarification, 2026-08-29: this record remains pinned to PR #32 head
    9b4ffee, the revision actually run. A later family revision or merge receives a new run
    record; this one is not rewritten. The sentence above asking for the pull-request
    reference to be replaced after merge is withdrawn.

E2, interop/mih-sato-composition-00/README.md, appended:

    Erratum, 2026-08-29: this record describes itself as an independent run. Under the
    definition adopted in CONTRIBUTING.md on 2026-08-28, a run whose recomputation is
    performed by adapters written by the runner is author-produced, whoever authored the
    vectors. The correct classification is Mode B, author-produced. The fact the record
    meant to state remains true: the run was not performed by the pack's authors. The
    27 results, the pins and the reference digest are unchanged.

E3, interop/scitt-cose-vectors-ietf126/README.md, appended:

    Erratum, 2026-08-29: this record describes itself as an independent verification run.
    Under the definition adopted in CONTRIBUTING.md on 2026-08-28, a from-scratch verifier
    written by the runner is the runner's implementation, so the classification is Mode B,
    author-produced. The run was not performed by the vectors' authors; that fact stands.
    The six results, the pin and the reference digest are unchanged.

## Not done in this document

No historical file is edited. No record is moved, renamed or merged. No OPEN-RUNS.md change
is made here; the three new rows (aat-amdal window bounds, nobulex preimage, receipts-amdal
did:key) land in the same commit as the A7 clarifications that send them.
