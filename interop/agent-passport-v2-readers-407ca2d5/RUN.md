# Agent Passport v2 vectors at 407ca2d5, two outside reader results and their comparison

## Purpose

A record of two readers, written outside the vectors' author, run over the frozen Agent Passport v2 vectors, and of a public comparison between their published outputs. It records what each run reported, where they agree, and the three cases where they differ. It does not decide which outcome is correct for those three cases. It is not a conformance verdict on either reader, a test of either project's service, or a statement about adoption. This record admits no external family and adds no vocabulary.

## Target

- Repository: https://github.com/aeoess/agent-passport-system
- Commit: 407ca2d5ad10c846860ad1b6faafc971ae9690e5
- File: `fixtures/agent-passport-v2/agent-passport-vectors-v2.json`
- File SHA-256: 9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5
- Twenty cases, `aps.agent-passport` 2.0, draft-pidlisnyi-aps-04 sections 3.1 and 3.2. Each case records the TypeScript SDK's output at the pinned commit. Five cases carry an `sdk_observation` note saying the recorded output is not required by draft-04.

## Runs recorded

### R1. HORIZON SHIELD admission reader

- Runner: ogasurfproject-jpg (HORIZON SHIELD), 2026-10-10 and 2026-10-11
- Implementation: the APS adapter of a closed-source admission reader, hs-seki-private `270502b`, `adapter_aps_v2.py` sha256 e82264c3663a80467bfadf8e1f2bb2b1496a7557c8148696bee0b3557cd376b0, command `python3 adapter_aps_v2.py --selftest` check [7], as stated by the runner. No APS SDK imported, as stated by the runner.
- Published output: https://github.com/ogasurfproject-jpg/horizon-shield/blob/f960c7d0b8829ea837b384329a8b91bf3db80134/verify-directory/admission/aps-v2/results-407ca2d5.json, sha256 3547cb5167c818a6f739c38f4d83f4f7e5cd97d4282c798dba581350ab2c7a02
- Reported result: state and code equal the vectors' recorded SDK output on 20 of 20. The reader follows the SDK where draft-04 leaves the outcome open, and says so in the file.
- Reproducibility: the reader is closed and its run cannot be repeated by anyone outside. What can be checked is the published output file. That the file is what the reader printed rests on the runner's statement.
- Thread: https://github.com/ogasurfproject-jpg/horizon-shield/issues/31

### R2. Probity reader

- Runner: astrogilda (Probity), 2026-10-10
- Implementation: `read_corpus.py`, https://github.com/probityai/agent-evidence-atlas/tree/82436c01307d425960f3b3353af35a824a1d3b21/experiments/aps-corrected20-2026-10-10. Python, Ed25519 through cryptography 50.0.2 (OpenSSL), canonicalization written by the runner for the corpus's printable ASCII subset. No APS SDK imported, as stated in the report.
- Published report: `report.json` at that commit, sha256 1598f87559130cb0e7a2e4ca59e5d6a2a584b402149bc28baad30dd9eaa01df1
- Reported result: diagnostic layers, resolver requests and published preimages agree on all 20 cases. Final outcomes: 4 valid, 11 invalid, 3 indeterminate, 2 unsupported. Three outcomes differ from the recorded SDK output, listed below.
- Stated by the runner: the expected answers were public before the reader was written and run. Resolver answers and evaluation times are supplied by the corpus. This is not a JCS or cryptographic backend qualification.

### R3. Comparison of the two published outputs, rerun

- Runner: aeoess (Tymofii Pidlisnyi), 2026-10-11
- Implementation: `tools/aps_compare/compare_probity.py` at horizon-shield f960c7d0, sha256 f293851f1516a0256e11685af00911c4174a2c2411d79eb217fe61f05443e544, written by HORIZON SHIELD. Standard library only. It compares the two published outputs case by case and runs neither reader.
- Environment: macOS 26.5 arm64, Python 3.14.6
- The same script runs in HORIZON SHIELD's public workflow `aps-reader-comparison`, run 38137175722 at f960c7d0, conclusion success.

## Commands (R3)

    $ gh api "repos/ogasurfproject-jpg/horizon-shield/contents/tools/aps_compare/compare_probity.py?ref=f960c7d0" --jq .content | base64 -d > compare_probity.py
    $ gh api "repos/ogasurfproject-jpg/horizon-shield/contents/verify-directory/admission/aps-v2/results-407ca2d5.json?ref=f960c7d0" --jq .content | base64 -d > results-407ca2d5.json
    $ gh api "repos/probityai/agent-evidence-atlas/contents/experiments/aps-corrected20-2026-10-10/report.json?ref=82436c01307d425960f3b3353af35a824a1d3b21" --jq .content | base64 -d > report.json
    $ shasum -a 256 compare_probity.py results-407ca2d5.json report.json
    $ cd /tmp && python3 -I <dir>/compare_probity.py --report <dir>/report.json --ours <dir>/results-407ca2d5.json
    exit=0

The script refuses a report whose sha256 is not the pinned one. Output, verbatim, also in `compare-output.log`:

    17 agree, 3 declared differences as declared, 0 problems

with the three rows:

    did-web-resolver-not-found   declared difference  outcome invalid / indeterminate; key_authority rejected / unresolved
    version-changed              declared difference  outcome invalid / unsupported
    record-type-changed          declared difference  outcome invalid / unsupported

A second check, `check-against-vectors.py`, written by the runner of R3 for this record, compares both published files with the vectors file at 407ca2d5 and refuses any input that is not the pinned file:

    $ cd /tmp && python3 -I <dir>/check-against-vectors.py agent-passport-vectors-v2.json results-407ca2d5.json report.json
    R1 cases 20, state and code differing from the vectors: none
    R2 cases 20, outcome differing from the vectors' state: 3
    exit=0

Full output in `check-output.log`.

## The three differences

Draft-04 assigns no outcome for these three on a passport. Section 3.1 does not name a state for a failed resolution of the agent's own key or for an unrecognised record_type or version. Section 3.5 maps a key that is not found to indeterminate for external and evidence signers. Other draft-04 record families report an unrecognised record_type or version as unsupported. The vectors' own `sdk_observation` notes say an implementation reporting indeterminate or unsupported on these cases is not nonconforming on these vectors alone. Both readers keep every one of the three cases out of valid.

| Case | SDK output in the vectors (R1 matches) | R2 |
|---|---|---|
| did-web-resolver-not-found | invalid / PASSPORT_KEY_NOT_FOUND, key_authority rejected | indeterminate, key_authority unresolved |
| version-changed | invalid / PASSPORT_MALFORMED | unsupported |
| record-type-changed | invalid / PASSPORT_MALFORMED | unsupported |

## Verification split

- state and code per case / R1 reader output; ogasurfproject-jpg; Mode B; author-produced; HORIZON SHIELD's closed admission reader at hs-seki-private 270502b. The runner wrote the reader that decides the outcome. Its run is operator-run and cannot be reproduced outside.
- diagnostic layers, resolver requests and preimages / R2 report; astrogilda; Mode B; author-produced; Probity `read_corpus.py` at 82436c01. The runner wrote the reader, including canonicalization and preimage construction. Ed25519 is the cryptography package, which the runner did not author.
- final outcome per case / R2 report; astrogilda; Mode B; author-produced; Probity `read_corpus.py` at 82436c01, as above.
- agreement between the published R1 and R2 outputs / R3; aeoess; Mode B; author-produced; `compare_probity.py` at horizon-shield f960c7d0, written by HORIZON SHIELD. The runner of R3 authored the vectors both readers ran over.
- agreement of each published output with the vectors' recorded SDK output / `check-against-vectors.py`; aeoess; Mode B; author-produced; written by the runner, who also authored the vectors.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Files

- `compare-output.log`: the R3 output above
- `check-against-vectors.py`, `check-output.log`: the second check and its output
- `CHECKSUMS.sha256`: digests of the three files above

Neither reader nor the comparison script is copied here. Each is pinned above by commit and sha256.
