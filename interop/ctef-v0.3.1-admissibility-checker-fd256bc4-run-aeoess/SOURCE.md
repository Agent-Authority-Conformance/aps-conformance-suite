# ctef-v0.3.1 at PR #43 head a642c17f: independent run of giskard09's admissibility checker by the lab

Family under review: `fixtures/cross-stack/ctef-v0.3.1/` as proposed in
[PR #43](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/43) at head
`a642c17f2b5b003d403d7d0faec4b72910afb787`. The family is not on `main` at the time of this
run. This record is pinned to those bytes; a later head with different fixture bytes gets a
new record, this one is not edited.

This is the independent record for the admissibility layer (claim model and expiry) that the
family's own run leaves author-produced. It completes the sequence in
`interop/ctef-v0.3.1-admissibility-giskard09-a642c17/`, which records the checker author's own
run of the same implementation. The byte, signature and Wycheproof layers are recorded
separately in `interop/crypto-recompute-ctef-v0.3.1-a642c17/`.

## The implementation

`giskard09/ctef-admissibility-independent-checker-giskard09`, tag `v1`, commit
`fd256bc41b3fbf2f2d70ee159822c712a89d2fcb`, published 2026-09-05 on issue #72. Its
PROVENANCE.md states it was built from the family's SOURCE.md, README.md, fixtures and
jwks.json at a642c17 only, without reading `plugins/admissibility.py` or the rest of
`plugins/`. It verifies each fixture's JWS with `cryptography`, recomputes the JCS bytes and
SHA-256 with its own canonicalizer, then applies four rules (closed `claim_type` set; identity
claims carry no delegation; composed chains share one resource path; `expires_at` strictly
after `verification_time`) and compares its own outcome and error code to the fixture's
declared ones. The lab read the code before running it: standard library plus `cryptography`,
local files only, no network, no subprocess.

## The run

Runner: aeoess, 2026-09-05, on a MacBook Air (macOS 26.5, arm64), Python 3.14.6, in a fresh
virtual environment holding only `cryptography==49.0.0`, no network after install.

Inputs pinned before the run: the checker repository's `fixtures/*.json` and `jwks.json` are
byte-identical to the family at a642c17 (git blob shas bca2ce37265c, 3369a64eeafc,
9ce243733794, 70a22b30a4d7, b110f9407feb for the five fixtures; jwks identical), verified with
`git hash-object` against a clean clone of the PR head.

    python3 checker.py

Result (`results-run-aeoess-2026-09-05.txt`, verbatim): 5 of 5 fixtures match the declared
outcome, exit 0.

    positive-authority:            pass
    negative-scope-violation:      fail-closed / INVALID_CLAIM_SCOPE
    negative-composition-failure:  fail-closed / INVALID_COMPOSITION
    negative-missing-claim-type:   fail-closed / INVALID_CLAIM_SCOPE
    negative-expired:              fail-closed / EXPIRED

Control, run in a scratch copy and not part of the record: flipping `expected_result` on one
fixture makes the checker report MISMATCH and exit 1, so it decides the outcome from its rules
rather than echoing the declared table.

## Where the runs differ, recorded and not adjudicated

They do not differ. The family's `validate.py` (five `admissibility:*` checks passing in
results.json), the checker author's own run (recorded beside this one), and this run all reach
the same five verdicts with the same error codes.

## Verification split

- Admissibility outcomes (claim model and expiry), five fixtures; runner: aeoess; Mode B;
  independent; implementation: giskard09's checker at fd256bc4, which the runner did not
  author, over fixtures the runner did not author.

These records are attributed per layer. Merge of this family is not an end-to-end verification
or a family-level verdict.

## What this record does not establish

It does not establish that the CTEF claim model is correct, only that an implementation
written from the published description by someone other than the family author, run by
someone other than that implementer, reaches the declared outcomes on these five fixtures. It
does not cover the header-policy semantics or the tamper control, which only the family's own
run exercises. It is not an adoption or endorsement claim by or about argentum-core, AgentAvow
or APS.
