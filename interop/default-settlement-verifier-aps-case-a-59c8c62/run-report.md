# Run record: @nutstrut's verifier on the APS Case A neutral vector

Recorded for [#140](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/140). This file records a run published by @nutstrut of his own verifier over one pinned APS vector, and a rerun of that verifier by @aeoess. The vector is not an admitted corpus vector. Before this record, lab `main` at `5500a56` contained neither the file nor its hash.

| field | value |
|---|---|
| who ran it | @nutstrut |
| date | First run reported on #140 on 2026-10-01. The published output is from the runner's rerun for the bundle, committed 2026-10-02T01:00:28Z |
| run mode | Mode B, alternate recomputation |
| implementation | `verify_case_a.py` at `nutstrut/default-settlement-verifier` `59c8c62d3fac4aeed06723242c3f71e2eff17913`, `evidence/aps-case-a-140/`, SHA-256 `ebaa2533ca1ef6dc50feb614fca6e9c700bc7ebba71a66bf42138f0d4947fb95`, 407 lines. It imports the Python standard library (`copy`, `hashlib`, `json`, `re`, `sys`, `datetime`) and `cryptography` for Ed25519. It imports no APS SDK, no `verify.mjs` and no other producer code. Canonicalization is a local RFC 8785 subset written for this vector |
| author-produced or independent | author-produced. The runner authored `verify_case_a.py`, the implementation that decides each result, so under `CONTRIBUTING.md` this record is not independent |
| relationship to the producer | third party. The runner did not author the vector, and the vector's author (@aeoess) did not write the verifier |
| what the verifier was written from | draft-pidlisnyi-aps-04, Sections 3.4, 3.5, 4.1, 4.2, 4.3, 4.5, 4.6, 6, 6.2, 8.2.1 and 13.5, per the runner's README |
| input | `vector/case-a-neutral-vector.CANDIDATE.json` at `aeoess/aps-openshell-reference-middleware` `2508f6a76a0cd86673a51441b9eb79f9197b12e5`, SHA-256 `4918125741234d749e4ab23cb6ec98c12f6b86b951147eca984b04a76bb53d31`, 4876 bytes. Status `CANDIDATE`, TEST ONLY keys, profile `aps:authority-delegation:v1`, evaluation instant `2026-06-01T00:00:00.000Z` |
| corpus reference | none. The vector is not an admitted corpus vector. A copy is in `inputs/` as an archived replay input |
| published output | `observed-output.txt` at the same commit, SHA-256 `dbb6808fc77c6166a04a9b0a0eaffe7f232e80f660f54281f255653309531552`, 7595 bytes. A copy is in `outputs/` |
| environment | Published output: Python 3.10.12, `cryptography` 50.0.0, Linux. The runner's README says the versions of the first run on 2026-10-01 were not recorded |
| blinding | not blinded. The runner had seen the expected results before writing the verifier, and disclosed it |
| suspected defective vectors | none reported |

## Results per case, as the runner reports them

| case | revocation state | observed | vector expectation |
|---|---|---|---|
| `ancestor-active` | nothing revoked | `valid` | same |
| `ancestor-revoked` | the root's grant to the parent is revoked, the child record is untouched | `invalid`, `REVOKED`, index 0, failed in the verifier's revocation phase | same |

The verifier prints a hash of its two observed results, `f5e27d0590f125bde42b5adde10e9fb1dc00ee7123e054602c72032148dc94aa`, before it reads the vector's `expected` members. The source removes each case's top-level `expected` field before evaluation and reads those fields again only for the final comparison.

The verifier's exit code reflects these two comparisons only. Exit 0 means both observed results equal the vector's expectations.

## Controls, as the published output shows them

The verifier prints each control's outcome and does not assert it. A control that came out differently would change the output and leave the exit code at 0. The outcomes below are read from `observed-output.txt`.

Ten controls on the vector's own records, changed in memory and not signed again. The output shows all ten as `invalid`: a flipped signature byte, a changed nonce, a changed parent link, evaluation after the child's `not_after`, before its `not_before` and exactly at its `not_after`, child revoked, both revoked, an untrusted root, and the wrong key for the parent.

Nine controls on a chain signed again with throwaway keys generated per run. The output shows the unchanged chain as `valid` and eight changed chains as `invalid`: a broken parent link, an issuer that does not match the parent's subject, and six widenings (scope, depth, cumulative spend, reputation ceiling, reversibility, `not_after`).

The rejection labels are the verifier's own. The runner's README notes that draft-04 defines no failure code vocabulary and that `REVOKED` is the vector's label, so agreement on that string is a naming match.

## What the verifier takes from the vector

For the two published cases, the trusted root and the verification keys are read from the vector's `trust_anchors` member. The verifier holds no separate key pins for them. A passing signature check in those cases therefore shows that the chain verifies under the TEST ONLY keys the vector itself supplies. The nine controls on the chain signed again use throwaway keys generated in each run.

## Limits the runner states

Revocation state is taken as supplied and fresh, so the stale or unavailable path is not exercised. The key pins carry no validity windows and there is no rotation. Closed schema checking of the inner facet key sets is the runner's reading of Sections 4.1 and 4.2. Spend accounting across a subtree and runtime reputation scoring are outside the vector. One implementation, one run environment.

## Claim ceiling, in the runner's words

"An independently implemented verifier, using the pinned APS draft, pinned test keys, pinned vector and fixed evaluation instant, reached the same per-case authority-chain result as the vector for the two named cases."

The runner lists as not established: general APS conformance, OpenShell correctness, middleware correctness, execution occurrence, production behavior, real-world authority, adoption, and external dependency.

The runner's phrase "independently implemented" describes where the code came from, and the import list above is consistent with it. The `author-produced` label in the table describes the runner's relationship to the implementation under `CONTRIBUTING.md`. The two statements are about different things and both stand.

## Reproduction of the published output

A rerun by @aeoess on 2026-10-02 (macOS 26.5 arm64, Python 3.14.6, `cryptography` 50.0.0) from a fresh clone at `59c8c62`, with the vector fetched from the pinned URL and its SHA-256 checked first, produced stdout byte for byte identical to `observed-output.txt`. Verifier exit 0, stderr empty, `cmp` exit 0.

```
git clone https://github.com/nutstrut/default-settlement-verifier.git dsv
git -C dsv checkout 59c8c62d3fac4aeed06723242c3f71e2eff17913
mkdir -p vec
curl -fL -o vec/case-a-neutral-vector.CANDIDATE.json \
  https://raw.githubusercontent.com/aeoess/aps-openshell-reference-middleware/2508f6a76a0cd86673a51441b9eb79f9197b12e5/vector/case-a-neutral-vector.CANDIDATE.json
shasum -a 256 vec/case-a-neutral-vector.CANDIDATE.json
python3 -m venv venv && ./venv/bin/pip install cryptography==50.0.0
./venv/bin/python dsv/evidence/aps-case-a-140/verify_case_a.py vec/case-a-neutral-vector.CANDIDATE.json > out.txt
cmp out.txt dsv/evidence/aps-case-a-140/observed-output.txt
```

This is a Mode A, author-produced reproduction of the runner's record. It is not a second implementation and not a review of the verifier's logic beyond the import list and the order in which `expected` is read. @aeoess authored the vector, so this rerun is not independent for any claim that reads it. Exit 0 covers the two case comparisons. The control outcomes are covered by the byte comparison of stdout.

## What this record does not establish

This record contains no run classified independent under `CONTRIBUTING.md`.

The vector needs neither OpenShell nor the APS OpenShell reference middleware and says nothing about either. This record adds nothing about that middleware, about any runtime, or about enforcement, deployment or adoption. The vector's status is `CANDIDATE`.
