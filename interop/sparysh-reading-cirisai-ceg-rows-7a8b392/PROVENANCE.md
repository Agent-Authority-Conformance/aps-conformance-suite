# Provenance

## Sources

| what | where | SHA-256 |
|---|---|---|
| The draft, TXT | `CIRISAI/CIRISConstitution` at `be06d3ba7103c844abc4d4a3fd1ab1abaa592f56`, `ietf/draft-moore-scitt-ciris-ceg-03.txt` | `9ec525d710fc310f6ac11086465064de9da0350db0cb23df75ae6baaa1c6ae02`, the digest CANDIDATE.md pins |
| The candidate | `aps-conformance-suite` at `7a8b3927e715a92cec447f3ceba84b45d6ac535d` (head of PR #246), `candidates/cirisai-ceg-rows/` | `inputs/SHA256SUMS` |
| The source vector files, for the split check only | `CIRISAI/CIRISVerify` at `ffd7af1f1b53a8a73289202d1b54f16444a0dca8` (tag v23.3.0), `src/ciris-verify-core/tests/vectors/edition2/` | `row_statements_v3.json` `0c072516…f920`, `key_of_iss_v1.json` `bd584d9b…1333`, as CANDIDATE.md and Appendix B pin them |

The datatracker copy of the draft could not be fetched from this run's environment. The TXT was taken from the author's repository at the commit that merged revision -03, and its digest matches the one the candidate pins.

## What was read

- **The draft:** Sections 1.3, 2, 3, 4, 5, 6, 7.1, 7.2 and 8 (with 8.1), and Appendices A and B. Section 6.4 and Tables 3 and 4 fixed the order of the checks.
- **The candidate, before the comparison:** CANDIDATE.md, NOTICE, `inputs/cases.json`, `inputs/keys.json` and `inputs/family_model.json`.
- **After the blind answers were frozen:** `expected.json`. `split.py` was run as the candidate's own check of its inputs (`logs/split-check.log`); its text was not used by the reader.
- **Not read:** any code of CIRISVerify or of the generators the candidate names, and the CIRIS Constitution.

## Events

1. The draft and the candidate's inputs were fetched, and their digests checked.
2. The reader was written from the draft: `reader/cbor_strict.py` and the reader as it ran in pass 1.
3. **Pass 1.** The reader ran on the inputs. Its answers were read, without `expected.json`, to find where the inputs use a structure the draft does not name.
4. **Pass 2.** The three changes of `out/changes.md` were made, and the reader ran again.
5. **Freeze.** The digests of the reader and of both answer files were written to `logs/frozen.sha256` at 2026-11-25T11:16:13Z (`logs/frozen-at.txt`). The working names in that file map to this directory as follows:
   - `checker/ceg_reader.pass1.py` is `reader/ceg_reader_pass1.py`;
   - `checker/ceg_reader.py` is `reader/ceg_reader_pass2.py`;
   - `checker/cbor_strict.py` is `reader/cbor_strict.py`.

   The digests are equal. The freeze is a local record, not anchored outside this run.
6. `expected.json` was opened, and `reader/compare.py` was written and run on the pass-2 answers.
7. **Pass 3.** The three omissions of `out/changes.md` were fixed, and the reader and the comparison ran again.
8. The B.1 known-answer check, the split check and `rerun.sh` were run (`logs/`). Every output of `rerun.sh` is byte-identical to `out/`.

## Authorship

Andrii Sparysh wrote the reader and the comparison for this run, using an AI assistant. He authored none of the candidate, its vectors, CIRISVerify or the draft. He is credited in the draft's acknowledgements, and the draft cites draft-sparysh-pala-audit-02 in Sections 10.3 and 11. Neither relation touches the text read here or the cases.

Third-party code used: pyca/cryptography 50.0.2 (with OpenSSL 4.0.3) for ML-DSA-65 key generation from a seed, ML-DSA-65 verification with a context string, and Ed25519. The Python standard library provides `hashlib`, `base64` and `json`.
