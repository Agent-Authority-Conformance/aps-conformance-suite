# Outside reading of aeoess-presenter-key-possession at 6ad8468, Mode B

*Carried out and checked by Andrii Sparysh, using an AI assistant.*

## What was run

- **Phase 1 (blind).**
  - A checker written from RFC 9449 sections 4.2, 4.3, 6.1, 7.1 and 11.1, with RFC 7638 and RFC 8037 for the thumbprint, decided each of the 28 cases.
  - It saw only each case's `input` and `outcome`, under identifiers B01 to B28, and the candidate's `text_status` and `readings`.
  - It recomputed every condition from the bytes: the Ed25519 signature, the JWK thumbprint, `ath`, the time difference, the URI comparison, the nonce, the replay and the scope.
  - Four choice points were evaluated both ways.
  - The output was frozen and zipped before the sealed inputs were opened.
- **Phase 2 (compare).**
  - The verdicts were mapped to the candidate's identifiers PK-01 to PK-28 and compared with `expect`.
  - The divergences were minimised, and findings were drafted.
  - The candidate's key claims were recomputed from `keys.seed_rule`.
  - Two choice points were then fixed by the axis map stated in `CANDIDATE.md` (`out/changes.md`).

## Result

Phase 1 matched the expected verdict in 25 of 28 cases and reported 4 `ambiguous`. After the axis map stated in `CANDIDATE.md` was applied, 27 of 28 match, and the one divergence is PK-18 (replayed `jti`): `ambiguous` here, `nonconformant` expected.

What the match shows, and what it does not:
- A match shows that this checker, written separately from the text, computed the same verdict as the candidate's expectation under the readings recorded in `ambiguity-log.md`.
- A match does not show that the expected result is the only reading of RFC 9449.
- A match does not show that the candidate's `check.py`, `generate.py` or `mutate.py` behave as described, since none of them was obtained.
- A match does not show that any implementation conforms.
- A divergence records that two parties computed different values from the same inputs, and either can be wrong.

## Re-running

From this directory, with bash, curl, Python 3 and `cryptography`:

```
bash inputs/presenter-key-possession-reading-1-fetch-inputs.sh
python3 -I reader/checker.py inputs/blind/cases.json inputs/rfc rerun
cmp rerun/phase1.json out/phase1.json && cmp rerun/phase1-sensitivity.json out/phase1-sensitivity.json
python3 -I reader/phase2.py inputs/blind/cases.json inputs/sealed/vectors.json inputs/sealed/id-map.json inputs/rfc rerun
cmp rerun/final.json out/final.json
python3 -I reader/compare.py out/phase1.json inputs/sealed/vectors.json inputs/sealed/id-map.json out/final.json
```

The re-run writes to `rerun/` and compares with `out/`. It takes each RFC from a supplied `.txt` copy found by its header in `.`, `/mnt/user-data/uploads` or `$HOME`, and otherwise from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`. It accepts RFC 9449 only if its SHA-256 is `3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13`. For RFC 7638, 8037 and the optional RFCs it records the digest. The digests used in this run are in `VECTOR-INVENTORY.md`. The checker stops if any cited sentence is not in the text it is given.

## Verification split

- **Ed25519 signature validity under the proof's embedded public key** (26 cases: 24 valid; PK-05 and PK-06 invalid); Andrii Sparysh; Mode B; independent; `cryptography` 50.0.1 `Ed25519PublicKey.verify`, called by a thin harness in `reader/checker.py` with the signing input as received. This establishes signature validity under that key only. It does not establish that the key is trusted or bound to the token.
- **The other conditions:** the signature facts for PK-08 and PK-25, header and form, required claims, JWK thumbprint against `cnf.jkt`, `ath`, `htm`/`htu`, nonce, `iat` window, `jti` replay and scope. Andrii Sparysh; Mode B; author-produced; `reader/checker.py`.
- **Axis values, `decision`, `reject_axis` and the 28 verdicts;** Andrii Sparysh; Mode B; author-produced; `reader/checker.py`, `reader/phase2.py`.
- **Key claims K1 to K8** (key derivation from `keys.seed_rule`, thumbprints, proof keys, PK-07's `d`); Andrii Sparysh; Mode B; author-produced; `reader/phase2.py`.

Authorship relationship, for every author-produced entry: the runner wrote the checker that supplies the result. The per-claim table is in `run-report.md`, "Labels per claim". These records are attributed per claim. This record is not an end-to-end verification or a verdict on the candidate.

What the labels do not change:
- Andrii Sparysh authored none of the candidate, its vectors, its generator, its checker or RFC 9449.
- The checker was written from the RFC text and a blind copy of the cases. Its phase-1 output was frozen and zipped before the expected verdicts were opened.
- The candidate's `check.py`, `mutate.py` and `generate.py` were not downloaded or read.

The lab certifies nothing. This directory is a record of one run. It is not a verdict on the candidate, RFC 9449 or any implementation.

## Layout

- `README.md`: this file.
- `run-report.md`: the lab's run fields, the per-vector table, and the commands with their output.
- `PROVENANCE.md`: the files read and their digests, the RFC sources, the boundary as kept, and events at the boundary.
- `RESULTS.md`: tallies, the per-case table, the facts table, sensitivity, byte identity, key checks, limits and environment.
- `ambiguity-log.md`: every reading chosen.
- `VECTOR-INVENTORY.md`: digests of the corpus inputs.
- `findings/`: F01 to F04, drafts addressed to the candidate's author. Not filed.
- `reader/`: `checker.py` (phase 1), `phase2.py` (key checks and final verdicts), `compare.py`, `tables.py`, and `explore.py` (decodes the blind cases for inspection).
- `out/`: `phase1.json`, `phase1-sensitivity.json`, `final.json`, `changes.md`.
- `logs/`: `fetch.log`, `transcript.log`, `explore-blind.txt`, `phase1.zip` as frozen, and `phase1-zip.sha256`.
- `inputs/`: `SHA256SUMS` and the fetch script.
- `SHA256SUMS.txt`: digests of every other file.
