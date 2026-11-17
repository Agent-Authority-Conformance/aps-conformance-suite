# VAID A2A extension vectors at `sig_version` 4, one clean-room verifier run (VAID main at abe1448)

## Purpose

A record of one verifier, written from the VAID prose by this lab's maintainer, run over the eighteen vectors on VAID's main branch at `abe1448`. It records what the verifier reported. It is not a conformance verdict on VAID or on `vaid-a2a`, and it admits no external family and adds no vocabulary. The earlier record, `interop/vaid-a2a-0.1.1-cleanroom-ca6077a2`, covers `sig_version` 3 only and is unchanged.

## Targets

- Repository: https://github.com/solara-associates/vaid at abe14480a5a47fe58fef7e03593403f0be022e1f, `docs/a2a/v1/vectors/`, eighteen vectors, each pinned in `vectors-main-abe1448.sha256`. Every VAID document in them carries `sig_version` 4. Vector 17 carries no VAID.
- Regression input: the twelve `sig_version` 3 vectors of `vaid-a2a` 0.1.1, pinned in `vectors-vaid-a2a-0.1.1.sha256`, the manifest the earlier record uses. The bytes for this run were taken from VAID at b63e764fb74915d2c73373866aa1427d37ff7066 and match that manifest.

## The verifier

`vaid_cr.py`, SHA-256 fa652557b5997eeaf83a10211c3400be86fed265ba5dfa487254ba29b9450445, Python. Lines 1 to 367 are the `sig_version` 3 verifier of the earlier record, byte for byte. The `sig_version` 4 part was appended by aeoess on 2026-11-15 from the prose at vaid abe1448: ADR-0009, `docs/spec/scope.md` revision 2, `docs/spec/encoding.md`, `docs/a2a/v1/extension.md`, `docs/a2a/v1/vectors/README.md`, sections 1a and 1b of ADR-0010, step 2a of `docs/jwt/v1/profile.md` and the release notes in `python/vaid-a2a/CHANGELOG.md`. It imports nothing from VAID. Ed25519 comes from `cryptography`, and the JCS used for VAID's value types is written in the file.

One call accepts one `sig_version`. `verify` is the version 3 verifier and `verify_v4` is the version 4 verifier. Neither falls back to the other.

`run_vectors.py` checks that the directory holds exactly the vectors the manifest names, each with its pinned digest, then runs every vector. With `--sig-version 4` it calls `verify_v4`, and without the option it calls the version 3 verifier. It exits 0 only when every result and error code equals the vector's expected pair, 1 on any mismatch or exception, and 2 on an empty or mismatched corpus.

## Readings the prose leaves open

The verifier had to choose a reading in three places.

- An empty `chain` list in a vector is read as no `/vaidChain` key. Vector 17 passes under this reading. `extension.md` calls a `/vaidChain` key without `/vaid` malformed input, so reading the empty list as a present key would refuse vector 17.
- Step 2a (`unknown_scope_kind`) is applied to the chain documents before step 3 authenticates them, which is the order in `extension.md`. `scope.md` S.10 places that verdict after the kernel signature. No vector has a chain document that is both inauthentic and of an unknown kind, so no expected pair depends on this.
- With `requireVaid` true and no VAID, the verifier returns `fail` with `no_vaid`. The text names no code for that case and no vector covers it.

## Authorship of the inputs

Vectors 01 to 06, 13 and 14 are VAID's. Vectors 07 to 11 began as attenuation negatives proposed by aeoess in solara-associates/vaid#108 and were generated with VAID's own generator. Vector 12 encodes the trust-domain case aeoess reported privately to VAID, published with GHSA-hfjh-v2x2-r58v. Vectors 15 to 17 are VAID's answer to an ordering question aeoess asked in a2aproject/A2A#2028, and vector 18 is the case aeoess asked for in that thread. VAID generated all four.

## Runs recorded

### R1. Eighteen vectors on VAID main at abe1448, version 4 verifier

- Runner: aeoess, 2026-11-15, repeated 2026-11-16 with byte-identical output. macOS 26.5 arm64, Python 3.14.6, `cryptography` 49.0.0.
- Result: 18 of 18, result and error code equal to each vector's expected pair, exit 0. Vectors 15 and 18 stop at the leaf signature with `inauthentic`, vector 16 stops at the chain walk with `unverifiable`, and vector 17 passes with `no_vaid`. Full output in `run-main-abe1448-v4.log`.

### R2. Twelve vectors of vaid-a2a 0.1.1, version 3 verifier

- Same runner and environment.
- Result: 12 of 12, exit 0. Full output in `run-v3-b63e764.log`. The version 3 path gives the result the earlier record reports.

### R3. Eighteen vectors on VAID main at abe1448, version 3 verifier

- Same runner and environment.
- Result: 0 of 18, exit 1. Seventeen vectors are refused with `unsupported_sig_version` at step 1 and vector 17 with `unparseable`. Full output in `run-main-abe1448-v3.log`. This shows the version 3 verifier accepts no version 4 document. It shows no disagreement with VAID.

### Runner controls

`self_test.sh` checks the exit codes in each mode: the pinned corpus 0, an empty corpus 2, an empty manifest 2, a missing vector 2, an edited vector under the old manifest 2, a wrong expected code 1, an unparseable vector 1, and a vector changed to the other `sig_version` 1. Output in `self-test-v3.log` and `self-test-v4.log`.

`v4_checks.py` runs seventeen cases for version 4 branches that no VAID vector reaches. Each case edits the leaf of vector 01 and signs it again with the test-only kernel seed published in the vectors README, so the signature is valid and only the edited property decides the verdict. 17 of 17 gave the expected code, exit 0. Output in `v4-checks.log`. These are this verifier's own controls and say nothing about VAID.

## Commands

    $ git clone https://github.com/solara-associates/vaid && git -C vaid checkout abe14480a5a47fe58fef7e03593403f0be022e1f
    $ python3 -I run_vectors.py --sig-version 4 vaid/docs/a2a/v1/vectors vectors-main-abe1448.sha256
    $ python3 -I run_vectors.py vaid/docs/a2a/v1/vectors vectors-main-abe1448.sha256
    $ ./self_test.sh vaid/docs/a2a/v1/vectors vectors-main-abe1448.sha256 4
    $ python3 -I v4_checks.py vaid/docs/a2a/v1/vectors/01-valid-two-hop-chain.json
    $ mkdir v3 && for f in $(cut -c67- vectors-vaid-a2a-0.1.1.sha256); do git -C vaid show b63e764fb74915d2c73373866aa1427d37ff7066:docs/a2a/v1/vectors/$f > v3/$f; done
    $ python3 -I run_vectors.py v3 vectors-vaid-a2a-0.1.1.sha256
    $ ./self_test.sh v3 vectors-vaid-a2a-0.1.1.sha256 3

Needs Python 3 and the `cryptography` package.

## Verification split

- result and error code per vector, VAID main at abe1448 / R1; aeoess; Mode B; author-produced; `vaid_cr.py` at fa652557, written by the runner. The runner also originated the inputs of vectors 07 to 12 and asked the question that vectors 15 to 18 answer.
- result and error code per vector, vaid-a2a 0.1.1 / R2; aeoess; Mode B; author-produced; `vaid_cr.py` at fa652557, written by the runner. The runner also originated the inputs of vectors 07 to 12.
- vectors on VAID main at abe1448 / R3; aeoess; Mode B; author-produced; `vaid_cr.py` at fa652557, written by the runner. No vector's claim is checked, because the version 3 verifier refuses `sig_version` 4.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Files

- `vaid_cr.py`: the verifier
- `run_vectors.py`, `self_test.sh`, `v4_checks.py`: the runner and the controls
- `vectors-main-abe1448.sha256`, `vectors-vaid-a2a-0.1.1.sha256`: the pinned inputs
- `run-main-abe1448-v4.log`, `run-v3-b63e764.log`, `run-main-abe1448-v3.log`, `self-test-v3.log`, `self-test-v4.log`, `v4-checks.log`: the outputs above
- `CHECKSUMS.sha256`: digests of every file above

VAID's vectors are not copied here. They are pinned by the manifests above.
