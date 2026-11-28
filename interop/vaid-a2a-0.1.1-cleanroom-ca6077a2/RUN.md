# VAID A2A extension vectors, one clean-room verifier run (vaid-a2a 0.1.1, and VAID main)

## Purpose

A record of one verifier, written from the VAID A2A extension prose by this lab's maintainer, run over the vectors that ship in the published `vaid-a2a` 0.1.1 package and over the vectors on VAID's main branch at `f51832a`. It records what the verifier reported. It is not a conformance verdict on VAID or on `vaid-a2a`, it covers signature version 3 only, and it admits no external family and adds no vocabulary.

## Targets

- Package: `vaid-a2a` 0.1.1, https://pypi.org/project/vaid-a2a/0.1.1/, wheel `vaid_a2a-0.1.1-py3-none-any.whl`, SHA-256 d4b0225f4f255df631a06d4182cbae1ca01c32e91d30fced4a07d3a5cc5ab795, Apache-2.0. Twelve vectors in `vaid_a2a/vectors/`, each pinned in `vectors-vaid-a2a-0.1.1.sha256`.
- Repository: https://github.com/solara-associates/vaid at f51832a96dc4968dfb0e28c2bcf81683c4b3aa9c, `docs/a2a/v1/vectors/`, fourteen vectors, each pinned in `vectors-main-f51832a.sha256`. Since 7611e97 (2026-10-12) every vector there uses `sig_version` 4.

## The verifier

`vaid_cr.py`, SHA-256 ca6077a2950519abae1e921e25236fe57892bb554b825b2b72907efcc26888f8, Python. Written by aeoess on 2026-10-08 from the prose at vaid 1936cee6 (`docs/a2a/v1/extension.md`, `docs/spec/encoding.md`, `docs/spec/scope.md`, ADR-0003, ADR-0007, `docs/spec/revocation.md` R.4.4) before the author's verifier was read. It imports nothing from VAID. Ed25519 comes from `cryptography`, and the JCS used for VAID's value types is written in the file. The file is unchanged since 2026-10-08. It supports `sig_version` 3 only and refuses any other version at step 1.

`run_vectors.py` checks that the directory holds exactly the vectors the manifest names, each with its pinned digest, then runs every vector. It exits 0 only when every result and error code equals the vector's expected pair, 1 on any mismatch or exception, and 2 on an empty or mismatched corpus.

## Authorship of the inputs

Vectors 01 to 06, 13 and 14 are VAID's. Vectors 07 to 11 began as attenuation negatives proposed by aeoess in solara-associates/vaid#108 and were generated with VAID's own generator. Vector 12 encodes the trust-domain case aeoess reported privately to VAID, published with GHSA-hfjh-v2x2-r58v.

## Runs recorded

### R1. Vectors in vaid-a2a 0.1.1

- Runner: aeoess, 2026-10-12. macOS 26.5 arm64, Python 3.14.6, `cryptography` 49.0.0.
- Result: 12 of 12, result and error code equal to each vector's expected pair, exit 0. Full output in `run-vaid-a2a-0.1.1.log`.

### R2. Vectors on VAID main at f51832a

- Same runner and environment.
- Result: 0 of 14. Every vector is refused with `unsupported_sig_version` at step 1, exit 1. Full output in `run-main-f51832a.log`. This is a coverage gap in this verifier. It evaluates no `sig_version` 4 behavior and shows no disagreement with VAID.

### Runner controls

`self_test.sh` checks the exit codes: the pinned corpus 0, an empty corpus 2, an empty manifest 2, a missing vector 2, an edited vector under the old manifest 2, a wrong expected code 1, an unparseable vector 1, and a vector changed to `sig_version` 4 1. Output in `self-test.log`.

## Commands

    $ python3 -m pip download --no-deps --only-binary=:all: vaid-a2a==0.1.1
    $ shasum -a 256 vaid_a2a-0.1.1-py3-none-any.whl
    $ unzip -q vaid_a2a-0.1.1-py3-none-any.whl -d w
    $ python3 -I run_vectors.py w/vaid_a2a/vectors vectors-vaid-a2a-0.1.1.sha256
    $ ./self_test.sh w/vaid_a2a/vectors vectors-vaid-a2a-0.1.1.sha256
    $ git clone https://github.com/solara-associates/vaid && git -C vaid checkout f51832a96dc4968dfb0e28c2bcf81683c4b3aa9c
    $ python3 -I run_vectors.py vaid/docs/a2a/v1/vectors vectors-main-f51832a.sha256

Needs Python 3 and the `cryptography` package.

## Verification split

- result and error code per vector, vaid-a2a 0.1.1 / R1; aeoess; Mode B; author-produced; `vaid_cr.py` at ca6077a2, written by the runner. The runner also originated the inputs of vectors 07 to 12.
- vectors on VAID main at f51832a / R2; aeoess; Mode B; author-produced; `vaid_cr.py` at ca6077a2, written by the runner. No vector's claim is checked, because the verifier refuses `sig_version` 4.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Files

- `vaid_cr.py`: the verifier
- `run_vectors.py`, `self_test.sh`: the runner and its controls
- `vectors-vaid-a2a-0.1.1.sha256`, `vectors-main-f51832a.sha256`: the pinned inputs
- `run-vaid-a2a-0.1.1.log`, `run-main-f51832a.log`, `self-test.log`: the outputs above
- `CHECKSUMS.sha256`: digests of every file above

VAID's vectors are not copied here. They are pinned by the manifests and the wheel digest above.
