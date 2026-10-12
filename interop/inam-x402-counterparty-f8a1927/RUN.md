# INAM x402 CounterpartyContext vectors, Mode B recomputation at f8a1927

## Purpose

A recomputation of the eight x402 CounterpartyContext vectors published by INAM, made at
the author's invitation in
[inamprotocol/inam-protocol#56](https://github.com/inamprotocol/inam-protocol/pull/56#issuecomment-6068687110).
It covers these eight published examples only. It is not a JCS conformance test, a review of
INAM's policy, a test of any INAM SDK or service, or a certification. This record admits no
external family and adds no vocabulary.

## Target

- Repository: https://github.com/inamprotocol/inam-protocol
- Commit: f8a19279cde2c3aab88bd4476a815287740c689e
- File: `tests/vectors/x402-counterparty-context.json`
- File SHA-256: b3ddccb56489593246cd15411eed70897779849899fa3eac589e0c6e3f54c0eb
- Vector history in that file: five vectors in 02945eb (#45), two added in dee930c (#56),
  one added and vector 7 changed in f8a1927 (#58). Eight at the pinned commit.

## Run

- Runner: aeoess (Tymofii Pidlisnyi), 2026-10-08
- Mode: B, alternate recomputation
- Corpus reference: this repository at 5e9f9d3fe69e93ccca4d02f24731f085d942d8d0
- Environment: macOS 26.5 arm64, Python 3.14.6, rfc8785 0.1.4 (PyPI), Node v24.11.1,
  canonicalize 4.0.0 (npm, pinned in `package.json`)

## Commands

    $ git clone https://github.com/inamprotocol/inam-protocol.git /tmp/inam-f8a1927
    $ git -C /tmp/inam-f8a1927 checkout f8a19279cde2c3aab88bd4476a815287740c689e
    $ cd interop/inam-x402-counterparty-f8a1927
    $ npm install
    $ python3 -m venv /tmp/inam-venv && /tmp/inam-venv/bin/pip install rfc8785==0.1.4
    $ /tmp/inam-venv/bin/python recompute.py /tmp/inam-f8a1927/tests/vectors/x402-counterparty-context.json
    exit=0

## Result

Verbatim, also in `recompute-output.log`:

    1 MATCH canon-py canon-js sha256 presented decision | allow: bound payTo, countersigned history
    2 MATCH canon-py canon-js sha256 presented decision | deny: payTo not bound to the DID (borrowed DID)
    3 MATCH canon-py canon-js sha256 presented decision | deny: newcomer with no countersigned work
    4 MATCH canon-py canon-js sha256 presented decision | deny: revoked DID
    5 MATCH canon-py canon-js sha256 presented decision | deny: score below policy minimum
    6 MATCH canon-py canon-js sha256 presented decision | deny: two conditions fail (payTo unbound and newcomer), payTo reason wins
    7 MATCH canon-py canon-js sha256 presented decision | allow: checksummed mixed-case payTo matches a lowercase bound wallet
    8 MATCH canon-py canon-js sha256 presented decision | allow: invalid EIP-55 casing of the bound address (checksum validation is out of scope)
    8/8 match
    corpus sha256 b3ddccb56489593246cd15411eed70897779849899fa3eac589e0c6e3f54c0eb
    Python 3.14.6; rfc8785 0.1.4
    Node v24.11.1

The script exits 1 if any check diverges. As a falsifiability check, a copy of the file with
the canonical form of vector 3 and the reason of vector 6 altered was run through the same
script and returned `DIVERGE` on exactly those two vectors, `6/8 match` and exit 1. That
mutated copy is not part of this record.

## What each check is

- `canon-py`, `canon-js`: two RFC 8785 libraries, one Python and one JavaScript, each
  canonicalize `policy_input`, and both outputs equal `policy_input_canonical` byte for byte.
- `sha256`: `"sha256:"` plus the SHA-256 of the UTF-8 canonical form equals
  `context.policy_input_hash`.
- `presented`: lowercasing `presented.bound_wallet` and `presented.pay_to` gives the values
  in `policy_input`.
- `decision`: the rule stated in the file's `description` (revoked, then payTo binding, then
  evidence rank, then trust score, first failure named), as written in `recompute.py`, gives
  `context.decision` and `context.reason`.

## Verification split

- canonical bytes / `policy_input_canonical`; aeoess; Mode B; independent; rfc8785 0.1.4 and
  canonicalize 4.0.0, which the runner did not author, invoked by a harness that only passes
  `policy_input` in and compares strings.
- digest / `policy_input_hash`; aeoess; Mode B; independent; Python hashlib SHA-256 over the
  published canonical bytes.
- address normalization / `presented` to `policy_input`; aeoess; Mode B; author-produced;
  the comparison in `recompute.py`, written by the runner, interprets the claimed result.
- decision and reason / `context.decision`, `context.reason`; aeoess; Mode B;
  author-produced; the decision rule in `recompute.py` is the runner's own implementation of
  the rule INAM states, so it is alternate code to INAM's but not an independent record
  under `CONTRIBUTING.md`.

Authorship relationship, stated in full: INAM wrote the vectors, their inputs and their
expected outputs. The runner reviewed earlier revisions of this file on #56 and #58 and
suggested the cases that became vectors 6 to 8 (reason precedence, a mixed-case address, a
checksum outside the gate). The runner did not write any vector bytes.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Files

- `recompute.py`: the recomputation, standard library plus rfc8785
- `canonical.mjs`, `package.json`, `package-lock.json`: the JavaScript canonicalizer
- `recompute-output.log`: the run output above
- `CHECKSUMS.sha256`: digests of the files above
