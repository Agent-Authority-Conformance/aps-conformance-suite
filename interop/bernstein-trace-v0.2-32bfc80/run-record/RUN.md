# Run record: Bernstein TRACE v0.2 Level 0 trust records

Runner: Tymofii Pidlisnyi (aeoess), 2026-11-10, on his own machine (macOS 26.5 arm64, Python 3.14.6).
Implementation under test: the seven committed trust records of [sipyourdrink-ltd/bernstein](https://github.com/sipyourdrink-ltd/bernstein) at `32bfc80ce084d5180a988bac9228aa6ba0c5c9ea`, `tests/fixtures/trust-record-vectors/`.
This record attributes two runs. It is not a conformance verdict, certification or endorsement by anyone.

## Inputs

Fetched from the GitHub contents API at the commit above. sha256 of each file:

```
879e907837215dd62223e22a7775499281f5b4a6852cb3dc8acd041113222670  aggregate-trust-record.json
3a017c5e3f488d0ac33d54a008ea993bf53dca2d4ed1193c99314333607972d8  delegated-child-trust-record.json
273692ecb82df02684c6bbd286ccd9ea8bea707e9a32e5e4f157e010555dc047  delegated-grandchild-trust-record.json
5d1cac9d1a5e187353567633a03d4cee34ebd44237ac63f317cd9dd7ae94643a  delegated-parent-trust-record.json
cda5cd941facac7c47462f909407e0e1349729182897c029f691e4f6c128b652  single-execution-trust-record.json
27e262c86fa25771b41f3b07ded603dd9c6ff4077293f695471211349fa74262  supplementary-plane-child-trust-record.json
72c12020bd37f119259aaf70c69620f10585f3e7ff5621b917a0dec8156434ef  supplementary-plane-parent-trust-record.json
59a691eab26a963fee78ccc34d2789dcb0eaab5bff6459cb3f3d8038f6820cce  trust-record-vectors-key.pem
```

Suite: `agentrust-trace-tests` 0.5.1 (PyPI, released 2026-08-23), installed in a fresh virtual environment:

```
python3 -m venv tvenv
printf 'agentrust-trace-tests==0.5.1 --hash=sha256:5c13421d41357a5b2e096eced457f5dee65d4921b253b25dac53684b3d31eeeb\n' > req.txt
./tvenv/bin/pip install --only-binary=:all: --no-deps --require-hashes -r req.txt
./tvenv/bin/pip install --only-binary=:all: click cryptography jsonschema rfc8785
```

Resolved environment (`pip freeze`):

```
agentrust-trace-tests==0.5.1
attrs==26.1.0
cffi==2.1.1
click==8.5.1
cryptography==50.0.2
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
pycparser==3.12
referencing==0.37.0
rfc8785==0.1.4
rpds-py==2026.9.1
```

## R1. Level 0 per record (Mode A, independent)

```
for r in vectors/*-trust-record.json; do
  trace-tests verify --record "$r" --level 0 --max-age 999999999999
  trace-tests report --record "$r" --max-age 999999999999 --json "run/$(basename "$r" .json).report.json"
done
```

Result: each of the seven exits 0 with `Result: PASS  (8 checks, 0 skipped)`: TR-ENV 4, TR-SIG 2, TR-POL 2. Each report gives `highest_level_passed: 0`, Level 1 not passed (2 failures), Level 2 not passed (3 failures), as expected for software-only records (ADR-016). Verbatim outputs: `*.verify.txt`, `*.report.json`.

Controls:
- Default freshness window (`--max-age` omitted, 86400 s): all seven exit 1 with TR-ENV-002 stale, `iat 1700000007`. Output: `control-default-maxage-all.txt`.
- Signature changed (last four characters of `signature` in a copy of `single-execution-trust-record.json`): exit 1, `TR-SIG FAIL signature verification failed`. Output: `neg-signature-tampered.txt`, input `neg-signature-tampered.json`.

## R2. Hash references between records (Mode B, independent)

`chain_check.py` (27 lines, in this record) parses each record, serializes it with `rfc8785.dumps`, hashes it with `hashlib.sha256` and compares strings. It does not use Bernstein's emitter or the TRACE suite. Every comparison is an assertion, so any mismatch exits nonzero.

```
./tvenv/bin/python chain_check.py vectors
```

Result (`chain-check.txt`, exit 0, last line `ALL CHECKS PASS`):
- Each child's `delegation.parent_record_hash` equals the RFC 8785 digest of its parent's full record, signature included (3 of 3).
- The aggregate has exactly three `member-execution` references. Each digest matches exactly one hop, each `id` equals that hop's `subject`, and the three references cover the three hops with no duplicate.
- For contrast, a `sort_keys` JSON serialization gives a different digest for the supplementary-plane parent and the same digest for the ASCII pairs. That serialization differs from RFC 8785 in more than key order, so this line is consistent with Bernstein's key-order explanation without isolating it.

Controls, run on modified copies of the vectors:
- Second aggregate reference replaced with the first (digest and id): exit 1, `duplicate member delegated-parent` (`chain-check-neg-duplicate-member.txt`).
- `delegated-child` `parent_record_hash` replaced with 64 zeros: exit 1, mismatch named (`chain-check-neg-parent-hash.txt`).

R2 checks hash and identifier references. It does not validate delegation scope, narrowing or any other rule across the chain.

## Authorship relationship

The runner authored none of the seven vectors, Bernstein's trust-record emitter (`src/bernstein/core/observability/trust_record.py`), the vector generator, or `agentrust-trace-tests` 0.5.1. Checked through the GitHub commit history of those paths on 2026-11-10.

Earlier contributions, for the reader to weigh:
- Bernstein `d4f8082` (2026-08-01, delegation chain grading) and `2a47323` (2026-09-05, delegation receipts at spawn). They touch `core/identity/delegation.py`, `delegation_scope.py`, `core/security/audit_chain.py` and CLI files. The emitter imports `identity.install_rev` and `identity.http_signing`, not those files.
- agentrust-io/trace-spec `#237` (docs, 2026-08-31) and `#553` (conformance TR-POL-003 verifier context, 2026-10-19). Both are later than the 0.5.1 release.

## Files

`SHA256SUMS` lists every file in this record.
