# Bernstein TRACE v0.2 trust records, Level 0 checks (software-only)

**Status:** run record with an external verification run, accepted by the Bernstein maintainer for scope and attribution on [sipyourdrink-ltd/bernstein discussion #6902](https://github.com/sipyourdrink-ltd/bernstein/discussions/6902). The results are the runner's.

This records the checks performed and their results. It does not establish full TRACE conformance, a TRACE level held by Bernstein, certification or endorsement by Bernstein, agentrust-io, Agent Authority Conformance or LF Decentralized Trust. It is a run record under `interop/`, listed on its own terms, and is not grouped with APS or any other result.

## Sources and scope

Bernstein remains the canonical source and maintains its own tests. The lab links to the pinned files without taking ownership or changing their licenses. This listing creates no obligation for Bernstein to maintain lab adapters.

- [Bernstein test commit](https://github.com/sipyourdrink-ltd/bernstein/tree/32bfc80ce084d5180a988bac9228aa6ba0c5c9ea), `32bfc80`
- [LICENSE](https://github.com/sipyourdrink-ltd/bernstein/blob/32bfc80ce084d5180a988bac9228aa6ba0c5c9ea/LICENSE) and [NOTICE](https://github.com/sipyourdrink-ltd/bernstein/blob/32bfc80ce084d5180a988bac9228aa6ba0c5c9ea/NOTICE)
- [ADR-016](https://github.com/sipyourdrink-ltd/bernstein/blob/485e06f9118fd4811f44ed0f2454f76a252b8038/docs/decisions/016-trace-conformance-level.md), software-only Level 0
- TRACE v0.2 specification, [`agentrust-io/trace-spec` at `e7e2ecab68cf3534c7d5fcb7e9a6f089fcb7d592`](https://github.com/agentrust-io/trace-spec/tree/e7e2ecab68cf3534c7d5fcb7e9a6f089fcb7d592)
- `agentrust-trace-tests` 0.5.1, the version the vectors README pins, wheel SHA-256 `5c13421d41357a5b2e096eced457f5dee65d4921b253b25dac53684b3d31eeeb`. The suite's current line is 0.6. A run against a newer version is a new record beside this one, not an edit of it.

## Tests covered

**Portable records:** seven committed JSON vectors in `tests/fixtures/trust-record-vectors/`, covering a single execution, three delegated records, an aggregate and a supplementary-plane parent-child pair. These can be checked without installing Bernstein.

**Bernstein-specific tests:** these test files exercise Bernstein's own implementation. They are listed for reference and were not run in this record.

- `tests/unit/core/observability/test_trust_record.py`
- `tests/unit/test_trace_conformance.py`
- `tests/unit/test_trust_record_conformance.py`. Part of this file is the portable check, because it also runs the upstream `trace-tests verify` against the same vectors when the suite is installed.
- `tests/unit/test_trust_record_format_vectors.py`

## Results

### R1. TRACE Level 0 verification

All seven records passed eight checks each, with none skipped. The checks covered envelope fields, the signature and policy fields.

The records use a fixed November 2023 timestamp, so they were run with `--max-age 999999999999`, the override the vectors README states. Without it, all seven failed the freshness check. Changing one record's signature also caused signature verification to fail.

Level 1 and Level 2 were not passed or claimed. The records do not contain the hardware evidence required for the higher levels.

### R2. Hash references (a check outside the TRACE suite, not a TRACE level result)

The hashes were recomputed separately using `rfc8785` 0.1.4 and SHA-256.

All three child records carry the RFC 8785 hash of their complete parent record. The aggregate's three member references each match exactly one execution record, by digest and by `id` equal to that record's `subject`, and together cover all three. The script exits nonzero on any mismatch, and two modified copies confirm that it does.

For the supplementary-plane parent, a `sort_keys` JSON serialization gives a different hash, consistent with the key-order difference Bernstein documents.

These checks establish the reported hash and identifier matches. They do not verify delegation scope or any other rule across the chain.

## Verification split

Labels follow the lab's definitions: [Mode A and Mode B](../../docs/RUN-REPORT.md#two-run-modes), and [`independent`](../../CONTRIBUTING.md#what-lands-by-pr) as defined in the paragraph that begins "A record is `independent` when". Records here are attributed per layer, meaning each verification claim carries its own runner, mode and authorship label.

- R1, TRACE Level 0 per-record verification; Tymofii Pidlisnyi (aeoess); Mode A; independent (the runner wrote none of the seven vectors, the trust-record emitter, the vector generator or the 0.5.1 suite, earlier contributions listed below); `agentrust-trace-tests` 0.5.1
- R2, record hash references, outside the TRACE suite; Tymofii Pidlisnyi (aeoess); Mode B; independent (same relationship, and the recomputation uses the `rfc8785` package, not Bernstein's canonicalizer); `rfc8785` 0.1.4 and SHA-256

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

**Earlier contributions by the runner, for the reader to weigh:**

- Bernstein [`3f8d75a6`](https://github.com/sipyourdrink-ltd/bernstein/commit/3f8d75a629ba355481cc58f44e6d163669c16ea1) (2026-07-25), which changed `tests/fixtures/showback/canonical_vectors.json`. That file is not one of the trust-record files. Its statement vectors exercise the RFC 8785 canonicalizer that the trust-record signing path also calls, and the commit added a case with supplementary-plane property names. Weigh it next to R2.
- Bernstein `d4f8082` (2026-08-01, delegation chain grading) and `2a47323` (2026-09-05, delegation receipts at spawn), outside the trust-record files.
- agentrust-io/trace-spec `#237` (docs, 2026-08-31) and `#553` (conformance TR-POL-003 verifier context, 2026-10-19), both later than the 0.5.1 release.

## Run record

`run-record/` is a byte-identical copy of the run record published at [gist revision `5cc2be6a`](https://gist.github.com/aeoess/ab8b637c25ce1715b96b9ac50583db9f/5cc2be6a10aaa6b905424659577fa6461c2115de), with the same `SHA256SUMS`. It has the input hashes, commands, verbatim outputs, the comparison script and the failed control runs. Its authorship section omits `3f8d75a6` and gives the trace-spec pin in short form. Both corrections are in `CLARIFICATIONS.md`, and the pinned files are unchanged.
