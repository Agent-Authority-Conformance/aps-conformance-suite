# jcs-admit 0.1.1 over the canonical-bytes cross-run cases at da95834

The canonical-bytes cross-run (`fixtures/canonical-bytes/README.md`, "Cross-run") gained a second Rust runner,
`fixtures/canonical-bytes/crossrun/rust-jcs-admit/`, which runs `jcs_admit::admit` from the published
`jcs-admit` crate over the ten cases in `canonical-bytes-jcs-v2.json`. This directory records the first run of
that runner. The run was agreed in issue #137 as author-produced: the runner wrote the crate.

## Result

10 of 10 cases byte-identical to `canonical_bytes_hex`, and 10 of 10 SHA-256 equal to `canonical_sha256`.
Three runs wrote a byte-identical report, SHA-256
`d85953a9f39eb3bd651af39cc905a36e153bd8a3e534edc21effa8070d2d71bf`.

## Fields

| field | value |
|---|---|
| who ran it | @astrogilda |
| date | 2026-10-04 |
| run mode | Mode B, alternate recomputation of the fixture's canonical bytes and digests |
| implementation name | `jcs_admit::admit` (RFC 8785 profile), crate `jcs-admit` |
| implementation repo and commit or version | `jcs-admit` 0.1.1 from crates.io, checksum `12044fdb81b1b883846eb7056ce857ea4523ab9f213990fa6cd797ec7c710ffe` (as locked in the runner's `Cargo.lock`); source at https://github.com/probityai/jcs-admit |
| corpus reference | `da95834aacbb5b5550872fc85f51d067652c9e7f`, fixture `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json`, SHA-256 `9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593` |
| per-vector result | `rust-jcs-admit.json` in this directory, the runner's report as written to `crossrun-results/`, schema-valid against `crossrun-result.schema.json` |
| verbatim command and output | `npm ci --include=dev`, the Python runner's `requirements.txt` installed, then `npm run crossrun:canonical-bytes`; output of the last run in `crossrun-output.txt` |
| environment | Linux x64; rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1; node v22.23.3 for the orchestrator |
| author-produced or independent | author-produced. The runner wrote `jcs-admit`. Its own parser builds the value it hands to `serde_json_canonicalizer` 0.3.2 for serialization, so the crate as a whole is the recomputation implementation. The runner also wrote the runner script |
| suspected defective vectors | none |

## Pinned version

Issue #137 reported a run of `jcs-admit` 0.1.0; this record pins 0.1.1, the current release. Between the two
published crates (https://crates.io/crates/jcs-admit/0.1.0 and https://crates.io/crates/jcs-admit/0.1.1),
`src/` differs in one line, the `html_root_url` documentation attribute in `src/lib.rs`. 0.1.1 lowers the
`serde` requirement from 1.0.229 to 1.0.100 and adds tests and CI, as the 0.1.1 entry of the crate's
`CHANGELOG.md` states. The canonicalization code is the same in both.

## Input bytes

`jcs-admit` decides on raw bytes before any decode. The runner hands it each vector's `input` exactly as the
fixture file spells it, read with `serde_json::value::RawValue`, so tokens such as `1e+21` and
`295147905179352825856` reach the canonicalizer unchanged and are not first rewritten by a JSON parser.

## Verification split

- RFC 8785 canonical bytes and SHA-256 of the ten `canonical-bytes-jcs-v2` cases; runner: astrogilda via
  `crossrun/rust-jcs-admit`; Mode B; author-produced; implementation: `jcs-admit` 0.1.1. The runner authored the
  implementation, so the record is not independent.
- No independent record exists for this layer. It is queued in `docs/OPEN-RUNS.md`; a run of the pinned crate by
  anyone who did not write it would supply one.

These records are attributed per layer. Merge of this record is not an end-to-end verification or a verdict on
the implementation.

## Files

`SHA256SUMS.txt` covers the other three files here.
