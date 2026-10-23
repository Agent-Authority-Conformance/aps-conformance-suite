# jcs-admit 0.1.3 over the canonical-bytes cross-run cases at b9918fc

The second Rust canonical-bytes runner, `fixtures/canonical-bytes/crossrun/rust-jcs-admit/`, moved from
`jcs-admit` 0.1.1 to 0.1.3 in PR #182. The repository's dependabot configuration requires a jcs-admit bump to
add a new record rather than edit the existing one. This directory is that record. The 0.1.1 record at
`interop/jcs-admit-0.1.1-canonical-bytes-da95834/` is unchanged.

## Result

10 of 10 cases byte-identical to `canonical_bytes_hex`, and 10 of 10 SHA-256 equal to `canonical_sha256`.
Three runs wrote a byte-identical report, SHA-256
`51fa24987b0dc4671d278c77977e4704731eb8540d2978b665db37bf4ae25dce`.

## Fields

| field | value |
|---|---|
| who ran it | @aeoess |
| date | 2026-10-23 |
| run mode | Mode B, alternate recomputation of the fixture's canonical bytes and digests |
| implementation name | `jcs_admit::admit` (RFC 8785 profile), crate `jcs-admit` |
| implementation repo and commit or version | `jcs-admit` 0.1.3 from crates.io, checksum `d5b06f8ba9b441bb49cc1156c967b7e33c9f8626360a5d5743808f9d8c7c2fb9` (as locked in the runner's `Cargo.lock`, and equal to the SHA-256 of the downloaded `.crate` file); source at https://github.com/probityai/agent-evidence |
| corpus reference | `b9918fcbd7e0741ca1e7324dc4e4a4d469454257` (PR #182 head, containing main at `4aa051bf`), fixture `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json`, SHA-256 `9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593` |
| per-vector result | `rust-jcs-admit.json` in this directory, the runner's report as written to `crossrun-results/` |
| verbatim command and output | `npm ci --include=dev`, the Python runner's `requirements.txt` installed in a virtual environment, then `npm run crossrun:canonical-bytes`; output of the third run in `crossrun-output.txt` |
| environment | macOS arm64; rustc 1.95.0 (59807616e 2026-04-14), cargo 1.95.0; node v24.11.1 for the orchestrator |
| author-produced or independent | author-produced. The runner did not write `jcs-admit` or the runner script, but did write the canonical-bytes vectors this run checks |
| suspected defective vectors | none |

## Pinned version

Between the published crates 0.1.1 and 0.1.3, `src/` changes in two places. `Options::check_input_length` is
added, and `admit_with` now calls it in place of the same inline byte-cap comparison. The error enum gains a
`serde::Serialize` derive behind the optional `serde` feature, which is off by default and not enabled by this
runner, whose `Cargo.toml` names `jcs-admit = "=0.1.3"` with no features. The crate's `CHANGELOG.md` describes
0.1.3 as a metadata change, the `repository` field moving to the monorepo, and 0.1.2 as the release that added
the helper and the optional derive.

This run covers the ten positive canonical-bytes cases only. The fixture has no refusal cases, so the run does
not exercise the crate's error behavior.

## Verification split

- RFC 8785 canonical bytes and SHA-256 of the ten `canonical-bytes-jcs-v2` cases; runner: aeoess via
  `crossrun/rust-jcs-admit`; Mode B; author-produced; implementation: `jcs-admit` 0.1.3. The runner authored the
  vectors, so the record is not independent.
- No independent record exists for this layer. It is queued in `docs/OPEN-RUNS.md`.

These records are attributed per layer. Merge of this record is not an end-to-end verification or a verdict on
the implementation.

## Files

`SHA256SUMS.txt` covers the other three files here.
