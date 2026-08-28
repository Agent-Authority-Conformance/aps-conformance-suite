# Canonical-bytes fixtures

Test vectors for the **string-concatenation preimage failure class**: where two semantically different inputs produce identical preimage bytes under naive `field1 + field2 + ...` concatenation, and the same hash, when the canonical-JSON path would distinguish them.

## Layout rationale

This directory is taxonomic-by-failure-class, not source-organization-specific. Future canonical-bytes fixtures from any implementation that hits the same class (APS, AgentGraph CTE, MoltyCel, others) land here under the same `canonical-bytes/` prefix. Filename carries source + version (`canonical-bytes-diff-v032.json`); category does not.

The class itself is documented under "INVALID_COMPOSITION" in the cross-impl conformance taxonomy (A2A#1786 §A): a chain hash fails to bind field boundaries, allowing two different field assignments to share a preimage.

## Cross-run

A cross-implementation byte diff. Any project can clone this repository, run one
command, and paste a machine-readable report of where its canonicalizer's bytes and
SHA-256 agree or differ from RFC 8785 on ten pinned cases.

What a result does NOT mean: it is a byte diff on ten cases, not a verdict on the
implementation and not a conformance claim of any kind.

### The ten cases

All ten live in `canonical-bytes-jcs-v2.json` (`v1` is the eight-case subset that v2
carries unchanged). Each names the RFC 8785 rule it exercises.

| case | rule exercised |
|---|---|
| `float-tenth` | Number serialization uses ECMAScript `Number::toString`, the shortest decimal that round-trips. `0.1` has no exact binary form. |
| `float-1e21-boundary` | `1e21` is the threshold where `Number::toString` switches to exponential, emitting `1e+21`. |
| `negative-zero` | JSON carries no distinct `-0`, and both zeroes render as `0`. |
| `integer-above-2pow53` | `2^53 + 2` is exactly representable as a double and emits as a plain integer, not exponential. |
| `small-exponent-vs-decimal` | `1e-7` stays exponential while `1e-6` becomes `0.000001`. Also pins key sorting, `dec` before `exp`. |
| `astral-key-ordering` | Object keys sort by UTF-16 code UNIT, not code point, so an astral key (lead unit `0xD834`) sorts before a BMP key (`0xFF61`). |
| `nfd-key-used-as-given` | Keys are emitted exactly as given and are never Unicode-normalized, so an NFD key stays NFD. |
| `nested-object-and-array` | Nested object keys sort recursively; array order is always preserved. |
| `integer-2pow60-inside-int64` | `2^60` is inside int64 but above `2^53`, so serialization follows the binary64 value rather than the caller's spelling. |
| `integer-2pow68-above-int64` | `2^68` is above int64 and exactly representable as a double; `|x| < 1e21` forces decimal notation. |

Four classes account for every real divergence seen so far:

1. **Exponent formatting.** Where a language switches between decimal and
   exponential notation, and how it spells the exponent.
2. **Astral and UTF-16 key order.** Sorting by code point instead of code unit
   reorders keys whenever an astral character meets a high BMP one.
3. **Non-ASCII output.** An encoder that escapes non-ASCII by default emits
   different bytes for the same string.
4. **The number model for large integers.** RFC 8785 serializes from the binary64
   value. A language that preserves an exact 64-bit integer through parsing
   diverges before serialization begins.

### Running it

```
npm ci
npm run crossrun:canonical-bytes
```

Node is a prerequisite of the orchestrator, so the TypeScript runner always runs.
Python, Go and Rust are optional: a missing toolchain produces a SKIP line and a
schema-valid SKIP result, never a pass. To run against a different fixture:

```
npm run crossrun:canonical-bytes -- path/to/fixture.json
```

The command exits non-zero only on a runner error or a schema failure. A byte or
digest mismatch is a recorded result, not a failed run, because publishing where
implementations differ is the point.

### Canonicalizers currently under test

| runner | implementation | kind |
|---|---|---|
| ts | `canonicalizeJCS` from the `agent-passport-system` npm package | first party |
| python | `agent_passport.canonical.canonicalize_jcs` from the `agent-passport-system` PyPI distribution | first party |
| go | `jcs.Canonicalize` from `github.com/aeoess/agent-passport-go` | first party |
| rust | `agent_passport::jcs::canonicalize` from the `agent-passport-system` crate | first party |

Each is depended on at an exact published version, never a local path, so a clone
reproduces the run without any sibling checkout.

The Python runner falls back to `json.dumps(sort_keys=True, separators=(",",":"),
ensure_ascii=False)` when the published distribution is not installed, and labels that
result `baseline_json_encoder`. It also refuses an editable install of a local checkout
as a first-party implementation, because that resolves to a working tree a person
cloning this suite does not have. Install `crossrun/python/requirements.txt` for the
first-party path.

A standard library encoder is never labeled as JCS or RFC 8785. It does not claim to
implement either, so its mismatches are comparative evidence about that standard
library, not a failed conformance run.

### Adding your own canonicalizer

Copy the runner closest to your language and replace one function.

1. `cp -r crossrun/ts crossrun/mylang` (or python, go, rust).
2. Replace the canonicalizer call. In each runner exactly one line turns a parsed
   JSON value into a canonical string; everything else is fixture reading,
   comparison and reporting.
3. Set `implementation`, `implementation_kind` and `implementation_version` to name
   what you are testing. Use `baseline_json_encoder` if it is a standard library
   encoder rather than an RFC 8785 implementation.
4. Register it in the `RUNNERS` array in `crossrun/run.mjs` with the command that
   invokes it and the toolchain to probe for.

Two rules the runners follow, and yours should too. Read every expected value from
the fixture at run time: a runner that embeds a byte string or a digest still agrees
with itself after the fixture changes. And accept an optional fixture path argument,
which is what lets the orchestrator point every runner at an alternative corpus.

### Result format

One JSON object per runner, written to `crossrun-results/<lang>.json` and validated
against [`crossrun-result.schema.json`](crossrun-result.schema.json). Per case the
report carries `name`, `byte_match`, `sha256_match`, `actual_bytes_hex`,
`actual_sha256`, and `first_divergent_byte_offset` (zero-based; when one byte sequence
is an exact prefix of the other it is the length of the shorter; null on a byte match).

```json
{
  "runner": "ts",
  "implementation": "agent-passport-system canonicalizeJCS",
  "implementation_kind": "first_party",
  "implementation_version": "4.5.1",
  "runtime_version": "node 24.11.1",
  "fixture": "fixtures/canonical-bytes/canonical-bytes-jcs-v2.json",
  "fixture_sha256": "9502d721...",
  "cases": [
    {
      "name": "float-tenth",
      "byte_match": true,
      "sha256_match": true,
      "actual_bytes_hex": "7b2276616c7565223a302e317d",
      "actual_sha256": "097a678e...",
      "first_divergent_byte_offset": null
    }
  ],
  "summary": { "total": 10, "byte_match": 10, "sha256_match": 10 }
}
```

A skipped runner produces the schema's other variant, carrying `runner`, `status`,
`reason`, and the detected orchestrator and runtime metadata. It has no `summary`: a
run that did not happen has no counts, and a zero-count summary would read as a
measurement.

`fixture_sha256` is over the fixture file bytes, so two runners can be shown to have
read the same input.

## Fixtures

### `canonical-bytes-diff-v032.json`

**Source:** [corpollc/qntm#15](https://github.com/corpollc/qntm/pull/15): qntm v0.3.2 canonical-bytes diff fixture for the string-concatenation preimage failure class. Mirrored under the cross-impl reciprocal-reference policy (A2A#1786 §A conformance appendix).

**Upstream verifier:** `specs/test-vectors/verify_canonical_bytes_diff.py` in the qntm repo. Five-check verifier (pre-fix hash, post-fix hash, divergence, collision, canonical immunity).

**Pre-fix sha256 (legacy concat path):** `sha256:53cce2bf015723f6ffe2eb31cccae5de9237c69c4ae49e3900a9295be7d6a332`
**Post-fix sha256 (canonical JSON path):** `sha256:040cfc8c93e252c8f9f524d9f947987a7a1e9bff7fc2952e0aa9ffe553811c69`
**File-level sha256 (byte-parity with qntm source):** `sha256:84df9e0a634eba40f5388872bed4f028a240e0c2f2d646755ecbdfb6b8ee0e42`

**APS-side regression test:** [`runners/ts/canonical-bytes-qntm-v0.3.2.test.ts`](../../runners/ts/canonical-bytes-qntm-v0.3.2.test.ts)

The APS-side test verifies all five checks of the upstream verifier plus a byte-equality assertion that the suite's vendored JCS canonicalizer (`runners/ts/canonicalize.ts`) produces output byte-identical to Python's `json.dumps(sort_keys=True, separators=(",", ":"))` for plain-string field objects. APS bilateral receipt construction (`agent-passport-system` `src/v2/accountability/bilateral.ts`) already uses canonical JSON, not string concatenation, and is therefore on the post-fix side of this diff. The fixture pins that property against regression.

## Cross-validation triangle

This fixture is one node in the three-impl / one-fixture / four-verifier-path conformance pattern documented at A2A#1786 §A:

| Impl | Verifier path |
|---|---|
| qntm (source) | Python `verify_canonical_bytes_diff.py` (`json.dumps`, `sort_keys=True`) |
| APS (this repo) | TypeScript `canonical-bytes-qntm-v0.3.2.test.ts` (vendored JCS canonicalizer) |
| AgentGraph (CTE) | CTE byte-parity vectors at `cross-impl-receipts/ctef-vectors.json` test the same canonical-JSON property at the bilateral-receipt layer |
| Future third-party impl | Imports either the upstream Python verifier or this TS test through the suite |

A change to either the canonical-JSON output or the legacy-concat preimage shape on any one impl would surface as a divergence here.

## Running

```bash
npm run test:canonical-bytes
```

Or via the full suite:

```bash
npm test
```

## Reciprocal pointer

This fixture closes the mirror commitment posted at [corpollc/qntm#15 (issuecomment-4376765242)](https://github.com/corpollc/qntm/pull/15#issuecomment-4376765242). The reciprocal pointer in qntm's repo references this directory.

## External byte-match verifier reciprocity

External cross-impl verifier scripts live at [arian-gogani/nobulex/scripts](https://github.com/arian-gogani/nobulex/tree/main/scripts):

- [`verify-aps-byte-match.mjs`](https://github.com/arian-gogani/nobulex/blob/main/scripts/verify-aps-byte-match.mjs): runs 10 vectors against APS `canonicalizeJCS` (`src/core/canonical-jcs.ts`)
- [`verify-ctef-byte-match.mjs`](https://github.com/arian-gogani/nobulex/blob/main/scripts/verify-ctef-byte-match.mjs): runs 4 vectors against CTEF v0.3.1

Most recent reciprocal verification: 2026-05-05, posted to [A2A#1786 (issuecomment-4384898059)](https://github.com/a2aproject/A2A/issues/1786#issuecomment-4384898059):

- APS receipt sha256: `5e31d6cf37d6a4ee7459a631a289733308c50f01b1f85db4c15370406a3e6dda` (10/10 PASS)
- CTEF receipt sha256: `a14e6db4477989a1f5c0d60078b0efcc4dc9dd7e3cd1276c4480bdd95b52bcfb` (4/4 PASS)

These external scripts complement the upstream Python verifier (column 1 of the cross-validation triangle) and the APS TypeScript test (column 2) by running byte-equality checks of full receipt envelopes against actual SDK output rather than testing the canonicalization function in isolation.

## JCS byte-contract vectors (canonical-bytes-jcs-v1.json)

Eight RFC 8785 JSON Canonicalization Scheme vectors generated from the
agent-passport-system `canonicalizeJCS` reference (npm 3.3.1) and verified by
this suite's vendored canonicalizer, proving byte-parity between the reference
and the standalone runner. Each vector carries an input document, the canonical
bytes as hex, and the SHA-256 of the canonical form.

They pin the byte-exact behaviors a naive canonicalizer gets wrong:

- ECMAScript `Number::toString`: `0.1` shortest round-trip, `1e21` boundary to
  exponential (`1e+21`), negative zero to `0`, an integer above 2^53 as a plain
  integer, and the `1e-7` exponential vs `1e-6` decimal threshold.
- Object keys sorted by UTF-16 code unit, so an astral-plane key (U+1D306, lead
  unit 0xD834) sorts before a BMP key U+FF61.
- Keys are used exactly as given: JCS does NOT Unicode-normalize keys, so an NFD
  key is preserved as NFD and is distinct from its NFC form.
- Recursive key sorting in nested objects, with array element order preserved.

## JCS byte-contract vectors v2 (canonical-bytes-jcs-v2.json)

Ten vectors: the eight v1 vectors carried byte-identical (v1 stays frozen) plus
two RFC 8785 integer-domain vectors derived per section 3.2.2.3 and appendix B:

- `integer-2pow60-inside-int64`: 1152921504606846976 canonicalizes to
  `1152921504606847000`. Inside signed int64, above 2^53, so a consumer that
  parses integer tokens as int64 and prints them exactly diverges here.
- `integer-2pow68-above-int64`: 295147905179352825856 canonicalizes to
  `295147905179352830000`. Above signed int64, so an int64 parse fails and a
  consumer that falls back to the original token diverges here instead.

The two exercise different consumer code paths and both are required to
attribute a divergence to the right branch. Verified byte-identical against the
agent-passport-system and agent-passport-python reference canonicalizers.
