# APS RFC 8785 canonical-bytes vectors, run against a2a-go PR #368 at 411e3e81

A neutral interop run by the Agent Authority Conformance lab. It records what an
unmerged candidate implementation from a2aproject/a2a-go PR #368 at 411e3e81 produced
when driven with our published RFC 8785 canonical-bytes vectors.

This is a record of agreement on a shared dependency. It is not an assessment of the
pull request, its author, or the project.

## What was pinned

| | |
|---|---|
| External PR | a2aproject/a2a-go #368, head repo kuangmi-bit/a2a-go, branch feat/pull-event-queue |
| External head SHA | `411e3e81e21318c14a9cd3f2a2999eb2fb96e396` |
| External base SHA | `d5d1cec20091eb8ed235128bb50712ee8aa3d42c` |
| External license | Apache-2.0 |
| Target file | `a2acrypto/canonical.go`, 303 lines |
| Target file sha256 | `fc3848074fe68d77df4e00fcd82cbab3a2f5961ca2ea8abbf509575d00cf3bec` |
| Our fixture | `fixtures/canonical-bytes/canonical-bytes-jcs-v2.json`, 10 vectors, generated_at 2026-08-19 |
| Fixture sha256 | `9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593` |
| Suite commit | `ee3d28de44ee8c1bab416946aa2eae6c1392279c` |

Both digests were verified before the run. No source file from the external repository
was copied into this repository; this directory carries our harness, our results, and
digests of their files.

## Environment

```
go version go1.26.3 darwin/arm64
date: 2026-08-19
os:   darwin/arm64
```

## Scope

The canonicalization surface only. `jcsMarshal(v any) ([]byte, error)` at line 60 is the
entry point and is generic over JSON. Nothing else in the pull request was exercised.

This covers RFC 8785 canonical bytes only. It says nothing about signing, key handling,
or interoperation at any layer above the canonical form.

## Two decode paths, reported separately

`canonicalPayload` at line 35 marshals the card, decodes with `dec.UseNumber()` at line
42, calls `sortObjectKeys(obj, true)` at line 46, then `jcsMarshal` at line 47. That
sequence is the AgentCard signing path and the harness replicates it exactly.

The secondary probe reaches the same generic entry point with numbers already widened to
`float64`, which is a path `canonicalPayload` does not take.

The two counts are never pooled.

## PRIMARY RESULT: the production number path

Decode with `json.Decoder.UseNumber()`, `sortObjectKeys(obj, true)`, then `jcsMarshal`.
Numbers arrive as `json.Number` and reach `canonicalNumber` at line 238.

**8 of 10 vectors produced byte-identical canonical output at this SHA under this decode
mode.**

| vector | canonical | hex | sha256 |
|---|---|---|---|
| float-tenth | match | match | match |
| float-1e21-boundary | match | match | match |
| negative-zero | match | match | match |
| integer-above-2pow53 | match | match | match |
| small-exponent-vs-decimal | match | match | match |
| astral-key-ordering | match | match | match |
| nfd-key-used-as-given | match | match | match |
| nested-object-and-array | match | match | match |
| integer-2pow60-inside-int64 | differs | differs | differs |
| integer-2pow68-above-int64 | differs | differs | differs |

### The two vectors that differ, expected and actual

`integer-2pow60-inside-int64`, input `{"value": 1152921504606846976}`

```
expected canonical : {"value":1152921504606847000}
actual   canonical : {"value":1152921504606846976}
first differing byte offset: 22
expected sha256 : 001814306319dfed540de7a22f61e88baf0288ebe916380796e8995d5db5eb00
actual   sha256 : 4a6dd55aad5394f2bcb6f3d9b304136d773d22411cebc1590540f34e6569d89e
```

`integer-2pow68-above-int64`, input `{"value": 295147905179352825856}`

```
expected canonical : {"value":295147905179352830000}
actual   canonical : {"value":295147905179352825856}
first differing byte offset: 26
expected sha256 : 57c82398dfd8be4a4ac903d1d2d01beee4c1d7179c9a5afc574bdf972646783b
actual   sha256 : ddf07dfbafdb059cc27251b827d08421790c56720806f515f85b64fa74e1435b
```

### Which branch executed, per numeric vector

`canonicalNumber` at line 238 branches on `strings.ContainsAny(s, ".eE")`. Values
carrying a decimal point or exponent go to `ParseFloat` then `canonicalFloat`. Everything
else goes to `ParseInt(s, 10, 64)` and returns `FormatInt`, and if `ParseInt` fails it
returns the input token verbatim. Recorded here, not judged.

| vector | branch taken | output |
|---|---|---|
| float-tenth | float, ContainsAny .eE, ParseFloat then canonicalFloat | matched expectation |
| small-exponent-vs-decimal | float, ContainsAny .eE, ParseFloat then canonicalFloat | matched expectation |
| integer-above-2pow53 | integer, ParseInt ok, FormatInt of the decimal text | matched expectation |
| integer-2pow60-inside-int64 | integer, ParseInt ok, FormatInt of the decimal text | `1152921504606846976` |
| integer-2pow68-above-int64 | integer, ParseInt FAILED, verbatim token fallback | `295147905179352825856` |

The three integer-shaped vectors split the branch as described: two sit inside signed
int64 so `ParseInt` succeeds, and one sits above signed int64 so the verbatim-token
fallback runs. Whether that formatting choice is correct is a separate question that
this artifact does not answer.

## SECONDARY PROBE: the direct float64 branch

Decode with plain `json.Unmarshal`, so numbers arrive as `float64` and reach
`canonicalFloat` at line 258 without passing through `canonicalNumber`. This is NOT the
path `canonicalPayload` takes. It is reachable by a caller who hands `map[string]any`
straight to the generic entry point.

**Secondary probe: 10 of 10 vectors produced byte-identical canonical output at this SHA
under this decode mode.**

All ten vectors matched on canonical string, hex, and sha256.

The generic `jcsMarshal` entry point agrees with all ten vectors when numbers arrive as
`float64`. The two vectors that differ above differ only when numbers arrive as
`json.Number`, which is the path the AgentCard production path takes.

## Reproduction

```
./run.sh
```

`run.sh` clones the external repository at the pinned head SHA into a scratch directory,
verifies the fixture digest and the target file digest, drops `aps_jcs_vectors_test.go`
into the checkout, and runs both decode modes. It exits non-zero on any digest mismatch,
and it does not mask the harness exit code.

The harness asserts each of the three comparisons per vector, so the two differing
vectors above make `go test` exit non-zero. That exit code is the mechanism that surfaces
a mismatch. It is not a verdict.

## Files

| file | what it is |
|---|---|
| `RUN.md` | this record |
| `results.json` | per-vector results keyed by decode path, never merged |
| `aps_jcs_vectors_test.go` | our harness, droppable into a checkout of their branch |
| `run.sh` | reproduction script, verifies both digests first |
| `CHECKSUMS.sha256` | digests of every file in this directory |
