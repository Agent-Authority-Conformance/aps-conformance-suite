# REMORA interoperability run, canonical bytes

## Labels

Mode B on the REMORA side: REMORA's own implementations recompute the canonical
bytes, and no APS SDK function computes any value on its behalf.
Author-produced: run by the author of the implementation under test
(`@darklordVirtual`, maintainer of REMORA), not by an independent party.
Independent reproduction is welcome and would be recorded under that label.

## Required fields

| field | value |
|---|---|
| who ran it | Stian Skogbrott, `@darklordVirtual` |
| date | 2026-08-29 |
| run mode | B |
| implementation name | REMORA |
| implementation repo and commit | `darklordVirtual/REMORA-research` at `edd8a4ece60129ff1d15b03ff9d78af0fd1e1d9d` |
| corpus reference | `2c3bdef91a70b40d7e9f1a30230be07a3645894b` |
| per-vector result | `results.json` in this directory, uncut, with observed bytes for every divergence |
| verbatim command and output | below, and `results.json` |
| environment | CPython 3.14.0, Node v24.11.0, Windows |

Both sides were cloned fresh and checked out at those revisions before the run.

## Relationship to the 2026-08-28 report

A REMORA x APS run report dated 2026-08-28 reported 51 of 60 on canonical bytes
against suite `3c8e165`, using an adapter with SHA-256 `700593e5c3a41cc...`.

**That adapter could not be located and its results are not carried forward.**
The file is not present on the machine that produced the report and is not in
the REMORA repository or its history, so its numbers are not reproducible.

This is a new run with a new adapter, a new hash, and different pins. The
denominator differs too: the canonical-bytes fixtures at `2c3bdef` hold 18
vectors, so the earlier 60 has no counterpart here.

## Adapter

`remora_aps_mode_b.py` in this directory, SHA-256 of the bytes this repository
ships:

```
45028c90b41e76f8245df46c417c8248ceada7997e277f1c01aa9028ffcd5162
```

Contributed under Apache-2.0, the licence of this repository. REMORA itself
remains BUSL-1.1 in its own repository and is only imported at run time.

## Verbatim commands and output

Mode B, from the root of a clean checkout of this repository:

```
$ REMORA_APS_RESULTS=interop/remora-edd8a4e/results.json \
  APS_SUITE=. \
  PYTHONPATH=/path/to/REMORA-research \
  python interop/remora-edd8a4e/remora_aps_mode_b.py
```

The full output is `results.json` in this directory, uncut. It carries every
vector, the observed bytes for every divergence, and the refusal text for every
refusal.

Mode A, same checkout:

```
$ npm ci --include=dev
$ npx tsx runners/ts/verify.ts

APS conformance suite v0.1.0
fixtures: 13 files

  bilateral-delegation         pass=10  fail=0  skip=0
  inference-session            pass=7  fail=0  skip=0
  instruction-provenance       pass=10  fail=0  skip=0
  aivss-scenarios              pass=10  fail=0  skip=0
  canonical-bytes              pass=18  fail=0  skip=1
  accountability-record        pass=12  fail=0  skip=0
  read-fidelity-receipt        pass=9  fail=0  skip=0
  actionref-canonical          pass=6  fail=0  skip=0
  bilateral-pair               pass=6  fail=0  skip=0
  bilateral-golden             pass=2  fail=0  skip=0
  merkle-root-parity           pass=6  fail=0  skip=0

TOTAL: 97 vectors  pass=96  fail=0  skip=1
```

Mode A is a reproduction of this corpus against itself and says nothing about
REMORA. It is included because the earlier run needed a second checkout, and
this one did not: at `2c3bdef`, in this environment, no `APS_SDK_PATH` and no
sibling checkout were required.

## Result: canonical bytes, 18 vectors

Every vector was serialised by two REMORA functions and byte-compared to
`canonical_bytes_hex`.

| serialiser | byte-identical | divergent | refused |
|---|---:|---:|---:|
| `remora/enforcement/result_envelope.py::_canonical_bytes` | 10 | 8 | 0 |
| `remora/interop/jcs.py::canonicalise` | 16 | 0 | 2 |

`_canonical_bytes` is what REMORA has always produced and what the earlier
report exercised. `canonicalise` was added in response to that report. Both are
reported: only the second would hide what changed, and only the first would hide
the work.

### The eight `_canonical_bytes` divergences

Observed bytes for each are in `results.json` under `legacy_bytes_hex`, beside
`expected_bytes_hex`.

| vector | fixture | cause |
|---|---|---|
| `small-exponent-vs-decimal` | v1, v2 | exponent formatting |
| `nfd-key-used-as-given` | v1, v2 | non-ASCII escaping |
| `astral-key-ordering` | v1, v2 | key ordering |
| `integer-2pow60-inside-int64` | v2 | number model |
| `integer-2pow68-above-int64` | v2 | number model |

These are the four classes recorded against attenu-guard 0.6.0 one day earlier.
A second implementation shows the same four classes.

### The two refusals

`canonicalise` closes exponent formatting, non-ASCII escaping and key ordering,
and byte-matches every vector that does not turn on the number model.

It refuses these two:

```
integer-2pow60-inside-int64
  input     {"value": 1152921504606846976}
  expected  {"value":1152921504606847000}

integer-2pow68-above-int64
  input     {"value": 295147905179352825856}
  expected  {"value":295147905179352830000}
```

RFC 8785 section 3.2.1 makes number data binary64 and recommends strings for
integers outside that range; Appendix B lists `~2**68` as
`295147905179352830000` and notes that extended precision is not considered. In
both vectors above the integer is adapted to binary64 and its image is not
unique: other integers map to the same double and therefore to the same
canonical bytes.

REMORA declines those cases. It binds an authorisation to the exact arguments it
was granted for and recomputes that binding immediately before dispatch, so it
does not emit canonical bytes for an integer whose binary64 image it cannot tell
apart from a neighbour's.

**The enforced property, stated exactly.** Integers whose binary64 image is not
unique are refused. `2**53` is refused, because `2**53 + 1` shares its double
under round-half-to-even. `2**53 + 2` passes, because no other integer maps to
its double, and the suite serialises it exactly.

That is narrower than "REMORA prevents two argument sets from sharing canonical
bytes", which this implementation does not do and which an earlier draft of this
record claimed. Distinct float literals collapse in `json.loads` before
`canonicalise` runs, so `0.1000000000000000055511151231257827` and `0.1` reach
it as one value and share bytes, and `-0.0` normalises to `0`. The integer rule
is what the vectors test and what mutation confirms.

Rationale in full:
[docs/design/aps-authority-profile-v0.md](https://github.com/darklordVirtual/REMORA-research/blob/edd8a4ece60129ff1d15b03ff9d78af0fd1e1d9d/docs/design/aps-authority-profile-v0.md).

Running these vectors also corrected the implementation. An earlier version used
a magnitude bound and refused `9007199254740994`, which sits above `2**53` and
is still the only integer mapping to its double. The suite serialises it
exactly, and so does REMORA now. The test is uniqueness, not magnitude.

## Two Windows environment defects in the harness

Neither affects the adapter result, which is byte-identical in a CRLF and an LF
checkout.

**1. `core.autocrlf` breaks every fixture manifest hash.** A default Git for
Windows clone rewrites LF to CRLF on checkout, so every fixture's bytes change
and `npm test` reports 13 `manifest sha256 mismatch` failures across every
family. It reads as the suite being broken.

```
CRLF checkout  322f8bd60fc0ad11…   canonical-bytes-jcs-v1.json
LF   checkout  914803e87ce165f5…   canonical-bytes-jcs-v1.json  (matches the manifest)
```

Cloning with `core.autocrlf=false` makes the fixture verification pass. There is
no `.gitattributes` in the tree at `2c3bdef`.

**2. `spawnSync` on the extensionless `.bin` shim fails on Windows.**
`runners/ts/fail-loud-and-wire.test.ts:47` spawns `node_modules/.bin/tsx`
without `shell: true`. On Windows that path is not executable; `tsx.cmd` is. The
spawn returns ENOENT, `r.status` is null, stdout is empty, and six checks fail
with `-- null` because their regexes matched nothing:

```
FAIL real fixtures exit 0 -- exit -1
FAIL actionref-canonical asserted (pass=6 fail=0 skip=0) -- null
FAIL bilateral-pair asserted (pass=6 fail=0 skip=0) -- null
FAIL total skip == 1 -- skip=null
FAIL corruption is reported as a failure, not a skip
FAIL unrecognized shape names the offending vector
```

Confirmed directly: `spawnSync('node_modules/.bin/tsx', ['--version'])` returns
`ENOENT`, and the same call with `shell: true` resolves. Fixture verification is
unaffected, so this hides only the meta-test that checks the runner fails
loudly.

## Families not run

**`interop/aae-envelope/` (V1 to V4).** The earlier report recorded 4 of 4 here.
The semantic mapping it used was never published: APS DID-bound links were
represented through REMORA's link-key registry, and `mandate.actions` through
REMORA's opaque scope strings. Re-deriving that mapping now, after the expected
answers are known, would produce a different mapping and a result that cannot be
compared to the earlier one. A mapping drawn to fit the answers is not evidence.
The directory's README carries the reason codes a REMORA map would target, so a
future run can be audited against it if the mapping is written down and reviewed
before the run rather than after.

**The earlier 29 Ed25519 known-answer tests.** They correspond to no fixture
family at `2c3bdef` and are not claimed here.

## APS families with no REMORA counterpart

Every family in `fixtures/` at `2c3bdef`, classified. REMORA has no wire type,
schema validator or adapter for any of these, so they are not run and not
claimed.

| family | |
|---|---|
| `accountability-record` | no REMORA counterpart |
| `actionref-canonical` | no REMORA counterpart |
| `aivss-scenarios` | no REMORA counterpart |
| `attribution` | no REMORA counterpart |
| `bilateral-delegation` | no REMORA counterpart |
| `bilateral-golden` | no REMORA counterpart |
| `bilateral-pair` | no REMORA counterpart |
| `canonical-bytes` | **run, see above** |
| `composition` | no REMORA counterpart |
| `inference-session` | no REMORA counterpart |
| `instruction-provenance` | no REMORA counterpart |
| `k8s-receipt-admission-stage-negatives` | no REMORA counterpart |
| `merkle-root-parity` | no REMORA counterpart |
| `read-fidelity-receipt` | no REMORA counterpart |
| `receipt-decision-relation` | no REMORA counterpart |

And the six under `fixtures/cross-stack/`: `aat-amdal`,
`action-ref-v1-negatives`, `nobulex-bilateral-v0`, `receipts-aeoess`,
`receipts-amdal`, `synthetic`. Same status.

## What this record does not establish

Byte agreement on the canonical-bytes vectors that do not turn on the number
model, from one serialiser, run by the implementation's author. Nothing about
DIDs, key resolution, APS envelopes, or any family above. REMORA signs policy
decision tokens with HMAC against a registry key rather than DID or key-id bound
Ed25519 at the link level, and has no ActionRef type, so no "REMORA APS
Authority Profile" is claimed.

## Provenance

Produced with AI assistance, which REMORA's own
[docs/AI_USE.md](https://github.com/darklordVirtual/REMORA-research/blob/edd8a4ece60129ff1d15b03ff9d78af0fd1e1d9d/docs/AI_USE.md)
requires it to disclose. The pins, the adapter and the results were checked
against the fixtures by hand before submission; tool-generated output is not
evidence on its own.
