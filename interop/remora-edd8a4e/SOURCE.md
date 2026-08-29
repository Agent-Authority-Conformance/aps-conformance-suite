# REMORA interoperability run, canonical bytes

One author-run Mode B interoperability run between the APS conformance surface
and REMORA, performed by Stian Skogbrott (`@darklordVirtual`) on 2026-08-29. It
is not an independent reproduction, it confers no conformance verdict on
REMORA, and it makes no claim about APS beyond the pinned fixtures it reads.

## Relationship to the 2026-08-28 report

A REMORA x APS run report dated 2026-08-28 reported 51 of 60 on canonical bytes
against suite `3c8e165`, using an adapter with SHA-256 `700593e5c3a41cc...`.

**That adapter could not be located and its results are not carried forward.**
The file is not present on the machine that produced the report and is not in
the REMORA repository or its history. Its numbers are therefore not
reproducible, and reporting them here as if they were would be a claim without
evidence.

This is a new run with a new adapter, a new hash, and different pins. The
denominator differs too: the canonical-bytes fixtures at `2c3bdef` hold 18
vectors, so the earlier 60 does not correspond to anything in this revision.

## Pinned revisions

| side | revision |
|---|---|
| APS conformance suite | `2c3bdef91a70b40d7e9f1a30230be07a3645894b` |
| REMORA | `edd8a4ece60129ff1d15b03ff9d78af0fd1e1d9d` |
| adapter | `remora_aps_mode_b.py`, SHA-256 `b19121cfece9b700144723ee16d4bbe49db96bdb43ff8dd038b98c40010c23c9` |
| Python | CPython 3.14.0, Windows |

Both sides were cloned fresh and checked out at those revisions before the run.
The suite revision is the one carrying the packaging fix described below, and
the run needed no `APS_SDK_PATH` and no second checkout.

## Re-run

```bash
APS_SUITE=/path/to/aps-conformance-suite \
PYTHONPATH=/path/to/REMORA-research \
python remora_aps_mode_b.py
```

The adapter reads fixtures and imports REMORA. It writes nothing, needs no
network, and no APS SDK function computes any REMORA value.

## Result: canonical bytes, 18 vectors

Every vector was serialised by two REMORA functions and byte-compared to
`canonical_bytes_hex`.

| serialiser | byte-identical | divergent | refused |
|---|---:|---:|---:|
| `remora/enforcement/result_envelope.py::_canonical_bytes` | 10 | 8 | 0 |
| `remora/interop/jcs.py::canonicalise` | 16 | 0 | 2 |

`_canonical_bytes` is what REMORA has always produced and what the earlier
report exercised. `canonicalise` was added in response to that report. Both are
reported, because reporting only the second would hide what changed and
reporting only the first would hide the work.

### The eight `_canonical_bytes` divergences

| vector | fixture | cause |
|---|---|---|
| `small-exponent-vs-decimal` | v1, v2 | exponent formatting |
| `astral-key-ordering` | v1, v2 | UTF-16 member ordering |
| `nfd-key-used-as-given` | v1, v2 | non-ASCII escaping |
| `integer-2pow60-inside-int64` | v2 | number model |
| `integer-2pow68-above-int64` | v2 | number model |

These are the four classes recorded against attenu-guard 0.6.0 one day earlier,
in the same order, from a different Python implementation. REMORA is a second
independent occurrence, not a separate defect.

### The two refusals

`canonicalise` closes exponent formatting, non-ASCII escaping and UTF-16
ordering, and byte-matches every vector that does not turn on the number model.

It refuses these two:

```
integer-2pow60-inside-int64
  input     {"value": 1152921504606846976}
  expected  {"value":1152921504606847000}

integer-2pow68-above-int64
  input     {"value": 295147905179352825856}
  expected  {"value":295147905179352830000}
```

The refusal is deliberate and is the one place REMORA declines to follow RFC
8785. In both cases the canonical form names a different integer than the
input, and every integer rounding to the same double produces the same bytes.
REMORA binds an authorisation to the exact arguments it was granted for and
recomputes that binding immediately before execution, so a number model under
which two different argument sets share canonical bytes would let an approval
for one authorise the other.

REMORA therefore refuses an integer whose binary64 form is shared with a
neighbour, and serialises every other integer exactly.

The test is uniqueness, not magnitude, and the vectors are what showed the
difference. `integer-above-2pow53` carries `9007199254740994`, which sits above
2^53 and is still the only integer mapping to its double. The suite serialises
it exactly and so does REMORA. An earlier version of this module used a
magnitude bound and refused that vector; running against these fixtures is what
caught it.

Rationale in full:
[docs/design/aps-authority-profile-v0.md](https://github.com/darklordVirtual/REMORA-research/blob/edd8a4ece60129ff1d15b03ff9d78af0fd1e1d9d/docs/design/aps-authority-profile-v0.md).

## Mode A: the suite against itself

```
TOTAL: 97 vectors  pass=96  fail=0  skip=1
```

Identical to the count in the 2026-08-28 report, at a different revision.

## Two Windows environment defects in the harness

Both are environment or harness defects rather than protocol divergence or
implementation defects, and both were found by running on Windows. Neither
affects the adapter result above, which is byte-identical in a CRLF and an LF
checkout.

**1. `core.autocrlf` breaks every fixture manifest hash.** A default Git for
Windows clone rewrites LF to CRLF on checkout, so every fixture's bytes change
and `npm test` reports 13 `manifest sha256 mismatch` failures across every
family. It reads as the suite being broken.

```
CRLF checkout  322f8bd60fc0ad11…   canonical-bytes-jcs-v1.json
LF   checkout  914803e87ce165f5…   canonical-bytes-jcs-v1.json  (matches the manifest)
```

Cloning with `core.autocrlf=false` makes the fixture verification pass. A
`.gitattributes` marking `fixtures/**` as `-text`, or `* -text`, would make the
repository self-protecting: byte-pinned fixtures cannot survive line-ending
normalisation, and a contributor on Windows has no way to guess that from the
failure message.

**2. `spawnSync` on the extensionless `.bin` shim fails on Windows.**
`runners/ts/fail-loud-and-wire.test.ts` spawns `node_modules/.bin/tsx` without
`shell: true`. On Windows that path is not executable; `tsx.cmd` is. The spawn
returns ENOENT, `r.status` is null, stdout is empty, and six checks fail with
`-- null` because their regexes matched nothing:

```
FAIL real fixtures exit 0 -- exit -1
FAIL actionref-canonical asserted (pass=6 fail=0 skip=0) -- null
FAIL bilateral-pair asserted (pass=6 fail=0 skip=0) -- null
FAIL total skip == 1 -- skip=null
FAIL corruption is reported as a failure, not a skip
FAIL unrecognized shape names the offending vector
```

Confirmed directly: `spawnSync('node_modules/.bin/tsx', ['--version'])` returns
`ENOENT`, and the same call with `shell: true` resolves. The fixture
verification itself is unaffected, so this hides only the meta-test that checks
the runner fails loudly.

## Suite defect found by the earlier run

The 2026-08-28 run needed a second checkout because two runners resolved the
APS SDK from `$HOME/agent-passport-system/dist` unless `APS_SDK_PATH` was set.
That is fixed at the pinned revision. This run used neither the environment
variable nor a sibling checkout, which is the observable confirmation.

## Families not run

Listed rather than omitted, because a family absent from a record reads as
untested and these were deliberately not claimed.

**`aae-delegation-semantics`.** The earlier report recorded 4 of 4 here. The
semantic mapping it used was never published: APS DID-bound links were
represented through REMORA's link-key registry, and `mandate.actions` through
REMORA's opaque scope strings. Re-deriving that mapping now, after the expected
answers are known, would produce a different mapping and a result that cannot
be compared to the earlier one. A mapping drawn to fit the answers is not
evidence. If the lab wants this family, the mapping should be written down
first and reviewed before the run.

**`ed25519-kat`.** The earlier report recorded 29 of 29. Those vectors were not
located as a single fixture family at this suite revision and are not claimed
here.

## Unsupported APS families

REMORA has no wire type, schema validator or adapter for these, so they are
unsupported rather than failed:

- ActionRef canonical profile and invocation filter
- bilateral pair and bilateral receipt wire schema
- accountability record schema
- read-fidelity receipt schema
- attribution wrapper chain
- instruction provenance
- inference session records
- merkle root parity

## REMORA reason-code mapping

Not exercised in this run, since the delegation family was not run, but
recorded so that a future run of it can be audited rather than trusted.

| REMORA failure code | APS reason class |
|---|---|
| `scope_exceeds_delegation` | `SCOPE_WIDENING` |
| `scope_widened_at_link` | `SCOPE_WIDENING` |
| `delegation_link_expired` | `DELEGATION_EXPIRED` |
| `envelope_expired` | `DELEGATION_EXPIRED` |
| `revoked_kid_at_link` | `DELEGATION_REVOKED` |
| `unknown_or_revoked_kid_at_link` | `DELEGATION_REVOKED` |

## What this record does not establish

Semantic alignment on canonicalisation for the vectors that do not turn on the
number model. Nothing about DIDs, key resolution, APS envelopes, or any family
listed as unsupported or not run. REMORA signs policy decision tokens with
HMAC against a registry key rather than DID or key-id bound Ed25519 at the link
level, and has no ActionRef type, so a "REMORA APS Authority Profile" is not
claimed.

## Provenance

Author-run. Produced by the REMORA author with AI assistance, as
[docs/AI_USE.md](https://github.com/darklordVirtual/REMORA-research/blob/edd8a4ece60129ff1d15b03ff9d78af0fd1e1d9d/docs/AI_USE.md)
requires REMORA to disclose. The adapter, the pins and the results were checked
against the fixtures by hand before submission; tool-generated output is not
evidence on its own.
