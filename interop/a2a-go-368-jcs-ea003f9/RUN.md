# APS RFC 8785 canonical-bytes vectors run against an unmerged candidate implementation from a2aproject/a2a-go PR #368 at ea003f9

## What was pinned

| Item | Value |
|---|---|
| External pull request | a2aproject/a2a-go #368 |
| External head repository | kuangmi-bit/a2a-go |
| External head SHA | ea003f9afb3312d88cc06fc7f38a98d1627beeb4 |
| External head branch | feat/pull-event-queue |
| External license | Apache-2.0 |
| Entry point exercised | jcsMarshal, unexported |
| Our fixture | fixtures/canonical-bytes/canonical-bytes-jcs-v2.json |
| Fixture sha256 | 9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593 |
| Fixture vector count | 10 |
| a2acrypto/canonical.go sha256 | c070b5c91ba848428669666a9bdd65806d7a3f208e6fda12efc05adc04d28ed7 |
| a2acrypto/canonical.go lines | 300 |

## What was run

jcsMarshal is unexported, so the harness is an in-package Go test file placed
inside a scratch checkout of the external branch at the pinned head. No file
from that checkout is copied into this repository. This directory carries our
harness, our results, and digests of their files.

Each of the 10 vectors was run down two decode modes. The modes are reported
separately and are never pooled. For every vector under every mode, three values
were compared independently against the fixture: the canonical string, the
lowercase hex of the canonical bytes, and the SHA-256 of the canonical bytes.

## PRIMARY: production number path (json.Decoder with UseNumber)

Each vector input is decoded with json.Decoder.UseNumber, passed through
sortObjectKeys(obj, true), then given to jcsMarshal. Numbers arrive as
json.Number. This is the decode sequence canonicalPayload uses.

**10 of 10 vectors produced byte-identical canonical output at this SHA under
this decode mode.**

| Vector | canonical | hex | sha256 |
|---|---|---|---|
| float-tenth | match | match | match |
| float-1e21-boundary | match | match | match |
| negative-zero | match | match | match |
| integer-above-2pow53 | match | match | match |
| small-exponent-vs-decimal | match | match | match |
| astral-key-ordering | match | match | match |
| nfd-key-used-as-given | match | match | match |
| nested-object-and-array | match | match | match |
| integer-2pow60-inside-int64 | match | match | match |
| integer-2pow68-above-int64 | match | match | match |

Integer vectors, code path taken at this SHA under this mode: the three vectors
integer-above-2pow53, integer-2pow60-inside-int64 and integer-2pow68-above-int64
each reached canonicalNumber as a json.Number, and canonicalNumber at this SHA
routes every token through strconv.ParseFloat and then canonicalFloat, with a
verbatim return only when parsing fails. Outputs produced:

| Vector | canonical output |
|---|---|
| integer-above-2pow53 | {"value":9007199254740994} |
| integer-2pow60-inside-int64 | {"value":1152921504606847000} |
| integer-2pow68-above-int64 | {"value":295147905179352830000} |

Each equalled the fixture value on all three comparisons.

## SECONDARY: direct float64 probe (plain json.Unmarshal)

Each vector input is decoded with json.Unmarshal, so numbers arrive as float64
and reach canonicalFloat without passing through canonicalNumber, then given to
jcsMarshal. This is reachable by a caller marshalling map[string]any directly.
It is not the path canonicalPayload uses, and a result here does not describe
AgentCard signing.

**10 of 10 vectors produced byte-identical canonical output at this SHA under
this decode mode.**

| Vector | canonical | hex | sha256 |
|---|---|---|---|
| float-tenth | match | match | match |
| float-1e21-boundary | match | match | match |
| negative-zero | match | match | match |
| integer-above-2pow53 | match | match | match |
| small-exponent-vs-decimal | match | match | match |
| astral-key-ordering | match | match | match |
| nfd-key-used-as-given | match | match | match |
| nested-object-and-array | match | match | match |
| integer-2pow60-inside-int64 | match | match | match |
| integer-2pow68-above-int64 | match | match | match |

The two modes agree on all ten vectors. At this SHA both decode paths converge on
canonicalFloat for these vectors, so agreement between them follows from that
convergence rather than being a notable finding.

## Environment

| Item | Value |
|---|---|
| Go | go version go1.26.3 darwin/arm64 |
| OS | macOS, darwin/arm64 |
| Date | 2026-08-24 |

## Reproduction

    ./run.sh

The script verifies the fixture digest, clones the external repository outside
this repository at the pinned head SHA, drops the harness into that checkout,
runs both decode modes to completion, and returns non-zero if the digest does
not match or if either mode reported a mismatch.

## Scope and limits

This observation covers RFC 8785 canonical bytes only. It records agreement on a
shared dependency between our fixture and an unmerged candidate implementation
from a2aproject/a2a-go PR #368 at ea003f9. It is silent on signing, on key
handling, and on every layer above canonical form. Nothing outside the
canonicalization surface was exercised.

## Earlier observation

An earlier observation of the same fixture against head 411e3e81 is recorded in
`interop/a2a-go-368-jcs/`.
