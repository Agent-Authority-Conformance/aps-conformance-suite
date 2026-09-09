# attenu-guard 0.6.1 interop runs, both directions

Successor to interop/attenu-guard-0.6.0, re-run on 2026-08-29 against the 0.6.1 release,
which is the first release to carry the eighth vector. Both runs were performed by
aeoess (the maintainer of this corpus): author-produced on the APS side, not an
independent reproduction. This family confers no conformance verdict on attenu-guard
and makes no claim about APS beyond the pinned fixtures it references.

## Counterparty artifacts, pinned

- Internet-Draft: draft-asor-wimse-agent-delegation-chain-00 (a -01 is announced by the
  author to add a normative wildcard sentence; not published at the time of this run).
- Package: attenu-guard 0.6.1 on PyPI, installed into a clean venv. The vectors ship
  inside the package as attenu_guard.vectors; the author states tests/vectors/ at the
  same tag is byte-identical and CI-enforced. Eight vectors: valid_chain,
  reject_bad_signature, reject_depth_exceeded, reject_exceeded_ceiling,
  reject_nonmonotonic_exp, reject_spliced_parent, reject_widened_scope, and the new
  reject_wildcard_widening (declared reason not_narrower: a child claiming crm.* over a
  parent holding only crm.read).

## Direction 1: attenu-guard serialization against the pinned JCS byte contract

Runner: jcs-byte-diff.py (requires pip install attenu-guard==0.6.1). Method unchanged
from the 0.6.0 record: attenu_guard.wire._canonical_json over every input in
fixtures/canonical-bytes v1 and v2, byte-compared to canonical_bytes_hex.

Result: identical to 0.6.0. 10 distinct cases, 5 byte-identical, 5 divergent in four
classes. Classified under the three-class split (protocol divergence / implementation
defect / harness or environment defect), each with the observed bytes:

| case | class | observed |
|---|---|---|
| small-exponent-vs-decimal | protocol divergence (the package's canonicalization is a distinct profile, per the author's 2026-08-29 statement) | 1e-06 / 1e-07 vs 0.000001 / 1e-7 |
| nfd-key-used-as-given | protocol divergence | \uXXXX escapes vs UTF-8 for the non-ASCII key |
| astral-key-ordering | protocol divergence | \uXXXX escapes vs UTF-8, and code-point vs UTF-16 key order (reversed) |
| integer-2pow60-inside-int64, integer-2pow68-above-int64 | protocol divergence | arbitrary-precision integer vs binary64 |

Five divergent cases, four classes; the match set is float-tenth, float-1e21-boundary,
negative-zero, integer-above-2pow53 and nested-object-and-array, as jcs-byte-diff.py
asserts.

No implementation defects and no harness defects were observed in this direction. The
author has confirmed the four classes independently (A2A#1575, 2026-08-29) and states
that only the exponent class can reach a Delegation Token in the current token shape.

## Direction 2: clean-room verifier for draft-asor-wimse-00 against the 0.6.1 vectors

Runner: cleanroom/verify_asor00.py, unchanged in logic from the 0.6.0 record (written
from the draft text and the published vector profile without reading the reference
implementation); one change: the completion label now prints the counted total instead
of a hardcoded "7", a defect in this corpus's own artifact found while re-running.

Result: 8 of 8. The valid chain accepts; all seven negatives land on their declared
reasons, including reject_wildcard_widening -> not_narrower. This is the case the 0.6.0
record identified as a spec gap (wildcard semantics deferred to the type and never
defined); the author has added the vector and announced a normative sentence for -01.

## Labels

Both directions: Mode B on the APS side (an independent implementation recomputes or
decides), author-produced (run by the corpus maintainer, not by an independent party).
Independent reproduction of either direction is welcome and would be recorded here
under the independent label.

## Re-run

    pip install attenu-guard==0.6.1
    python3 interop/attenu-guard-0.6.1/jcs-byte-diff.py
    python3 interop/attenu-guard-0.6.1/cleanroom/verify_asor00.py

## Artifact identity, added 2026-09-09 (Day 205)

This record named no artifact digest of any kind when it was written: the runs of
2026-08-28 and 2026-08-29 pinned the release by version and did not hash the wheel
or the vector files. That gap was found while adding prerequisite identity checks to
`scripts/run-all.sh`. The values below were derived on 2026-09-09 by downloading the
release from PyPI with `pip download --no-deps attenu-guard==0.6.1` and hashing the
wheel and each vector member inside it. They are therefore evidence about the
published release as PyPI serves it today, recorded now; they are NOT a restatement
of anything the original runs checked, and nothing above this heading changes.

    wheel attenu_guard-0.6.1-py3-none-any.whl
    sha256 50ffb686627c13e0be88601eccb73ca05216025373f7849a8239f61f55601fe6

| vector file, path inside the wheel | bytes | sha256 |
|---|---|---|
| `attenu_guard/vectors/reject_bad_signature.json` | 1981 | `18e1b5edbadbc354beba5adeabe1b9b742245030db7d36714ad7123b6ef09400` |
| `attenu_guard/vectors/reject_depth_exceeded.json` | 2149 | `1a052d933256fd5af7578fa2e6e73183fe84361f2daeb9135388097a650300e1` |
| `attenu_guard/vectors/reject_exceeded_ceiling.json` | 2050 | `11902c6680e9ef0c714e49c5964a681ddecad979a372801698a3d1f520b490d5` |
| `attenu_guard/vectors/reject_nonmonotonic_exp.json` | 2206 | `1f41a0bbded4a5546985bee43b616fbee87c51d29652f9cfdbd9f61ab14a8c70` |
| `attenu_guard/vectors/reject_spliced_parent.json` | 1922 | `25e4f90a39400e9e1165209165096099594147af50aa5f11a8ec8b089e015287` |
| `attenu_guard/vectors/reject_widened_scope.json` | 2077 | `e5fe880824e48a6b4180966200e8c685b382735980f8343d040708e46201d257` |
| `attenu_guard/vectors/reject_wildcard_widening.json` | 2596 | `90a99490ce7a8c5dcc46fdd5bc1fe03ee44d10278cbde72e935f7d9d6b016961` |
| `attenu_guard/vectors/valid_chain.json` | 2109 | `c5c896d9c8bf0aa09c9a3b60435260a6727277cde025ca6870d1f3c64e42cd11` |

Why the runner gates this family on the installed version rather than on one of these
digests: the vectors are eight separate files reached through `attenu_guard.vectors.
load_vectors()`, an API call with no single path to hash, and seven of the eight are
byte-identical to the 0.6.0 files. The eighth, `reject_wildcard_widening.json`, is the only
file that distinguishes the two vector sets, and it is the vector this record exists for.
Only the version, and the presence of that file, tell the releases apart.
