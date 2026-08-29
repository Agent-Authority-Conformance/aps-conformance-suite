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
| string-escape-unicode, nfd-key-used-as-given, key-ordering-unicode (v1) | protocol divergence | \uXXXX escapes vs UTF-8 |
| astral-key-ordering | protocol divergence | code-point vs UTF-16 key order, reversed |
| integer-2pow60-inside-int64, integer-2pow68-above-int64 | protocol divergence | arbitrary-precision integer vs binary64 |

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
