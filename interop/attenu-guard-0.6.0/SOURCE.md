# attenu-guard 0.6.0 interop runs, both directions

Two author-run interoperability runs between the APS conformance surface and
attenu-guard, the reference implementation of
draft-asor-wimse-agent-delegation-chain-00. Both runs were performed by aeoess on
2026-08-28 against the counterparty's published artifacts; neither is an independent
reproduction, and this family confers no conformance verdict on attenu-guard and
makes no claim about APS beyond the pinned fixtures it references.

## Counterparty artifacts, pinned

- Internet-Draft: draft-asor-wimse-agent-delegation-chain-00, datatracker submission
  2026-08-27, fetched from the IETF archive as plain text.
- Package: attenu-guard 0.6.0 on PyPI (release history 0.4.0, 0.4.1, 0.5.0, 0.6.0),
  installed into a clean venv for both runs.
- Vectors: the seven offline-verification test chains shipped inside the package
  (attenu_guard.vectors), byte-identical to tests/vectors/ in the
  attenu-io/attenu-guard repository per that repository's own wire test.

## Direction 1: attenu-guard serialization against the pinned JCS byte contract

Method: attenu_guard.wire._canonical_json (sorted-key, compact-separator
json.dumps, the package's canonicalization step) run over every input in
fixtures/canonical-bytes/canonical-bytes-jcs-v1.json and -v2.json, byte-compared to
each vector's canonical_bytes_hex. Runner: jcs-byte-diff.py in this directory,
requires pip install attenu-guard==0.6.0.

Result: 18 entries, of which v2 repeats the 8 v1 cases unchanged, so 10 distinct
cases. 5 of 10 byte-identical (float-tenth, the 1e21 boundary, negative zero,
integers just above 2^53, nested structures). The 5 divergent cases reduce to four
causes:

1. Exponent formatting: JCS 0.000001 and 1e-7; Python 1e-06 and 1e-07.
2. Non-ASCII escaping: JCS emits UTF-8 directly; json.dumps escapes by default.
3. Key ordering: JCS sorts by UTF-16 code units, Python by code point; the
   astral/BMP case reverses the key order.
4. Number model: JCS serializes per ECMAScript binary64; Python keeps
   arbitrary-precision integers, so the 2^60 and 2^68 cases serialize differently
   even though those powers of two are representable as binary64.

The seven attenu-guard vectors carry no non-ASCII and no beyond-double integers;
causes 2 through 4 do not reach its current token shapes, and cause 1 is reachable
through its decimal-number constraints.

## Direction 2: clean-room verification of the seven attenu-guard vectors

Method: cleanroom/verify_asor00.py in this directory, written from the draft text
(Section 6 verification algorithm, Section 4.2 subsumption) plus the published
vector profile, WITHOUT reading the reference implementation's verifier source. 115
lines of Python stdlib; the interop vectors sign HS256 over a fixed shared secret,
so step 1 is HMAC-SHA256 over the JWS signing input. Steps 6 (holder binding), 7
(status list) and 8 (attempted-action authorization) are outside the vector profile
and not exercised.

Result: 7 of 7. The valid chain accepts; the six adversarial vectors reject with
their declared reason strings (signature_invalid, par_hash_mismatch, depth_invalid,
not_narrower twice, expired).

Honest iteration count: the first pass scored 5 of 7. Both misses shared one cause:
crm.* covering crm.read. The draft defers wildcard semantics to "as defined by the
type" and never defines the agent_delegation rule; the vectors make the intended
behavior clear. Reported to the author on a2aproject/A2A#1575.

## Draft and vector-set drift, observed 2026-08-28

Appendix B of draft-00 describes the accompanying vectors as including revoked-entry
and replayed-token cases. The shipped set of seven contains neither and instead
includes a bad-signature case. Recorded here as an observation about the artifacts
at their pinned versions, nothing more.

## Re-running

Direction 1: python3 -m venv v; v/bin/pip install attenu-guard==0.6.0; v/bin/python3 jcs-byte-diff.py
Direction 2: v/bin/python3 cleanroom/verify_asor00.py

Both scripts exit nonzero on any disagreement with the results recorded above.
