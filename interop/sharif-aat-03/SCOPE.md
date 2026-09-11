# Scope

Exercised: 6.1 hash computation, 6.2 signature envelope, 6.3 steps 1 to 6,
4.2 pre-execution requirements for decision+denied.

Not exercised: 6.3 step 7 (nonce uniqueness; no fixture carries a nonce),
tombstone chain-break acceptance (9.3), session close `session_hash` (8.3),
export formats (10), decision reproducibility (13), MCPS trust levels beyond
the literal `trust_level` string. Records use only the mandatory fields of
3.1 plus `deny_reasons`, `recording_component` and `signature`.

Result vocabulary is the adapter's own: `reproduced`, `NOT_REPRODUCED`,
`unresolved`. It is not a conformance verdict on any implementation.

## Lab interpretations the draft does not settle

- Signature encoding. 6.2 step 5 says Base64url per RFC 4648 section 5 over
  a fixed 64-byte input and does not say "unpadded". RFC 4648's default is
  padded; omission is allowed only where the referring specification says so.
  The lab uses the padded canonical form (86 characters plus "=="), and the
  verifier accepts exactly that form with the URL-safe alphabet only. An
  implementation that emits unpadded signatures would fail `AAT-SIG-01` under
  this interpretation. This is a draft ambiguity, recorded here and not
  decided for the author.
- Timestamps. RFC 3339 5.6 syntax with 5.7 calendar and range validation,
  exact fractional precision, leap seconds accepted syntactically and keyed
  as distinct instants, occurrence not validated. See `adapter/py/rfc3339.py`.

## Isolation is enforced

`run.py` counts a negative as reproduced only when the verifier reports
exactly one finding and it is the expected check. A negative that fails for
an additional reason is reported `NOT_REPRODUCED`.
