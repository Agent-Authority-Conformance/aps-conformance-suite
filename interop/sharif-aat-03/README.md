# draft-sharif-agent-audit-trail-03: byte-exact fixtures, independent run

Six executable fixtures and one unresolved case for the Agent Audit Trail
format as specified in draft-sharif-agent-audit-trail-03 (individual
Internet-Draft, R. Sharif, dated 2026-09-05). The draft's own Appendix A
truncates every hash, so no executable example exists in the document. These
fixtures are a byte-exact corpus for sections 6.1, 6.2, 6.3 and 4.2.

Three positive/negative pairs, each pinned to the normative sentence that
determines its expected result:

| pair | positive | negative | sentence |
|---|---|---|---|
| chain | `AAT-CHAIN-01` | `AAT-CHAIN-02` | 6.1, 6.2 note (prev_hash covers the complete stored previous record including its signature), 6.3 step 2c |
| signature | `AAT-SIG-01` | `AAT-SIG-02` | 6.2 steps 1 and 5, verifier removes `signature` before hashing |
| phase | `AAT-PHASE-01` | `AAT-PHASE-02` | 4.2 decision+denied MUST be pre_execution, 6.3 step 6 |

Each negative fails exactly one 6.3 check. `AAT-CHAIN-02` re-signs the
mutated parent so that every signature still verifies and only the chain
link is stale.

Result: all six reproduce their expected outcome. See `results.json`.

## The unresolved case

`AAT-RECORDER-01` carries no expected result on purpose. Section 5.2 says an
independent recording component SHOULD sign with its own key, distinct from
the agent's. Section 6.2 step 4 signs with the agent's private key. Section
6.3 step 3 verifies with the agent's public key. The record format defines
`recording_component` as a URI and no signer key reference. The fixture is a
genesis record signed per 5.2 with a recorder key. The adapter reports both
observations: under the agent key the signature fails 6.3 step 3, under the
recorder key it verifies. The draft does not say which key applies or how a
verifier obtains it. The lab does not decide that on the author's behalf.

## From-scratch

`adapter/py/aat.py` implements JCS (RFC 8785) for the value domain the
fixtures use (objects, arrays, strings, integers, booleans, null; no floating
point values appear in any fixture and non-integer number serialization is
deliberately not implemented), SHA-256 via the Python standard library, RFC 3339 timestamps parsed with a
section 5.6 syntax plus section 5.7 calendar and range parser
(`adapter/py/rfc3339.py`: lowercase t/z accepted, `+0000` rejected, `:60`
accepted syntactically as a distinct instant between :59.999999 and the next
minute, leap-second occurrence not validated against a leap-second table,
`-00:00` ordered as zero offset with no RFC 9557 semantics projected) and compared as
instants (6.3 step 4), and
ECDSA P-256 via the `cryptography` package. No JCS library and no code from
any AAT implementation is used. Test keys are fixed scalars in `generate.py`
and are not secrets. Signing uses RFC 6979 deterministic ECDSA.

The six ordinary fixtures declare trust level L1 with self recording, so no
5.2 recommendation about independent recording bears on them. Only
`AAT-RECORDER-01` is L2.

## Re-run

    cd interop/sharif-aat-03
    python3 adapter/py/run.py
    python3 adapter/py/test_timestamps.py

Regenerating (`python3 adapter/py/generate.py`) reproduces the stored corpus
byte for byte: keys are fixed scalars and signing is RFC 6979 deterministic.
The stored corpus is the reference either way.

## Lab operating constraints

The lab certifies nothing and issues no conformance verdicts. Each fixture
records the draft revision it targets and the sentence its expectation rests
on. This run was independently produced, not by the draft's author.
