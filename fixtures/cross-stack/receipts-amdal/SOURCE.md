# AgentLair receipt vectors (bilateral exchange, outbound leg)

Source: emailed by Pico Amdal (pico@amdal.dev), schema `agentlair-receipt-vectors-v1`.
Round 1 authored 2026-07-29T18:19:18Z, received the same evening, run 2026-08-05.

This is the reverse direction of the AAT corpus in `../aat-amdal/`. There the issuer mints
bearer tokens and we verify them. Here the issuer mints signed receipts and we verify those.
The two corpora do not share a key: receipts are signed by
`did:key:z6MktWEUC4pUCK1Lk6Mnr5LWgf2sn7GWtGkAssqdMQV9k4on`, while `al_nid` in the AAT corpus
names a different key whose private half the issuer does not hold. A bridge assertion between
the two corpora is therefore not available and must not be inferred.

## Scope

Transport and identity only: did:key resolution, RFC 8785 JCS canonicalization, Ed25519
signature, and content-addressed id recomputation. It asserts nothing about APS receipt
semantics, and nothing about the issuer's own runtime behaviour. A run records what was
executed against which bytes at which time. It is not a conformance verdict.

## Profile, as stated by the issuer

- Canonicalization: RFC 8785 JCS over the envelope with `signature` excluded, keys sorted by
  UTF-16 code unit at serialization time, NFC values, no whitespace.
- Scalars: string only. v1 carries no JSON numbers, booleans or nulls, so JCS number
  canonicalization is out of scope for this round.
- Signature: Ed25519 over `utf8(canonical bytes)`, base64url unpadded.
- `receipt_id` = `"r1:" + base64url(SHA-256(utf8("agentlair-receipt/v1:" + JCS(body0))))`
  where `body0` is the envelope minus `receipt_id` and `signature`. `receipt_id` is itself
  covered by the signature.
- Evaluation order: profile, key resolution, signature, `receipt_id`. Signature before
  `receipt_id` so a tampered id can never be masked by a bad signature.

## Ingestion note

The vectors reached us as text in mail rather than as a file, so transcription was proven
before the result was trusted. Three of the six carry a signature that is valid over their own
envelope, and an Ed25519 signature over canonical bytes cannot verify against a mistyped
envelope. Those three verifying is the proof. The three negatives were additionally diffed
against the valid vector to confirm each differs in exactly the one field the issuer named.

## Result, 2026-08-05

`runners/receipt_runner.py`, 6/6 match expectation, 0 failures.

Two structural observations recorded rather than scored. For `did:key` the document is derived
from the identifier, so a key-absent condition cannot fire on this method; it is reachable on
`did:web` only. And `receipt-2026-07-29-key-order-reversed` is byte-identical content
transmitted with reversed key order, so it verifies only under serialization-time sorting; it
would fail any implementation that trusts wire order.

## Verification split

- did:key resolution of the receipt signer; runner aeoess; Mode B; independent; Python stdlib (`runners/receipt_runner.py`); vectors and issuing implementation by AgentLair (Pico Amdal).
- RFC 8785 JCS canonical bytes of the envelope with `signature` excluded; runner aeoess; Mode B; independent; same runner.
- Ed25519 signature over the canonical bytes; runner aeoess; Mode B; independent; same runner.
- `receipt_id` recomputation from `body0` under the issuer's stated formula; runner aeoess; Mode B; independent; same runner.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

Classification clarification, 2026-08-29: the row(s) above labeled independent on
2026-08-28 are restated under the single definition. receipts-amdal: did:key resolution
is a hand-written decoder, author-produced, listed in docs/OPEN-RUNS.md; canonical bytes
(json.dumps primitive with the stated equivalence), Ed25519 (the cryptography library,
not stdlib as written above; the runner uses Python stdlib for canonicalization and
hashing and cryptography for Ed25519 verification) and receipt_id (hashlib) stay
independent. Results and pins are unchanged.
