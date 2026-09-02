# Clean-room recompute of the JCS, SHA-256 and Ed25519 outer-witness surfaces of the oracle-safety-check vectors

Corpus: `fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1/`, 13 vectors. Durable
corpus pointer: merge commit `6e8b05b202d727ef18e84e100fc31db11f36529f` (squash of PR #32).

## Provenance of this run, stated exactly

- Executed 2026-09-02 against the vector bytes at PR #32 head
  `cbc805d54e39bf5069b160084568173ea7a8ff5f` (corpus tree `4d314f06e2cdc77091d400e6a95d1e9814d97929`).
- The squash merge produced `6e8b05b2`; the corpus tree there is the same object, byte-identical
  to what was executed. Recorded against the merge commit as the durable pointer, not dated to it.
- An earlier run of the same recompute on 2026-08-31 (during review, over the same bytes at head
  8515a75) reached the same 13/13; this directory records the run that was executed against the
  bytes that merged.

## What was run

`cleanroom_osc.py` with `rfc8785==0.1.4` and `cryptography==50.0.1` in a fresh venv
(`pip install -r requirements.txt`, then `python cleanroom_osc.py <corpus dir>`). For each vector
it canonicalizes the `envelope` with RFC 8785 and compares the bytes to `canonical_bytes_hex`,
hashes them and compares to `canonical_sha256`, and verifies `ed25519_signature_over_canonical_hex`
under `ed25519_pubkey_hex` over those bytes. No suite code, no SDK, no vendored code in the process.

## Result (results-cleanroom-recompute.txt, verbatim)

13/13: JCS bytes, SHA-256 and the Ed25519 outer witness reproduce on every vector, including the
negatives. The negatives are expected to verify here: the outer witness attests the envelope
bytes as committed, and the faults in the negative vectors are nested (a decision signature, an
oracle field, a delegation), which this surface does not cover.

## Not covered, deliberately

Nested Ed25519 signatures inside the envelope (their preimage is not derivable from the fixture
without suite or SDK code), the EIP-712 digest and secp256k1 layer (see the ethers record beside
this one), keccak address derivation, the four ABI-keccak commitments, and the composite-gate
semantics. This record establishes the outer three primitives only.

## Verification split

- JCS canonical bytes, SHA-256, Ed25519 outer witness, 13 vectors; runner aeoess; Mode B;
  implementation rfc8785 + cryptography, independently authored libraries with a runner-authored
  20-line harness; vectors by imokokok. Not labeled independent of the family, for the same reason
  as the ethers record beside it.
