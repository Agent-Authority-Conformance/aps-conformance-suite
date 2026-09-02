# ethers Mode B recompute of the oracle-safety-check EIP-712 layer, successor to the 9b4ffee record

Corpus: `fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1/`, 13 vectors plus
index.json. Durable corpus pointer: merge commit `6e8b05b202d727ef18e84e100fc31db11f36529f`
(squash of PR #32).

## Provenance of this run, stated exactly

- Executed 2026-09-02 against the vector bytes at PR #32 head `cbc805d54e39bf5069b160084568173ea7a8ff5f`
  (and, identically, at the earlier reviewed head `42a9e3f9`; the corpus tree is
  `4d314f06e2cdc77091d400e6a95d1e9814d97929` at both).
- The squash merge then produced `6e8b05b2`. The corpus tree at `6e8b05b2` is
  `4d314f06e2cdc77091d400e6a95d1e9814d97929`, byte-identical to what was executed.
- The run is therefore recorded against the merge commit as its corpus pointer without claiming
  it executed at a commit that did not exist when it ran. The 14 file digests are in the results
  file for anyone to compare.

## What was run

`eip712-recompute.mjs`, unchanged from `interop/ethers-oracle-safety-check-9b4ffee/`, with ethers
6.17.0 pinned exactly by this directory's package.json and lockfile (`npm ci` in this directory,
then `node eip712-recompute.mjs <corpus dir>`). For each vector it recomputes the EIP-712 digest
from the vector's own `eip712` typed data and recovers the signer from `secp256k1_signature_hex`,
comparing both against the values the vector declares. It imports nothing from the suite, the
SDK or the vendored Insight builder.

## Result (results-eip712-recompute.txt, verbatim)

digest match 12/13; signer match 12/13. The two divergences are `tampered-oracle` (digest) and
`wrong-signer` (signer), which are exactly the two declared negative vectors; the other eleven
match on both axes. Same shape as the 9b4ffee record.

## Verification split

- EIP-712 digest and secp256k1 signer recovery, 13 vectors; runner aeoess; Mode B; implementation
  ethers 6.17.0, independently authored; vectors by imokokok. The runner did not author the vectors
  or the implementation, but the runner authored the SDK the vectors ride on, so under this corpus's
  definition the record is not labeled independent of the family.
- Supersedes `interop/ethers-oracle-safety-check-9b4ffee/` as the current record; that record stays
  as observed at 9b4ffee.
