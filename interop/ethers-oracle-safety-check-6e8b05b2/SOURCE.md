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

## Classification clarification (dated append, 2026-10-18)

`CONTRIBUTING.md` defines a record as independent when the runner authored neither the vectors
nor any claim inputs being checked, and did not author the implementation whose behavior or
output supplies the recomputation. The verification split above declined that label because the
runner authored the SDK the vectors ride on. A field level trace shows that SDK authorship does
not reach the inputs this record checks, so under that definition this layer is independent.

The trace, against corpus tree `4d314f06e2cdc77091d400e6a95d1e9814d97929`:

- The vectors were produced by `fixtures/oracle-safety-check/generate-fixtures.ts` in
  `aeoess/agent-passport-system` at `ba32424f40bd14d0ff7d20b9d66774022b5905d9`. In the history
  reachable from `ba32424f`, the only commit touching that directory is
  `06d3d14f2ab4756bfa74d7b20848007039a8ff63`, authored by imokokok.
- The fields this record checks are the vector's `envelope.oracle` `eip712`, `data`, `uid`,
  `signature` and `attester`. They are returned by `signOracleSafetyCheck` from the vendored
  Insight builder, which signs with viem, over the generator's own `oracleInput`. The EVM
  attester key is derived in the same generator from its seed with node crypto. The two negative
  vectors are mutations written in the same generator.
- The vendored Insight files (`abi.ts`, `oracleSafetyCheck.ts`, `types.ts`) at `ba32424f` are
  byte identical to the copies in this suite at `6e8b05b2`, and none of them imports SDK code.
- The generator does import APS SDK functions (`canonicalizeJCS`, receipt, decision and
  delegation builders), but they build the rest of the envelope. None of them produces a field
  this record checks.

The runner-authored `eip712-recompute.mjs` is a thin harness. It converts the vector's integer
fields to BigInt, recomputes the EIP-712 digest with ethers `TypedDataEncoder.hash`, and
separately recovers the signer with ethers `recoverAddress` from the declared `uid` and
`signature`. It compares both results with the declared values. It implements neither EIP-712
hashing nor secp256k1 signer recovery, and it does not construct the oracle data or decide the
composite authorization verdict.

This is an independent Mode B recomputation of the EIP-712 layer in the 13 vectors at tree
`4d314f06`. The result is 12/13 digest agreement and 12/13 signer agreement. The two declared
negatives diverge on their respective axes.

The corpus was later re-minted (`32de530`). The re-mint changed the outer receipts and the
canonical envelope bytes, but `oracle_input`, `envelope.oracle`, `eip712_digest_hex` and
`secp256k1_signature_hex` are byte identical in all 13 vectors, as the family `SOURCE.md` also
records. This remains a historical run, not a new execution against the re-minted corpus. It
establishes no independent result for the outer envelope or the composite authorization.

The clean-room record beside this one remains author-produced, because the SDK's
`canonicalizeJCS` produced the canonical bytes it checks. Its record and classification are
unchanged. The original ethers run record and results file above are unchanged. This note changes
only the independence label, and this row is removed from `docs/OPEN-RUNS.md` in the same commit.
