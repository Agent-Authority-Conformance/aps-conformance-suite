# Verax ledger vectors v1, bounded run (records and chain)

Input: [verax-ai/verax](https://github.com/verax-ai/verax) tag `vectors-v1`, commit `f50c59befbfb133a8d6f219ee171d4246debd823`, `test-vectors/`. `sha256sum -c SHA256SUMS` passed for all 144 listed files. The tag holds 16 vectors. `valid-anchored` was added after the tag (`3aac7c7`) and is not part of this run.

Spec sources: draft-dogru-cedulon-decision-profile-03 Section 4 and its normative reference draft-dogru-cedulon-08 Sections 6.1 to 6.3, RFC 9052 Section 4.4, RFC 8032. The checker in `checker/` uses no Verax code. The vector set's README was read for its stage names and order. `test-vectors/tools/` was not read or run.

## What was assessed

Four of the twelve stages: `record-header`, `record-signature`, `record-claims`, `chain`. The other eight (`inputs-binding`, `effect-binding`, `index`, `approval-signature`, `checkpoint-signature`, `checkpoint-coverage`, `checkpoint-totals`, `control`) are not implemented here, so nothing in this record says whether a ledger is valid as a whole. Deterministic encoding of the protected header and payload is not checked.

`checker/run.ts` lists the vector directories itself and never opens `expected.json` or `manifest.json`. Its output was byte identical with every `expected.json` deleted. `checker/compare.ts` runs afterwards and reads `expected.json`.

## Results

| classification | count | vectors |
|---|---|---|
| first failing stage matches | 7 | `fail-record-alg-8`, `fail-record-content-type`, `fail-record-key-not-pinned`, `fail-record-signature`, `fail-record-claims-mismatch`, `fail-record-claim-rule`, `fail-chain-removed` |
| no failure in the four assessed stages, named stage not assessed | 7 | `fail-inputs-approver-downgraded`, `fail-approval-signature`, `fail-effect-hash`, `fail-checkpoint-signature`, `fail-tail-truncated`, `fail-checkpoint-totals`, `fail-allow-while-halted` |
| no failure in the four assessed stages, later stages not assessed | 2 | `valid-full`, `valid-deny-only` |

SHA-256 over each record's COSE_Sign1 octets equals `record_hashes` in `expected.json` for all 16 vectors.

`checker/selfattack.ts` tests this checker, not Verax. It has 17 cases with stated outcomes: 16 single changes, each rejected at the stated stage, and one re-signed control with no change, accepted. Cases 10 to 17 re-sign the ledger under a key generated in the run, to reach rules the vector set does not exercise (allow without `effectClass`, empty `ref`, twelve labels, uppercase hash, `timestampMs` above 2^53 - 1, a header or claim key repeated under a second integer encoding). Case 16 was added after review found that the first version of the decoder judged duplicate keys on their octets and accepted `alg` encoded as `01` with -19 and again as `18 01` with -8. Duplicates are now judged on the decoded key. Generated keys make `results/selfattack.json` differ from run to run in key ids only.

Runner: aeoess, Node v24.11.1, macOS. Outputs in `results/`.

## Reproduce

```bash
git clone https://github.com/verax-ai/verax && git -C verax checkout vectors-v1
node checker/run.ts verax/test-vectors results/observed.json
node checker/compare.ts results/observed.json verax/test-vectors results/compare.json
node checker/selfattack.ts verax/test-vectors results/selfattack.json
```
