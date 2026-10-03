# Verax ledger vectors v1, bounded run (records, chain, inputs binding, checkpoints)

Input: [verax-ai/verax](https://github.com/verax-ai/verax) tag `vectors-v1`, commit `f50c59befbfb133a8d6f219ee171d4246debd823`, `test-vectors/`. `sha256sum -c SHA256SUMS` passed for all 144 listed files. The tag holds 16 vectors. `valid-anchored` was added after the tag (`3aac7c7`) and is not part of this run.

Spec sources: draft-dogru-cedulon-decision-profile-03 Section 4 and its normative reference draft-dogru-cedulon-08 Sections 6.1 to 6.3 and 7, RFC 9052 Section 4.4, RFC 8032, RFC 8785. The checker in `checker/` uses no Verax code. The vector set's README was read for its stage names and order. `test-vectors/tools/` was not read or run.

## What was assessed

Eight of the twelve stages: `record-header`, `record-signature`, `record-claims`, `chain`, `inputs-binding`, `checkpoint-signature`, `checkpoint-coverage`, `checkpoint-totals`. The other four (`effect-binding`, `index`, `approval-signature`, `control`) are not implemented here, so nothing in this record says whether a ledger is valid as a whole. Deterministic encoding of the protected header and payload is not checked.

`checker/run.ts` lists the vector directories itself and never opens `expected.json` or `manifest.json`. Its output was byte identical with every `expected.json` and `manifest.json` deleted, and byte identical between two runs. `checker/compare.ts` runs afterwards and reads `expected.json`.

`inputs-binding` hashes the canonical JSON (RFC 8785) of the `inputs` member of the `ledger/inputs.jsonl` row whose `ref` matches the record, per decision-profile-03 Section 4.1 ("inputsHash ... is the SHA-256 of whatever further context the Decider consulted, encoded the same way [as requestHash]"). This is the one construction implemented: it was checked against the signed `inputsHash` of every non-null record in all 16 vectors before anything else was written, and no alternative preimage was tried. The canonicalizer handles the ASCII text, safe integers, booleans, null, arrays and objects this vector set's `inputs.jsonl` rows carry. It was not built for RFC 8785's float or lone-surrogate rules, which this set does not exercise.

`checkpoint-coverage` and `checkpoint-totals` compare against the records clean through `record-header`, `record-signature`, `record-claims` and `chain` ("attested", decision-profile-03 Section 4.4) whose `timestampMs` falls in the checkpoint's half-open `[startMs, endMs)` window, per cedulon-08 Section 11.1 ("receiptCount MUST equal the number of receipts ... whose timestampMs falls in that window"). decision-profile-03 4.4 carries this unchanged for records. `chainHeadHash` is SHA-256 of the last such record's COSE_Sign1 octets, in ledger order. This set never carries more than one checkpoint, so no vector exercises `prevCheckpointHash` chaining across epochs. A checkpoint that signs `totals: null` (the redaction cedulon-08 MUST-T11-12 allows) is accepted without a totals comparison. No vector in this set signs that.

## Ordering rule

A vector's first failing stage is claimed as a MATCH only when every stage earlier than it, in the vector set's twelve-stage order, was assessed. That holds for `record-header` through `inputs-binding` (stages 1 to 5): nothing earlier than any of them is unassessed. It does not hold for `checkpoint-signature`, `checkpoint-coverage` and `checkpoint-totals` (stages 9 to 11): `effect-binding`, `index` and `approval-signature` (stages 6 to 8) sit in front of them and are not implemented. For those three, `compare.ts` reports `REACHED, earlier stages 6 to 8 not assessed` rather than MATCH, because a ledger that actually fails one of stages 6 to 8 first would read the same way here: this checker cannot tell "the named stage is the first failure" apart from "an earlier, unassessed stage would have failed first." A stage whose expected failure is not assessed at all is still `CONSISTENT, named stage ... not assessed` as before, and any other disagreement is `MISMATCH`.

## Results

| classification | count | vectors |
|---|---|---|
| first failing stage matches, every earlier stage assessed | 8 | `fail-record-alg-8`, `fail-record-content-type`, `fail-record-key-not-pinned`, `fail-record-signature`, `fail-record-claims-mismatch`, `fail-record-claim-rule`, `fail-chain-removed`, `fail-inputs-approver-downgraded` |
| first failing stage reached, but stages 6 to 8 are not assessed | 3 | `fail-checkpoint-signature`, `fail-tail-truncated`, `fail-checkpoint-totals` |
| no failure in the assessed stages, named stage not assessed | 2 | `fail-approval-signature`, `fail-effect-hash` |
| no failure in the assessed stages, control stage not assessed | 1 | `fail-allow-while-halted` |
| no failure in the assessed stages, later stages not assessed | 2 | `valid-full`, `valid-deny-only` |

SHA-256 over each record's COSE_Sign1 octets equals `record_hashes` in `expected.json` for all 16 vectors.

`checker/selfattack.ts` tests this checker, not Verax. It has 23 cases with stated outcomes: 21 single changes, each rejected at the stated stage, and 2 re-signed controls with no change, accepted. Cases 10 to 17 re-sign the whole ledger under a key generated in the run, to reach rules the vector set does not exercise (allow without `effectClass`, empty `ref`, twelve labels, uppercase hash, `timestampMs` above 2^53 - 1, a header or claim key repeated under a second integer encoding). Case 16 was added after review found that the first version of the decoder judged duplicate keys on their octets and accepted `alg` encoded as `01` with -19 and again as `18 01` with -8. Duplicates are now judged on the decoded key. Cases 18 to 23 reach the four stages added after that first run. 18 and 19 mutate `ledger/inputs.jsonl`, which a decision record does not sign over, so no record needs re-signing. 20 to 23 re-sign only the checkpoint, under a witness key generated in the run, because a changed claim breaks the original witness signature. Case 10's re-signed ledger also re-signs the checkpoint over the new chain, under a second generated witness key, so that resigning decisions alone does not read as a `checkpoint-coverage` mismatch against an unrelated checkpoint. Case 21 is that resigning path's own control. Generated keys make `results/selfattack.json` differ from run to run in key ids only.

Runner: aeoess, Node v24.11.1, macOS. Outputs in `results/`.

A green run here shows that this one implementation reads these encodings and reaches the same first-failing-stage, over bytes it did not produce, for the eight stages above. It is not a conformance claim, a validation of Verax, or a statement about adoption. It says nothing about the four stages left unassessed.

## Reproduce

```bash
git clone https://github.com/verax-ai/verax && git -C verax checkout vectors-v1
node checker/run.ts verax/test-vectors results/observed.json
node checker/compare.ts results/observed.json verax/test-vectors results/compare.json
node checker/selfattack.ts verax/test-vectors results/selfattack.json
```
