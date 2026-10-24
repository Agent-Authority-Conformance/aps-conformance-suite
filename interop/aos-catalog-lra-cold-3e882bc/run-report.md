# aos-standard/catalog clean-room model over lease-revocation-axes revision 2

Tetsurohhori (aos-standard/catalog) wrote a Python model of the `lease-revocation-axes` family from its README,
ORACLE.md and the input shape of the vectors, then ran it against the frozen revision 2 vectors. The run was
reported in issue #186. This directory records it with the runner's own labels. The run files stay in the
catalog repository and are linked here by commit.

## Result

176 of 176 call profiles match, 1584 of 1584 field comparisons. The eleven non-diagnostic oracle checkpoints
agree. The diagnostic checkpoint (index 5) is outside the model, which makes no diagnostic read.

The twelve declared defective variants were reproduced in three steps, each published beside the first run
without changing it.

- `RUN.md` at `3e882bc`: written from the variant names, 6 of the 10 variants with value-observable effects
  reproduce their declared failure sets. A post hoc second reading reproduces the other four. This showed that
  four one-line descriptions admitted two readings.
- `ADDENDUM-bccef3e.md` at `bbf68c7`: written from the one-sentence rules added at `bccef3e`, 10 of 11 reproduce.
  `sticky-unavailable` differed and `fabricated-live-read` was not written.
- `CORRECTION-86e5e7a.md` at `f90ec2f`: with the source read count added from the `86e5e7a` README, all 12
  reproduce. The runner states this reading is post hoc, written after the family's author explained the read check.

## Fields

| field | value |
|---|---|
| who ran it | @Tetsurohhori (aos-standard/catalog) |
| date | 2026-10-24 (JST), first run committed 2026-10-23T23:08:34Z |
| run mode | Mode B, alternate recomputation |
| implementation name | `lra_cold_model.py` and `run_lra.py`, with `lra_mutants.py`, `lra_mutants_alt.py`, `lra_mutants_v3.py`, `lra_mutants_v4.py` |
| implementation repo and commit or version | https://github.com/aos-standard/catalog `docs/runs/aps-lease-revocation-axes-cold/`, first run at `3e882bcffef1b1c88cf3ff5bb17a5fedd19c94f7`, addendum at `bbf68c7cdbb498b62ae159c050a91c30e11905c4`, correction at `f90ec2fa3cf3b41536a170a7e613c6bb041de8fd` |
| corpus reference | PR #180 head `b745d252191e89fe123e33411f124a1b67542c2a`, `revision-2/vectors.json` SHA-256 `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8`, `revision-2/oracle-checkpoints.json` `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea`. The addendum and correction read the README at `bccef3e` and `86e5e7a` against the same vectors |
| per-vector result | `PER_VECTOR.txt` and `first_run_b745d25.json` at `3e882bc` |
| verbatim command and output | `VERBATIM.txt` at `3e882bc` |
| environment | Python 3.10.12, standard library only, Linux 6.8 |
| author-produced or independent | author-produced, as the runner labels it under `CONTRIBUTING.md`: the catalog wrote the alternate implementation that supplies the recomputation. It wrote none of the vectors, claim inputs or the family's implementation |
| answer exposure | answer-exposed. Each call's `expected` block was visible while the input shape was read, before the model was written |
| suspected defective vectors | none |

## Checksums of the linked run files

| file at commit | SHA-256 of that manifest |
|---|---|
| `SHA256SUMS` at `3e882bc` | `1365ffe82d5e1858e58719431ba85d570b78e6e5b8470dc8f5662794d9bf550e` |
| `SHA256SUMS-bccef3e` at `bbf68c7` | `20040cc2317f8e61db2f0ca2aaeb3d767597f2dc1ae9bfeb6e7e375479bafc49` |
| `SHA256SUMS-86e5e7a` at `f90ec2f` | `93383ec67146fc535d2f79e4e312f80493453d133b33ad80640d3eadfaac7d1c` |

On 2026-10-23 @aeoess checked, without executing the catalog's code, that the first run's vector and oracle
digests match the pinned files and that its `SHA256SUMS` verifies.

## Verification split

- Frozen revision 2 timelines, oracle checkpoints and declared variant sets of `lease-revocation-axes`; runner:
  Tetsurohhori via aos-standard/catalog; Mode B; author-produced; answer-exposed. The runner did not author the
  vectors, so the remaining gap is the authorship of the recomputation, not of the corpus.
- No independent record exists for this layer. It stays queued in `docs/OPEN-RUNS.md`.

These records are attributed per layer. Merge of this record is not an end-to-end verification or a verdict on
the implementation.
