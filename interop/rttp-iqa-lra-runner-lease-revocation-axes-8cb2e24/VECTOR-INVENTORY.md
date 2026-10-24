# Vector inventory

Digests of the frozen family inputs vendored in this directory (`vendor/`), measured
2026-10-24, against the lab's pinned manifest
(`fixtures/lease-revocation-axes/revision-2/SHA256SUMS.txt` at PR #180 commit
`b745d252191e89fe123e33411f124a1b67542c2a`):

| file | sha256 (this directory) | pinned in family manifest |
|---|---|---|
| `vendor/vectors.json` | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` — match |
| `vendor/oracle-checkpoints.json` | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` — match |
| `vendor/SHA256SUMS.txt` | `9e8a43648df97638632dc0785c3b4925b2ad03ab38272125109727607149412c` | (the manifest itself; verbatim copy) |

The family manifest also pins `model.json`, `sdk-7.1.0.json` and `sdk-8.0.1.json`,
which this runner does not read (the runner scores against the vectors' expected
blocks and checkpoint table, never against lab model output), so they are not vendored
here. The runner additionally refuses to score any vectors whose sha256 is not in the
pinned manifest (hard digest gate, verified negatively with a tampered copy).

Digests of the other files in this directory (runner, report, recorded output) are in
`SHA256SUMS.txt`.
