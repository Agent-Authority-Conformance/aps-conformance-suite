# Vector inventory

Digests of the frozen family inputs vendored in this directory (both revision trees), measured 2026-10-26, against the lab's pinned manifests.

## Revision 3 (`vendor-r3/`) — pinned in `fixtures/lease-revocation-axes/revision-3/SHA256SUMS.txt` (merged PR #191, head `9a28261967bf0d2f9d08ed48f06026871818e816`)

| file | sha256 (this directory) | pinned in family manifest |
|---|---|---|
| `vendor-r3/vectors.json` | `3b7b3fb97682fb967801641b8ed680a9cae608ff57738a594fc6f0314aac1bb6` | `3b7b3fb97682fb967801641b8ed680a9cae608ff57738a594fc6f0314aac1bb6` — match |
| `vendor-r3/oracle-checkpoints.json` | `08293dbd991fe3f76534e176800e15365545a43a6d94e4d89f79d6d58ec7e830` | `08293dbd991fe3f76534e176800e15365545a43a6d94e4d89f79d6d58ec7e830` — match |
| `vendor-r3/SHA256SUMS.txt` | `cba3a45f7af063fae454ac5a2c3b0d57fe9ab2ceb17018c4bed5ec485837c7a1` | (the manifest itself; trimmed to the two vendored files) |

The revision-3 family manifest also pins `model.json` (`b71f02f570237a354cf23abd515c1bd1138461016f7eaaed7e83e16d61bc8237`), which this runner deliberately does not vendor and does not read (the runner scores against the vectors' expected blocks and checkpoint table, never against lab model output), so it is not vendored here.

## Revision 2 (`vendor/`) — pinned in `fixtures/lease-revocation-axes/revision-2/SHA256SUMS.txt` (unchanged from the revision-2 record `interop/rttp-iqa-lra-runner-lease-revocation-axes-8cb2e24/`)

| file | sha256 (this directory) | pinned in family manifest |
|---|---|---|
| `vendor/vectors.json` | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` — match |
| `vendor/oracle-checkpoints.json` | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` — match |
| `vendor/SHA256SUMS.txt` | `f953d881da666c5dca8ec25d0c7680f070421cac6908fd58fbea2bc2b863f292` | (the manifest itself; trimmed to the two vendored files) |

The runner additionally refuses to score any vectors whose sha256 is not in the pinned manifest of its revision (hard digest gate, verified negatively with a tampered copy).

Digests of the other files in this directory (runner, reports, recorded outputs) are in `SHA256SUMS.txt`.

The artifact of record carrying these inputs is sealed as [`lra-runner-20261026a.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261026a.tar.gz) (sha256 `0bd67a7a89c1a0ff46f72c119ca847868d04b5ca333d5eb35701ff88e7e0d152`) and carries two addresses derived from that digest — one per sister scheme, nothing invented, nothing registered, both resolve live: [`rttp://0bd67a7a.conformance.iqa`](https://rttp.com/open/?uri=rttp://0bd67a7a.conformance.iqa) (the question side, WHERE + WHEN) and [`iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa`](https://iqa.org/open/?uri=iqa://0bd67a7a89c1a0ff46f72c119ca84786.forge.iqa) (the answer side, WHETHER).