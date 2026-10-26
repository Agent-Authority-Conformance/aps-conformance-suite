# Vector inventory

Digests of the frozen family inputs vendored in this directory (`vendor/`), measured
2026-10-24, against the lab's pinned manifest
(`fixtures/lease-revocation-axes/revision-2/SHA256SUMS.txt` at PR #180 commit
`b745d252191e89fe123e33411f124a1b67542c2a`):

| file | sha256 (this directory) | pinned in family manifest |
|---|---|---|
| `vendor/vectors.json` | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` | `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8` — match |
| `vendor/oracle-checkpoints.json` | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` | `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea` — match |
| `vendor/SHA256SUMS.txt` | `f953d881da666c5dca8ec25d0c7680f070421cac6908fd58fbea2bc2b863f292` | (the manifest itself; trimmed to the two vendored files) |

The family manifest also pins `model.json`, `sdk-7.1.0.json` and `sdk-8.0.1.json`,
which this runner does not read (the runner scores against the vectors' expected
blocks and checkpoint table, never against lab model output), so they are not vendored
here. The runner additionally refuses to score any vectors whose sha256 is not in the
pinned manifest (hard digest gate, verified negatively with a tampered copy).

Digests of the other files in this directory (runner, report, recorded output) are in
`SHA256SUMS.txt`.

The artifact of record carrying these inputs is sealed as
[`lra-runner-20261023c.tar.gz`](https://iqa.org/conformance/files/lra-runner-20261023c.tar.gz)
(sha256 `94bbaf3c292abf69595bf5782d1db8cbb4178536d53182578b46cff94a5c4b15`) and carries
two addresses derived from that digest — one per sister scheme, nothing invented,
nothing registered, both resolve live:
[`rttp://94bbaf3c.conformance.iqa`](https://rttp.com/open/?uri=rttp://94bbaf3c.conformance.iqa)
(the question side, WHERE + WHEN) and
[`iqa://94bbaf3c292abf69595bf5782d1db8cb.forge.iqa`](https://iqa.org/open/?uri=iqa://94bbaf3c292abf69595bf5782d1db8cb.forge.iqa)
(the answer side, WHETHER).
