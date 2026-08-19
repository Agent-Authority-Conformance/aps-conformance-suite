# Results

All 27 cases reproduce their pinned expectations. No case diverged.

| metric | value |
|---|---|
| cases | 27 |
| reproduced | 27 |
| divergent | 0 |
| composition pin | draft-mih-sato-agent-accountability-composition-00 |

## Digests recomputed independently

Both adapters recompute the manifest and bundle digests from the corpus bytes.
Both equal the values the pack's own external report template carries pre-filled.

| digest | value | matches pack pin |
|---|---|---|
| manifest_digest | `sha256:f2cdeb77e2337d25d387c5468e3b69c1cc7541aa0340c91a7a91ba063cc22575` | yes |
| bundle_digest | `sha256:a1c28295a87882a32360b5a5d3c00583c25b8627c0628a7fe0707f1c17aa9470` | yes |

## Two-run byte identity

Each adapter was run twice in the worktree. Digests recorded before and after.

```
results.json      (either adapter)  4720733963b29f9f416c674fea651aa81906a36add2e3884d78fd5b24cc68046
results-ts.json   (run 1 and run 2) fc8f5bcb11ce172637b32e8e23fe706759e769df0c7935dfd10148a78de7fa59
results-py.json   (run 1 and run 2) 2b16dea2463a21097c8ad4494196fbb76f49a53a08f19a59b874416ae977792d
```

results.json carries no toolchain and no adapter name, so both adapters write
it byte-identically. results-ts.json and results-py.json are identical to each
other once the toolchain and adapter fields are removed.

## Environment

| component | version |
|---|---|
| os | macOS 26.5 arm64 |
| node | v24.11.1 |
| tsx | v4.23.12 |
| python | 3.14.6 |

External dependencies: none in either adapter.

## Provenance

See PROVENANCE.md for the exact sources, commits and input digests.
See SCOPE.md for what is and is not exercised.
